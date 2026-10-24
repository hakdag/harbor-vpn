#!/usr/bin/env python3
"""Operator-run scoped IPv4 PoC rules. Never flushes chains or changes defaults."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess

STATE=Path('/run/harbor-iphone-poc')

def call(*args,check=True):
    return subprocess.run(args,check=check,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['setup','cleanup'])
    p.add_argument('--wan');p.add_argument('--server-ip');p.add_argument('--phone-ip')
    p.add_argument('--subnet',default='10.77.0.0/24')
    p.add_argument('--apply',action='store_true')
    p.add_argument('--restore-forwarding',action='store_true',help='cleanup: operator confirms no other service now depends on forwarding enabled by setup')
    args=p.parse_args()
    if args.action=='setup':
        if not args.wan or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',args.wan):p.error('reviewed --wan interface required')
        server=ipaddress.IPv4Address(args.server_ip);phone=ipaddress.IPv4Address(args.phone_ip)
        subnet=ipaddress.IPv4Network(args.subnet,strict=True)
        if not subnet.is_private or subnet.prefixlen!=24:p.error('use a conflict-free private /24 matching the configured pool')
        values={'wan':args.wan,'server':str(server),'phone':str(phone),'subnet':str(subnet)}
        operations=rules(values)
    else:
        if not STATE.is_dir() or STATE.is_symlink():p.error('no owned setup state')
        values=json.loads((STATE/'state.json').read_text());operations=values['operations']
    print(('Apply' if args.apply else 'Preview only')+': scoped '+args.action+'; '+str(len(operations))+' iptables operations')
    if not args.apply:return
    if os.geteuid()!=0:p.error('root required for operator networking changes')
    if args.action=='setup':
        # Existing named chains or state belong to an operator; never overwrite them.
        if STATE.exists():p.error('setup state exists; clean up/review first')
        for table,chain in [('filter','HVPOC_IN'),('filter','HVPOC_FWD'),('nat','HVPOC_NAT')]:
            if call('iptables','-t',table,'-S',chain,check=False).returncode==0:p.error('reserved chain exists: '+chain)
        call('ip','link','show','dev',values['wan'])
        STATE.mkdir(mode=0o700)
        os.chmod(STATE,0o700)
        values['forward_before']=Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()
        values['operations']=[]
        save(values)
        try:
            for op in operations:
                call('iptables','-w','5',*op)
                values['operations'].append(op);save(values)
            # Append explicit sysctl only after scoped forwarding/NAT rules exist.
            call('sysctl','-q','-w','net.ipv4.ip_forward=1')
            values['forward_changed']=values['forward_before']!='1';save(values)
        except Exception:
            print('Setup incomplete; owned successful operations retained in state; run cleanup.')
            raise
    else:
        if STATE.stat().st_uid!=0 or STATE.stat().st_mode&0o077:p.error('unsafe state directory')
        for op in reversed(operations):
            inverse=op.copy()
            if '-N' in inverse:inverse[inverse.index('-N')]='-X'
            elif '-I' in inverse:
                i=inverse.index('-I');inverse[i]='-D';del inverse[i+2] # remove insertion position
            else:inverse[inverse.index('-A')]='-D'
            call('iptables','-w','5',*inverse)
            values['operations'].pop();save(values)
        if args.restore_forwarding and values.get('forward_before')=='0':
            call('sysctl','-q','-w','net.ipv4.ip_forward=0')
        elif values.get('forward_before')=='0':
            print('Forwarding left enabled to preserve shared host state; after dependency review rerun cleanup --restore-forwarding --apply.')
            return
        (STATE/'state.json').unlink();STATE.rmdir()

def save(values):
    path=STATE/'state.json'
    flags=os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW
    fd=os.open(path,flags,0o600)
    with os.fdopen(fd,'w') as f:json.dump(values,f);f.flush();os.fsync(f.fileno())

def rules(v):
    s=v['subnet'];w=v['wan']
    return [
        ['-t','filter','-N','HVPOC_IN'],['-t','filter','-N','HVPOC_FWD'],['-t','nat','-N','HVPOC_NAT'],
        ['-t','filter','-A','HVPOC_IN','-j','ACCEPT'],
        ['-t','filter','-A','HVPOC_FWD','-s',s,'-o',w,'-m','policy','--dir','in','--pol','ipsec','--proto','esp','--mode','tunnel','-j','ACCEPT'],
        ['-t','filter','-A','HVPOC_FWD','-d',s,'-i',w,'-m','policy','--dir','out','--pol','ipsec','--proto','esp','--mode','tunnel','-j','ACCEPT'],
        ['-t','filter','-A','HVPOC_FWD','-s',s,'-j','DROP'],
        ['-t','filter','-A','HVPOC_FWD','-d',s,'-j','DROP'],
        ['-t','nat','-A','HVPOC_NAT','-s',s,'-o',w,'-m','policy','--dir','out','--pol','none','-j','MASQUERADE'],
        ['-t','filter','-I','INPUT','1','-d',v['server'],'-s',v['phone'],'-p','udp','-m','multiport','--dports','500,4500','-j','HVPOC_IN'],
        ['-t','filter','-I','FORWARD','1','-s',s,'-j','HVPOC_FWD'],
        ['-t','filter','-I','FORWARD','1','-d',s,'-j','HVPOC_FWD'],
        ['-t','nat','-I','POSTROUTING','1','-s',s,'-o',w,'-j','HVPOC_NAT'],
    ]

if __name__=='__main__':main()
