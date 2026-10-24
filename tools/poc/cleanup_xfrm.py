#!/usr/bin/env python3
"""Operator crash reconciliation: exact ESP states/policies in a reserved reqid range."""
import argparse
import ipaddress
import re
import subprocess

def blocks(what):
    # iproute2 releases do not consistently implement JSON for XFRM. This output
    # includes keys: keep it in process memory, never print/store it or errors with it.
    text=subprocess.check_output(['ip','-s','-d','xfrm',what],text=True)
    return [block for block in re.split(r'(?m)(?=^src )',text) if block.strip()]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reqid-start',type=int,default=65536)
    p.add_argument('--apply',action='store_true')
    args=p.parse_args()
    if not 65536<=args.reqid_start<=0xffff0000:p.error('invalid reserved range')
    def ours(reqid):return args.reqid_start<=reqid<args.reqid_start+65536
    commands=[];state_count=0;policy_count=0
    for block in blocks('policy'):
        reqids=[int(r) for r in re.findall(r'\breqid (\d+)\b',block)]
        if not any(ours(r) for r in reqids):continue
        if not all(ours(r) for r in reqids):raise RuntimeError('mixed policy ownership')
        index=re.search(r'\bindex (0x[0-9a-fA-F]+|\d+)\b',block)
        direction=re.search(r'\bdir (in|out|fwd)\b',block)
        if not index or not direction:raise RuntimeError('unsupported policy display format; no wildcard deletion')
        commands.append(['ip','xfrm','policy','delete','index',index[1],'dir',direction[1]])
        policy_count+=1
    for block in blocks('state'):
        reqid=re.search(r'\breqid (\d+)\b',block)
        if not reqid or not ours(int(reqid[1])):continue
        identity=re.search(r'\bproto esp spi (0x[0-9a-fA-F]+)\b',block)
        if not identity:raise RuntimeError('unsupported owned state display format; no wildcard deletion')
        address=re.match(r'src (\S+) dst (\S+)\s',block)
        if not address:raise RuntimeError('unsupported state display format; no wildcard deletion')
        src=str(ipaddress.IPv4Address(address[1]));dst=str(ipaddress.IPv4Address(address[2]))
        commands.append(['ip','xfrm','state','delete','src',src,'dst',dst,'proto','esp','spi',identity[1]])
        state_count+=1
    print(f'Owned candidates: {state_count} ESP states, {policy_count} policies. Stop daemon first. '+('Deleting.' if args.apply else 'Preview only.'))
    if args.apply:
        for command in commands:subprocess.run(command,check=True)

if __name__=='__main__':main()
