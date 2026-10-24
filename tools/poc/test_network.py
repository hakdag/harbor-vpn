#!/usr/bin/env python3
"""Real scoped-rule rollback smoke; fresh user/network namespace mandatory."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

parent=os.environ.get('POC_PARENT_NETNS')
if os.environ.get('POC_ISOLATED_XFRM_TEST')!='1' or not parent or parent==os.readlink('/proc/self/ns/net'):
    raise SystemExit('fresh isolated network namespace required')
spec=importlib.util.spec_from_file_location('poc_network',Path(__file__).with_name('network.py'))
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def call(*args):return subprocess.check_output(args,text=True)

with tempfile.TemporaryDirectory() as temp:
    module.STATE=Path(temp)/'state'
    call('iptables','-N','UNRELATED_POC_SENTINEL')
    before_filter=call('iptables-save','-t','filter')
    before_nat=call('iptables-save','-t','nat')
    # Compare rule declarations only; iptables-save headers contain wall-clock timestamps.
    normalize=lambda text:[line for line in text.splitlines() if not line.startswith('#')]
    before_forward=Path('/proc/sys/net/ipv4/ip_forward').read_text()
    sys.argv=['network.py','setup','--wan','lo','--server-ip','192.0.2.1','--phone-ip','192.0.2.2','--apply']
    module.main()
    assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()=='1'
    assert '-j HVPOC_NAT' in call('iptables-save','-t','nat')
    sys.argv=['network.py','cleanup','--apply','--restore-forwarding']
    module.main()
    assert normalize(call('iptables-save','-t','filter'))==normalize(before_filter)
    assert normalize(call('iptables-save','-t','nat'))==normalize(before_nat)
    assert Path('/proc/sys/net/ipv4/ip_forward').read_text()==before_forward
    assert not module.STATE.exists()
print('Scoped iptables/NAT setup and rollback preserve sentinel and prior forwarding: PASS')
