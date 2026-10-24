#!/usr/bin/env python3
"""Synthetic Linux data-plane test; refuses parent network namespace. No host rules."""
import os
import subprocess
import sys
from pathlib import Path

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)

def client_setup(binary):
    run('ip','link','set','lo','up')
    run('ip','link','set','poc-peer','up')
    run('ip','addr','add','192.0.2.2/24','dev','poc-peer')
    run('ip','addr','add','10.77.0.10/32','dev','lo')
    run('ip','addr','add','10.77.0.11/32','dev','lo')
    run('ip','route','add','default','via','192.0.2.1')
    for src,dst,spi,key in [('192.0.2.2','192.0.2.1','0x1000','07'),('192.0.2.1','192.0.2.2','0x1001','08')]:
        run('ip','xfrm','state','add','src',src,'dst',dst,'proto','esp','spi',spi,'reqid','2','mode','tunnel','replay-window','32','aead','rfc4106(gcm(aes))','0x'+key*36,'128','encap','espinudp','4500','4500','0.0.0.0')
    for direction,src,dst,outer_src,outer_dst in [('out','10.77.0.0/24','0.0.0.0/0','192.0.2.2','192.0.2.1'),('in','0.0.0.0/0','10.77.0.10/32','192.0.2.1','192.0.2.2')]:
        run('ip','xfrm','policy','add','dir',direction,'src',src,'dst',dst,'tmpl','src',outer_src,'dst',outer_dst,'proto','esp','reqid','2','mode','tunnel')
    subprocess.run([binary,'client'],check=True)

def main():
    original=os.environ.get('POC_PARENT_NETNS')
    if os.environ.get('POC_ISOLATED_XFRM_TEST')!='1' or not original or original==os.readlink('/proc/self/ns/net'):
        raise SystemExit('Run only under fresh unshare --user --map-root-user --net, passing parent namespace')
    if len(sys.argv)==3 and sys.argv[1]=='client':
        sys.stdin.buffer.read(1)
        client_setup(sys.argv[2]);return
    binary=str(Path('src/target/debug/examples/kernel_echo').resolve())
    run('ip','link','set','lo','up')
    run('ip','link','add','poc-server','type','veth','peer','name','poc-peer')
    client=subprocess.Popen(['unshare','--net',sys.executable,__file__,'client',binary],stdin=subprocess.PIPE)
    server=None
    try:
        # Wait for the child namespace to differ, with a strict bound.
        import time
        for _ in range(100):
            if os.readlink(f'/proc/{client.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
            time.sleep(.01)
        else:raise RuntimeError('child namespace setup timeout')
        run('ip','link','set','poc-peer','netns',str(client.pid))
        run('ip','link','set','poc-server','up')
        run('ip','addr','add','192.0.2.1/24','dev','poc-server')
        run('ip','addr','add','203.0.113.1/32','dev','lo')
        run('ip','route','add','10.77.0.10/32','via','192.0.2.2')
        server=subprocess.Popen([binary,'server'],stdout=subprocess.PIPE,text=True)
        import select
        if not select.select([server.stdout],[],[],5)[0] or server.stdout.readline().strip()!='ready':raise RuntimeError('server not ready')
        client.stdin.write(b'1');client.stdin.close()
        if client.wait(timeout=10)!=0:raise RuntimeError('client failed')
        if server.wait(timeout=10)!=0:raise RuntimeError('server failed')
        print('Rust XFRM adapter / independent iproute2 peer encrypted round trip: PASS')
    finally:
        for process in [client,server]:
            if process and process.poll() is None:process.kill();process.wait()
        # Namespace destruction removes only this synthetic test's interfaces/state.

if __name__=='__main__':main()
