#!/usr/bin/env python3
"""Independent struct/hashlib/hmac IKE_SA_INIT golden bytes; synthetic lab data."""
from pathlib import Path
import struct
import hashlib
import hmac
import ipaddress

folder = Path(__file__).parent
spii = bytes.fromhex('0102030405060708')
spir = bytes([2])*8
peer, local = '198.51.100.10', '192.0.2.1'
ni, nr = bytes(range(32)), bytes([3])*32
public_i = bytes.fromhex('dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c37725811805271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3')
public_r = bytes.fromhex('d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf6356fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab')
# One 36-byte proposal, three transforms, 256-bit AES key-length attribute.
sa = bytes.fromhex('0000002401010003 0300000c01000014800e0100 0300000802000005 0000000804000013')
def payload(next_kind, body):
    return struct.pack('!BBH', next_kind, 0, len(body)+4) + body
def nat(a, b, ip):
    return hashlib.sha1(a+b+ipaddress.ip_address(ip).packed+struct.pack('!H',500)).digest()
def notify(kind, data):
    return struct.pack('!BBH',0,0,kind)+data
def packet(b, flags, body, first):
    return spii+b+struct.pack('!BBBBII',first,0x20,34,flags,0,28+len(body))+body
def body(b, public, nonce, source, destination):
    return (payload(34,sa)+payload(40,struct.pack('!HH',19,0)+public)+payload(41,nonce)
            +payload(41,notify(16388,nat(spii,b,source)))+payload(0,notify(16389,nat(spii,b,destination))))
request = packet(bytes(8),8,body(bytes(8),public_i,ni,peer,local),33)
response = packet(spir,32,body(spir,public_r,nr,local,peer),33)
context=(b'harbor-ikev2-cookie-v1'+bytes(8)+struct.pack('!H',len(ni))+ni+spii
         +ipaddress.ip_address(peer).packed+struct.pack('!H',500)
         +ipaddress.ip_address(local).packed+struct.pack('!H',500))
cookie=bytes(8)+hmac.digest(bytes([1])*32,context,'sha256')
challenge=packet(bytes(8),32,payload(0,notify(16390,cookie)),41)
for name, data in [('request',request),('response',response),('cookie',challenge)]:
    (folder/(name+'.hex')).write_text('\n'.join(data[i:i+16].hex() for i in range(0,len(data),16))+'\n')
