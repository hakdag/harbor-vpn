"""Independent Python hmac/struct + PyCA reference. Synthetic inputs only.
RSA private key is generated in memory and never written. Tests consume frozen
public-key/signature output; regenerating changes those two fields together.
"""
import hashlib
import hmac
import json
from pathlib import Path
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def mac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

ni, nr, shared = bytes([2])*32, bytes([3])*32, bytes([1])*32
seed = ni + nr + struct.pack('!QQ', 1, 2)
skeyseed = mac(ni+nr, shared)
material = b''
previous = b''
for counter in range(1, 7):
    previous = mac(skeyseed, previous + seed + bytes([counter]))
    material += previous
material = material[:168]
inner = bytes.fromhex('0000000c0b000000') + b'User'
plain = inner + b'\0'
iv = bytes(range(1,9))
length = 28+4+8+len(plain)+16
header = struct.pack('!QQBBBBII', 1, 2, 46, 0x20, 35, 8, 1, length)
sk_header = struct.pack('!BBH', 35, 0, length-28)
aad = header+sk_header
wire = aad+iv+AESGCM(material[32:64]).encrypt(material[64:68]+iv, plain, aad)
initial = b'synthetic INIT response'
id_body = bytes([2,0,0,0])+b'vpn.hypervault.biz'
signed = initial+ni+mac(material[136:168], id_body)
private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
signature = private.sign(signed, padding.PKCS1v15(), hashes.SHA256())
algorithm = bytes.fromhex('0f300d06092a864886f70d01010b0500')
msk = bytes(range(64))
# RFC 2759/3079 published PasswordHashHash and NT-Response; SHA-1 composition
# is calculated independently of the Rust verifier/provider.
hh = bytes.fromhex('41c00c584bd2d91c4017a2a12fa59f3f')
nt = bytes.fromhex('82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df')
master = hashlib.sha1(hh+nt+b'This is the MPPE Master Key').digest()[:16]
recv = hashlib.sha1(master+bytes(40)+b'On the client side, this is the send key; on the server side, it is the receive key.'+bytes([0xf2])*40).digest()[:16]
send = hashlib.sha1(master+bytes(40)+b'On the client side, this is the receive key; on the server side, it is the send key.'+bytes([0xf2])*40).digest()[:16]
result = {
    'rfc3079_msk_hex': (recv+send+bytes(32)).hex(),
    'synthetic_inputs': 'shared=01*32, Ni=02*32, Nr=03*32, SPIi=1, SPIr=2; no production secrets',
    'protected_ike_hex': wire.hex(),
    'signed_octets_hex': signed.hex(),
    'signature_auth_hex': (algorithm+signature).hex(),
    'public_key_pem': private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
    'final_auth_hex': mac(mac(msk,b'Key Pad for IKEv2'),signed).hex(),
}
Path(__file__).with_name('auth-reference.json').write_text(json.dumps(result,indent=2)+'\n')
