#!/usr/bin/env python3
"""Independent stdlib HMAC reference for RFC 7296 schedule; public test data."""
import hashlib
import hmac
import json
from pathlib import Path

shared = bytes.fromhex('d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de')
ni, nr = bytes(range(32)), bytes(range(32, 64))
spii, spir = bytes.fromhex('0102030405060708'), bytes.fromhex('1112131415161718')
skeyseed = hmac.digest(ni + nr, shared, 'sha256')
seed = ni + nr + spii + spir
previous, material = b'', b''
for i in range(1, 7):
    previous = hmac.digest(skeyseed, previous + seed + bytes([i]), 'sha256')
    material += previous
reference = {'skeyseed': skeyseed.hex(), 'material': material[:168].hex(),
             'nat_source': hashlib.sha1(spii + bytes(8) + bytes([192, 0, 2, 10]) + (500).to_bytes(2,'big')).hexdigest()}
Path(__file__).with_name('schedule.json').write_text(json.dumps(reference, indent=2) + '\n')
