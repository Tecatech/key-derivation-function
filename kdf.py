from Crypto.Random import get_random_bytes

import hashlib
import struct

trans_5C = bytes((x ^ 0x5C) for x in range(256))
trans_36 = bytes((x ^ 0x36) for x in range(256))

def HmacSha256(key, data):
    outer = hashlib.sha256()
    inner = hashlib.sha256()
    
    key = key.ljust(inner.block_size, b'\0')
    outer.update(key.translate(trans_5C))
    inner.update(key.translate(trans_36))
    
    inner.update(data)
    outer.update(inner.digest())
    return outer.digest()

def HkdfExtract(XTS, SKM):
    return HmacSha256(XTS, SKM)

def HkdfExpand(PRK, lastKey, CTX, i):
    if lastKey is None:
        lastKey = b''
    return HmacSha256(PRK, lastKey + CTX + i)

def pbkdf2_function(key, XTS, count, i):
    r = u = HmacSha256(key, XTS + struct.pack(">i", i))
    for i in range(2, count + 1):
        u = HmacSha256(key, u)
        r = bytes(i ^ j for i, j in zip(r, u))
    return r

def pbkdf2(key, XTS, count = 10000, dk_length = 64):
    dk, h_length = b'', hashlib.sha256().digest_size
    blocks = (dk_length // h_length) + (1 if dk_length % h_length else 0)
    for i in range(1, blocks + 1):
        dk += pbkdf2_function(key, XTS, count, i)
    return dk[:dk_length]