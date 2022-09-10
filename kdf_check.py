#!/usr/bin/env python3
from Crypto.Random import get_random_bytes
import json
import struct

from kdf import *

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def hkdf_check():
    data = [50.78, 49.93, 49.61, 49.13, 48.59, 48.1, 47.27, 46.5, 46.19, 47.12, 48.78, 50.17, 51.94, 54.27, 55.96,
            58.08, 59.5, 59.69, 58.03, 55.31, 53.09, 52.05, 51.43, 50.95, 50.39, 49.96, 49.6, 49.14, 48.73, 48.07,
            47.31, 46.47, 46.61, 47.8, 49.71, 51.76, 54.63, 57.87, 60.75, 62.53, 63.6, 63.55, 62.24, 59.63, 57.64,
            56.72, 56.26, 55.88, 55.4]
    XTS = get_random_bytes(32)
    SKM = bytes()
    for x in data:
        SKM += struct.pack("f", x)
    
    PRK = HkdfExtract(XTS, SKM)
    lastKey = None
    CTX = b'Dimarik'
    keys = []
    for i in range(1000):
        lastKey = HkdfExpand(PRK, lastKey, CTX, int_to_bytes(i))
        keys.append(lastKey)
    
    with open('data/hkdf_keys.txt', 'w') as file:
        for key in keys:
            file.write(key.hex() + '\n')

def pbkdf2_check():
    with open('data/passwords.json', 'r') as file:
        data = json.loads(file.read())
    
    XTS = get_random_bytes(32)
    keys = []
    for password in data:
        key = password.encode('ascii')
        keys.append(pbkdf2(key, XTS))
    
    with open('data/pbkdf2_keys.txt', 'w') as file:
        for key in keys:
            file.write(key.hex() + '\n')

if __name__ == '__main__':
    hkdf_check()
    pbkdf2_check()