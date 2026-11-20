# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, r'D:\MemLens')
from memlens.core.hashing import sm3, hash_bytes
v = sm3(b'abc').hex()
print('SM3(abc) =', v)
print('expect   = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
print('match', v == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
print('SM3(abcd*16) =', sm3(b'abcd' * 16).hex())
print('md5    ', hash_bytes(b'abc', ['md5'])['md5'])
print('sha256 ', hash_bytes(b'abc', ['sha256'])['sha256'])
print('sm3    ', hash_bytes(b'abc', ['sm3'])['sm3'])
