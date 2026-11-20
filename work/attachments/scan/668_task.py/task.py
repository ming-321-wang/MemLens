import random
import os
from Crypto.Util.number import *
from gmpy2 import lcm, gcd
def exgcd(a, b):
    if b == 0: return 1, 0
    x, y = exgcd(b, a%b)
    return y, x - a//b*y


def get_k():
    while True:
        p = getPrime(512)
        q = getPrime(512)
        phi = (p - 1) * (q - 1)
        if gcd(p * q, phi) == 1:
            break
    n = p * q
    while True:
        g = random.randint(1, n * n)
        if gcd((g - 1) // n, n) == 1:
            break
    return (n, g), (p, q)


def Paillier_encode(m, g, n):
    while True:
        r = random.randint(1, n - 1)
        if gcd(r, n) == 1:
            break
    return (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)


def Paillier_decode(c, p, q, g, n):
    lam = lcm(p - 1, q - 1)
    mi = exgcd((pow(g, lam, n * n) - 1) // n, n)[0] % n
    return (pow(c, lam, n * n) - 1) // n * mi % n


pk, sk = get_k()
n, g = pk
p, q = sk
m1 = bytes_to_long(flag)
m2 = bytes_to_long(os.urandom(2) * 35)
c1 = Paillier_encode(m1, g, n)
c2 = Paillier_encode(m2, g, n)
print(f'c = {Paillier_decode(c1 * c2, p, q, g, n)}')

# c = 1426774899479339414711783875769670405758108494041927642533743607154735397076811133205075799614352194241060726689487117802867974494099614371033282640015883625484033889861