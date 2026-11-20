from Crypto.Util.number import getPrime, bytes_to_long
import math

FLAG = b'**************'


def generate_parameters(bit_length=512):
    p = getPrime(bit_length)
    q = getPrime(bit_length)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    s = p ** 4 + q ** 4
    return n, e, d, s, p, q


def main():
    n, e, d, s, p, q = generate_parameters()
    c = pow(bytes_to_long(FLAG), e, n)

    with open('output.txt', 'w') as f:
        f.write(f"n = {n}\n")
        f.write(f"e = {e}\n")
        f.write(f"c = {c}\n")
        f.write(f"s = {s}\n")

    print("[+] Parameters saved to output.txt")


if __name__ == "__main__":
    main()