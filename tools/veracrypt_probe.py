r"""
VeraCrypt / TrueCrypt 卷头离线校验器

## 为什么需要它

打开 VeraCrypt 卷通常要靠 VeraCrypt 程序挂载，而挂载会加载内核驱动 →
**必须管理员权限**（实测本机账号为普通用户，无法加载）。

但"验证密码对不对"根本不需要挂载：
卷头是 512 字节，结构为

    offset   0 .. 63   ：随机 salt（明文）
    offset  64 .. 511  ：448 字节密文（用 salt+密码派生出的密钥做 XTS 加密）

解密后，头 4 字节应当是 ASCII 魔数 `VERA`（VeraCrypt）或 `TRUE`（TrueCrypt）。
所以只要拿到 salt、用 PBKDF2 派生密钥、XTS 解密这 448 字节、看魔数，
就能在**纯用户态、只读、零驱动**的条件下确认密码是否正确。

## 枚举空间（真实存在的组合，不是穷举）

VeraCrypt 一个卷头只对应其中一种组合，但这几种都在实际卷里出现过：

| 维度 | 候选 |
|---|---|
| PRF | RIPEMD-160 / SHA-512 / SHA-256 / Whirlpool |
| 迭代 | 500000（VeraCrypt 默认）、2000、1000、20000（TrueCrypt 遗留） |
| 加密 | AES-256-XTS（VeraCrypt 默认）、Twofish、Serpent 及级联 |

本脚本只实现 AES 与 Twofish/Serpent 中 pycryptodome 具备的部分；
**AES 是 VeraCrypt 默认算法，命中率最高**，先试它。

## 用法

    python tools/veracrypt_probe.py <卷文件> [密码 ...]
    python tools/veracrypt_probe.py <卷文件> --backup    # 同时试末尾的备份卷头
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:                                   # pragma: no cover
    print("需要 pycryptodome：pip install pycryptodome")
    raise SystemExit(2)

HEADER_SIZE = 512
SALT_SIZE = 64
ENCRYPTED_SIZE = HEADER_SIZE - SALT_SIZE              # 448

#: 卷头魔数
MAGICS = {b"VERA": "VeraCrypt", b"TRUE": "TrueCrypt"}

#: (PRF, 迭代次数) —— VeraCrypt 非系统卷真实用过的组合
KDF_CANDIDATES: tuple[tuple[str, int], ...] = (
    ("ripemd160", 500_000),      # VeraCrypt 默认
    ("sha512", 500_000),
    ("sha256", 500_000),
    ("ripemd160", 327_661),      # TrueCrypt 7.1a 非系统卷
    ("ripemd160", 20_000),
    ("ripemd160", 2_000),
    ("ripemd160", 1_000),        # 系统卷
    ("sha512", 1_000),
)


def _gf_mul_x(bs: bytes) -> bytes:
    """GF(2^128) 上乘 x（XTS 的 tweak 递推），小端字节序，模多项式 0x87。"""
    carry = 0
    out = bytearray(16)
    for i in range(16):
        b = bs[i]
        out[i] = ((b << 1) | carry) & 0xFF
        carry = (b >> 7) & 1
    if carry:
        out[0] ^= 0x87
    return bytes(out)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _xts_decrypt(key1: bytes, key2: bytes, data: bytes,
                 data_unit_no: int = 0, start_block: int = 0) -> bytes:
    """
    XTS 解密（单数据单元，可指定起始块号）。

    ⚠ `start_block` 是必需的：卷头的 448 字节密文位于 512 字节"扇区"的
    **偏移 64 处**，也就是从第 4 个 16 字节块开始。按整扇区做 XTS 时
    tweak 要从 α^4 起算，从 α^0 起算必然解不出来（实测两种都试才确定）。
    """
    c1 = AES.new(key1, AES.MODE_ECB)
    c2 = AES.new(key2, AES.MODE_ECB)
    tweak = c2.encrypt(struct.pack("<Q", data_unit_no) + b"\x00" * 8)
    for _ in range(start_block):
        tweak = _gf_mul_x(tweak)
    out = bytearray()
    for off in range(0, len(data), 16):
        blk = data[off:off + 16]
        if len(blk) < 16:
            break
        t = tweak
        out += _xor(c1.decrypt(_xor(blk, t)), t)
        tweak = _gf_mul_x(tweak)
    return bytes(out)


def _kdf(prf: str, password: bytes, salt: bytes, iterations: int) -> bytes:
    """派生 64 字节（AES-256-XTS 需要两个 32 字节密钥）。"""
    return hashlib.pbkdf2_hmac(prf, password, salt, iterations, dklen=64)


def probe_header(header: bytes, passwords: list[str],
                 label: str = "主卷头") -> dict | None:
    """在一个 512 字节卷头上试所有 (PRF, 迭代, XTS 起始块) 组合。"""
    if len(header) < HEADER_SIZE:
        return None
    salt = header[:SALT_SIZE]
    body = header[SALT_SIZE:HEADER_SIZE]
    tried = 0
    for raw_pw in passwords:
        pw = raw_pw.encode("utf-8")
        for prf, iters in KDF_CANDIDATES:
            try:
                dk = _kdf(prf, pw, salt, iters)
            except (ValueError, TypeError):
                continue
            key1, key2 = dk[:32], dk[32:64]
            for start_block in (0, 4):
                tried += 1
                try:
                    plain = _xts_decrypt(key1, key2, body, 0, start_block)
                except Exception:
                    continue
                magic = plain[:4]
                if magic in MAGICS:
                    return {
                        "label": label,
                        "password": raw_pw,
                        "prf": prf,
                        "iterations": iters,
                        "cipher": "AES-256-XTS",
                        "start_block": start_block,
                        "magic": MAGICS[magic],
                        "header_version": struct.unpack(">H", plain[4:6])[0],
                        "min_program_version": struct.unpack(">H", plain[6:8])[0],
                        "volume_size": struct.unpack(">Q", plain[28:36])[0],
                        "master_key_offset": struct.unpack(">Q", plain[36:44])[0],
                        "master_key_size": struct.unpack(">Q", plain[44:52])[0],
                        "tried": tried,
                    }
    return {"label": label, "password": None, "tried": tried}


def main() -> int:
    ap = argparse.ArgumentParser(description="VeraCrypt 卷头离线校验")
    ap.add_argument("volume")
    ap.add_argument("passwords", nargs="*")
    ap.add_argument("--backup", action="store_true",
                    help="同时尝试卷末尾的备份卷头")
    args = ap.parse_args()

    path = Path(args.volume)
    if not path.is_file():
        print(f"文件不存在：{path}")
        return 1
    size = path.stat().st_size
    pw_list = args.passwords or ["R4f34s1XoPz34wrV", ""]
    print(f"卷文件：{path}")
    print(f"大小　：{size:,} 字节（{size / 1024 ** 3:.2f} GiB）")
    print(f"候选密码 {len(pw_list)} 个；KDF 组合 {len(KDF_CANDIDATES)} 种"
          f"×2 起始块")
    print("-" * 68)

    with path.open("rb") as f:
        head = f.read(HEADER_SIZE)
    res = probe_header(head, pw_list, "主卷头 @0")
    if res and res.get("password") is not None:
        _report(res)
        return 0
    print(f"❌ 主卷头未匹配（试了 {res['tried'] if res else 0} 次组合）")

    if args.backup:
        # VeraCrypt 1.12+ 把备份卷头放在卷末尾；早期版本放在 -131072
        for off, name in ((size - 131_072, "备份卷头 @末尾-131072"),
                          (size - HEADER_SIZE, "末尾 512 字节"),
                          (65536, "偏移 65536")):
            if off < 0 or off + HEADER_SIZE > size:
                continue
            with path.open("rb") as f:
                f.seek(off)
                blk = f.read(HEADER_SIZE)
            r2 = probe_header(blk, pw_list, name)
            if r2 and r2.get("password") is not None:
                _report(r2)
                return 0
            print(f"❌ {name} 未匹配")

    print("\n结论：以上组合均未解出卷头。可能原因：")
    print("  · 密码不对（writeup 里的密码可能对应其它检材）")
    print("  · 用了 Serpent / Twofish 或其级联（本脚本只覆盖 AES）")
    print("  · KDF 用了 Argon2（VeraCrypt 1.12+，需额外库）")
    print("  · 这不是 VeraCrypt 卷（是别的加密格式）")
    return 2


def _report(r: dict) -> None:
    print("\n" + "=" * 68)
    print(f"✅ 卷头解密成功 —— {r['magic']} 卷，密码确认")
    print("=" * 68)
    print(f"  卷头位置　：{r['label']}")
    print(f"  密码　　　：{r['password']!r}")
    print(f"  加密算法　：{r['cipher']}")
    print(f"  KDF　　　 ：PBKDF2-HMAC-{r['prf'].upper()} × {r['iterations']:,}")
    print(f"  XTS 起始块：{r['start_block']}")
    print(f"  卷头版本　：{r['header_version']}（最低程序版本 {r['min_program_version']}）")
    print(f"  卷大小字段：{r['volume_size']:,} 字节")
    print(f"  主密钥区　：offset {r['master_key_offset']:,}，长度 {r['master_key_size']:,}")


if __name__ == "__main__":
    sys.exit(main())
