# -*- coding: utf-8 -*-
"""MemLens · 哈希工具箱（MD5 / SHA-1 / SHA-256 / SM3）

CarveScope 底座含 MD5/SHA-1/SHA-256/SM3 四件套；MemLens 之前散落各处用
hashlib，没有统一入口。这里补一个统一 API：流式分块计算、零第三方依赖
（SM3 纯 Python 流式实现），供 `memlens hash` 命令与 Web 复用。

SM3（GB/T 32905-2016）为标准 256-bit 哈希，此处实现为增量式（分块喂入，
不整块缓冲），可对 70 GiB 级镜像流式计算。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable, Iterator

_ALGOS = ("md5", "sha1", "sha256", "sm3")

_M = 0xFFFFFFFF
_IV = (0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
       0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E)


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _M


def _p0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _ff(j: int, x: int, y: int, z: int) -> int:
    return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))


def _gg(j: int, x: int, y: int, z: int) -> int:
    return (x ^ y ^ z) if j < 16 else ((x & y) | (~x & z))


def _sm3_compress(v: list[int], blk: bytes) -> list[int]:
    """GB/T 32905-2016 标准压缩函数（64 轮）。"""
    w = [int.from_bytes(blk[j * 4:j * 4 + 4], "big") for j in range(16)]
    for j in range(16, 68):
        w.append(_p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
                 ^ _rotl(w[j - 13], 7) ^ w[j - 6])
    w1 = [w[j] ^ w[j + 4] for j in range(64)]
    a, b, c, d, e, f, g, h = v
    for j in range(64):
        t_j = 0x79CC4519 if j < 16 else 0x7A879D8A
        ss1 = _rotl((_rotl(a, 12) + e + _rotl(t_j, j % 32)) & _M, 7)
        ss2 = ss1 ^ _rotl(a, 12)
        tt1 = (_ff(j, a, b, c) + d + ss2 + w1[j]) & _M
        tt2 = (_gg(j, e, f, g) + h + ss1 + w[j]) & _M
        d, c, b, a = c, _rotl(b, 9), a, tt1
        h, g, f, e = g, _rotl(f, 19), e, _p0(tt2)
    return [
        a ^ v[0], b ^ v[1], c ^ v[2], d ^ v[3],
        e ^ v[4], f ^ v[5], g ^ v[6], h ^ v[7],
    ]


class SM3:
    """增量 SM3：update() 喂字节，hexdigest() 收尾。"""

    def __init__(self) -> None:
        self._v = list(_IV)
        self._buf = bytearray()
        self._bitlen = 0

    def update(self, data: bytes) -> None:
        self._buf.extend(data)
        self._bitlen += len(data) * 8
        while len(self._buf) >= 64:
            self._v = _sm3_compress(self._v, bytes(self._buf[:64]))
            del self._buf[:64]

    def digest(self) -> bytes:
        pad = bytearray(self._buf)
        pad.append(0x80)
        while len(pad) % 64 != 56:
            pad.append(0)
        pad += self._bitlen.to_bytes(8, "big")
        v = list(self._v)
        for i in range(0, len(pad), 64):
            v = _sm3_compress(v, bytes(pad[i:i + 64]))
        return b"".join(x.to_bytes(4, "big") for x in v)

    def hexdigest(self) -> str:
        return self.digest().hex()


def sm3(data: bytes) -> bytes:
    """一次性 SM3。"""
    h = SM3()
    h.update(data)
    return h.digest()


def _chunks(reader: Callable[[int, int], bytes], total: int,
            chunk: int = 4 << 20) -> Iterator[bytes]:
    off = 0
    while off < total:
        n = min(chunk, total - off)
        yield reader(off, n)
        off += n


def hash_reader(reader: Callable[[int, int], bytes], total: int,
                algos: list[str] | None = None,
                progress_cb: Callable[[int, int], None] | None = None) -> dict[str, str]:
    """对 [0,total) 字节流算哈希。reader(off,n)->bytes。返回 {algo: hex}。"""
    algos = algos or list(_ALGOS)
    hs: dict[str, Any] = {}
    for a in algos:
        hs[a] = SM3() if a == "sm3" else hashlib.new(a)
    done = 0
    for chunk in _chunks(reader, total):
        for h in hs.values():
            h.update(chunk)
        done += len(chunk)
        if progress_cb:
            progress_cb(done, total)
    return {a: h.hexdigest() for a, h in hs.items()}


def hash_file(path: str | Path, algos: list[str] | None = None,
              progress_cb: Callable[[int, int], None] | None = None) -> dict[str, str]:
    p = Path(path)
    size = p.stat().st_size

    def _read(off: int, n: int) -> bytes:
        with p.open("rb") as f:
            f.seek(off)
            return f.read(n)

    return hash_reader(_read, size, algos, progress_cb)


def hash_bytes(data: bytes, algos: list[str] | None = None) -> dict[str, str]:
    def _read(off: int, n: int) -> bytes:
        return data[off:off + n]

    return hash_reader(_read, len(data), algos)


def hash_sha256_upper(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


__all__ = ["SM3", "sm3", "hash_reader", "hash_file", "hash_bytes",
           "hash_sha256_upper", "_ALGOS"]
