r"""
MemLens · VeraCrypt 卷用户态读取器（零驱动、零管理员）

## 为什么不用 VeraCrypt 挂载

挂载要加载内核驱动 ⇒ 必须管理员。实际环境里操作员账号常常不是管理员
（本机实测即如此），此时**取证就卡住了**——但取证根本不需要"挂载"，
只需要"能按偏移解密读取"。

## 原理

VeraCrypt 卷的结构（非系统卷）：

    offset 0        .. 511      卷头（0..63 是 salt 明文，64..511 是密文）
    offset 131072   ..          加密数据区（EncryptedAreaStart）

解密流程：

    1. 用 (密码, salt, PBKDF2) 派生卷头密钥 → XTS 解密卷头
    2. 校验魔数 `VERA`；读出 **主密钥**（256 字节，AES 用前 64 字节）
    3. 数据区按 **512 字节数据单元** 做 XTS 解密：
           data_unit_no = (offset - EncryptedAreaStart) // 512
       同一个数据单元内，块的 tweak 序列是固定的 —— 见下面的加速说明

## 加速：为什么不能一个块一个块地 XOR

朴素写法是每个 16 字节块在 Python 里做一次 `bytes(a ^ b for ...)`，
512 字节就是 32 次 Python 级循环 —— 实测只有 1~2 MB/s，读几 MB 都要等。

这里改成**整数级 XOR**：把整个数据单元和整串 tweak 各自 `int.from_bytes`
成一个大整数，一次 `^` 完成（C 速度），再交给 pycryptodome 的 ECB 一次性解密。
实测提升到几十 MB/s —— 足以按需读取引导扇区、MFT、以及单个文件。
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:                      # pragma: no cover
    np = None                           # type: ignore
    _HAS_NUMPY = False

HEADER_SIZE = 512
SALT_SIZE = 64
ENCRYPTED_HEADER_SIZE = HEADER_SIZE - SALT_SIZE
DATA_UNIT = 512
MAGIC_VERA = b"VERA"
MAGIC_TRUE = b"TRUE"

#: 卷头派生用的 (PRF, 迭代) 候选 —— 与 veracrypt_probe 保持一致
KDF_CANDIDATES: tuple[tuple[str, int], ...] = (
    ("ripemd160", 500_000), ("sha512", 500_000), ("sha256", 500_000),
    ("ripemd160", 327_661), ("ripemd160", 20_000), ("ripemd160", 2_000),
    ("ripemd160", 1_000), ("sha512", 1_000),
)

_MASK128 = (1 << 128) - 1


# ------------------------------------------------------------------ XTS

def _xts_decrypt_batch(ct: bytes, start_dun: int, c1: AES, c2: AES) -> bytes:
    """
    ★ 批量 XTS 解密（一次解多个数据单元）。

    为什么需要它：逐扇区解密时，每 512 字节要做
    「1 次 AES(取 tweak 种子) + 32 次 GF(2^128) 乘法 + 2 次大整数 XOR」，
    Python 层的循环直接把吞吐压到 **~4 MB/s** —— 读 15.9 GB 的 vmdk 要 68 分钟。

    批量化后：
      · 所有 tweak 种子用**一次** AES-ECB 批量算（pycryptodome 走 C）
      · GF 乘法用 numpy 向量化（每步 16 次 numpy 运算，整批一起做）
      · 密文与 tweak 的 XOR 用 numpy 整块做
      · 数据用**一次** AES-ECB 批量解密
    实测吞吐从 ~4 MB/s 提升到 ~90 MB/s（见 tools/bench_vcrypt.py）。

    依赖 numpy（已在依赖里）；没有 numpy 时自动退回逐扇区实现。
    """
    if not _HAS_NUMPY:
        out = bytearray()
        for i in range(0, len(ct), DATA_UNIT):
            dun = start_dun + i // DATA_UNIT
            out += _xts_decrypt_unit(ct[i:i + DATA_UNIT], dun, c1, c2)
        return bytes(out)

    n_units = len(ct) // DATA_UNIT
    if n_units == 0:
        return ct
    body = ct[:n_units * DATA_UNIT]

    # ① tweak 种子：一次 ECB 批量加密
    seeds = c2.encrypt(b"".join(
        struct.pack("<Q", start_dun + i) + b"\x00" * 8 for i in range(n_units)))

    # ② 每个数据单元 32 个 tweak（GF 递推，向量化）
    t = np.frombuffer(seeds, dtype=np.uint8).reshape(n_units, 16).copy()
    tweaks = np.empty((n_units, 32, 16), dtype=np.uint8)
    for j in range(32):
        tweaks[:, j, :] = t
        carry = np.zeros(n_units, dtype=np.uint8)
        for i in range(16):
            b = t[:, i].copy()
            t[:, i] = ((b << 1) | carry) & 0xFF
            carry = (b >> 7) & 1
        t[:, 0] ^= (carry * 0x87) & 0xFF

    # ③ XOR + ④ 一次批量 AES 解密 + ⑤ XOR 回去
    buf = np.frombuffer(body, dtype=np.uint8).reshape(n_units, 32, 16).copy()
    buf ^= tweaks
    dec = c1.decrypt(buf.reshape(-1).tobytes())
    out = np.frombuffer(dec, dtype=np.uint8).reshape(n_units, 32, 16).copy()
    out ^= tweaks
    return out.reshape(-1).tobytes()


def _xts_decrypt_unit(ct: bytes, dun: int, c1: AES, c2: AES) -> bytes:
    """
    解密一个数据单元（512 字节），整数级 XOR 加速。

    Args:
        ct: 密文（必须是 512 的整数倍，或正好一个单元）
        dun: data unit number
        c1: 数据密钥的 ECB 实例
        c2: tweak 密钥的 ECB 实例
    """
    n = len(ct) // 16
    # tweak 种子 = E_k2(data_unit_no)（128 位小端）
    seed = c2.encrypt(struct.pack("<Q", dun) + b"\x00" * 8)
    t = int.from_bytes(seed, "little")
    tw = bytearray()
    for _ in range(n):
        tw += t.to_bytes(16, "little")
        carry = t >> 127
        t = (t << 1) & _MASK128
        if carry:
            t ^= 0x87
    twi = int.from_bytes(bytes(tw), "little")
    x = (int.from_bytes(ct, "little") ^ twi).to_bytes(len(ct), "little")
    dec = c1.decrypt(x)
    return (int.from_bytes(dec, "little") ^ twi).to_bytes(len(ct), "little")


# ------------------------------------------------------------------ 卷对象

class VeraCryptVolume:
    """只读的 VeraCrypt 卷（按偏移解密读取）。"""

    def __init__(self, path: str | Path, password: str, *,
                 pkcs5_prf: str | None = None, iterations: int | None = None,
                 hidden: bool = False) -> None:
        self.path = Path(path)
        self.size = self.path.stat().st_size
        self.hidden = hidden
        self.opened = False
        self.info: dict[str, Any] = {}
        self._fh = self.path.open("rb")
        self._cache: dict[int, bytes] = {}
        self._cache_order: list[int] = []
        self._open(password, pkcs5_prf, iterations)

    # -------------------------------------------------------------- 打开
    def _open(self, password: str, prf: str | None, iters: int | None) -> None:
        with self.path.open("rb") as f:
            head = f.read(HEADER_SIZE)
        combos = [(prf, iters)] if (prf and iters) else list(KDF_CANDIDATES)
        pw = password.encode("utf-8")
        salt = head[:SALT_SIZE]
        body = head[SALT_SIZE:HEADER_SIZE]
        for p, it in combos:
            try:
                dk = hashlib.pbkdf2_hmac(p, pw, salt, it, dklen=64)
            except (ValueError, TypeError):
                continue
            c1 = AES.new(dk[:32], AES.MODE_ECB)
            c2 = AES.new(dk[32:64], AES.MODE_ECB)
            plain = _xts_decrypt_unit(body, 0, c1, c2)
            if plain[:4] in (MAGIC_VERA, MAGIC_TRUE):
                self._parse_header(plain)
                self.info.update({"pkcs5_prf": p, "iterations": it,
                                  "cipher": "AES-256-XTS",
                                  "format": "VeraCrypt" if plain[:4] == MAGIC_VERA
                                            else "TrueCrypt"})
                # ★ 数据区必须用**卷头里的主密钥**解密，不是用卷头派生密钥！
                #   （我第一版把 dk 直接当数据密钥，解密出来全是乱码。）
                mk = self.master_keys
                if not any(mk):
                    raise ValueError("卷头已解开但主密钥区全零 —— 偏移解析有误")
                self._mk1, self._mk2 = mk[0:32], mk[32:64]
                self._c1 = AES.new(self._mk1, AES.MODE_ECB)
                self._c2 = AES.new(self._mk2, AES.MODE_ECB)
                self.opened = True
                return
        raise ValueError("卷头解密失败：密码错误，或 KDF 组合不在候选集内")

    def _parse_header(self, plain: bytes) -> None:
        """
        解析已解密的 448 字节卷头。

        ⚠ 字段偏移容易搞错（我第一版就读偏了 8 字节，把"主密钥区偏移"
        读成了"卷大小"）。权威布局：

            +0   magic(4)   +4 版本(2)  +6 最低程序版本(2)  +8 CRC(4)
            +12  保留(16)
            +28  隐藏卷大小(8)
            +36  卷大小(8)
            +44  主密钥区起始偏移(8)
            +52  主密钥区加密长度(8)
            +60  标志(1)  +61 扇区大小(1)
            +256 主密钥（256 字节）
        """
        self.info.update({
            "header_version": struct.unpack(">H", plain[4:6])[0],
            "min_program_version": struct.unpack(">H", plain[6:8])[0],
            "hidden_volume_size": struct.unpack(">Q", plain[28:36])[0],
            "volume_size": struct.unpack(">Q", plain[36:44])[0],
            "encrypted_area_start": struct.unpack(">Q", plain[44:52])[0],
            "encrypted_area_length": struct.unpack(">Q", plain[52:60])[0],
            "flags": plain[60],
            "sector_size": plain[61] * 512 if plain[61] else 512,
        })
        # ⚠ 偏移换算：VeraCrypt 头里的 TC_HEADER_OFFSET_MASTER_KEYDATA = 256
        #   是**相对卷起点**的；已解密的 448 字节从卷偏移 64 开始，
        #   所以主密钥在解密缓冲里的偏移是 256 - 64 = 192（实测踩过：
        #   直接读 256 会拿到 192 字节的全零尾巴，解密出来全是乱码）。
        #   主密钥区共 256 字节，单一算法只占前 64 字节，其余为零填充。
        self.master_keys = plain[192:448]

    # -------------------------------------------------------------- 读取
    @property
    def data_start(self) -> int:
        return int(self.info.get("encrypted_area_start") or 131072)

    def read(self, offset: int, length: int) -> bytes:
        """
        从**加密数据区**读取 length 字节（offset 相对数据区起点）。

        ★ 数据单元编号用的是**卷内绝对扇区号**，不是"相对数据区起点"的扇区号。
          也就是说数据区首扇区的 dun = EncryptedAreaStart / 512 = 256，**不是 0**。
          这一点极容易搞错：按 dun=0 解出来的字节看着也是"随机"，不会报错，
          但整片数据都是错的 —— 实测就是卡在这里，最后靠暴力枚 (k1,k2,dun)
          找引导扇区尾签名 `55 AA` 才定位到。
        """
        if not self.opened:
            raise RuntimeError("卷未打开")
        # 直接读加密跨度 + 一次整体批量解密（numpy 对大数组效率高，见 _xts_decrypt_batch）。
        # 注意 data_unit_no 是"卷内绝对扇区号"，见上方说明。
        abs_off = self.data_start + offset          # ← 绝对偏移
        start_dun = abs_off // DATA_UNIT
        in_unit = abs_off % DATA_UNIT
        n_units = (in_unit + length + DATA_UNIT - 1) // DATA_UNIT
        abs_read = start_dun * DATA_UNIT
        self._fh.seek(abs_read)
        ct = self._fh.read(n_units * DATA_UNIT)
        if len(ct) % DATA_UNIT:
            ct = ct[:len(ct) - (len(ct) % DATA_UNIT)]
        pt = _xts_decrypt_batch(ct, start_dun, self._c1, self._c2)
        return pt[in_unit:in_unit + length]

    #: 批量解密块大小（数据单元数）—— 256 = 128 KiB
    BATCH_UNITS = 256

    def _batch(self, dun: int) -> bytes:
        """取一个**批量解密块**（BATCH_UNITS 个数据单元），带缓存。"""
        hit = self._cache.get(dun)
        if hit is not None:
            return hit
        abs_off = dun * DATA_UNIT
        self._fh.seek(abs_off)
        ct = self._fh.read(self.BATCH_UNITS * DATA_UNIT)
        if len(ct) < DATA_UNIT:
            return b""
        if len(ct) % DATA_UNIT:
            ct = ct[:len(ct) - (len(ct) % DATA_UNIT)]
        pt = _xts_decrypt_batch(ct, dun, self._c1, self._c2)
        self._cache[dun] = pt
        self._cache_order.append(dun)
        while len(self._cache_order) > 64:          # 64 × 128 KiB = 8 MiB
            self._cache.pop(self._cache_order.pop(0), None)
        return pt

    def _unit(self, dun: int) -> bytes:
        """按**卷内绝对扇区号**取一个已解密数据单元。"""
        base = (dun // self.BATCH_UNITS) * self.BATCH_UNITS
        blk = self._batch(base)
        if not blk:
            return b""
        off = (dun - base) * DATA_UNIT
        return blk[off:off + DATA_UNIT]

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass

    def __enter__(self) -> "VeraCryptVolume":
        return self

    def __exit__(self, *a) -> None:
        self.close()

    # -------------------------------------------------------------- 摘要
    def summary(self) -> dict[str, Any]:
        i = dict(self.info)
        import hashlib as _h
        i.update({"file_size": self.size,
                  "data_start": self.data_start,
                  "master_key_sha256": _h.sha256(self.master_keys[:64]).hexdigest()[:32],
                  "master_key_nonzero": sum(1 for b in self.master_keys if b)})
        return i

    # -------------------------------------------------------------- 文件系统
    def identify_fs(self) -> dict[str, Any]:
        """读数据区首扇区，识别文件系统。"""
        boot = self.read(0, 512)
        res: dict[str, Any] = {"oem": boot[3:11].decode("ascii", "replace").strip()}
        if boot[:3] == b"\xeb\x52\x90" or res["oem"] == "NTFS":
            res["fs"] = "NTFS"
            res["bytes_per_sector"] = struct.unpack("<H", boot[11:13])[0]
            res["sectors_per_cluster"] = boot[13]
            res["mft_cluster"] = struct.unpack("<Q", boot[48:56])[0]
            res["mftmirr_cluster"] = struct.unpack("<Q", boot[56:64])[0]
            res["total_sectors"] = struct.unpack("<Q", boot[40:48])[0]
        elif boot[82:90] == b"FAT32   " or boot[54:62] == b"FAT16   ":
            res["fs"] = "FAT"
        elif boot[3:11] == b"EXFAT   ":
            res["fs"] = "exFAT"
            res["bytes_per_sector"] = 1 << boot[108]
            res["sectors_per_cluster"] = 1 << boot[109]
            res["cluster_count"] = struct.unpack("<I", boot[92:96])[0]
            res["root_cluster"] = struct.unpack("<I", boot[96:100])[0]
        elif boot[3:11].startswith(b"MSDOS"):
            res["fs"] = "FAT"
        elif boot[:2] == b"BM":
            res["fs"] = "BMP(位图，说明偏移不对)"
        else:
            # 全零 / 全 FF 通常意味着这不是文件系统起始
            nz = sum(1 for b in boot if b)
            res["fs"] = "unknown"
            res["nonzero_bytes"] = nz
            res["head_hex"] = boot[:48].hex()
        return res
