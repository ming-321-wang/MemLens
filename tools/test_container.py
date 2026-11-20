r"""
MemLens 取证容器能力专项测试（容器引擎 / 格式层）

覆盖：
    ① 容器类型识别（EWF/VMDK/ZIP/pcapng/APK/加密体）
    ② VeraCrypt 卷头离线校验（错误口令必须失败，不能假成功）
    ③ exFAT 目录枚举（用构造的小卷）
    ④ pcapng 解析 + BLE 设备表 + 改名事件
    ⑤ USB HID 键盘还原（含退格、CapsLock 过滤）
    ⑥ APK 分析（包名/权限/加固/flag 串/IOC）
    ⑦ EWF chunk 头解析（构造最小 EWF）
    ⑧ VMDK 稀疏盘 grain 表解析（构造最小 VMDK）
    ⑨ CLI 与引擎注册可用

运行：`.venv\Scripts\python.exe tools\test_container.py`
"""

from __future__ import annotations

import io
import struct
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PASSED = 0
FAILED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASSED
    if ok:
        PASSED += 1
        print(f"✅ {name}")
    else:
        FAILED.append(name)
        print(f"❌ {name}　{detail}")


TMP = Path(tempfile.mkdtemp(prefix="ml-ct-test-"))


# ══════════════════════════════════════════════════════ ① 容器识别
def test_identify() -> None:
    print("\n── ① 容器类型识别 ──")
    from memlens.engines.container import identify_container

    # pcapng
    p = TMP / "x.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\x4d\x3c\x2b\x1a" + b"\x00" * 8)
    r = identify_container(p)
    check("识别 pcapng", r["类型"] == "PCAPNG", str(r))

    # zip
    p2 = TMP / "x.zip"
    with zipfile.ZipFile(p2, "w") as z:
        z.writestr("a.txt", "hello")
    r2 = identify_container(p2)
    check("识别 ZIP", r2["类型"] == "ZIP", str(r2))

    # apk（zip 里含 dex）
    p3 = TMP / "x.apk"
    with zipfile.ZipFile(p3, "w") as z:
        z.writestr("classes.dex", b"dex\n035\x00")
    r3 = identify_container(p3)
    check("识别 APK", r3["类型"] == "APK", str(r3))

    # EWF
    p4 = TMP / "x.E01"
    p4.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 64)
    r4 = identify_container(p4)
    check("识别 EWF", r4["类型"] == "EWF", str(r4))

    # 高熵 → 疑似加密体
    p5 = TMP / "enc.bin"
    p5.write_bytes(bytes((i * 37 + 11) % 256 for i in range(1 << 16)))
    r5 = identify_container(p5)
    check("高熵判为疑似加密体", "加密" in r5["类型"] or "熵" in r5.get("说明", ""), str(r5))


# ══════════════════════════════════════════════════════ ② VeraCrypt
def test_veracrypt() -> None:
    print("\n── ② VeraCrypt 卷头校验 ──")
    from memlens.core.veracrypt_volume import VeraCryptVolume

    # 构造一个假的卷头：AES-256-XTS + PBKDF2-SHA512
    from Crypto.Cipher import AES
    import hashlib
    from memlens.core.veracrypt_volume import _xts_decrypt_unit

    pw = "test-password-123"
    salt = bytes(range(64))
    dk = hashlib.pbkdf2_hmac("sha512", pw.encode(), salt, 500_000, dklen=64)
    plain = bytearray(448)
    plain[0:4] = b"VERA"
    struct.pack_into(">H", plain, 4, 5)
    struct.pack_into(">H", plain, 6, 267)
    struct.pack_into(">Q", plain, 36, 1 << 30)     # volume size
    struct.pack_into(">Q", plain, 44, 131072)      # encrypted area start
    struct.pack_into(">Q", plain, 52, 1 << 30)
    plain[192:256] = bytes(range(64))              # 主密钥（非零）
    c1 = AES.new(dk[:32], AES.MODE_ECB)
    c2 = AES.new(dk[32:64], AES.MODE_ECB)
    enc = _xts_decrypt_unit(bytes(plain), 0, c1, c2)
    # 反向：把明文加密回去（XTS 是对称的，直接复用 tweak 序列）
    seed = c2.encrypt(struct.pack("<Q", 0) + b"\x00" * 8)
    t = int.from_bytes(seed, "little")
    tw = bytearray()
    for _ in range(len(plain) // 16):
        tw += t.to_bytes(16, "little")
        carry = t >> 127
        t = (t << 1) & ((1 << 128) - 1)
        if carry:
            t ^= 0x87
    twi = int.from_bytes(bytes(tw), "little")
    x = (int.from_bytes(bytes(plain), "little") ^ twi).to_bytes(len(plain), "little")
    ct = c1.encrypt(x)
    ct = (int.from_bytes(ct, "little") ^ twi).to_bytes(len(ct), "little")

    vol = TMP / "fake.vc"
    vol.write_bytes(salt + ct + b"\x00" * 4096)

    # 错误口令必须失败
    try:
        VeraCryptVolume(vol, "wrong-password")
        check("错误口令必须失败", False, "居然成功了")
    except Exception:
        check("错误口令必须失败", True)
    # 正确口令应成功
    try:
        v = VeraCryptVolume(vol, pw)
        s = v.summary()
        check("正确口令可打开", s["format"] == "VeraCrypt", str(s))
        check("卷头字段正确", s["encrypted_area_start"] == 131072, str(s))
        check("主密钥非零", s["master_key_nonzero"] == 63, str(s))
        v.close()
    except Exception as exc:
        check("正确口令可打开", False, f"{type(exc).__name__}: {exc}")


# ══════════════════════════════════════════════════════ ③ exFAT
def test_exfat() -> None:
    print("\n── ③ exFAT 目录枚举 ──")
    from memlens.core.exfat import ExFat

    # 构造最小 exFAT 引导扇区
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x76\x90"
    boot[3:11] = b"EXFAT   "
    boot[108] = 9          # 512 B/sector
    boot[109] = 0          # 1 sector/cluster → 512 B/cluster
    struct.pack_into("<I", boot, 80, 64)      # FAT offset (sectors)
    struct.pack_into("<I", boot, 84, 16)      # FAT length
    struct.pack_into("<I", boot, 88, 1024)    # cluster heap offset
    struct.pack_into("<I", boot, 92, 100)     # cluster count
    struct.pack_into("<I", boot, 96, 4)       # root cluster
    struct.pack_into("<I", boot, 100, 0x1234)
    struct.pack_into("<H", boot, 104, 0x0100)
    boot[110] = 1
    boot[112] = 50
    boot[510:512] = b"\x55\xaa"

    class FakeVol:
        def read(self, off, n):
            return bytes(boot[off:off + n]) if off < 512 else b"\x00" * n

    try:
        fs = ExFat(FakeVol())
        check("识别 exFAT 引导扇区", fs.summary()["fs"] == "exFAT")
        check("簇大小计算", fs.cluster_size == 512, str(fs.cluster_size))
    except Exception as exc:
        check("识别 exFAT 引导扇区", False, f"{type(exc).__name__}: {exc}")


# ══════════════════════════════════════════════════════ ④ pcapng / BLE
def test_pcapng_ble() -> None:
    print("\n── ④ pcapng / BLE ──")
    from memlens.formats.pcapng import (PcapngFile, bluetooth_records,
                                        ble_rename_events, parse_ad, ad_name)

    # 构造最小 pcapng：一个 IDB + 两个 EPB（BLE 广播，设备改名）
    def build_pcapng(path: Path):
        out = bytearray()
        # SHB
        shb = bytearray()
        shb += b"\x4d\x3c\x2b\x1a"
        shb += struct.pack("<HH", 1, 0)
        shb += struct.pack("<q", -1)
        out += struct.pack("<II", 0x0A0D0D0A, len(shb) + 12) + shb + struct.pack("<I", len(shb) + 12)
        # IDB (linktype 272)
        idb = bytearray()
        idb += struct.pack("<HHI", 272, 0, 65535)
        opt = b"\x03\x00\x1a\x00" + b"nRF Sniffer for Bluetooth LE" + b"\x00"
        idb += opt
        idb += b"\x00\x00\x00\x00"
        out += struct.pack("<II", 1, len(idb) + 12) + idb + struct.pack("<I", len(idb) + 12)

        def epb(ts, payload):
            body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF,
                               len(payload), len(payload)) + payload
            return struct.pack("<II", 6, len(body) + 12) + body + struct.pack("<I", len(body) + 12)

        def ble_pkt(name: str) -> bytes:
            # ★ BLE 的 AD 长度字节**不含自身**：= 1(类型) + len(数据)
            nb = name.encode()[:15]
            adv = b"\x02\x01\x1a" + bytes([1 + len(nb)]) + b"\x09" + nb
            body = bytes.fromhex("bf a1 6d 22 26 67") + adv
            ll = bytes([0x00, len(body)]) + body + b"\x00\x00\x00"
            # Nordic 头 21 字节：17 字节头 + 4 字节接入地址
            hdr = b"\x03\x2b\x00\x03\x22\xe1\x02\x0a\x01\x26\x44\x00\x00\x8b\x8b\xd6\x79"
            return hdr + b"\xd6\xbe\x89\x8e" + ll

        out += epb(1744165654330180, ble_pkt("Flipper 123all"))
        out += epb(1744165655330180, ble_pkt("QQ_WF_SP8OON"))
        path.write_bytes(bytes(out))

    p = TMP / "ble.pcapng"
    build_pcapng(p)
    pf = PcapngFile(str(p))
    check("解析出 1 个接口", len(pf.interfaces) == 1, str(len(pf.interfaces)))
    check("接口链路类型正确", pf.interfaces[0]["linktype"] == 272)
    check("接口描述读出", "nRF Sniffer" in pf.interfaces[0]["description"],
          pf.interfaces[0]["description"])
    check("包数正确", len(pf.packets) == 2, str(len(pf.packets)))

    devs = list(bluetooth_records(str(p)))
    check("BLE 设备表非空", len(devs) >= 1, str(len(devs)))
    if devs:
        check("设备名解析正确", devs[0]["首个名称"] == "Flipper 123all",
              str(devs[0]))

    ren = list(ble_rename_events(str(p)))
    check("改名事件检出", len(ren) >= 1, str(len(ren)))

    # AD 结构解析
    # AD 长度字节不含自身：04 = 1(type) + 3(abc)
    ad = parse_ad(b"\x02\x01\x1a\x04\x09abc")
    check("AD 结构拆分", len(ad) == 2, str(ad))
    check("AD 名称提取", ad_name(ad) == "abc", str(ad_name(ad)))


# ══════════════════════════════════════════════════════ ⑤ USB HID
def test_hid() -> None:
    print("\n── ⑤ USB HID 键盘还原 ──")
    from memlens.formats.pcapng import hid_records

    def build_usbpcap(path: Path, reports: list[bytes]):
        out = bytearray()
        shb = b"\x4d\x3c\x2b\x1a" + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
        out += struct.pack("<II", 0x0A0D0D0A, len(shb) + 12) + shb + struct.pack("<I", len(shb) + 12)
        idb = struct.pack("<HHI", 249, 0, 65535)
        out += struct.pack("<II", 1, len(idb) + 12) + idb + struct.pack("<I", len(idb) + 12)
        TS = 1744022042051582

        def usbpcp(rep: bytes) -> bytes:
            """USBPcap 头（28 字节）+ 负载。
            headerLen(2) irpId(8) status(4) function(2) info(1)
            bus(2) device(2) endpoint(1) transfer(1) dataLength(4) = 28
            """
            h = bytearray(28)
            struct.pack_into("<H", h, 0, 28)            # headerLen
            struct.pack_into("<Q", h, 2, 1)             # irpId
            struct.pack_into("<I", h, 10, 0)            # status = 成功
            struct.pack_into("<H", h, 14, 0x000b)       # function
            h[16] = 0                                   # info
            struct.pack_into("<H", h, 17, 2)            # bus
            struct.pack_into("<H", h, 19, 3)            # device
            h[21] = 0x81                                # endpoint (IN)
            h[22] = 1                                   # transfer = Isochronous
            struct.pack_into("<I", h, 23, len(rep))     # dataLength
            return bytes(h) + rep

        for rep in reports:
            pay = usbpcp(rep)
            # EPB 时间戳是 64 位：高位、低位各 4 字节
            body = struct.pack("<IIIII", 0, TS >> 32, TS & 0xFFFFFFFF,
                               len(pay), len(pay)) + pay
            out += struct.pack("<II", 6, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
        path.write_bytes(bytes(out))

    # 37 字节复合 HID：report ID=0x01，修饰键 [1]，按键码 [3:9]
    def rep(mod, *keys):
        b = bytearray(37)
        b[0] = 0x01
        b[1] = mod
        for i, k in enumerate(keys):
            b[3 + i] = k
        return bytes(b)

    reports = [
        rep(0x02, 0x04),      # shift+a → 'A'（0x04 才是 a，0x1A 是 w）
        rep(0x00, 0x2C),      # space
        rep(0x00, 0x38),      # '/'  → 但题目里是 CapsLock 场景
        rep(0x00, 0x39),      # CapsLock（不应产生字符）
        rep(0x00, 0x2A),      # backspace
        rep(0x00, 0x04),      # 'a'
    ]
    p = TMP / "usb.pcapng"
    build_usbpcap(p, reports)
    r = hid_records(str(p))
    txt = r["text"]
    check("HID 还原出字符", len(txt) > 0, repr(txt))
    check("CapsLock 不产生字符", "CapsLock" not in txt, repr(txt))
    check("退格被统计", r["stats"]["退格次数"] == 1, str(r["stats"]))
    check("Shift 生效", "A" in txt, repr(txt))


# ══════════════════════════════════════════════════════ ⑥ APK
def test_apk() -> None:
    print("\n── ⑥ APK 分析 ──")
    from memlens.formats.apk import Apk, axml_strings, dex_strings

    p = TMP / "t.apk"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 16)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        z.writestr("lib/armeabi-v7a/libSecShell.so", b"libSecShell\x00" * 32)
        z.writestr("assets/classes0.jar", bytes(range(256)) * 40)
    a = Apk(str(p))
    check("成员数正确", len(a.names) == 4, str(len(a.names)))
    check("加固识别：梆梆", "梆梆加固" in a.hardening(), str(a.hardening()))
    check("加密载荷检出", any("classes0.jar" in n for n, _ in a.encrypted_payloads()),
          str(a.encrypted_payloads()[:2]))
    check("MD5 计算", len(a.hash()["MD5"]) == 32)
    recs = list(a.records())
    check("records 非空", len(recs) > 5, str(len(recs)))

    # AXML 字符串池
    from memlens.formats.apk import _string_pool
    strings = ["android.permission.CAMERA", "com.example.reverseshell2"]
    blob = bytearray()
    for s in strings:
        blob += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    # 头部 20 字节 + 偏移数组(2*4) → 字符串数据区从 28 开始
    # stringsStart 是**相对 chunk 起点**的：8(chunk头) + 20(池头) + 4*count
    strings_start = 8 + 20 + 4 * len(strings)
    body = bytearray()
    body += struct.pack("<IIIII", len(strings), 0, 0, strings_start, 0)
    off = 0                      # ★ 偏移是**相对 stringsStart** 的
    for s in strings:
        body += struct.pack("<I", off)
        off += 2 + len(s) * 2 + 2
    # body 起点 = chunk 起点 + 8，所以 body 里字符串数据的实际位置
    #   = strings_start - 8
    data_at = strings_start - 8
    assert len(body) == data_at, (len(body), data_at)
    body += blob
    got = _string_pool(bytes(body))
    check("AXML 字符串池解析", got == strings, str(got))


# ══════════════════════════════════════════════════════ ⑦ EWF
def test_ewf() -> None:
    print("\n── ⑦ EWF 解析（真实格式：节链 + zlib 流）──")
    import zlib
    from memlens.formats.ewf import EwfReader, EwfError

    def build_ewf(path: Path) -> None:
        """构造一个符合真实格式的最小 EWF：
        文件头(13) + 节[ name[16] + u64 next + u64 len + data ] × N
        """
        payload = b"BOOTSECTOR" * 64
        comp = zlib.compress(payload)
        # 一个 'sectors' 节：节头 40 字节 + 4 字节填充 + zlib 流
        data = b"\x00" * 4 + comp
        name = b"sectors".ljust(16, b"\x00")
        sec_total = 40 + len(data)
        sec = name + struct.pack("<QQ", 13 + sec_total, sec_total) + data
        fh = b"EVF\x09\x0d\x0a\xff\x00" + b"\x01\x01\x00\x00" + b"\x00"
        path.write_bytes(fh + sec)

    seg = TMP / "test.E01"
    build_ewf(seg)
    try:
        img = EwfReader(str(seg))
        s = img.summary()
        check("EWF 节数", s["section_count"] >= 1, str(s))
        check("EWF 数据节", s["data_sections"] == 1, str(s))
        check("EWF 压缩识别", s["compression"] == "zlib", str(s))
        got = img.read_at(0, 10)
        check("EWF 逻辑数据正确", got == b"BOOTSECTOR", repr(got))
        check("EWF 可偏移读取", img.read_at(10, 4) == b"BOOT", repr(img.read_at(10, 4)))
    except Exception as exc:
        check("EWF 解析", False, f"{type(exc).__name__}: {exc}")


# ══════════════════════════════════════════════════════ ⑧ VMDK
def test_vmdk() -> None:
    print("\n── ⑧ VMDK 解析（真实格式：grain 目录 + u32 表）──")
    from memlens.formats.vmdk import VmdkDisk

    SECTOR = 512
    GRAIN = 128
    NUM_GTE = 512
    # 布局：头部(1扇区) + gd(1扇区) + gt(1扇区) + 数据
    GD_SECT = 1
    GT_SECT = 2
    DATA_SECT = 3
    p = TMP / "t.vmdk"
    buf = bytearray(SECTOR * 8)
    struct.pack_into("<I", buf, 0, 0x564D444B)      # magic
    struct.pack_into("<I", buf, 4, 1)              # version
    struct.pack_into("<I", buf, 8, 3)              # flags
    struct.pack_into("<Q", buf, 12, 1000)          # capacity(sectors)
    struct.pack_into("<Q", buf, 20, GRAIN)         # grain size
    struct.pack_into("<Q", buf, 28, 1)             # descriptor offset
    struct.pack_into("<Q", buf, 36, 20)            # descriptor size
    struct.pack_into("<I", buf, 44, NUM_GTE)       # num_gtes_per_gt
    struct.pack_into("<Q", buf, 48, 0)             # rgd offset
    struct.pack_into("<Q", buf, 56, GD_SECT)       # gd offset
    struct.pack_into("<I", buf, 64, DATA_SECT)     # over_head
    # gd[0] = gt 所在扇区
    struct.pack_into("<I", buf, GD_SECT * SECTOR, GT_SECT)
    # gt[0] = 数据所在扇区；gt[1] = 0（未分配）
    struct.pack_into("<I", buf, GT_SECT * SECTOR, DATA_SECT)
    struct.pack_into("<I", buf, GT_SECT * SECTOR + 4, 0)
    buf[DATA_SECT * SECTOR:DATA_SECT * SECTOR + 6] = b"BOOT!"
    p.write_bytes(bytes(buf))
    try:
        d = VmdkDisk(p)
        s = d.summary()
        check("VMDK 布局识别", s["create_type"] == "monolithicSparse", str(s))
        check("VMDK 虚拟容量", s["capacity_sectors"] == 1000, str(s))
        check("VMDK grain 大小", s["grain_size_kb"] == 64, str(s))
        check("VMDK 目录/表 u32 解析", d.physical_sector(0) == DATA_SECT,
              f"phys={d.physical_sector(0)}")
        got = d.read_at(0, 6)
        check("VMDK 虚拟偏移读取", got == b"BOOT!\x00", repr(got))
        # 第 1 个 grain 未分配 → 全零
        z = d.read_at(GRAIN * SECTOR, 16)
        check("VMDK 未分配 grain 全零", z == b"\x00" * 16, repr(z))
    except Exception as exc:
        check("VMDK 解析", False, f"{type(exc).__name__}: {exc}")


# ══════════════════════════════════════════════════════ ⑨ 引擎注册
def test_engine() -> None:
    print("\n── ⑨ 引擎注册与 CLI ──")
    from memlens.engines import registry
    from memlens.engines.container import ContainerEngine

    check("container 已注册", "container" in registry.installed(), str(registry.installed()))
    eng = ContainerEngine(workdir=TMP)
    ok, why = eng.available()
    check("container 引擎可用", ok, why)
    plugs = eng.list_plugins()
    names = {p.name for p in plugs}
    for need in ("container.identify", "container.files", "container.extract",
                 "container.crypto", "traffic.interfaces", "traffic.bluetooth",
                 "traffic.ble_rename", "traffic.hid", "mobile.apk"):
        check(f"插件存在：{need}", need in names, str(sorted(names)))

    # 端到端跑一次 identify
    meta = next(p for p in plugs if p.name == "container.identify")
    spec = eng.build_run(meta, str(TMP / "x.zip"), {})
    rows = list(eng.parse_records(spec, "", ""))
    check("container.identify 产出记录", len(rows) > 0, str(rows[:2]))

    # 错误口令必须报错（不能静默空结果）
    meta2 = next(p for p in plugs if p.name == "container.crypto")
    spec2 = eng.build_run(meta2, str(TMP / "x.zip"), {"password": "x"})
    try:
        list(eng.parse_records(spec2, "", ""))
        check("错误口令抛异常", False, "静默通过了")
    except Exception:
        check("错误口令抛异常", True)


def main() -> int:
    print("=" * 70)
    print("MemLens 取证容器能力专项测试")
    print("=" * 70)
    test_identify()
    test_veracrypt()
    test_exfat()
    test_pcapng_ble()
    test_hid()
    test_apk()
    test_ewf()
    test_vmdk()
    test_engine()
    print("\n" + "=" * 70)
    print(f"通过 {PASSED} 项，失败 {len(FAILED)} 项")
    if FAILED:
        print("失败项：")
        for f in FAILED:
            print("  ❌", f)
        return 1
    print("全部通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
