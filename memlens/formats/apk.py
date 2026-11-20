r"""
MemLens · APK / 二进制 AXML / DEX 解析

## AndroidManifest.xml 是二进制 AXML

不是文本！直接当文本读只能看到乱码。它的结构：

    RES_XML_TYPE(0x0003) 头 → 字符串池(0x0001) → 资源ID块(0x0180) → XML节点

字符串池里所有字符串都是**明文**（UTF-8 或 UTF-16LE，由 flags 的 0x100 位决定），
所以只要把池子抽出来，package 名、权限、receiver/service 名就都到手了，
不必完整还原 XML 树。

## DEX 字符串池

dex 头部 `string_ids_size` / `string_ids_off` 指向一串偏移，
每个偏移处是 uleb128 长度 + MUTF-8 字符串。

## 加固识别

梆梆(SecShell) / 360(jiagu) / 腾讯乐固 / 阿里聚安全 / 爱加密 … 的特征库。
加固壳通常把**真正的 dex 加密后放在 assets/classes0.jar**，
并把 AndroidManifest.xml 也处理掉——这时静态看不到业务逻辑，只能脱壳。
"""

from __future__ import annotations

import hashlib
import re
import struct
import zipfile
from typing import Any, Iterator

#: 加固特征库：特征串 → 加固厂商
HARDENING_SIGNATURES: dict[str, str] = {
    "libSecShell": "梆梆加固",
    "libDexHelper": "梆梆加固",
    "libjiagu": "360 加固",
    "libjiagu_art": "360 加固",
    "libmobisec": "阿里聚安全",
    "libsgmain": "阿里聚安全",
    "libshella": "腾讯乐固",
    "libshellx": "腾讯乐固",
    "libtup": "腾讯乐固",
    "libnesec": "网易易盾",
    "libexec.so": "爱加密",
    "ijiami": "爱加密",
    "libbaiduprotect": "百度加固",
    "libnqshield": "网秦",
    "libkwscmm": "几维安全",
    "kiwisec": "几维安全",
    "libchaosvmp": "娜迦加固",
    "libDexProtector": "DexProtector",
    "libAppShield": "顶象",
}

#: 常见危险权限（木马判定辅助）
DANGEROUS_PERMISSIONS: tuple[str, ...] = (
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.INTERNET",
)


# ─────────────────────────────────────────────────────── AXML 字符串池
def axml_strings(data: bytes) -> list[str]:
    """从二进制 AXML 抽字符串池。"""
    if len(data) < 8:
        return []
    try:
        typ, hsize, _size = struct.unpack_from("<HHI", data, 0)
    except struct.error:
        return []
    if typ != 0x0003:
        return []
    pos = hsize
    while pos + 8 <= len(data):
        ctype, chs, csz = struct.unpack_from("<HHI", data, pos)
        if csz == 0 or pos + csz > len(data):
            break
        if ctype == 0x0001:
            # ★ 字符串池 chunk 的 headerSize = 28（8 字节 chunk 头 + 20 字节池头），
            #   但**池头紧跟在 8 字节 chunk 头之后**。
            #   所以这里只能跳过 8 字节，用 data[pos+chs:] 会把池头整段跳掉，
            #   count/flags/stringsStart 全读成偏移数组里的垃圾 → 解析结果为空。
            #   （实测踩过：真实 AndroidManifest.xml 解析出 0 条字符串。）
            return _string_pool(data[pos + 8:pos + csz])
        pos += csz
    return []


def _string_pool(body: bytes) -> list[str]:
    if len(body) < 28:
        return []
    scount, style_count, flags, sstart, _styles = struct.unpack_from("<IIIII", body, 0)
    utf8 = bool(flags & 0x100)
    if scount > 200000:
        return []
    # ★ 偏移数组的位置：字符串池 chunk 的布局是
    #     [chunk 头 8 字节][池头 20 字节][偏移数组][字符串数据]
    #   本函数收到的 body 已经去掉了 8 字节 chunk 头，
    #   所以偏移数组在 body[20]，不是 body[28]（实测踩过：解析结果为空）。
    try:
        offs = struct.unpack_from("<%dI" % scount, body, 20) if scount else ()
    except struct.error:
        return []
    # ★ stringsStart 按 AOSP 规范是**相对 chunk 起点**的偏移，
    #   而本函数的 body 已经去掉了 8 字节 chunk 头 → 基址 = stringsStart - 8。
    #   偏移数组里的值又是**相对 stringsStart** 的，三者叠加才是最终位置。
    #   实测踩过：把 stringsStart 当 body 相对，整池字符串全部错位。
    #   为兼容个别工具写成 body 相对的情况，这里做一次**可读性校验 + 回退**。
    def _base_ok(b: int) -> bool:
        if not (0 <= b <= len(body)) or not offs:
            return False
        p0 = b + offs[0]
        if p0 + 2 > len(body):
            return False
        n0 = struct.unpack_from("<H", body, p0)[0]
        return 0 < n0 < 0x8000 and p0 + 2 + n0 * 2 <= len(body) + 2

    cands = [sstart - 8, sstart, 20 + 4 * scount + 4 * style_count]
    base = next((b for b in cands if _base_ok(b)), cands[0])
    out: list[str] = []
    for off in offs:
        p = base + off
        if p >= len(body):
            continue
        try:
            if utf8:
                n = body[p]
                p += 2 if (n & 0x80) else 1
                n = body[p]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | body[p + 1]
                    p += 1
                p += 1
                out.append(body[p:p + n].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from("<H", body, p)[0]
                p += 2
                if n & 0x8000:
                    n2 = struct.unpack_from("<H", body, p)[0]
                    n = ((n & 0x7FFF) << 16) | n2
                    p += 2
                out.append(body[p:p + n * 2].decode("utf-16-le", "replace"))
        except Exception:
            continue
    return out


# ─────────────────────────────────────────────── resources.arsc
def arsc_strings(data: bytes) -> list[str]:
    """抽 resources.arsc 的全局字符串池（用于解析 @string/xxx 形式的 label）。"""
    if len(data) < 12:
        return []
    try:
        typ, hsize, _size = struct.unpack_from("<HHI", data, 0)
    except struct.error:
        return []
    if typ != 0x0002:                    # RES_TABLE_TYPE
        return []
    pos = hsize
    while pos + 8 <= len(data):
        ctype, chs, csz = struct.unpack_from("<HHI", data, pos)
        if csz < 8 or pos + csz > len(data):
            break
        if ctype == 0x0001:
            return _string_pool(data[pos + 8:pos + csz])
        pos += csz
    return []


# ─────────────────────────────────────────────── AXML 树解析
#: AXML 节点类型
NODE_START_NS = 0x0100
NODE_END_NS = 0x0101
NODE_START_ELEM = 0x0102
NODE_END_ELEM = 0x0103
NODE_CDATA = 0x0104
NODE_RESOURCE_MAP = 0x0180

#: typedValue 的 dataType
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_BOOLEAN = 0x12


def axml_tree(data: bytes) -> dict[str, Any]:
    """
    解析二进制 AXML 的 XML 树。

    ★ 为什么必须解析树而不是只取字符串池：
      字符串池里**属性名和属性值混在一起**（"minSdkVersion"、"versionCode"、
      "android.hardware.camera.autofocus" 全在里面），
      只按字符串猜"哪个是包名/应用名"必然误判（实测踩过）。
      真正的答案在 <manifest package="…"> 与 <application android:label="…">
      这两个**元素属性**上，必须顺着节点结构去取。

    返回：
        package / label / permissions / components / strings
    """
    out: dict[str, Any] = {
        "package": "", "label": "", "label_ref": "",
        "permissions": [], "components": [], "strings": [],
        "activities": [], "services": [], "receivers": [], "providers": [],
    }
    if len(data) < 8:
        return out
    try:
        _t, hsize, _sz = struct.unpack_from("<HHI", data, 0)
    except struct.error:
        return out
    if struct.unpack_from("<H", data, 0)[0] != 0x0003:
        return out

    strings: list[str] = []
    resmap: list[int] = []
    pos = hsize
    ns_prefix: dict[int, str] = {}      # 命名空间 URI 索引 → 前缀

    while pos + 8 <= len(data):
        ctype, chs, csz = struct.unpack_from("<HHI", data, pos)
        if csz < 8 or pos + csz > len(data):
            break
        if ctype == 0x0001:                                # 字符串池
            strings = _string_pool(data[pos + 8:pos + csz])
        elif ctype == NODE_RESOURCE_MAP:
            body = data[pos + 8:pos + csz]
            n = len(body) // 4
            resmap = list(struct.unpack_from("<%dI" % n, body, 0)) if n else []
        elif ctype == NODE_START_NS:
            body = data[pos + 8:pos + csz]
            # ★ 命名空间节点布局：lineNumber(0) comment(4) prefix(8) uri(12)
            #   读成 body[0]/body[4] 会把 lineNumber 当 prefix、comment 当 uri，
            #   结果 ns_prefix 整个错位 —— 属性名被加上错误前缀，
            #   表现为包名/权限"明明在却取不到"（实测踩过：'icon:package'）。
            if len(body) >= 16:
                prefix, uri = struct.unpack_from("<II", body, 8)
                if prefix < len(strings) and uri < len(strings):
                    ns_prefix[uri] = strings[prefix]
        elif ctype == NODE_START_ELEM:
            body = data[pos + 8:pos + csz]
            # lineNumber(4) comment(4) ns(4) name(4) attrStart(2) attrSize(2)
            # attrCount(2) idIndex(2) classIndex(2) styleIndex(2)
            if len(body) < 36:
                pos += csz
                continue
            ns_i, name_i = struct.unpack_from("<II", body, 8)
            # ★ 属性头字段在 body[16]，不是 body[20] ——
            #   body 布局：lineNumber(0) comment(4) ns(8) name(12)
            #            attributeStart(16) attributeSize(18) attributeCount(20)
            #            idIndex(22) classIndex(24) styleIndex(26)
            #   读错位置会拿到 idIndex/classIndex/styleIndex，
            #   表现为 attributeCount=0 —— 整棵树的属性全部丢失（实测踩过）。
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", body, 16)
            elem = strings[name_i] if name_i < len(strings) else ""
            # 属性数组基址：规范说 attributeStart 相对节点起点，
            # 但各版本工具写法不一（实测有 20 / 36 两种）。
            # 这里**用数据校验**选一个能解出合法字符串索引的基址，
            # 而不是赌某一种约定（赌错 = 属性全丢）。
            def _attr_base_ok(b: int) -> bool:
                if b < 0 or b + 20 > len(body):
                    return False
                a_ns2, a_name2, a_raw2 = struct.unpack_from("<III", body, b)
                if not (0 < a_name2 < max(1, len(strings))):
                    return False
                if a_raw2 != 0xFFFFFFFF and a_raw2 >= len(strings):
                    return False
                if struct.unpack_from("<H", body, b + 12)[0] != 8:   # typedValue.size
                    return False
                return True

            # ★ 实测：属性数组起点是 body[28]（固定头 28 字节），
            #   与 header 里的 attributeStart(=20) **不是同一个约定**。
            #   不同工具写法不一，所以用数据校验挑一个能解出合法属性名的基址，
            #   而不是赌某一种（赌错 = 属性全丢，表现为包名/权限全空）。
            cands = [28, 16 + attr_start, attr_start, 36]
            base = next((b for b in cands if _attr_base_ok(b)), 28)
            attrs: list[tuple[str, str]] = []
            for k in range(attr_count):
                off = base + k * attr_size
                if off + 20 > len(body):
                    break
                a_ns, a_name, a_raw = struct.unpack_from("<III", body, off)
                a_type = body[off + 15]
                a_data = struct.unpack_from("<I", body, off + 16)[0]
                aname = strings[a_name] if a_name < len(strings) else ""
                prefix = ns_prefix.get(a_ns)
                if prefix:
                    aname = f"{prefix}:{aname}"
                if a_raw != 0xFFFFFFFF and a_raw < len(strings):
                    aval = strings[a_raw]
                elif a_type == TYPE_STRING and a_data < len(strings):
                    aval = strings[a_data]
                elif a_type == TYPE_INT_BOOLEAN:
                    aval = "true" if a_data else "false"
                else:
                    aval = ""
                attrs.append((aname, aval))

            def _get(*names: str) -> str:
                """取属性值：先按全名匹配，再按**本地名**匹配（忽略命名空间前缀）。"""
                for n in names:
                    for an, av in attrs:
                        if an == n:
                            return av
                for n in names:
                    for an, av in attrs:
                        if an.split(":")[-1] == n:
                            return av
                return ""

            if elem == "manifest":
                out["package"] = _get("package")
            elif elem == "application":
                lbl = _get("android:label")
                if lbl.startswith("@"):
                    out["label_ref"] = lbl
                else:
                    out["label"] = lbl
            elif elem in ("uses-permission", "uses-permission-sdk-23"):
                p = _get("android:name")
                if p:
                    out["permissions"].append(p)
            elif elem in ("activity", "activity-alias"):
                n = _get("android:name")
                if n:
                    out["activities"].append(n)
                    out["components"].append(n)
            elif elem == "service":
                n = _get("android:name")
                if n:
                    out["services"].append(n)
                    out["components"].append(n)
            elif elem == "receiver":
                n = _get("android:name")
                if n:
                    out["receivers"].append(n)
                    out["components"].append(n)
            elif elem == "provider":
                n = _get("android:name")
                if n:
                    out["providers"].append(n)
                    out["components"].append(n)
        pos += csz

    out["strings"] = strings
    return out


# ─────────────────────────────────────────────────────── DEX 字符串池
def dex_strings(data: bytes) -> list[str]:
    """抽 DEX 字符串池。"""
    if len(data) < 0x70 or data[:3] != b"dex":
        return []
    try:
        n_str = struct.unpack_from("<I", data, 0x38)[0]
        off_str = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return []
    if n_str > 200000 or off_str >= len(data):
        return []
    out: list[str] = []
    for i in range(n_str):
        try:
            soff = struct.unpack_from("<I", data, off_str + i * 4)[0]
        except struct.error:
            break
        if soff >= len(data):
            continue
        p = soff
        ln = 0
        shift = 0
        while p < len(data):
            b = data[p]
            p += 1
            ln |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        raw = data[p:p + ln]
        if raw.endswith(b"\x00"):
            raw = raw[:-1]
        out.append(raw.decode("utf-8", "replace"))
    return out


# ─────────────────────────────────────────────────────── APK
class Apk:
    """APK 只读分析器。"""

    def __init__(self, path: str) -> None:
        self.path = path
        self.members: dict[str, bytes] = {}
        self.names: list[str] = []
        with zipfile.ZipFile(path) as z:
            self.names = z.namelist()
            for n in self.names:
                try:
                    if not n.endswith("/"):
                        self.members[n] = z.read(n)
                except Exception:
                    pass
        self.manifest_strings = axml_strings(self.members.get("AndroidManifest.xml", b""))
        self.tree = axml_tree(self.members.get("AndroidManifest.xml", b""))
        self.arsc = arsc_strings(self.members.get("resources.arsc", b""))
        self.dex_strings: list[str] = []
        for n in self.names:
            if n.endswith(".dex"):
                self.dex_strings.extend(dex_strings(self.members[n]))

    # ------------------------------------------------------------ 摘要
    def hash(self) -> dict[str, str]:
        raw = open(self.path, "rb").read()
        return {
            "MD5": hashlib.md5(raw).hexdigest(),
            "SHA1": hashlib.sha1(raw).hexdigest(),
            "SHA256": hashlib.sha256(raw).hexdigest(),
            "大小": str(len(raw)),
        }

    def package_name(self) -> str:
        """
        包名：取 <manifest package="…"> 的属性值。

        ★ 树里解析不到就**返回空**——多半是加固壳把 manifest 处理了。
          这时**不能**从字符串池里瞎猜一个"看起来像包名"的串：
          实测会猜成 "android.hardware.camera.autofocus"（那是权限名，不是包名）。
        """
        return self.tree.get("package", "")

    def app_label(self) -> str:
        """
        应用名：取 <application android:label="…"> 的属性值。

        label 常常是资源引用（"@string/app_name"），这时去 resources.arsc 的
        字符串池里按名字找（"app_name" → 对应下标的值）。
        """
        lbl = self.tree.get("label", "")
        if lbl:
            return lbl
        ref = self.tree.get("label_ref", "")
        if ref.startswith("@string/") and self.arsc:
            key = ref[len("@string/"):]
            pool = self.arsc
            for i, v in enumerate(pool):
                if v == key and i + 1 < len(pool):
                    return pool[i + 1]
            for i, v in enumerate(pool):
                if v == key:
                    return pool[i + 1] if i + 1 < len(pool) else ""
        return ""

    def permissions(self) -> list[str]:
        """权限：<uses-permission android:name="…"> 的属性值。"""
        if self.tree.get("permissions"):
            return list(dict.fromkeys(self.tree["permissions"]))
        return [s for s in self.manifest_strings
                if s.startswith("android.permission.")
                or s.startswith("android.hardware.")]

    def dangerous_permissions(self) -> list[str]:
        ps = set(self.permissions())
        return [p for p in DANGEROUS_PERMISSIONS if p in ps]

    def components(self) -> list[str]:
        """组件：activity / service / receiver / provider 的 android:name。"""
        if self.tree.get("components"):
            return list(dict.fromkeys(self.tree["components"]))
        kw = ("Receiver", "Service", "Provider", "Activity", "JobService",
              "AccessibilityService", "DeviceAdminReceiver", "BroadcastReceiver")
        return [s for s in self.manifest_strings
                if any(k in s for k in kw) and s.count(".") >= 1 and len(s) < 160]

    def hardening(self) -> list[str]:
        """识别加固厂商。"""
        found: set[str] = set()
        for name, data in self.members.items():
            low = name.lower()
            for sig, vendor in HARDENING_SIGNATURES.items():
                if sig.lower() in low:
                    found.add(vendor)
            if not data:
                continue
            txt = data.decode("latin-1", "ignore").lower()
            for sig, vendor in HARDENING_SIGNATURES.items():
                if sig.lower() in txt:
                    found.add(vendor)
        return sorted(found)

    def native_libs(self) -> list[str]:
        return [n for n in self.names if n.endswith(".so")]

    def encrypted_payloads(self) -> list[tuple[str, int]]:
        """疑似加密的载荷（熵 > 7.8 且体积可观）。"""
        import collections
        import math
        out = []
        for n, d in self.members.items():
            if len(d) < 4096:
                continue
            c = collections.Counter(d)
            ln = len(d)
            ent = -sum((v / ln) * math.log2(v / ln) for v in c.values())
            if ent > 7.8:
                out.append((n, len(d)))
        return sorted(out, key=lambda x: -x[1])

    def iocs(self) -> dict[str, list[str]]:
        """从字符串池里捞网络指标。"""
        blob = "\n".join(self.dex_strings + self.manifest_strings)
        ips: set[str] = set()
        for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b", blob):
            ip = m.group(1)
            octs = [int(x) for x in ip.split(".")]
            if any(o > 255 for o in octs):
                continue
            if ip.startswith(("0.", "127.", "255.")):
                continue
            ips.add(f"{ip}:{m.group(2)}" if m.group(2) else ip)
        urls = set(re.findall(r"https?://[^\s\"'<>]{5,120}", blob))
        domains = set(re.findall(
            r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
            r"(?:com|cn|net|org|io|xyz|top|cc|me|info|ru|tk|ml|ga))\b", blob, re.I))
        skip = ("android.com", "googleapis", "schemas.android", "apache.org",
                "w3.org", "json.org", "slf4j", "kotlin", "jetbrains",
                "bouncycastle", "androidx")
        return {
            "IP": sorted(ips),
            "URL": sorted(urls),
            "域名": sorted(d for d in domains if not any(k in d.lower() for k in skip)),
        }

    def flags(self) -> list[str]:
        """字符串池里的 flag 样式串。"""
        out = set()
        for s in self.dex_strings + self.manifest_strings:
            for m in re.finditer(r"flag\{[^}]{0,80}\}", s, re.I):
                out.add(m.group(0))
        return sorted(out)

    # ------------------------------------------------------------ 记录
    def records(self) -> Iterator[dict[str, Any]]:
        """产出 APK 属性记录（可直接进 MemLens 证据库）。"""
        h = self.hash()
        yield {"项目": "文件", "值": self.path.rsplit("\\", 1)[-1], "说明": "APK 路径"}
        yield {"项目": "MD5", "值": h["MD5"], "说明": "样本指纹"}
        yield {"项目": "SHA256", "值": h["SHA256"], "说明": "样本指纹"}
        yield {"项目": "大小", "值": h["大小"], "说明": "字节"}
        mani_ok = bool(self.tree.get("package") or self.tree.get("components"))
        yield {"项目": "包名", "值": self.package_name() or "(未解析)",
               "说明": "AndroidManifest" if mani_ok else "manifest 未解析（疑为加固/加密）"}
        yield {"项目": "manifest 状态",
               "值": "已解析" if mani_ok else "未能解析（加固壳处理）",
               "说明": "AXML 树"}
        yield {"项目": "应用名", "值": self.app_label(), "说明": "AndroidManifest"}
        yield {"项目": "加固", "值": " | ".join(self.hardening()) or "无明显加固",
               "说明": "native 库 / 载荷特征"}
        yield {"项目": "成员数", "值": str(len(self.names)), "说明": "zip 条目"}
        for n in self.native_libs():
            yield {"项目": "native 库", "值": n, "说明": "so"}
        for p in self.permissions():
            yield {"项目": "权限", "值": p,
                   "说明": "危险权限" if p in self.dangerous_permissions() else "普通权限"}
        for c in self.components()[:40]:
            yield {"项目": "组件", "值": c, "说明": "manifest"}
        iocs = self.iocs()
        for i in iocs["IP"]:
            yield {"项目": "IP", "值": i, "说明": "dex/manifest 字符串池"}
        for u in iocs["URL"][:40]:
            yield {"项目": "URL", "值": u, "说明": "dex/manifest 字符串池"}
        for d in iocs["域名"][:40]:
            yield {"项目": "域名", "值": d, "说明": "dex/manifest 字符串池"}
        for f in self.flags():
            yield {"项目": "FLAG 串", "值": f, "说明": "字符串池"}
        for n, sz in self.encrypted_payloads()[:10]:
            yield {"项目": "加密载荷", "值": f"{n} ({sz:,} 字节)", "说明": "熵 > 7.8"}
