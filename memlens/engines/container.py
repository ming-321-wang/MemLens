r"""
MemLens · 取证容器引擎（容器 / 流量 / 移动端）

对应方案 §2.2「数据接入」与 §2.3「分析引擎」里的"非内存镜像检材"通道。

## 解决的问题

取证现场的检材不只有内存镜像：

    VeraCrypt 加密卷      —— 整个检材包加密，无驱动无管理员也要能读
    EWF（E01）分段        —— 55 GB 计算机检材
    VMDK 稀疏盘          —— 虚拟机服务器检材
    pcapng 抓包          —— 蓝牙 / USB 流量
    APK                  —— 手机木马样本

这些都需要**"打开容器 → 列举内容 → 按需提取 → 解析"**的能力。
本引擎把它们统一成 MemLens 的产物模型：

    产物名（插件名）        内容
    ────────────────────────────────────────────────
    container.identify     容器类型识别 + 卷头摘要
    container.files        容器内文件清单
    container.extract      按路径提取单个文件（needs_params: path）
    container.crypto       加密卷头详情（VeraCrypt 参数与主密钥指纹）
    traffic.interfaces     pcapng 接口与链路类型
    traffic.bluetooth      BLE 设备表（地址 / 名称 / 厂商数据）
    traffic.ble_rename     蓝牙改名事件（伪装设备的核心线索）
    traffic.hid            USB HID 键盘还原文本
    mobile.apk             APK 属性（包名 / 权限 / 加固 / IOC / flag 串）

## 为什么不用子进程

这些都是"读字节 → 出结构"的纯函数，走引擎的 `build_run/parse_records`
（子进程模型）反而绕。引擎内部自己实现 `EngineAdapter` 要求的四个方法，
`build_run` 把参数装进 `RunSpec.argv`（作为"参数容器"），`parse_records`
直接产出记录 —— 与 memprocfs 引擎的产物型模式一致。
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from typing import Any, Iterator

from memlens.engines.base import EngineAdapter, OutputKind, PluginMeta, RunSpec

# ─────────────────────────────────────────────────────── 容器识别
#: 容器魔数 → (类型, 说明)
CONTAINER_MAGICS: list[tuple[bytes, str, str]] = [
    (b"EVF\x09\x0d\x0a\xff\x00", "EWF", "Expert Witness Format（E01 分段）"),
    (b"LVF\x09\x0d\x0a\xff\x00", "EWF", "Logical EWF（L01）"),
    (b"KDMV", "VMDK", "VMware 虚拟磁盘（稀疏）"),
    (b"# Disk DescriptorFile", "VMDK", "VMware 虚拟磁盘（描述符）"),
    (b"conectix", "VHD", "Virtual Hard Disk"),
    (b"vhdxfile", "VHDX", "Virtual Hard Disk v2"),
    (b"QFI\xfb", "QCOW2", "QEMU 磁盘镜像"),
    (b"PK\x03\x04", "ZIP", "ZIP 压缩包"),
    (b"7z\xbc\xaf\x27\x1c", "7Z", "7-Zip 压缩包"),
    (b"\x1f\x8b", "GZIP", "gzip"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG", "pcapng 抓包"),
    (b"\xd4\xc3\xb2\xa1", "PCAP", "经典 pcap 抓包"),
    (b"\xa1\xb2\xc3\xd4", "PCAP", "经典 pcap 抓包（字节序相反）"),
    (b"dex\n", "DEX", "Dalvik 可执行文件"),
    (b"\x50\x4b\x03\x04", "ZIP", "ZIP"),
    (b"MZ", "PE", "Windows 可执行文件"),
]


def identify_container(path: str | Path) -> dict[str, Any]:
    """识别容器类型。"""
    p = Path(path)
    if not p.exists():
        return {"类型": "不存在", "说明": str(p)}
    head = p.open("rb").read(4096)
    # ★ APK 是 ZIP 的子集，**必须先查内容再查魔数** ——
    #   否则 PK\x03\04 先命中，会把 APK 认成普通 ZIP（实测踩过）。
    if head[:2] == b"PK":
        try:
            import zipfile
            with zipfile.ZipFile(p) as z:
                names = z.namelist()
            if any(n.endswith(".dex") for n in names):
                return {"类型": "APK", "说明": "Android 应用包",
                        "成员数": len(names), "大小": p.stat().st_size}
            return {"类型": "ZIP", "说明": "ZIP 压缩包", "成员数": len(names),
                    "大小": p.stat().st_size}
        except Exception:
            pass
    for magic, kind, desc in CONTAINER_MAGICS:
        if head.startswith(magic):
            size = p.stat().st_size
            return {"类型": kind, "说明": desc, "大小": size,
                    "大小GB": round(size / 1024 ** 3, 2)}
    # ZIP/APK 靠尾部与内容再判
    if head[:2] == b"PK":
        try:
            import zipfile
            with zipfile.ZipFile(p) as z:
                names = z.namelist()
            if any(n.endswith(".dex") for n in names):
                return {"类型": "APK", "说明": "Android 应用包", "成员数": len(names),
                        "大小": p.stat().st_size}
            return {"类型": "ZIP", "说明": "ZIP 压缩包", "成员数": len(names),
                    "大小": p.stat().st_size}
        except Exception:
            pass
    # VeraCrypt：没有魔数，靠"熵高 + 无结构"判定
    import collections
    import math
    c = collections.Counter(head[: 1 << 20])
    n = min(len(head), 1 << 20)
    ent = -sum((v / n) * math.log2(v / n) for v in c.values()) if n else 0
    if ent > 7.9:
        return {"类型": "疑似加密体", "说明": f"熵 {ent:.3f}，无已知魔数（VeraCrypt 卷？加密归档？）",
                "大小": p.stat().st_size, "熵": round(ent, 4)}
    return {"类型": "未知", "说明": "无匹配魔数", "大小": p.stat().st_size, "熵": round(ent, 4)}


# ─────────────────────────────────────────────────────── 产物清单
ARTIFACT_PLUGINS: tuple[PluginMeta, ...] = (
    PluginMeta("container.identify", "容器类型识别", "容器",
               OutputKind.SCALAR,
               "识别 EWF/VMDK/ZIP/pcapng/APK/加密体，给出卷头摘要"),
    PluginMeta("container.files", "容器内文件清单", "容器",
               OutputKind.TABLE,
               "列出加密卷（VeraCrypt+exFAT）或归档内的全部条目"),
    PluginMeta("container.extract", "提取容器内文件", "容器",
               OutputKind.FILE_SET,
               "按路径从容器里提取单个文件（需要参数 path）",
               needs_params=("path",)),
    PluginMeta("container.crypto", "加密卷卷头详情", "容器",
               OutputKind.SCALAR,
               "VeraCrypt 卷头：算法 / KDF / 迭代 / 主密钥指纹"),
    PluginMeta("traffic.interfaces", "抓包接口信息", "流量",
               OutputKind.SCALAR,
               "pcapng 的接口名 / 链路类型 / 抓包系统"),
    PluginMeta("traffic.bluetooth", "蓝牙设备表", "流量",
               OutputKind.TABLE,
               "BLE 广播设备：地址 / 名称 / 厂商数据 / 出现时间"),
    PluginMeta("traffic.ble_rename", "蓝牙改名事件", "流量",
               OutputKind.TABLE,
               "同一地址出现多个设备名 —— 蓝牙伪装设备的核心线索"),
    PluginMeta("traffic.hid", "USB 键盘还原", "流量",
               OutputKind.SCALAR,
               "USBPcap 的 HID 键盘还原文本（含退格修正）"),
    PluginMeta("mobile.apk", "APK 属性分析", "移动端",
               OutputKind.TABLE,
               "包名 / 应用名 / 权限 / 加固 / IOC / flag 串"),
    PluginMeta("container.xfs", "服务器磁盘/XFS 分析", "磁盘",
                OutputKind.TABLE,
                "VeraCrypt卷→exFAT→VMDK→LVM→XFS：超级块/inode表/目录树/文件读取"),
    PluginMeta("container.xfs_read", "按inode读XFS文件", "磁盘",
                OutputKind.FILE_SET,
                "按 inode 号读取 XFS 文件内容（需要参数 ino）",
                needs_params=("ino",)),
)


class ContainerEngine(EngineAdapter):
    """取证容器引擎。"""

    name = "container"
    display = "取证容器（加密卷/镜像/抓包/APK）"
    supported_containers = ("veracrypt", "ewf", "vmdk", "zip", "pcapng", "apk", "xfs")

    def __init__(self, workdir: str | Path | None = None) -> None:
        self.workdir = Path(workdir or Path.cwd() / "work")

    # ------------------------------------------------------------ 环境
    def available(self) -> tuple[bool, str]:
        try:
            import memlens.formats.apk          # noqa: F401
            import memlens.formats.ewf          # noqa: F401
            import memlens.formats.pcapng        # noqa: F401
            import memlens.formats.vmdk         # noqa: F401
            import memlens.formats.xfs          # noqa: F401
        except Exception as exc:
            return False, f"格式层导入失败：{exc}"
        return True, "内置格式层可用（VeraCrypt/exFAT/EWF/VMDK/pcapng/BLE/HID/APK）"

    def list_plugins(self, *, refresh: bool = False) -> list[PluginMeta]:
        return list(ARTIFACT_PLUGINS)

    def build_run(self, plugin: PluginMeta, image: str,
                  params: dict[str, Any] | None = None) -> RunSpec:
        params = params or {}
        argv = [plugin.name, str(image)]
        for k, v in params.items():
            argv.append(f"{k}={v}")
        return RunSpec(plugin=plugin, argv=argv, output_kind=plugin.kind)

    # ------------------------------------------------------------ 执行
    def parse_records(self, spec: RunSpec, stdout: str,
                      stderr: str) -> Iterator[dict[str, Any]]:
        plugin = spec.plugin.name
        image = spec.argv[1] if len(spec.argv) > 1 else ""
        params: dict[str, Any] = {}
        for a in spec.argv[2:]:
            if "=" in a:
                k, _, v = a.partition("=")
                params[k] = v
        fn = getattr(self, f"_run_{plugin.replace('.', '_')}", None)
        if fn is None:
            raise RuntimeError(f"未知插件：{plugin}")
        yield from fn(image, params)

    # ------------------------------------------------------------ 各插件
    def _run_container_identify(self, image: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        info = identify_container(image)
        for k, v in info.items():
            yield {"项目": str(k), "值": str(v), "说明": "容器识别"}

    def _run_container_crypto(self, image: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        from memlens.core.veracrypt_volume import VeraCryptVolume
        pw = params.get("password", "")
        if not pw:
            raise RuntimeError("需要参数 password（加密卷口令）")
        vol = VeraCryptVolume(image, pw)
        try:
            i = vol.summary()
            for k, v in i.items():
                yield {"项目": str(k), "值": str(v), "说明": "VeraCrypt 卷头"}
        finally:
            vol.close()

    def _run_container_files(self, image: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        from memlens.core.exfat import ExFat
        from memlens.core.veracrypt_volume import VeraCryptVolume
        pw = params.get("password", "")
        if not pw:
            raise RuntimeError("需要参数 password（加密卷口令）")
        vol = VeraCryptVolume(image, pw)
        try:
            fs = ExFat(vol)
            for e in fs.list_dir(fs.root_cluster):
                yield {
                    "类型": "目录" if e["is_dir"] else "文件",
                    "名称": e["name"],
                    "大小": e["size"],
                    "修改时间": e["mtime"],
                    "首簇": e["first_cluster"],
                }
        finally:
            vol.close()

    def _run_container_extract(self, image: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        from memlens.core.exfat import ExFat
        from memlens.core.veracrypt_volume import VeraCryptVolume
        pw = params.get("password", "")
        target = params.get("path", "")
        if not pw:
            raise RuntimeError("需要参数 password（加密卷口令）")
        if not target:
            raise RuntimeError("需要参数 path（要提取的卷内路径）")
        outdir = Path(self.workdir) / "extract"
        outdir.mkdir(parents=True, exist_ok=True)
        vol = VeraCryptVolume(image, pw)
        try:
            fs = ExFat(vol)
            parts = [p for p in target.replace("\\", "/").split("/") if p]
            cur = fs.root_cluster
            ent = None
            for part in parts:
                hit = next((x for x in fs.list_dir(cur)
                            if x["name"].lower() == part.lower()), None)
                if not hit:
                    raise RuntimeError(f"卷内找不到：{part}")
                ent = hit
                cur = hit["first_cluster"]
            if ent is None or ent["is_dir"]:
                raise RuntimeError(f"不是文件：{target}")
            dst = outdir / Path(ent["name"]).name
            done = 0
            with dst.open("wb") as f:
                if ent["no_fat_chain"]:
                    base = fs.cluster_offset(ent["first_cluster"])
                    while done < ent["data_len"]:
                        n = min(4 << 20, ent["data_len"] - done)
                        f.write(vol.read(base + done, n))
                        done += n
                else:
                    for c in fs.chain(ent["first_cluster"]):
                        d = fs.read_cluster(c)
                        n = min(len(d), ent["data_len"] - done)
                        f.write(d[:n])
                        done += n
                        if done >= ent["data_len"]:
                            break
            yield {"项目": "提取路径", "值": str(dst), "说明": target}
            yield {"项目": "字节数", "值": str(done), "说明": ""}
        finally:
            vol.close()

    def _run_traffic_interfaces(self, image: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        from memlens.formats.pcapng import PcapngFile
        pf = PcapngFile(image)
        for i, f in enumerate(pf.summary()["interfaces"]):
            yield {"项目": f"接口[{i}]", "值": f.get("name") or "(无名)",
                   "说明": f"{f.get('linktype_name', '')} {f.get('description', '')} {f.get('os', '')}".strip()}
        yield {"项目": "包数", "值": str(len(pf.packets)), "说明": "EPB"}

    def _run_traffic_bluetooth(self, image: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        from memlens.formats.pcapng import bluetooth_records
        yield from bluetooth_records(image)

    def _run_traffic_ble_rename(self, image: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        from memlens.formats.pcapng import ble_rename_events
        yield from ble_rename_events(image)

    def _run_traffic_hid(self, image: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        from memlens.formats.pcapng import hid_records
        r = hid_records(image)
        for k, v in r["stats"].items():
            yield {"项目": k, "值": str(v), "说明": "统计"}
        yield {"项目": "还原文本", "值": r["text"][:8000], "说明": "HID 键盘"}

    def _run_mobile_apk(self, image: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        from memlens.formats.apk import Apk
        yield from Apk(image).records()

    def _run_container_xfs(self, image: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        """
        服务器磁盘/XFS 分析。

        参数：
          password  加密卷口令（VeraCrypt 卷必填）
          lv        LVM 逻辑卷名（默认 root）
          scan      扫描 GiB 数（默认 1；越大 inode 表越全越慢）
          ino       （可选）只看单个 inode 的详情 + 数据预览
          list      （可选）inode 清单："" 默认 / "top" 按大小排序
          limit     清单条数上限（默认 200）
        """
        from memlens.formats.xfs import open_server_fs
        pw = params.get("password", "")
        lv = params.get("lv", "root")
        scan_gib = int(params.get("scan", 1))
        x, meta = open_server_fs(image, pw, lv_name=lv)

        # ---- 磁盘布局（VMDK → 分区表 → LVM → 超级块）----
        yield {"项目": "VMDK", "值": f'{meta.get("capacity_gb", "?")} GiB',
               "说明": f'grain={meta.get("grain_size_sectors", "?")} 扇区 / '
                       f'{meta.get("create_type", "?")}'}
        for p in meta.get("partitions", []):
            yield {"项目": f"分区{p.get('idx')}", "值": f"类型0x{p.get('ptype',0):02x} LBA {p.get('lba',0):,}",
                   "说明": f"{p.get('sectors',0):,} 扇区"}
        yield {"项目": "LVM逻辑卷", "值": lv,
               "说明": f"字节偏移 {meta.get('lvm_offset', 0):,}"}
        yield {"项目": "超级块", "值": str(x.summary()), "说明": "XFS"}

        # ---- 单 inode 详情模式 ----
        ino_s = str(params.get("ino", "")).strip()
        if ino_s:
            ino = int(ino_s)
            info = x.inode(ino)
            data = x.read_inode_data(ino)
            kind = "目录" if info["is_dir"] else ("普通" if info["is_reg"] else "特殊")
            yield {"项目": f"inode {ino} 详情", "值": f"{kind} mode=0{info['mode']:o} fmt={info['fmt']}",
                   "说明": f"size={info['size']:,}B nextents={info['nextents']} 真实ino={info['real_ino']}"}
            yield {"项目": "inode数据预览", "值": data[:256].hex(" "),
                   "说明": f"前{min(256, info['size'])}字节"}
            return

        # ---- 扫描 inode（分块 + 进度）----
        total = scan_gib << 30
        chunk = 256 << 20
        base = 0
        while base < total:
            n2 = min(chunk, total - base)
            x.find_inodes_range(base, n2)
            base += n2
            yield {"项目": "inode扫描进度", "值": f"{base>>30} GiB / {total>>30} GiB",
                   "说明": f"已定位 {len(x._ino_loc)} 个"}
        yield {"项目": "已定位inode", "值": str(len(x._ino_loc)),
               "说明": f"扫描 {total/1024**3:.0f} GiB"}

        # ---- inode 清单模式（top 按大小）----
        mode = str(params.get("list", "")).strip()
        if mode:
            limit = int(params.get("limit", "200") or 200)
            rows = []
            for ino, _ in x._ino_loc.items():
                try:
                    info = x.inode(ino)
                    if info["size"] == 0 and not info["is_dir"]:
                        continue
                    rows.append((info["size"], ino, info["fmt"],
                                 info["is_dir"], info["is_reg"], info["mode"]))
                except Exception:
                    continue
            rows.sort(key=lambda r: -r[0])
            rows = rows[:limit]
            for size, ino, fmt, is_dir, is_reg, modev in rows:
                kind = "目录" if is_dir else ("普通" if is_reg else "特殊")
                yield {"项目": f"ino{ino}", "值": f"{kind} {size:,}B",
                       "说明": f"fmt={fmt} mode=0{modev:o}"}
            return

        # ---- 默认：根目录 + 抽样 inode ----
        try:
            for e in x.dir_entries(x.rootino):
                yield {"项目": f"根目录/{e['name']}", "值": e["ftype_s"],
                       "说明": f"ino字段={e['ino']}（合成FS中不可全信）"}
        except Exception as ex:
            yield {"项目": "根目录", "值": f"解析失败: {ex}", "说明": ""}
        for ino in (72, 65, 64, 69, 66, 67, 68, 70, 71, 73, 74, 75):
            try:
                info = x.inode(ino)
                head = x.read_inode_data(ino)[:4]
                kind = "文本/脚本" if head[:2] == b"#!" or head[:1] in (b"<", b"{") else "二进制"
                yield {"项目": f"inode {ino}", "值": f"{kind} {info['size']}B fmt={info['fmt']}",
                       "说明": head[:8].hex(" ")}
            except Exception:
                pass

    def _run_container_xfs_read(self, image: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
        """
        按 inode 号读取 XFS 文件内容。

        参数：
          ino       inode 号（必填）
          mode      save（默认，写文件）| text（文本预览 ≤8KB）| hex（hex 预览 ≤512B）
          limit     读取字节数上限（默认 0 = 全部）
          password  VeraCrypt 卷口令
          lv        LVM 逻辑卷名（默认 root）
        """
        from memlens.formats.xfs import open_server_fs
        pw = params.get("password", "")
        lv = params.get("lv", "root")
        ino = int(params.get("ino", "0"))
        if ino <= 0:
            raise RuntimeError("需要参数 ino（inode 号）")
        mode = str(params.get("mode", "save")).strip() or "save"
        limit = int(params.get("limit", "0") or 0)
        x, _ = open_server_fs(image, pw, lv_name=lv)
        info = x.inode(ino)
        data = x.read_inode_data(ino)
        if limit > 0:
            data = data[:limit]

        if mode == "text":
            text = data.decode("utf-8", "replace")
            yield {"项目": "inode", "值": str(ino),
                   "说明": f"{info['size']}B fmt={info['fmt']}"}
            yield {"项目": "文本内容", "值": text[:8192], "说明": f"{len(text)} 字符"}
            return
        if mode == "hex":
            yield {"项目": "inode", "值": str(ino),
                   "说明": f"{info['size']}B fmt={info['fmt']}"}
            yield {"项目": "HEX", "值": data[:512].hex(" "),
                   "说明": f"前{min(512, info['size'])}字节"}
            return

        outdir = Path(self.workdir) / "extract"
        outdir.mkdir(parents=True, exist_ok=True)
        dst = outdir / f"ino{ino}.bin"
        dst.write_bytes(data)
        yield {"项目": "inode", "值": str(ino), "说明": f"{info['size']}B fmt={info['fmt']}"}
        yield {"项目": "提取路径", "值": str(dst), "说明": ""}
        yield {"项目": "前128字节", "值": data[:128].hex(" "), "说明": ""}
