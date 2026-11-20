r"""
MemLens · 格式解析层（取证容器 / 流量 / 移动端）

## 为什么单独一层

这些解析器**不是插件**，也不是子进程，而是"读字节 → 出结构"的纯函数。
把它们放在 `memlens/formats/` 下，好处是：

  · 引擎（`memlens/engines/`）只负责"编排 + 登记产物"，不重复实现解析；
  · CLI / Web / 检测器都能直接复用同一套实现，不会出现"三套解析三种结果"；
  · 每个解析器都能被单测覆盖，不依赖镜像、不依赖外部工具。

## 包含

  · `pcapng.py` —— pcapng 容器 + BLE 链路层（含 Nordic 私有封装）+ USB HID 键盘
  · `apk.py`    —— APK / 二进制 AXML / DEX 字符串池 / 加固识别
  · `ewf.py`    —— EWF（E01）分段与数据块
  · `vmdk.py`   —— VMDK 稀疏盘描述符与 extents

## 血泪教训（都写进注释了，别再踩）

1. **Nordic nRF Sniffer 私有封装不是标准 BLE**
   linktype=272，21 字节头 + 4 字节接入地址（D6BE898E）+ LL 包（含 3 字节 CRC）。
   按标准 BLE 的 16 字节头去解，会解出满屏乱码且**不报错**。

2. **BLE 广播地址长度不能写死 6**
   部分 ADV_IND 的 AdvData 少一个字节，写死 6 会让 AD 结构整体错位 1 字节，
   设备名解出来变成 `LE-YANG`QC\x135 Ei` 这种鬼样子。
   正解：按 AD 结构能否自洽走完来反推地址长度（5/6/7）。

3. **USB 键盘报告不是 8 字节标准布局**
   本例是 37 字节复合 HID：第 0 字节是 **Report ID=0x01**，
   真正的 boot 协议报告在 [1] 修饰键 / [3:9] 按键码。

4. **CapsLock 之类不产生字符的键必须跳过**
   不然 `abcdefghijkImn` 会变成 `abcdefghijkCapsLockiCapsLockmn`。
"""

from __future__ import annotations

__all__ = ["pcapng", "apk", "ewf", "vmdk"]
