"""
MemLens · 情报层（intel）

回答一个取证问题：**"这些结果里，哪些是值得单独拎出来看的"**。

取证引擎（vol3 / static / pcap …）产出的是"事实"，但从事实到结论之间还差一步：
散落在几十万行里的 IP、域名、flag、远控进程名、持久化路径。本层负责这一步：

    ① ioc.py    IOC 自动提取（IP / URL / 域名 / 邮箱 / 钱包 / 路径 / 注册表键 …）
    ② dict.py   词典模型（关键词 + 正则），可编辑、可扩展
    ③ builtin.py 内置词典（独立编写，含中文说明与处置建议）
    ④ scan.py   把 ①② 的结果写回统一证据模型（artifacts/records）

与检测器（detectors/）的分工：
    detectors  = 有推理链的"研判"（pslist−psscan 差集 → 隐藏进程）
    intel      = 无推理的"提取"（把 IOC 和关键词捞出来，附上下文与出处）
两者互补，不可互相替代。
"""

from __future__ import annotations

__all__ = ["ioc", "dict", "builtin", "scan"]
