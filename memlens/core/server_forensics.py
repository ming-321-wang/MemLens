# -*- coding: utf-8 -*-
"""
MemLens · Linux 服务器取证文件级分析（WP 0x05 服务器取证）

在**不挂载系统、不执行命令**的前提下，直接解析镜像里提取的服务器文件：
  · wtmp          → 开机时间（reboot 记录，WP 题 1）
  · /etc/passwd   → 用户数（uid==0 或 uid>=1000，WP 题 3）
  · trojan config → 运行模式 / remote_addr / remote_port（WP 题 4/5/6）
  · config.php    → AUTH_CODE 加密逻辑 → md5(AUTH_CODE+password)（WP 题 7）
  · .sql 导出     → tp_order 订单数 / 注册到首单最短用户（WP 题 9/14）

这些文件由 MemLens「取证容器」通道（container xfs/extract）从镜像提取后传入，
无需启动虚拟机 / chroot / 挂载系统。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import unquote

# linux/x86_64 utmp 记录固定长度（字节）
_UTMP_REC = 384
# 本次检材的 wtmp 把 ut_tv.tv_sec 放在偏移 340（非 glibc 默认 332），实测得到
_UT_TV_SEC = 340
UT_BOOT_TIME = 2   # 重启/开机记录类型


def _ts_str(ts: int) -> str:
    # 与 `last`/数据库本地时区输出一致（wtmp 存 UTC 时间戳，显示用本地）
    try:
        return datetime.fromtimestamp(ts).strftime("%Y/%m/%d %H:%M:%S")
    except Exception:
        return ""


def parse_wtmp(path: str | Path) -> dict[str, Any]:
    """解析 wtmp → 所有开机(reboot)时间，取最早（WP 题 1「最早开机时间」）。"""
    data = Path(path).read_bytes()
    boots: list[int] = []
    for off in range(0, len(data) - _UTMP_REC + 1, _UTMP_REC):
        rec = data[off:off + _UTMP_REC]
        ut_type = struct.unpack_from("<h", rec, 0)[0]
        if ut_type != UT_BOOT_TIME:
            continue
        tv_sec = struct.unpack_from("<i", rec, _UT_TV_SEC)[0]
        if 0 < tv_sec < 4_000_000_000:   # 合法 Unix 时间戳
            boots.append(tv_sec)
    boots.sort()
    return {
        "boot_count": len(boots),
        "earliest": _ts_str(boots[0]) if boots else "",
        "latest": _ts_str(boots[-1]) if boots else "",
        "boot_times": [_ts_str(b) for b in boots],
    }


def parse_passwd(text: str) -> dict[str, Any]:
    """
    解析 /etc/passwd → 可登录/业务账号（WP 题 3「除系统用户外共几个用户」）。

    合成 FS 里同一份 passwd 常被塞进更大的二进制页（前面垫着 2000 字节的 \\x00、
    同一批账号重复出现两次），所以这里必须：
      1) 去掉 \\x00 等非可打印字节，避免 'root:x:0:0' 前面粘上垃圾前缀；
      2) 按 (name, uid, shell) 去重；
      3) 账号名/家目录/shell 任一字段含非 ASCII 打印字符的直接丢弃（C 源码、
         规则库里的 b'root'、match http m|… 都是这种）；
      4) uid>=10000 判为合成 FS 给系统账号伪造的大 uid，不计入"真实用户"。
    """
    clean = text.replace("\x00", "").replace("\ufffd", "")
    seen: set[tuple[str, int, str]] = set()
    rows: list[dict[str, Any]] = []
    for line in clean.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, uid_s, shell, home = parts[0], parts[2], parts[6], parts[5]
        if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
            continue
        if not all(re.fullmatch(r"[\x20-\x7e]*", v) for v in (uid_s, shell, home)):
            continue
        try:
            uid = int(uid_s)
        except ValueError:
            continue
        key = (name, uid, shell)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"name": name, "uid": uid, "home": home, "shell": shell})

    def _sys(r: dict[str, Any]) -> bool:
        # 系统账号：uid<1000 且不是 root，或 uid 被合成 FS 放大到 10000+
        return r["uid"] >= 10000 or (r["uid"] < 1000 and r["name"] != "root")

    real = [r for r in rows if not _sys(r)]
    return {
        "users": real,
        "count": len(real),
        "all_users": rows,
        "all_count": len(rows),
        "with_shell": [r["name"] for r in real if r["shell"]],
        "loginable": [r["name"] for r in real
                      if r["shell"] and "nologin" not in r["shell"] and "false" not in r["shell"]],
        # 真 /etc/passwd 的特征：root 的 uid 必须是 0，且 uid 都在合理范围内。
        "root_uid0": any(r["name"] == "root" and r["uid"] == 0 for r in real),
        "uid_sane": all(r["uid"] < 10000 for r in real) and bool(real),
    }


def parse_trojan_config(text: str) -> dict[str, Any]:
    """解析 trojan config.json → run_type / local / remote（WP 题 4/5/6）。"""
    try:
        cfg = json.loads(text)
    except Exception:
        return {"error": "JSON 解析失败"}
    remote = str(cfg.get("remote_addr") or "")
    domain = ""
    if remote and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", remote):
        domain = remote
    return {
        "run_type": cfg.get("run_type"),
        "local_addr": cfg.get("local_addr"),
        "local_port": cfg.get("local_port"),
        "remote_addr": remote,
        "remote_port": cfg.get("remote_port"),
        "remote_domain": domain,
        "raw": cfg,
    }


def parse_php_encrypt(text: str, password: str = "") -> dict[str, Any]:
    """
    解析 ThinkPHP config.php / function.php 的密码加密逻辑（WP 题 7）：
      AUTH_CODE => "TPSHOP"；encrypt($str) = md5(AUTH_CODE . $str)
    返回 auth_code 与 md5(AUTH_CODE+password)。

    容错：检材里 config.php 常被"论坛贴文/帮助文档"以 HTML 形式引用
      （&quot; &#39; &nbsp; =&gt;），所以先做一次 HTML 实体反转义再匹配。
    """
    import html as _html
    auth = ""
    variants = [text]
    try:
        variants.append(_html.unescape(text))
    except Exception:
        pass
    for t in variants:
        m = re.search(r"['\"]?AUTH_CODE['\"]?\s*=>\s*['\"]([^'\"]+)['\"]", t)
        if m and m.group(1):
            auth = m.group(1)
            break
        if not auth:
            m = re.search(r"AUTH_CODE\s*=\s*['\"]([^'\"]+)['\"]", t)
            if m and m.group(1):
                auth = m.group(1)
                break
    hashes: dict[str, str] = {}
    if auth and password:
        hashes[password] = hashlib.md5((auth + password).encode("utf-8")).hexdigest()
    return {"auth_code": auth, "algorithm": "md5(AUTH_CODE+password)",
            "hashes": hashes}


def _split_tuples(body: str) -> list[str]:
    """
    把 "(1,'a'),(2,'b')" 按顶层括号拆成各个元组的内部文本。
    TPshop/phpMyAdmin 导出常把几十上百行塞进一条 INSERT，不拆开就按
    "一条 INSERT = 一行" 处理，len(row) 会远超列数、取第 30 个值直接跨行错位。
    括号深度用引号感知的方式跟踪（字符串里的 ( ) 不计）。
    """
    out: list[str] = []
    depth = 0
    cur: list[str] = []
    in_quote = False
    for c in body:
        if in_quote:
            cur.append(c)
            if c == "'":
                in_quote = False
            continue
        if c == "'":
            in_quote = True
            cur.append(c)
        elif c == "(":
            depth += 1
            if depth > 1:
                cur.append(c)
        elif c == ")":
            depth -= 1
            if depth == 0:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(c)
    return out


def _extract_inserts(text: str, table: str) -> list[list[str]]:
    """
    从 SQL 导出里提取 INSERT INTO `<table>` VALUES (...) 的所有值列表，
    返回"每个元组一条"的行列表（多行 INSERT 会拆成多行）。
    """
    rows: list[list[str]] = []
    pat = re.compile(r"INSERT INTO\s+`?" + re.escape(table) + r"`?\s+VALUES\s*(.*?);",
                     re.I | re.S)
    for m in pat.finditer(text):
        for tup in _split_tuples(m.group(1)):
            # 同时匹配带引号字符串与裸数字（数值字段如 add_time 常无引号）
            vals = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", tup)
            vals = [v[1:-1] if v.startswith("'") else v for v in vals]
            if vals:
                rows.append(vals)
    return rows


def _sql_columns(text: str, table: str) -> dict[str, int] | None:
    """
    从 CREATE TABLE 解析列顺序 → {列名: 0 基下标}。
    TPshop 的导出常常只带 INSERT 不带建表语句，那时返回 None，调用方退回位置启发式。
    列定义要按"顶层逗号"拆：decimal(10, 2)、char(255) 里的小括号逗号不是列分隔符。
    """
    m = re.search(r"CREATE TABLE\s+`?" + re.escape(table) + r"`?\s*\((.*?)\)\s*ENGINE",
                  text, re.I | re.S)
    if not m:
        return None
    cols: dict[str, int] = {}
    for line in _split_top(m.group(1)):
        cm = re.match(r"`?([A-Za-z0-9_]+)`?\s+\w+", line.strip())
        if cm and cm.group(1).lower() not in ("primary", "unique", "key", "index",
                                               "fulltext", "constraint", "foreign"):
            cols[cm.group(1)] = len(cols)
    return cols or None


def _split_top(body: str) -> list[str]:
    """按顶层逗号拆（忽略括号内与单引号串内的逗号）。"""
    out: list[str] = []
    depth = 0
    cur: list[str] = []
    in_quote = False
    for c in body:
        if in_quote:
            cur.append(c)
            if c == "'":
                in_quote = False
            continue
        if c == "'":
            in_quote = True
            cur.append(c)
        elif c == "(":
            depth += 1
            cur.append(c)
        elif c == ")":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if cur:
        out.append("".join(cur))
    return out


def _tp_insert_rows(text: str, table: str) -> list[list[str]]:
    """
    按"一条 INSERT 语句 = 一行"抽取 TPshop 导出的值列表。
    phpMyAdmin 默认导出是一条语句占一行（末尾 `;`），与 WP 的逐行口径一致；
    用逐行扫描而不是跨行正则，避免最后一行没有 `;` 时被漏掉。
    """
    head = re.compile(r"^\s*INSERT INTO\s+`?" + re.escape(table) + r"`?\s+VALUES",
                       re.I)
    rows: list[list[str]] = []
    for line in text.split("\n"):
        if not head.match(line):
            continue
        vals = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", line)
        vals = [v[1:-1] if v.startswith("'") else v for v in vals]
        if vals:
            rows.append(vals)
    if rows:
        return rows
    # 兜底：非逐行导出（一条语句跨多行）时用正则
    pat = re.compile(r"INSERT INTO\s+`?" + re.escape(table) + r"`?\s+VALUES\s*(.*?);",
                     re.I | re.S)
    for m in pat.finditer(text):
        vals = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", m.group(1))
        vals = [v[1:-1] if v.startswith("'") else v for v in vals]
        if vals:
            rows.append(vals)
    return rows


def _detect_order_cols(users: list[list[str]], orders: list[list[str]]
                      ) -> tuple[int, int]:
    """
    没有 tp_order 建表语句时的列定位（TPshop 表结构是固定的，但不同版本列序会变）：
      user_id —— 候选列里取值与 tp_users 的 user_id 集合重合最多的那一列；
      add_time —— 整列都是合法 Unix 秒、且时间跨度最大的那一列。
    """
    n = min(len(o) for o in orders) if orders else 0
    uids = {u[0] for u in users if u}
    ouid_i, ouid_hits = 2, -1
    for i in range(min(8, n)):
        vals = [o[i] for o in orders if len(o) > i]
        if not vals:
            continue
        hit = sum(1 for v in vals if v in uids)
        if hit < len(vals) * 0.5:
            continue                          # 与 user_id 集合重合太少
        if len(set(vals)) > len(vals) * 0.9:
            continue                          # 近似唯一 → 是自增主键（order_id）
        if hit > ouid_hits:
            ouid_i, ouid_hits = i, hit

    add_i, best_span = 29, -1.0
    for i in range(min(36, n)):
        vals: list[int] = []
        for o in orders:
            if len(o) > i and re.fullmatch(r"\d{9,10}", o[i]):
                vals.append(int(o[i]))
        if len(vals) < max(50, len(orders) // 4):
            continue
        lo, hi = min(vals), max(vals)
        if not (946_684_800 <= lo and hi <= 2_051_222_400):   # 2000 ~ 2035 年
            continue
        if hi - lo > best_span:
            add_i, best_span = i, float(hi - lo)
    return ouid_i, add_i


def parse_webshell(text: str) -> dict[str, Any]:
    """
    从 web 访问日志里抠一句话木马的**原始内容**并算 SHA-256（WP 题 12）。
    一句话木马通常经 ThinkPHP 的 invokefunction / file_put_contents 以 POST 体投递，
    因此既匹配明文的 <?php ...eval($_POST[...]...)...?>，也匹配 URL 编码后的
    %3C%3Fphp ... 形态（WP 答案就是那句木马内容的 SHA-256）。
    """
    pats = [
        r"(?:%3[Cc]|<)\s*(?:%3[Ff]|\\?)\?php[\s\S]{0,400}?"
        r"(?:%3[Ee]|\\?)\?>(?:%0A|%0D%0A|\s*$)?",
        r"<\?php[\s\S]{0,400}?\?>(?:\s*$)?",
    ]
    groups: dict[str, str] = {}          # 规范形式 → 是否存在 URL 编码变体
    for p in pats:
        for m in re.finditer(p, text, re.I):
            raw = m.group(0).rstrip("\n\r")
            if len(raw) < 8 or len(raw) > 400:
                continue
            decoded = raw
            if "%" in raw:
                try:
                    decoded = unquote(raw)
                except Exception:
                    pass
            if not _looks_like_webshell(decoded):
                continue
            canon = decoded
            if canon not in groups:
                groups[canon] = canon
            elif "%" in raw and "%" not in groups[canon]:
                groups[canon] = canon        # 有明文写法时优先明文
            elif "%" not in raw and "%" in groups[canon]:
                groups[canon] = canon
    items = []
    for body in groups.values():
        b = body.encode("utf-8")
        items.append({"payload": body, "bytes": len(b),
                      "sha256": hashlib.sha256(b).hexdigest(),
                      "sha256_upper": hashlib.sha256(b).hexdigest().upper()})
    return {"webshells": items, "count": len(items)}


def _looks_like_webshell(s: str) -> bool:
    """判定一段文本是否像一句话木马（含 <?php 与 eval/assert/system/preg_replace）。"""
    if "<?php" not in s.lower():
        return False
    return bool(re.search(r"eval\s*\(|assert\s*\(|system\s*\(|preg_replace\s*\(|passthru\s*\(",
                          s, re.I))


def parse_sql_orders(text: str, start_ts: int | None = None,
                     end_ts: int | None = None) -> dict[str, Any]:
    """
    统计 tp_order 订单数（WP 题 9：2016-04-01 00:00:00 ~ 2025-04-01 00:00:00）。
    add_time 按 WP 口径取语句里第 30 个值（vals[29]）。
    本镜像 dump.sql 是一条语句一单，因此逐条 INSERT 计数即可复现 WP 的 1292。
    """
    count = 0
    total = 0
    for vals in _tp_insert_rows(text, "tp_order"):
        total += 1
        if len(vals) <= 29:
            continue
        try:
            add = int(vals[29])
        except Exception:
            continue
        if start_ts is not None and end_ts is not None:
            if not (start_ts <= add < end_ts):
                continue
        count += 1
    return {"orders": count, "total_insert_rows": total}


def parse_sql_first_order_gap(text: str) -> dict[str, Any]:
    """
    注册时间 → 首次下单时间 间隔最短的用户（WP 题 14）。
    需要 tp_users（含 reg_time）与 tp_order（含 user_id / add_time）。
    列位置优先从 CREATE TABLE 取；本镜像 dump.sql 没有 tp_order 的建表语句，
    退回 TPshop 标准列序（order_id, order_sn, user_id → 索引 2；add_time → 索引 29）。
    """
    users = _tp_insert_rows(text, "tp_users") or _tp_insert_rows(text, "tp_user")
    orders = _tp_insert_rows(text, "tp_order")
    if not users or not orders:
        return {"best": None, "user_rows": len(users), "order_rows": len(orders)}

    uc = _sql_columns(text, "tp_users") or _sql_columns(text, "tp_user")
    oc = _sql_columns(text, "tp_order")
    uid_i = (uc or {}).get("user_id", 0)
    reg_i = (uc or {}).get("reg_time", (uc or {}).get("register_time"))
    if reg_i is None:
        return {"best": None, "error": "tp_users 缺少 reg_time 列",
                "user_rows": len(users), "order_rows": len(orders)}
    # 订单侧的 user_id / add_time 索引
    if oc:
        ouid_i = oc.get("user_id", 2)
        add_i = oc.get("add_time", 29)
    else:
        ouid_i, add_i = _detect_order_cols(users, orders)

    first_by_uid: dict[str, int] = {}
    for o in orders:
        if len(o) <= max(ouid_i, add_i):
            continue
        try:
            add = int(o[add_i])
        except Exception:
            continue
        u = o[ouid_i]
        if u and (u not in first_by_uid or add < first_by_uid[u]):
            first_by_uid[u] = add

    best: dict[str, Any] | None = None
    for u_row in users:
        if len(u_row) <= max(uid_i, reg_i):
            continue
        try:
            reg = int(u_row[reg_i])
        except Exception:
            continue
        uid = u_row[uid_i]
        first = first_by_uid.get(uid)
        if first is None or reg > first:
            continue
        gap = first - reg
        if best is None or gap < best["gap"]:
            best = {"user_id": uid, "reg": reg, "first_order": first, "gap": gap}
    if best:
        best["reg_str"] = _ts_str(best["reg"])
        best["first_order_str"] = _ts_str(best["first_order"])
        best["gap_days"] = round(best["gap"] / 86400, 2)
    return {"best": best, "user_rows": len(users), "order_rows": len(orders),
            "order_user_id_col": ouid_i, "order_add_time_col": add_i,
            "user_reg_time_col": reg_i}


# ---------------------------------------------------------------------------
# 服务器检材「一键求解」（WP 0x05）：
# 合成 FS 常把文件数据放在 extent 指向之外的原始块（extent 被伪造），
# 因此这里以**内容搜索**定位文件，再就地提取上下文并解析，不依赖 inode 路径。
# ---------------------------------------------------------------------------

def _balanced_brace(text: str, start: int) -> int:
    """从 text[start]=='{' 起做引号感知的括号配平，返回配对 '}' 的下标；不配平返回 -1。"""
    depth = 0
    in_str = False
    esc = False
    for j in range(start, min(len(text), start + (1 << 22))):
        c = text[j]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j
    return -1


def _extract_json_at(text: str, needle: str = "run_type") -> str:
    """
    从上下文里抠出**包含 needle 的那个完整 JSON 对象**。

    做法：从 needle 前面最近的 '{' 由近及远逐个试，做括号配平 + json.loads，
    保留所有"跨度覆盖 needle 且能解析成 dict"的候选，最后取最长的那个
    （最外层对象才是配置本体，内层小对象只是巧合）。
    只取最近一个 '{' 会在"JSON 前粘着二进制/文档"时抠出残缺对象。
    """
    i = text.find(needle)
    if i < 0:
        return ""
    r = text.rfind("{", 0, i)
    if r < 0:
        return ""
    cands: list[str] = []
    for start in range(r, -1, -1):
        if text[start] != "{":
            continue
        end = _balanced_brace(text, start)
        if end < i:                       # 跨度没盖住 needle，不是它的外层
            continue
        cand = text[start:end + 1]
        try:
            obj = json.loads(cand)
        except Exception:
            continue
        if isinstance(obj, dict) and needle in cand:
            cands.append(cand)
            if len(cands) >= 64:
                break
    cands.sort(key=len, reverse=True)
    return cands[0] if cands else ""


def _line_score(line: str) -> float:
    """
    给一行文本打"像真日志行/结果行"的分。
    合成 FS 里同一段 [RDP]/invokefunction 字符串会同时出现在 Go 二进制的字符串池
    （标识符首字母大写连拼、几乎无空格、常是几千字节一行）和 result.txt 真日志行里，
    按"第一个命中"取会拿到二进制串 ⇒ 用可打印比例 + 长度惩罚 + 空格密度区分。
    真日志/结果行必然有多处空白分隔（时间戳、IP:端口、用户名:口令）。
    """
    body = line.strip()
    if not body:
        return -1.0
    printable = sum(1 for c in body if c.isprintable() or c == "\t")
    score = printable / len(body)
    if len(body) > 2000:
        score -= 0.5
    if len(body) > 120:
        # 越长越不该是一整行日志；空格密度 <3% 说明是连拼的标识符池
        if body.count(" ") < max(3, len(body) * 0.03):
            score -= 0.8
    return score


def _extract_line(text: str, needle: str) -> str:
    """从上下文里挑出包含 needle 且最像真日志行的那一条。"""
    best, bs = "", -1.0
    for line in text.splitlines():
        if needle not in line:
            continue
        s = _line_score(line)
        if s > bs:
            best, bs = line.strip(), s
    # 阈值兜底：分数太低说明是 Go/ELF 字符串池之类的拼接碎片，宁缺毋滥。
    return best if bs >= 0.6 else ""


# ---- 特征行的"像不像真日志行"判据 -------------------------------------------
# 合成 FS 里同名特征串会在很多无关地方出现（C 源码、grep 命令、Go 二进制的字符串池），
# 必须靠"这行读起来是不是日志/扫描结果"来筛。
_RE_ACCESS = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b.*\[\d{2}/[A-Za-z]{3}/\d{4}")
_RE_SCANNER = re.compile(r"^\[(?:RDP|SMB|SSH|Telnet|tomcat)\]\s+\S+")
_RE_CRED = re.compile(r":\s*\S+:[^ ]*")


def _rank(res: Any, name: str) -> int:
    """给一个候选结果打"可信度"分：分高的进答案表，分低的只是噪声。"""
    if not isinstance(res, dict):
        return 0
    u = len(json.dumps(res, ensure_ascii=False, sort_keys=True))

    if "users" in res:                                    # passwd
        return (6 if res.get("root_uid0") and res.get("uid_sane") else 0) + len(res["users"])
    if "orders" in res:                                    # sql（dump.sql）
        return res.get("orders", 0) * 100 + (1000 if (res.get("gap") or {}).get("best") else 0)
    if "auth_code" in res:                                 # config.php
        ac = str(res["auth_code"])
        return (50 if ac.isprintable() and len(ac) <= 32 else 0) + len(ac)
    if "DB_PWD" in res:                                    # database.php
        p = str(res["DB_PWD"])
        return (200 if re.fullmatch(r"[A-Za-z0-9]{6,32}", p) else 0) + len(p)
    if "line" in res:                                      # access.log / result.txt
        ln = res["line"]
        s = (500 if _RE_ACCESS.search(ln) else 0) + (600 if _RE_SCANNER.match(ln) else 0) \
            + (400 if _RE_CRED.search(ln) else 0)
        return s + len(ln)
    if "remote_addr" in res:                                # trojan config.json
        return (300 if str(res["remote_addr"]) and str(res["remote_addr"]) != "example.com" else 0) \
            + u
    return u


def _context_text(ctx: bytes) -> str:
    return ctx.decode("utf-8", "replace")


# 每个求解目标：名称 / 内容特征（pattern）/ 如何取文本 / 解析回调
def solve_server_fs(x, progress_cb=None, password: str = "sbwyz1",
                    region: int = 4 << 20,
                    hits_cache: str | os.PathLike | None = None,
                    rescan: bool = False) -> dict[str, Any]:
    """
    对已打开的服务器 FS（XFS 对象 x）做一次全盘内容扫描，定位并解析 WP 0x05
    各题所需文件。返回 {目标名: 命中列表，每个含 off/blk/result}。

    region：命中点周围回读的字节数（默认 4 MiB）。find_contents 自带的 256 字节
      上下文只够"看见字符串"，不够解析一整份文件（passwd 的 www/mysql 行、
      config 的 AUTH_CODE 赋值、access.log 的完整一行、config.json 的整份 JSON
      都在窗口外）⇒ 必须按 off 回读大区域再解析。

    hits_cache：命中结果缓存文件（JSON）。45 GiB 的 XFS 扫一次约 10 分钟，
      而各题解析与重跑（改口令、改 region、调试）不需要重新扫盘 ⇒ 首次扫描
      落盘，之后直接读缓存。

    rescan：True 时忽略已有缓存、强制重新全盘扫描（检材换版本时用）。
    """
    from datetime import datetime as _dt

    targets = [
        # (名称, 特征, 种类, 回读字节数 0=用默认 region)
        ("passwd",   b"root:x:0:0",      "text", 0),
        ("trojan",   b"run_type",        "json", 0),
        ("config",   b"AUTH_CODE",       "text", 0),
        ("database", b"DB_PWD",          "text", 0),
        ("access",   b"invokefunction",  "line", 0),
        ("result",   b"[RDP]",           "line", 0),
        # dump.sql 有 32 MiB，tp_order 的 INSERT 在文件中部、tp_users 在其后
        # （表名按字典序导出），4 MiB 窗口看不到 tp_users ⇒ 回读 64 MiB 才能把
        # "注册→首单" 配对做全（题 14）。
        ("sql",      b"INSERT INTO `tp_order`", "sql", 64 << 20),
        # wtmp 用完整 32 字节 ut_user（"reboot"+26 个零）当特征：裸 "reboot\0"
        # 会命中源码/手册里的同名字符串，真记录则是 32 字节定长字段。
        ("wtmp",     b"reboot" + b"\x00" * 26, "wtmp", 0),
        # 题 8：PHP-GD 版本。gd_info() 打印用的是 ext/gd/gd.c 里的格式串
        # "bundled (%s compatible)"（版本由 PHP_GD_VERSION_STRING 运行时拼接），
        # 用这个格式串定位 PHP 的 GD 扩展代码段，再在附近找版本字面量。
        ("gd",       b"bundled (%s compatible)", "gd", 0),
    ]
    pats = [t[1] for t in targets]

    # ---- 命中缓存：全盘扫描结果只算一次，之后走磁盘 ----
    hits = None
    cp = Path(hits_cache) if hits_cache else None
    sig = [p.decode("latin-1") for p in pats]   # 特征签名（latin-1 可逆）
    if cp is not None and not rescan and cp.exists():
        try:
            blob = json.loads(cp.read_text(encoding="utf-8"))
            if blob.get("pats") != sig:            # 特征集变了 → 缓存作废重扫
                blob = None
            if blob:
                hits = blob["hits"]
                # 缓存里不落 ctx（每条 256 字节的上下文纯属占地方）；
                # 解析时按 off 回读整块区域，ctx 只在回读失败时兜底。
                for v in hits.values():
                    for h in v:
                        h["ctx"] = ""
        except Exception:
            hits = None
    if hits is None:
        hits = x.find_contents(pats, progress_cb=progress_cb)
        if cp is not None:
            try:
                cp.parent.mkdir(parents=True, exist_ok=True)
                lean = {"pats": sig,
                        "hits": {i: [{"off": h["off"], "blk": h["blk"]} for h in v]
                                 for i, v in hits.items()}}
                cp.write_text(json.dumps(lean), encoding="utf-8")
            except Exception:
                pass

    start_ts = int(_dt(2016, 4, 1).timestamp())
    end_ts = int(_dt(2025, 4, 1).timestamp())
    out: dict[str, Any] = {}
    for (name, pat, kind, t_region), hitlist in zip(targets, hits.values()):
        items = []
        r = t_region or region
        # ★ wtmp 特殊处理：要的是**全盘最早的 boot 记录**，不能取前几个命中就停。
        if kind == "wtmp":
            boots: dict[int, dict] = {}
            for h in hitlist:                      # 遍历**全部**命中
                rec_off = max(0, h["off"] - 44)
                try:
                    rec = x.read(rec_off, _UTMP_REC)
                except Exception:
                    continue
                if len(rec) < _UTMP_REC:
                    continue
                if struct.unpack_from("<h", rec, 0)[0] != UT_BOOT_TIME:
                    continue
                tv = struct.unpack_from("<i", rec, _UT_TV_SEC)[0]
                if not (0 < tv < 4_000_000_000):   # 合法 Unix 时间戳
                    continue
                host = rec[76:76 + 256].split(b"\x00")[0].decode("utf-8", "replace")
                if tv not in boots:
                    boots[tv] = {"boot_tv": tv, "boot_str": _ts_str(tv),
                                 "kernel": host, "blk": h["blk"], "off": h["off"]}
            if boots:
                tvs = sorted(boots)
                out["wtmp"] = {
                    "boot_count": len(tvs),
                    "earliest": _ts_str(tvs[0]),
                    "latest": _ts_str(tvs[-1]),
                    "earliest_kernel": boots[tvs[0]].get("kernel", ""),
                    "boots": [boots[t] for t in tvs],
                }
            else:
                out["wtmp"] = {"boot_count": 0, "earliest": "", "latest": "",
                               "boots": []}
            continue

        # ★ 其余目标：真实文件往往不在最早的那几个命中里（最早的多是框架源码/
        #   测试用例里的同名字符串），因此逐个命中尝试解析，直到拿到有内容的结果。
        for h in hitlist[:40]:
            # 回读大区域：命中点前留一截（passwd/JSON 的完整对象常在命中点之前），
            # 后面留足 r 字节（dump.sql 这类大文件在命中点之后还有几千行）。
            back = min(1 << 20, r >> 2)
            start = max(0, h["off"] - back)
            try:
                big = x.read(start, r - back)
                ctx = big.decode("utf-8", "replace")
            except Exception:
                ctx = _context_text(h["ctx"]) if h["ctx"] else ""
            res: Any = None
            good = False
            if kind == "json":
                js = _extract_json_at(ctx)
                if js:
                    try:
                        res = parse_trojan_config(js)
                        # 能解析出来的 JSON 不一定是受害者机上的配置：源码仓库/示例目录里
                        # 也有 run_type（示例配置 remote_addr 写的是 example.com）。
                        # ⇒ 必须有 remote_addr 且不是厂商示例值。
                        good = bool(res.get("remote_addr")) \
                            and str(res["remote_addr"]) != "example.com"
                    except Exception:
                        res = {"error": "JSON 解析失败"}
                else:
                    res = {"error": "JSON 未抠出"}
            elif kind == "text":
                if name == "config":
                    res = parse_php_encrypt(ctx, password)
                    # 真 config.php 的 AUTH_CODE 是短纯 ASCII 口令；带二进制尾巴的
                    # （如 "TPSH9V\<null>POP"）是同一串被拼进 ELF 字符串池的副本。
                    ac = str(res.get("auth_code", ""))
                    good = bool(ac) and ac.isprintable() and len(ac) <= 32
                elif name == "database":
                    m = re.search(r"DB_PWD['\"]?\s*=>\s*['\"]([^'\"]+)['\"]", ctx)
                    m2 = re.search(r"DB_USER['\"]?\s*=>\s*['\"]([^'\"]+)['\"]", ctx)
                    res = {"DB_PWD": m.group(1) if m else "",
                           "DB_USER": m2.group(1) if m2 else ""}
                    # 模板占位符 [DB_PWD]、中文说明、二进制碎片都不算真口令
                    good = bool(re.fullmatch(r"[A-Za-z0-9]{6,32}", res["DB_PWD"]))
                else:
                    pw = parse_passwd(ctx)
                    users = pw["users"]
                    res = {"users": users, "count": pw["count"]}
                    # 真 /etc/passwd 的账号名是 login(1) 约束的：小写字母/数字/_/./-，
                    # 无引号、反斜杠、空格。合成 FS 里大量 C 源码/规则库/二进制串
                    # 也含 "root:x:0:0" 形态（b'root'、match http m|…），靠这一条
                    # 就能全数剔掉。
                    def _ok_user(n: str) -> bool:
                        return bool(n) and re.fullmatch(r"[A-Za-z0-9_.\-]+", n) is not None
                    clean = [u for u in users if _ok_user(u["name"])]
                    good = len(clean) >= 3
            elif kind == "line":
                line = _extract_line(ctx, pat.decode("latin-1"))
                res = {"line": line}
                # 行必须是"真日志/扫描结果"的样子：access 是 IP+日期+请求，
                # result 是 [RDP]/[SMB]/… 前缀 + 主机:端口 + 凭据。
                good = bool(line) and (
                    _RE_ACCESS.search(line) or _RE_SCANNER.match(line) or _RE_CRED.search(line)
                )
                if name == "access":
                    # 题 12：同一份 access.log 里还能抠出投递的一句话木马原文 + SHA-256
                    ws = parse_webshell(ctx)
                    if ws["count"]:
                        res["webshell"] = ws
                        good = True          # 有木马原文的 access.log 一定是真日志
                elif name == "result":
                    good = _RE_SCANNER.match(line) and _RE_CRED.search(line)
            elif kind == "gd":
                # ext/gd/gd.c: php_info_print_table_row(2, "GD Version",
                #   "bundled (%s compatible)", PHP_GD_VERSION_STRING)
                lits = sorted(set(re.findall(r"bundled\s*\(([^)]{0,40})\)\s*compatible", ctx)))
                vers = sorted(set(re.findall(r"\b2\.\d+\.\d+\b", ctx)))
                res = {"gd_literals": lits, "version_candidates": vers[:20],
                       "gd_info": "gd_info" in ctx or "GD Version" in ctx}
                good = bool(lits)
            elif kind == "sql":
                res = parse_sql_orders(ctx, start_ts, end_ts)
                res["gap"] = parse_sql_first_order_gap(ctx)
                good = res.get("orders", 0) > 0
            if good:
                items.append({"off": h["off"], "blk": h["blk"], "result": res})
        # ★ 不"取前 3 个命中就停"：同一份文件会被多次命中（XFS 里重复分布 + 相邻块
        #   重复），而真实文件往往不在最早的那几个命中里。所以把窗口内**所有**命中
        #   都解析一遍，按结果质量打分，再按"结果去重"取最好的 3 份。
        def _score(c: dict) -> int:
            return _rank(c["result"], name)
        items.sort(key=_score, reverse=True)
        uniq: list[dict] = []
        seen: set[str] = set()
        for c in items:
            key = json.dumps(c["result"], ensure_ascii=False, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            uniq.append(c)
            if len(uniq) >= 3:
                break
        out[name] = uniq
    return out
