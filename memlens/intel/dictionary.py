r"""
MemLens · 词典模型

词典 = 一组「值得注意的特征」的集合。用于把几十万行结果里的线索一键捞出来。

与参考实现（逐条目 × 逐行 双层循环、每次匹配重新编译）的关键差别：
  * **一次编译，一趟扫描**：同一词典内所有条目合并成一个带命名组的正则，
    `finditer` 一趟就能同时命中所有条目，并通过组名反查是哪个条目命中的。
  * **条目数很大时自动降级**：合并正则过长会拖慢编译，超过阈值改用分批编译。
  * **file_globs 路由**：词典/条目级都能限定适用文件名（例如"敏感端口"只喂给
    `*net*` 的产物），避免在无关文件上做无意义的全量扫描。

匹配模式：
  * kind="keyword" → 子串包含，大小写按 `case_sensitive`；
    `whole_word=True` 时加词边界。
    ⚠ 注册表路径（`HKLM\` 开头）**绝不能加词边界**——`\` 不是单词字符，
    `\bHKLM\\...\b` 永远匹配不上，这是个经典的坑。
  * kind="regex"   → 交给 `re` 编译，语法错误会在加载时报出来（不静默跳过）。
"""

from __future__ import annotations

import dataclasses
import fnmatch
import json
import re
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

# 合并正则的规模上限：超过就分批编译，避免单条正则编译耗时失控
MAX_COMBINED_PATTERNS = 3000
MAX_COMBINED_CHARS = 400_000

SEVERITIES = ("info", "low", "medium", "high", "critical")

#: "强"正则元字符——出现即认为该模式本身是正则。
#: 刻意**不含** `.` 与 `*`：`mimikatz.exe`、`a*b` 这类关键词非常常见，
#: 若按正则解释会把 `mimikatzXexe` 也命中（误报），且 `*` 还能构造出灾难性回溯。
_STRONG_META = re.compile(r"[\\\[\](){}|^$+?{}]")

#: 前导内联全局标志，如 `(?i)` / `(?is)`。合并正则里必须把它们提出来用 flags= 传。
_INLINE_FLAGS = re.compile(r"^\(\?([aiLmsux]+)\)")
_FLAG_MAP = {"a": re.ASCII, "i": re.IGNORECASE, "L": re.LOCALE,
             "m": re.MULTILINE, "s": re.DOTALL, "u": re.UNICODE, "x": re.VERBOSE}


def _split_inline_flags(pattern: str) -> tuple[int, str]:
    """拆出表达式开头内联全局标志，返回 (flags, 剩余表达式)。"""
    flags = 0
    rest = pattern
    while True:
        m = _INLINE_FLAGS.match(rest)
        if not m:
            return flags, rest
        for ch in m.group(1):
            flags |= _FLAG_MAP.get(ch, 0)
        rest = rest[m.end():]


# ------------------------------------------------------------------ 条目


@dataclasses.dataclass
class Entry:
    """词典中的一个条目（一个"特征"的全部表述）。"""

    name: str
    patterns: list[str]
    kind: str = "auto"                   # auto | keyword | regex
    note: str = ""                        # 中文说明 / 为什么要找它
    advice: str = ""                      # 命中后建议做什么
    tags: list[str] = dataclasses.field(default_factory=list)
    severity: str = "medium"
    whole_word: bool = False              # 关键词是否要求单词边界
    case_sensitive: bool = False
    file_globs: tuple[str, ...] = ()      # 空 = 不限；否则只对这些文件名生效

    def applies_to(self, filename: str | None) -> bool:
        if not self.file_globs:
            return True
        if filename is None:
            return False
        low = filename.lower()
        return any(fnmatch.fnmatch(low, g.lower()) for g in self.file_globs)

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "patterns": list(self.patterns),
            "note": self.note,
            "advice": self.advice,
            "tags": list(self.tags),
            "severity": self.severity,
            "whole_word": self.whole_word,
            "case_sensitive": self.case_sensitive,
            "file_globs": list(self.file_globs),
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Entry":
        pats = d.get("patterns")
        if pats is None:
            # 兼容紧凑写法：{"name":..,"content":"a, b, c"}
            raw = d.get("content", "")
            pats = [p.strip() for p in str(raw).split(",") if p.strip()]
        if isinstance(pats, str):
            pats = [p.strip() for p in pats.split(",") if p.strip()]
        return cls(
            name=str(d.get("name", "")),
            patterns=[str(p) for p in pats],
            kind=str(d.get("kind") or ("regex" if d.get("type_name") == "正则表达式" else "auto")),
            note=str(d.get("note") or d.get("description") or ""),
            advice=str(d.get("advice") or ""),
            tags=[str(t) for t in (d.get("tags") or [])],
            severity=str(d.get("severity", "medium")),
            whole_word=bool(d.get("whole_word", d.get("is_exact_match", False))),
            case_sensitive=bool(d.get("case_sensitive", False)),
            file_globs=tuple(d.get("file_globs") or ()),
        )


# ------------------------------------------------------------------ 词典


@dataclasses.dataclass
class Dictionary:
    """一组条目。"""

    id: str
    name: str
    description: str = ""
    entries: list[Entry] = dataclasses.field(default_factory=list)
    file_globs: tuple[str, ...] = ()     # 词典级路由
    builtin: bool = False
    source: str = ""

    # ------------------------------------------------------------ 匹配
    def applies_to(self, filename: str | None) -> bool:
        if not self.file_globs:
            return True
        if filename is None:
            return False
        low = filename.lower()
        return any(fnmatch.fnmatch(low, g.lower()) for g in self.file_globs)

    def candidates(self, filename: str | None) -> list[Entry]:
        """按文件名过滤出真正要扫的条目。"""
        return [e for e in self.entries if e.applies_to(filename)]

    def __len__(self) -> int:
        return len(self.entries)

    def iter_patterns(self) -> Iterator[tuple[Entry, str]]:
        for e in self.entries:
            for p in e.patterns:
                yield e, p

    # ------------------------------------------------------------ 序列化
    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "file_globs": list(self.file_globs),
            "entries": [e.to_json() for e in self.entries],
        }

    @classmethod
    def from_json(cls, d: dict[str, Any], *, source: str = "") -> "Dictionary":
        entries = []
        for raw in (d.get("entries") or d.get("items") or []):
            try:
                entries.append(Entry.from_json(raw))
            except Exception:
                continue
        return cls(
            id=str(d.get("id") or d.get("name") or "dict"),
            name=str(d.get("name") or d.get("id") or "未命名词典"),
            description=str(d.get("description") or ""),
            entries=entries,
            file_globs=tuple(d.get("file_globs") or ()),
            builtin=bool(d.get("builtin", False)),
            source=source,
        )


# ------------------------------------------------------------------ 命中


@dataclasses.dataclass(frozen=True)
class Hit:
    """一次命中。"""

    dict_id: str
    dict_name: str
    entry_name: str
    pattern: str
    value: str
    severity: str
    tags: tuple[str, ...]
    note: str = ""
    advice: str = ""
    line_no: int = -1
    context: str = ""
    #: 出处（哪个插件的记录）
    source_plugin: str = ""
    offset: int = -1

    def to_record(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "dict": self.dict_name,
            "entry": self.entry_name,
            "match": self.value,
            "severity": self.severity,
            "tags": ",".join(self.tags),
        }
        if self.note:
            d["note"] = self.note
        if self.advice:
            d["advice"] = self.advice
        if self.line_no >= 0:
            d["line"] = self.line_no
        if self.context:
            d["context"] = self.context
        if self.source_plugin:
            d["source_plugin"] = self.source_plugin
        if self.offset >= 0:
            d["offset"] = self.offset
        return d


# ------------------------------------------------------------------ 扫描器


class DictionaryScanner:
    """
    把词典编译成可执行的匹配器。

    编译策略：
      * 条目少/短 → 合并成一个带命名组的正则，一趟扫描（最快）
      * 规模大     → 分批编译（每批不超过阈值），多趟扫描
    """

    def __init__(self, dictionary: Dictionary) -> None:
        self.dict = dictionary
        self._batches: list[tuple[re.Pattern[str], dict[str, tuple[Entry, str]]]] = []
        self._errors: list[str] = []
        self._compile()

    # ------------------------------------------------------------ 编译
    def _compile(self) -> None:
        pairs = list(self.dict.iter_patterns())
        if not pairs:
            return

        # ---- 归一化：把前导内联全局标志 (?i)(?is)… 摘出来 ----
        #
        # ⚠ 这不是洁癖：Python 3.11 起，"global flags not at the start of the expression"
        #    是**编译期错误**。合并正则里每个分支都裹在 (?P<gN>…) 里，
        #    于是用户写的 `(?i)password...` 会落到中间位置直接编译失败。
        #    正确做法是把标志提出来用 flags= 传，而不是留在表达式里。
        normalized: list[tuple[str, Entry, str, int]] = []
        needs_per_pattern = False
        for entry, pat in pairs:
            flags, body = _split_inline_flags(pat)
            if flags:
                needs_per_pattern = True       # 各分支标志可能不同，放弃合并
            try:
                lit = self._literal(entry, body)
            except re.error as exc:
                self._errors.append(f"条目「{entry.name}」正则有误：{exc}")
                continue
            normalized.append((lit, entry, pat, flags))

        if not normalized:
            return

        # ---- 逐条模式 ----
        if needs_per_pattern:
            for lit, entry, pat, flags in normalized:
                try:
                    # ⚠ 必须保留命名组：表的键是组名，编译出来却没有这个组，
                    #    扫描时 m.group() 会抛 IndexError（这个坑踩过）。
                    rx = re.compile(f"(?P<g0>{lit})", flags)
                    self._batches.append((rx, {"g0": (entry, pat)}))
                except re.error as exc:
                    self._errors.append(f"条目「{entry.name}」正则有误：{exc}")
            return

        # ---- 合并模式（快路径）----
        budget_n, budget_c = MAX_COMBINED_PATTERNS, MAX_COMBINED_CHARS
        batch: list[tuple[str, Entry, str]] = []

        def flush() -> None:
            nonlocal batch
            if not batch:
                return
            parts: list[str] = []
            table: dict[str, tuple[Entry, str]] = {}
            for idx, (lit, entry, pat) in enumerate(batch):
                gname = f"g{idx}"
                parts.append(f"(?P<{gname}>{lit})")
                table[gname] = (entry, pat)
            try:
                compiled = re.compile("|".join(parts))
                self._batches.append((compiled, table))
            except re.error as exc:
                self._errors.append(f"合并编译失败（{len(batch)} 条）：{exc}；改用逐条模式")
                self._batches.clear()
                for lit, entry, pat, _f in batch:
                    try:
                        self._batches.append(
                            (re.compile(f"(?P<g0>{lit})"), {"g0": (entry, pat)}))
                    except re.error as exc2:
                        self._errors.append(f"条目「{entry.name}」正则有误：{exc2}")
            batch = []

        for lit, entry, pat, _flags in normalized:
            budget_c -= len(lit) + 8
            batch.append((lit, entry, pat))
            if len(batch) >= budget_n or budget_c <= 0:
                flush()
        flush()

    def _literal(self, entry: Entry, pattern: str) -> str:
        """
        把一个模式变成正则字面量，并决定它到底按关键词还是按正则处理。

        `kind="auto"` 的判定规则：出现**强正则元字符**就按正则，否则按字面量。
        之所以不把 `.` 当强元字符，是因为 `mimikatz.exe` 这类关键词里点号极常见，
        按正则解释就变成了"任意字符"，会把 `mimikatzXexe` 也命中（误报）。

        （这条坑踩过：条目默认按 keyword 处理时，正则会被 re.escape 成
          `flag\\{[^}]+\\}` 这种死字符串，于是永远扫不到东西。）
        """
        if entry.kind == "regex" or (entry.kind == "auto" and _STRONG_META.search(pattern)):
            return pattern
        lit = re.escape(pattern)
        if entry.whole_word and not _starts_with_path_root(pattern):
            lit = r"\b" + lit + r"\b"
        return lit

    @property
    def errors(self) -> list[str]:
        return list(self._errors)

    # ------------------------------------------------------------ 扫描
    def scan_text(
        self,
        text: str,
        *,
        filename: str | None = None,
        source_plugin: str = "",
        offset_base: int = 0,
        context_chars: int = 60,
        max_hits: int = 500,
    ) -> list[Hit]:
        """在一段文本里匹配整个词典。"""
        if not text:
            return []
        if not self.dict.applies_to(filename):
            return []
        allowed = {id(e) for e in self.dict.candidates(filename)}

        hits: list[Hit] = []
        seen: set[tuple[str, str, int]] = set()
        for compiled, table in self._batches:
            known = compiled.groupindex
            for m in compiled.finditer(text):
                gname = m.lastgroup
                if gname not in table:
                    # lastgroup 可能指向模式内部的匿名组；回退到逐个比对
                    gname = next((g for g in table
                                  if g in known and m.group(g) is not None), None)
                if gname is None:
                    continue
                entry, pat = table[gname]
                if id(entry) not in allowed:
                    continue
                value = m.group(gname)
                key = (entry.name, value, m.start())
                if key in seen:
                    continue
                seen.add(key)
                lo = max(0, m.start() - context_chars)
                hi = min(len(text), m.end() + context_chars)
                hits.append(Hit(
                    dict_id=self.dict.id,
                    dict_name=self.dict.name,
                    entry_name=entry.name,
                    pattern=pat,
                    value=value[:200],
                    severity=entry.severity,
                    tags=tuple(entry.tags),
                    note=entry.note,
                    advice=entry.advice,
                    line_no=text.count("\n", 0, m.start()) + 1,
                    context=" ".join(text[lo:hi].split())[:300],
                    source_plugin=source_plugin,
                    offset=offset_base + m.start() if offset_base >= 0 else -1,
                ))
                if len(hits) >= max_hits:
                    return hits
        return hits


def _starts_with_path_root(pattern: str) -> bool:
    """
    判断一个关键词是否以"根"开头（注册表路径、盘符、UNC 等）。

    这类模式必须用子串匹配：反斜杠不是单词字符，加 `\\b` 必然匹配失败。
    这是词典扫描最常见的"配了却永远搜不到"的原因。
    """
    p = pattern.strip()
    roots = ("HKLM\\", "HKCU\\", "HKU\\", "HKCR\\", "HKCC\\",
             "HKEY_LOCAL_MACHINE\\", "HKEY_CURRENT_USER\\", "HKEY_USERS\\",
             "HKEY_CLASSES_ROOT\\", "HKEY_CURRENT_CONFIG\\")
    return p.upper().startswith(roots) or (len(p) > 2 and p[1] == ":" and p[2] == "\\")


# ------------------------------------------------------------------ 词库加载


def load_dictionary_file(path: str | Path) -> list[Dictionary]:
    """
    从 JSON 文件加载词典。文件可以是一个词典对象，也可以是 `{"dictionaries": [...]}`。

    也兼容常见的紧凑条目写法 `{"items":[{"name":..,"content":"a, b"}]}`。
    """
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8-sig"))
    out: list[Dictionary] = []
    if isinstance(data, list):
        for d in data:
            out.append(Dictionary.from_json(d, source=str(p)))
    elif isinstance(data, dict):
        if "dictionaries" in data:
            for d in data.get("dictionaries") or []:
                out.append(Dictionary.from_json(d, source=str(p)))
        elif "items" in data or "entries" in data:
            out.append(Dictionary.from_json(data, source=str(p)))
        else:
            out.append(Dictionary.from_json(data, source=str(p)))
    return [d for d in out if d.entries]


def save_dictionary_file(dicts: Iterable[Dictionary], path: str | Path) -> None:
    """保存词典到 JSON（用户自定义词典用）。"""
    payload = {"dictionaries": [d.to_json() for d in dicts]}
    Path(path).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def load_all(paths: Iterable[str | Path]) -> list[Dictionary]:
    """从多个文件加载，后加载的同名词典会覆盖先加载的。"""
    merged: dict[str, Dictionary] = {}
    for path in paths:
        try:
            for d in load_dictionary_file(path):
                merged[d.id] = d
        except Exception:
            continue
    return list(merged.values())
