r"""
MemLens · 时间基准模块（统一 UTC 存储 + 原始时区留存 + 换算留痕）

## 为什么这是第一优先级

方案《计算机系统数字取证工作台开发方案》5.3 明确写道：

> 一条报告曾因把**设备本地时间当成协调世界时**直接与日志比对，
> 整整错了八小时，结论从"吻合"变成"完全对不上"，最后是复核时才发现。
> 此后时间换算列为强制留痕项。

这条坑的成因不是精度，是**语义**：同一串 `2026-03-01 10:00:00`，
在 UTC+8 的机器上解析出来是 `02:00Z`，在 UTC 的机器上是 `10:00Z`。
取证工具跑在**分析机**上，用分析机的时区去解析**目标机**的时间，
必然随作业机而变——同一份镜像，换台机器跑，时间线就整体平移。

⇒ 本模块的硬规矩：**任何时间一律先转 UTC 入库，同时保留原始时区与偏移量**，
换算走哪条路径、做了什么假设，全部留痕。

## 四条设计约定

1. **单一入口**：全项目只有本模块能把"任意时间表达"变成 UTC。
   其它模块（timeline / records 抽取 / sysprofile / report）一律调它，
   不允许各自写 `fromtimestamp`。
2. **naive 时间必须显式声明假设**：没有时区信息的时间串，
   按 `assume` 参数（默认 `local`）处理，并把假设写进 `tz_assumption`。
   **不猜、不静默**。
3. **原始值必须留存**：`ts_raw` 保存未经改写的原始表示，
   `tz_offset` 保存偏移秒数，`tz_name` 保存原始时区标识（如 `UTC+08:00`）。
   复核时能一眼看出"这个时间是怎么来的"。
4. **可逆**：给定 `ts_utc` + `tz_offset`，能还原出目标机本地时间。

## 时间表达类型

| 类型 | 例子 | 处理 |
|---|---|---|
| Unix 秒 / 毫秒 / 微秒 | `1780000000` | 数值量级判定 |
| Windows FILETIME | `133000000000000000` | 1601 纪元，100 ns |
| ISO 8601 带偏移 | `2026-03-01T10:00:00+08:00` | 直接取偏移 |
| ISO 8601 无偏移 | `2026-03-01 10:00:00` | 按 `assume` 补时区 |
| 带时区名 | `2026-03-01 10:00:00 UTC` | 按名字补时区 |
| 浏览器纪元 | Chromium `1601` 纪元微秒 / Firefox `1970` 纪元微秒 | 由调用方显式指定 |
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import re
from typing import Any

__all__ = [
    "TimeValue",
    "TIME_ASSUMPTIONS",
    "normalize",
    "to_utc_iso",
    "utc_now_iso",
    "from_utc_iso",
    "to_local",
    "describe_conversion",
]


#: 时间假设类型（写进证据项，供复核）
TIME_ASSUMPTIONS: tuple[str, ...] = ("utc", "local", "explicit_offset", "explicit_tz", "epoch_known")

#: 本机时区（缓存，避免反复取）
_LOCAL_TZ: dt.tzinfo | None = None


def _local_tz() -> dt.tzinfo:
    global _LOCAL_TZ
    if _LOCAL_TZ is None:
        _LOCAL_TZ = dt.datetime.now().astimezone().tzinfo or dt.timezone.utc
    return _LOCAL_TZ


# ---------------------------------------------------------------- 正则

_ISO_RE = re.compile(
    r"(?P<y>\d{4})[-/](?P<mo>\d{1,2})[-/](?P<d>\d{1,2})"
    r"(?:[T ](?P<h>\d{1,2}):(?P<mi>\d{2})(?::(?P<s>\d{2}))?(?:\.(?P<f>\d+))?)?"
)
#: 时区偏移：只认 `+08:00` / `+0800` / `+08` 三种形态。
#: ⚠ **绝不能直接全文搜**——`2026-03-01 10:00:00` 里的 `-03` 会被当成 "-3 小时"，
#:   于是朴素时间被误判成"带偏移"，换算结果凭空偏 3 小时（实测踩过）。
#:   ⇒ 偏移**只允许出现在时间部分之后**（见 normalize 的处理顺序）。
_OFFSET_RE = re.compile(
    r"(?P<sign>[+-])(?P<oh>\d{1,2})(?::(?P<om>\d{2}))?(?!\d)"
)
#: 时区名：只认明确的 UTC/GMT/Z 及其带偏移写法。
#:   不认 `[A-Z]{2,5}T` 这种"单词以 T 结尾"的模式——它会把 IMPORT 之类误判成时区。
_TZ_NAME_RE = re.compile(
    r"(?:UTC|GMT)(?P<sign>[+-])(?P<oh>\d{1,2})(?::(?P<om>\d{2}))?(?!\d)"
    r"|\b(?P<plain>UTC|GMT)\b"
    r"|(?<![0-9A-Za-z])Z(?![0-9A-Za-z])",
    re.IGNORECASE,
)
_NUM_RE = re.compile(r"^\s*[-+]?\d{9,19}\s*$")
_SIZE_RE = re.compile(r"^\s*(\d{1,4})\s*([KMG]B)\s*$", re.IGNORECASE)


@dataclasses.dataclass
class TimeValue:
    """
    一次时间归一化的结果。

    Attributes:
        utc: 归一后的 UTC 时间（带 tzinfo）。解析失败为 None。
        raw: 原始表示（原样保留，供复核）
        offset: 偏移秒数（东八区 = 28800）。无时区信息且按 local 处理时为本地偏移。
        tz_name: 原始时区标识（若原串带 UTC / UTC+08:00 之类）
        assumption: 采用的假设（TIME_ASSUMPTIONS 之一）；无法解析时为空
        note: 换算过程的自然语言说明（留痕）
    """

    utc: dt.datetime | None
    raw: str = ""
    offset: int | None = None
    tz_name: str = ""
    assumption: str = ""
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.utc is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts_utc": self.utc.isoformat() if self.utc else "",
            "ts_raw": self.raw,
            "tz_offset": self.offset,
            "tz_name": self.tz_name,
            "tz_assumption": self.assumption,
            "tz_note": self.note,
        }


# ---------------------------------------------------------------- 工具

def _looks_like_filetime(v: int) -> bool:
    """FILETIME：1601-01-01 起的 100 ns 计数（合理区间约 1970–2100）。"""
    return 116_444_736_000_000_000 < v < 134_000_000_000_000_000


def _parse_offset(text: str) -> int | None:
    m = _OFFSET_RE.search(text)
    if not m:
        return None
    oh = int(m.group("oh"))
    om = int(m.group("om") or 0)
    secs = oh * 3600 + om * 60
    return -secs if m.group("sign") == "-" else secs


def _tz_from_name(name: str) -> dt.tzinfo | None:
    """把 `UTC` / `UTC+08:00` / `GMT-5` 之类转成 tzinfo。"""
    if not name:
        return None
    u = name.upper()
    if u in ("UTC", "GMT", "Z", "UTC+0", "GMT+0"):
        return dt.timezone.utc
    m = re.match(r"(?:UTC|GMT)([+-])(\d{1,2})(?::?(\d{2}))?$", u)
    if m:
        secs = int(m.group(2)) * 3600 + int(m.group(3) or 0) * 60
        if m.group(1) == "-":
            secs = -secs
        return dt.timezone(dt.timedelta(seconds=secs))
    return None


def _offset_seconds(tz: dt.tzinfo | None, at: dt.datetime) -> int | None:
    """取某时区在指定时刻的实际偏移秒数。"""
    if tz is None:
        return None
    try:
        off = at.utcoffset()
    except Exception:
        return None
    return int(off.total_seconds()) if off is not None else None


# ---------------------------------------------------------------- 主入口

def normalize(
    value: Any,
    *,
    assume: str = "local",
    epoch: str | None = None,
    default_tz: dt.tzinfo | None = None,
) -> TimeValue:
    """
    把任意时间表达归一化为 UTC。

    Args:
        value: 时间值（datetime / 数字 / 字符串）
        assume: naive 时间（无时区信息）的假设：`local`（默认，作业机本地时区）
                或 `utc`。**假设会被记录**，不是静默行为。
        epoch: 已知纪元（`webk it` → 1601 微秒 / `unix` → 1970 微秒 / `filetime`）。
               浏览器与 Windows 专用纪元必须显式声明，不猜。
        default_tz: 目标机时区（已知时传入，比 `local` 更准）

    Returns:
        TimeValue：含 UTC 值、原始表示、偏移、假设与留痕说明
    """
    raw = "" if value is None else str(value)

    # ---- ① datetime 对象 ----
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            return _from_naive(value, assume=assume, default_tz=default_tz, raw=raw)
        return _from_aware(value, raw=raw)

    if value is None or (isinstance(value, str) and not value.strip()):
        return TimeValue(None, raw=raw, note="空值")

    # ---- ② 数值：Unix / FILETIME / 已知纪元 ----
    if isinstance(value, (int, float)) or _NUM_RE.match(str(value).strip()):
        try:
            n = int(float(str(value).strip()))
        except (TypeError, ValueError):
            return TimeValue(None, raw=raw, note="数值无法解析")
        return _from_number(n, epoch=epoch, raw=raw)

    text = str(value).strip()

    # ---- ③ 先定位 ISO 主干（日期 + 可选时间）----
    m = _ISO_RE.search(text)
    naive = _build_naive(m) if m else None
    if naive is None:
        return TimeValue(None, raw=raw, note="无法识别的时间格式")

    # ★ **偏移与时区名只在时间部分之后找**（tail）——
    #   否则 `2026-03-01 10:00:00` 的日期分隔符会被误读成时区偏移。
    tail = text[m.end():] if m.group("h") is not None else ""

    # ---- ④ tail 里的显式偏移（+08:00 / -0500）----
    off_secs = _parse_offset(tail)
    if off_secs is not None:
        tz = dt.timezone(dt.timedelta(seconds=off_secs))
        aware = naive.replace(tzinfo=tz)
        return TimeValue(
            aware.astimezone(dt.timezone.utc), raw=raw, offset=off_secs,
            tz_name=_off_label(off_secs), assumption="explicit_offset",
            note=f"串内含显式偏移 {_off_label(off_secs)} → 转 UTC",
        )

    # ---- ⑤ tail 里的时区名（UTC+08:00 / GMT / UTC / Z）----
    tm = _TZ_NAME_RE.search(tail)
    if tm:
        tz = None
        name = ""
        if tm.group("sign"):
            secs = int(tm.group("oh")) * 3600 + int(tm.group("om") or 0) * 60
            if tm.group("sign") == "-":
                secs = -secs
            tz = dt.timezone(dt.timedelta(seconds=secs))
            name = _off_label(secs)
        elif tm.group("plain"):
            tz = dt.timezone.utc
            name = "UTC"
        else:                                   # 单独的 Z
            tz = dt.timezone.utc
            name = "UTC"
        aware = naive.replace(tzinfo=tz)
        off = _offset_seconds(tz, aware)
        return TimeValue(
            aware.astimezone(dt.timezone.utc), raw=raw, offset=off,
            tz_name=name, assumption="explicit_tz",
            note=f"串内含时区标识 {name} → 转 UTC",
        )

    # ---- ⑥ naive ISO 串（走假设，留痕）----
    return _from_naive(naive, assume=assume, default_tz=default_tz, raw=raw)


def _build_naive(m: re.Match) -> dt.datetime | None:
    try:
        micro = 0
        if m.group("f"):
            frac = (m.group("f") + "000000")[:6]
            micro = int(frac)
        return dt.datetime(
            int(m.group("y")), int(m.group("mo")), int(m.group("d")),
            int(m.group("h") or 0), int(m.group("mi") or 0), int(m.group("s") or 0),
            micro,
        )
    except (TypeError, ValueError):
        return None


def _from_naive(naive: dt.datetime, *, assume: str, default_tz: dt.tzinfo | None,
                raw: str) -> TimeValue:
    """naive（无时区）时间 → UTC。**假设显式记录**。"""
    if default_tz is not None:
        aware = naive.replace(tzinfo=default_tz)
        off = _offset_seconds(default_tz, aware)
        return TimeValue(
            aware.astimezone(dt.timezone.utc), raw=raw, offset=off,
            tz_name=_tz_label(default_tz),
            assumption="explicit_offset",
            note=f"按目标机时区 {_tz_label(default_tz)} 补全 → 转 UTC",
        )
    if assume == "utc":
        aware = naive.replace(tzinfo=dt.timezone.utc)
        return TimeValue(
            aware.astimezone(dt.timezone.utc), raw=raw, offset=0, tz_name="UTC",
            assumption="utc", note="无时区信息，按 UTC 假设处理",
        )
    tz = _local_tz()
    aware = naive.replace(tzinfo=tz)
    off = _offset_seconds(tz, aware)
    return TimeValue(
        aware.astimezone(dt.timezone.utc), raw=raw, offset=off,
        tz_name=_tz_label(tz), assumption="local",
        note=(f"无时区信息，按作业机本地时区 {_tz_label(tz)} 假设换算"
              + ("（如已知目标机时区，请改用 default_tz 以免偏差）" if off else "")),
    )


def _from_aware(value: dt.datetime, *, raw: str) -> TimeValue:
    off = _offset_seconds(value.tzinfo, value)
    return TimeValue(
        value.astimezone(dt.timezone.utc), raw=raw, offset=off,
        tz_name=_tz_label(value.tzinfo), assumption="explicit_offset",
        note="带时区对象，直接转 UTC",
    )


def _from_number(n: int, *, epoch: str | None, raw: str) -> TimeValue:
    """数值时间 → UTC。纪元必须可判定，不猜。"""
    e = (epoch or "").lower().replace(" ", "")
    if e in ("webkit", "chrome", "edge", "1601"):
        try:
            return TimeValue(
                dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
                + dt.timedelta(microseconds=n), raw=raw, offset=0,
                tz_name="UTC", assumption="epoch_known",
                note="按 WebKit/1601 纪元（微秒）换算",
            )
        except (OverflowError, ValueError):
            return TimeValue(None, raw=raw, note="WebKit 纪元溢出")
    if e in ("unix_us", "unix_micro"):
        return TimeValue(
            dt.datetime.fromtimestamp(n / 1_000_000, tz=dt.timezone.utc),
            raw=raw, offset=0, tz_name="UTC", assumption="epoch_known",
            note="按 Unix 微秒纪元换算")
    if e in ("unix_ms", "unix_milli"):
        return TimeValue(
            dt.datetime.fromtimestamp(n / 1000, tz=dt.timezone.utc),
            raw=raw, offset=0, tz_name="UTC", assumption="epoch_known",
            note="按 Unix 毫秒纪元换算")
    if e == "filetime":
        try:
            return TimeValue(
                dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
                + dt.timedelta(microseconds=n // 10), raw=raw, offset=0,
                tz_name="UTC", assumption="epoch_known",
                note="按 FILETIME（1601 纪元 100ns）换算")
        except (OverflowError, ValueError):
            return TimeValue(None, raw=raw, note="FILETIME 溢出")

    # 未声明纪元：按量级推断（Unix 秒/毫秒/微秒 或 FILETIME）
    if _looks_like_filetime(n):
        try:
            return TimeValue(
                dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
                + dt.timedelta(microseconds=n // 10), raw=raw, offset=0,
                tz_name="UTC", assumption="epoch_known",
                note="按量级判定为 FILETIME（1601 纪元 100ns）")
        except (OverflowError, ValueError):
            return TimeValue(None, raw=raw, note="FILETIME 溢出")
    if 1_000_000_000 <= n < 100_000_000_000:
        return TimeValue(
            dt.datetime.fromtimestamp(n, tz=dt.timezone.utc), raw=raw, offset=0,
            tz_name="UTC", assumption="epoch_known", note="按量级判定为 Unix 秒")
    if 100_000_000_000 <= n < 10_000_000_000_000:
        return TimeValue(
            dt.datetime.fromtimestamp(n / 1000, tz=dt.timezone.utc), raw=raw, offset=0,
            tz_name="UTC", assumption="epoch_known", note="按量级判定为 Unix 毫秒")
    if 10_000_000_000_000 <= n < 100_000_000_000_000:
        return TimeValue(
            dt.datetime.fromtimestamp(n / 1_000_000, tz=dt.timezone.utc), raw=raw,
            offset=0, tz_name="UTC", assumption="epoch_known", note="按量级判定为 Unix 微秒")
    return TimeValue(None, raw=raw, note=f"数值 {n} 量级无法判定纪元")


def _off_label(secs: int) -> str:
    """偏移秒数 → `UTC+08:00` 形式。"""
    sign = "+" if secs >= 0 else "-"
    a = abs(int(secs))
    return f"UTC{sign}{a // 3600:02d}:{a % 3600 // 60:02d}"


def _tz_label(tz: dt.tzinfo | None) -> str:
    if tz is None:
        return ""
    if isinstance(tz, dt.timezone):
        off = tz.utcoffset(None)
        if off is not None and off.total_seconds() == 0:
            return "UTC"
        secs = int(off.total_seconds()) if off else 0
        sign = "+" if secs >= 0 else "-"
        secs = abs(secs)
        return f"UTC{sign}{secs // 3600:02d}:{secs % 3600 // 60:02d}"
    name = getattr(tz, "key", None) or getattr(tz, "zone", None)
    return str(name) if name else tz.__class__.__name__


# ---------------------------------------------------------------- 对外便捷

def to_utc_iso(value: Any, *, assume: str = "local",
               epoch: str | None = None) -> str:
    """归一化并直接取 UTC ISO 串（``...Z``）。失败返回空串。"""
    tv = normalize(value, assume=assume, epoch=epoch)
    return to_utc_iso_dt(tv.utc)


def to_utc_iso_dt(dtv: dt.datetime | None) -> str:
    """UTC ISO 串（带 Z 后缀）。"""
    if dtv is None:
        return ""
    return dtv.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + (
        f".{dtv.microsecond:06d}"[:4] if dtv.microsecond else "") + "Z"


def utc_now_iso() -> str:
    """当前 UTC 时间（ISO）。"""
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def from_utc_iso(text: str) -> dt.datetime | None:
    """解析 UTC ISO 串（``Z`` 后缀）→ aware datetime。"""
    if not text:
        return None
    t = text.strip().replace("Z", "+00:00")
    try:
        d = dt.datetime.fromisoformat(t)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc)


def to_local(utc: dt.datetime | None, offset_seconds: int | None = None) -> str:
    """UTC → 目标机本地时间串（按记录的偏移还原），用于报告呈现。"""
    if utc is None:
        return ""
    if offset_seconds is None:
        return utc.astimezone(_local_tz()).strftime("%Y-%m-%d %H:%M:%S")
    tz = dt.timezone(dt.timedelta(seconds=int(offset_seconds)))
    return utc.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")


def describe_conversion(tv: TimeValue) -> str:
    """把换算过程渲染成一行可读留痕（写进报告与证据项）。"""
    if not tv.ok:
        return f"时间未解析：{tv.note}（原始值 {tv.raw or '空'}）"
    off = tv.offset
    off_txt = "UTC+0" if off in (0, None) else f"UTC{off // 3600:+d}"
    parts = [f"原始 {tv.raw or '空'} → UTC {to_utc_iso_dt(tv.utc)}"]
    if off is not None:
        parts.append(f"原偏移 {off_txt}")
    if tv.assumption:
        parts.append(f"假设 {tv.assumption}")
    if tv.note:
        parts.append(tv.note)
    return "；".join(parts)
