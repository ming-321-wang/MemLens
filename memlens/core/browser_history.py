r"""
MemLens · 本机浏览器历史采集（**按需触发，绝不随启动自动跑**）

## 为什么要它

内存镜像/虚拟机分析解决"别人机器发生过什么"；而**本机取证**（应急自查、
授权红队演练后自查、查"这台机器上访问过什么"）绕不开浏览器历史：
访问过的 URL、标题、访问次数、首次/末次时间，常直接指向钓鱼站、C2 面板、
数据外泄目标、凭据泄露页面。

## 三条硬规则（决定了实现方式）

1. **可选、按需**：只有用户显式调用 CLI/点按钮/请求 Web 接口时才读取。
   模块**没有导入即扫描的副作用**，也没有任何定时/后台任务。
2. **只读 + 副本**：浏览器运行时对 `History` 加了锁，直接开会失败/断连。
   做法：先把库文件（含 `-wal`/`-shm`）复制到临时目录，再用
   `file:...?mode=ro` 只读打开副本 —— **原库一个字节都不动**。
3. **不联网、不上传**：纯本地解析，产物只落到工作区，界面里给明文提示。

## 支持的浏览器

| 浏览器 | 历史库 | 时间戳纪元 |
|---|---|---|
| Edge / Chrome / Brave / Vivaldi / 360 极速（Chromium 系） | `User Data\<Profile>\History`（SQLite） | WebKit 微秒（自 **1601-01-01 UTC**） |
| Firefox | `Profiles\<p>\places.sqlite` | 微秒（自 **1970-01-01 UTC**） |

产物：每条访问一行（URL / 标题 / 访问时间 / 访问类型），另附按域名聚合的摘要。
"""

from __future__ import annotations

import csv
import dataclasses
import os
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import urlparse

USER = Path.home()
LOCAL = Path(os.environ.get("LOCALAPPDATA", USER / "AppData/Local"))
ROAMING = Path(os.environ.get("APPDATA", USER / "AppData/Roaming"))

#: Chromium 系浏览器的 User Data 根（按优先级）
CHROMIUM_ROOTS: tuple[tuple[str, Path], ...] = (
    ("Edge", LOCAL / "Microsoft/Edge/User Data"),
    ("Chrome", LOCAL / "Google/Chrome/User Data"),
    ("Brave", LOCAL / "BraveSoftware/Brave-Browser/User Data"),
    ("Vivaldi", LOCAL / "Vivaldi/User Data"),
    ("360极速", LOCAL / "360Chrome/Chrome/User Data"),
    ("QQ浏览器", LOCAL / "Tencent/QQBrowser/User Data"),
    ("Chromium", LOCAL / "Chromium/User Data"),
    ("搜狗", LOCAL / "SogouExplorer/User Data"),
    # Opera：历史库直接在根目录（无 User Data\<Profile> 层）
    ("Opera", LOCAL / "Opera Software/Opera Stable"),
)
#: Firefox
FIREFOX_ROOT = ROAMING / "Mozilla/Firefox/Profiles"

#: 全驱动器扫描（`--all-drives`）：在 C–Z 盘的这两个前缀下找浏览器
#   · <drive>\Users\<user>\AppData\Local\<App>\User Data\   （Chromium 系）
#   · <drive>\Users\<user>\AppData\Roaming\Mozilla\*       （Firefox）
CHROMIUM_APP_ROOTS: tuple[tuple[str, str], ...] = (
    ("Edge", "Microsoft/Edge"),
    ("Chrome", "Google/Chrome"),
    ("Brave", "BraveSoftware/Brave-Browser"),
    ("Vivaldi", "Vivaldi"),
    ("360极速", "360Chrome/Chrome"),
    ("QQ浏览器", "Tencent/QQBrowser"),
    ("Chromium", "Chromium"),
    ("搜狗", "SogouExplorer"),
    ("Opera", "Opera Software/Opera Stable"),
)
FIREFOX_APP_ROOTS: tuple[tuple[str, str], ...] = (
    ("Firefox", "Mozilla/Firefox"),
    ("Thunderbird", "Mozilla/Thunderbird"),
)

#: Chromium 时间戳纪元：1601-01-01 UTC
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


@dataclasses.dataclass
class Visit:
    """一次浏览访问。"""

    browser: str
    profile: str
    url: str
    title: str
    visited_at: str          # ISO8601（本地时区）
    transition: str = ""     # 访问类型（链接/地址栏/重定向…）
    visit_count: int = 0     # 该 URL 的累计访问次数
    source: str = ""         # 全盘扫描时标注来源驱动器（如 C:）

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------- 时间换算


def webkit_to_dt(us: Any) -> datetime | None:
    """Chromium 的 `last_visit_time`（自 1601-01-01 的微秒）→ datetime。"""
    try:
        v = int(us)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    try:
        return _WEBKIT_EPOCH + timedelta(microseconds=v)
    except (OverflowError, ValueError):
        return None


def firefox_to_dt(us: Any) -> datetime | None:
    """Firefox `visit_date`（自 1970-01-01 的微秒）→ datetime。"""
    try:
        v = int(us)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    try:
        return datetime.fromtimestamp(v / 1_000_000, tz=timezone.utc)
    except (OverflowError, ValueError, OSError):
        return None


def _iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


_CHROMIUM_TRANSITION = {
    0: "链接", 1: "输入", 2: "自动补全", 3: "自动跳转", 4: "手动重定向",
    5: "自动重定向", 6: "地址栏", 7: "起始页", 8: "表单提交", 9: "刷新",
    10: "关键词", 11: "关键词跳转",
}


def _transition_name(raw: Any) -> str:
    try:
        core = int(raw) & 0xFF
    except (TypeError, ValueError):
        return ""
    return _CHROMIUM_TRANSITION.get(core, str(core))


# ---------------------------------------------------------------- 发现


def discover_chromium() -> list[tuple[str, str, Path]]:
    """返回 [(浏览器名, Profile 名, History 路径)]。

    兼容两种布局：
      · `User Data\\<Profile>\\History`（Chrome/Edge/Brave/Vivaldi…）
      · `Opera Stable\\History`（Opera 直接在根目录）。
    """
    out: list[tuple[str, str, Path]] = []
    for name, root in CHROMIUM_ROOTS:
        if not root.is_dir():
            continue
        # Opera 等：历史库直接在根目录
        try:
            direct = root / "History"
            if direct.is_file():
                out.append((name, root.name, direct))
        except OSError:
            pass
        try:
            entries = list(root.iterdir())
        except OSError:
            continue
        for d in entries:
            if not d.is_dir():
                continue
            hist = d / "History"
            if hist.is_file():
                out.append((name, d.name, hist))
    return out


def discover_firefox() -> list[tuple[str, str, Path]]:
    out: list[tuple[str, str, Path]] = []
    if not FIREFOX_ROOT.is_dir():
        return out
    try:
        for d in FIREFOX_ROOT.iterdir():
            places = d / "places.sqlite"
            if d.is_dir() and places.is_file():
                out.append(("Firefox", d.name, places))
    except OSError:
        pass
    return out


def discover_all() -> list[tuple[str, str, Path]]:
    """所有可用的历史库（Chromium 系 + Firefox）。"""
    return discover_chromium() + discover_firefox()


def discover_in_appdata(appdata_root: str | Path) -> list[tuple[str, str, Path]]:
    """
    在**任意 AppData 根目录**下发现所有浏览器历史库。

    用途：
      · 本机**其它用户**（`C:\\Users\\<其它用户>\\AppData`）；
      · **磁盘镜像**里提取的 `Users\\<user>\\AppData`（容器挂载后）——
        即分析镜像/检材里的浏览器历史，解决"检测不到全部"。
    """
    appdata_root = Path(appdata_root)
    out: list[tuple[str, str, Path]] = []
    local = appdata_root / "Local"
    roaming = appdata_root / "Roaming"

    # Chromium 系：Local\<App>\<User Data>\<Profile>\History（主流），
    # 或 Local\<App>\<Profile>\History（部分），Opera 例外：根目录直接放 History
    for name, app_rel in CHROMIUM_APP_ROOTS:
        ud = local / Path(app_rel)
        if not ud.is_dir():
            continue
        # A) Opera 等：History 直接在根
        if (ud / "History").is_file():
            out.append((name, ud.name, ud / "History"))
        # B) <Profile>/History；C) User Data\<Profile>/History（Chrome/Edge/Brave 主流）
        for sub in _iter_dir(ud):
            if not sub.is_dir():
                continue
            if (sub / "History").is_file():
                out.append((name, sub.name, sub / "History"))
            if sub.name.lower() in ("user data", "userdata"):
                for prof in _iter_dir(sub):
                    if prof.is_dir() and (prof / "History").is_file():
                        out.append((name, prof.name, prof / "History"))
    # Firefox / Thunderbird：Roaming\Mozilla\<App>\Profiles\<Profile>\places.sqlite
    # 或 Roaming\Mozilla\<App>\<Profile>\places.sqlite（Profiles 即 App 目录）
    for name, app_rel in FIREFOX_APP_ROOTS:
        moz = roaming / Path(app_rel)
        if not moz.is_dir():
            continue
        if (moz / "Profiles").is_dir():
            for prof in _iter_dir(moz / "Profiles"):
                if prof.is_dir() and (prof / "places.sqlite").is_file():
                    out.append((name, prof.name, prof / "places.sqlite"))
        for sub in _iter_dir(moz):
            if not sub.is_dir():
                continue
            if (sub / "places.sqlite").is_file():
                out.append((name, sub.name, sub / "places.sqlite"))
            if (sub / "Profiles").is_dir():
                for prof in _iter_dir(sub / "Profiles"):
                    if prof.is_dir() and (prof / "places.sqlite").is_file():
                        out.append((name, prof.name, prof / "places.sqlite"))
    return out


def discover_all_drives() -> list[tuple[str, str, Path]]:
    """
    全驱动器扫描（`--all-drives`）：在 C–Z 盘的 `Users\\<user>\\AppData` 下找
    Chromium 系 `Local\\<App>\\User Data\\<Profile>` 与 Firefox
    `Roaming\\Mozilla\\<Profile>`；另扫盘根的便携版浏览器目录。

    用途：本机取证时查"这台机器装过哪些浏览器 / 其它用户 profile /
    数据盘里藏了哪些历史"。只做**目录级**遍历，不递归进历史库内部；
    在 500 GB 机器上 < 1 秒。
    """
    import string

    out: list[tuple[str, str, Path]] = []
    seen: set[Path] = set()

    def _add(name: str, prof: str, db: Path) -> None:
        """登记一个可用的历史库（去重）。"""
        if not _has_history(db, seen):
            return
        try:
            seen.add(db.resolve())
        except OSError:
            seen.add(db)
        out.append((name, prof, db))

    # ── 0) 当前用户（保证本机当前用户的库一定被找到，且排前面）──
    for name, prof, db in discover_all():
        _add(name, prof, db)

    for drive in string.ascii_uppercase:
        root = Path(f"{drive}:\\")
        users_dir = root / "Users"
        if not users_dir.is_dir():
            continue
        try:
            user_names = [u.name for u in users_dir.iterdir() if u.is_dir()]
        except OSError:
            user_names = []
        for user in user_names:
            local = root / "Users" / user / "AppData" / "Local"
            roaming = root / "Users" / user / "AppData" / "Roaming"
            # Chromium 系：Local\<App>\<User Data>\<Profile>（主流），
            # 或 Local\<App>\<Profile>（部分）；Opera 例外：根目录直接放 History
            for name, app_rel in CHROMIUM_APP_ROOTS:
                ud = local / Path(app_rel)
                if not ud.is_dir():
                    continue
                if (ud / "History").is_file():
                    _add(name, ud.name, ud / "History")
                for sub in _iter_dir(ud):
                    if not sub.is_dir():
                        continue
                    if (sub / "History").is_file():
                        _add(name, sub.name, sub / "History")
                    if sub.name.lower() in ("user data", "userdata"):
                        for prof_dir in _iter_dir(sub):
                            if prof_dir.is_dir():
                                _add(name, prof_dir.name, prof_dir / "History")
            # Firefox / Thunderbird：Roaming\Mozilla\<App>\Profiles\<Profile>
            # 或 Roaming\Mozilla\<App>\<Profile>
            for name, app_rel in FIREFOX_APP_ROOTS:
                moz = roaming / Path(app_rel)
                if not moz.is_dir():
                    continue
                if (moz / "Profiles").is_dir():
                    for prof_dir in _iter_dir(moz / "Profiles"):
                        if prof_dir.is_dir():
                            _add(name, prof_dir.name, prof_dir / "places.sqlite")
                for sub in _iter_dir(moz):
                    if not sub.is_dir():
                        continue
                    if (sub / "places.sqlite").is_file():
                        _add(name, sub.name, sub / "places.sqlite")
                    if (sub / "Profiles").is_dir():
                        for prof_dir in _iter_dir(sub / "Profiles"):
                            if prof_dir.is_dir():
                                _add(name, prof_dir.name, prof_dir / "places.sqlite")
        # 便携版浏览器直接放盘根：<drive>\<App>\User Data\<Profile>
        for name, app_rel in CHROMIUM_APP_ROOTS:
            leaf = Path(app_rel).name
            ud = root / leaf
            if ud.is_dir():
                for prof_dir in _iter_dir(ud):
                    if prof_dir.is_dir():
                        _add(name + "（便携版）", prof_dir.name, prof_dir / "History")
    return out


def _has_history(db: Path, seen: set[Path]) -> bool:
    """`db` 指向一个可用的历史库（History / places.sqlite），且没被登记过。"""
    if not db.is_file():
        return False
    try:
        rp = db.resolve()
    except OSError:
        rp = db
    if rp in seen:
        return False
    return True


def _iter_dir(p: Path):
    try:
        yield from p.iterdir()
    except (OSError, PermissionError):
        return


# ---------------------------------------------------------------- 读取


def _open_copy(db: Path) -> tuple[sqlite3.Connection, Path]:
    """
    把历史库（含 wal/shm）复制到临时目录后**只读**打开。

    为什么必须复制：浏览器运行时会锁住 History，直接 connect 会
    `database is locked`，甚至因为 -wal 未合并读到旧数据。
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="memlens-hist-"))
    dst = tmpdir / db.name
    shutil.copy2(db, dst)
    for suffix in ("-wal", "-shm"):
        side = db.with_name(db.name + suffix)
        if side.is_file():
            try:
                shutil.copy2(side, tmpdir / (db.name + suffix))
            except OSError:
                pass
    con = sqlite3.connect(f"file:{dst}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    return con, tmpdir


def _read_chromium(name: str, profile: str, db: Path,
                   *, since: datetime | None, until: datetime | None) -> Iterator[Visit]:
    con, tmp = _open_copy(db)
    try:
        # 优先用 visits（每次访问一行 = "全部浏览记录"），拿不到再退回 urls
        try:
            rows = con.execute(
                "SELECT u.url, u.title, u.visit_count, v.visit_time, v.transition "
                "FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time DESC"
            ).fetchall()
            for r in rows:
                dt = webkit_to_dt(r["visit_time"])
                if not _in_range(dt, since, until):
                    continue
                yield Visit(name, profile, r["url"] or "", r["title"] or "",
                            _iso(dt), _transition_name(r["transition"]),
                            int(r["visit_count"] or 0))
            return
        except sqlite3.Error:
            pass
        rows = con.execute(
            "SELECT url, title, visit_count, last_visit_time FROM urls "
            "ORDER BY last_visit_time DESC").fetchall()
        for r in rows:
            dt = webkit_to_dt(r["last_visit_time"])
            if not _in_range(dt, since, until):
                continue
            yield Visit(name, profile, r["url"] or "", r["title"] or "",
                        _iso(dt), "", int(r["visit_count"] or 0))
    finally:
        con.close()
        shutil.rmtree(tmp, ignore_errors=True)


def _read_firefox(name: str, profile: str, db: Path,
                  *, since: datetime | None, until: datetime | None) -> Iterator[Visit]:
    con, tmp = _open_copy(db)
    try:
        rows = con.execute(
            "SELECT p.url, p.title, p.visit_count, h.visit_date, h.visit_type "
            "FROM moz_historyvisits h JOIN moz_places p ON p.id = h.place_id "
            "ORDER BY h.visit_date DESC").fetchall()
        for r in rows:
            dt = firefox_to_dt(r["visit_date"])
            if not _in_range(dt, since, until):
                continue
            vt = r["visit_type"]
            yield Visit(name, profile, r["url"] or "", r["title"] or "",
                        _iso(dt), f"类型{vt}" if vt is not None else "",
                        int(r["visit_count"] or 0))
    except sqlite3.Error:
        return
    finally:
        con.close()
        shutil.rmtree(tmp, ignore_errors=True)


def _in_range(dt: datetime | None, since: datetime | None,
              until: datetime | None) -> bool:
    if dt is None:
        return False
    if since is not None and dt < since:
        return False
    if until is not None and dt > until:
        return False
    return True


# ---------------------------------------------------------------- 对外


def collect(
    *, browser: str = "all", profile: str = "",
    since: str | None = None, until: str | None = None,
    keyword: str = "", limit: int = 0,
    all_drives: bool = False,
    appdata: str | Path | None = None,
    sources: list[tuple[str, str, Path]] | None = None,
) -> list[Visit]:
    """
    采集浏览历史（**按需调用**，本模块不在任何启动路径上被自动执行）。

    Args:
        browser: `all` / `edge` / `chrome` / `firefox` / 浏览器显示名
        profile: 只取某个 Profile（如 `Default`、`Profile 1`），空=全部
        since/until: `YYYY-MM-DD` 或 `YYYY-MM-DD HH:MM:SS`（本地时区）
        keyword: 只在 URL/标题里匹配该关键字
        limit: 最多返回多少条（0 = 不限）
        all_drives: True 时做全驱动器扫描（C–Z 盘的常见前缀），用于"这台
                    机器上到底装过哪些浏览器 / 数据盘里藏了哪些历史"。
        appdata: 任意 AppData 根目录（镜像里提取的 `Users\\<user>\\AppData`、
                 本机其它用户），用于**分析检材/镜像里的浏览器历史**。
        sources: 直接用外部提供的发现结果（[(浏览器, profile, 历史库)]）。
    """
    lo = _parse_dt(since)
    hi = _parse_dt(until)
    want = (browser or "all").lower()
    if sources is not None:
        srcs = sources
    elif appdata is not None:
        srcs = discover_in_appdata(appdata)
    else:
        srcs = discover_all_drives() if all_drives else discover_all()
    out: list[Visit] = []
    for name, prof, db in srcs:
        if want not in ("all", "") and want not in name.lower():
            continue
        if profile and prof.lower() != profile.lower():
            continue
        reader = _read_firefox if name == "Firefox" else _read_chromium
        drive = _drive_of(db)
        try:
            for v in reader(name, prof, db, since=lo, until=hi):
                if keyword:
                    hay = f"{v.url} {v.title}".lower()
                    if keyword.lower() not in hay:
                        continue
                if all_drives:
                    v.source = drive
                out.append(v)
                if limit and len(out) >= limit:
                    return out
        except (sqlite3.Error, OSError):
            continue
    out.sort(key=lambda v: v.visited_at, reverse=True)
    return out


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s.strip(), fmt)
            return dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
        except ValueError:
            continue
    return None


def summarize(visits: Iterable[Visit]) -> dict[str, Any]:
    """按域名/浏览器/时间聚合（给界面一眼看结论）。"""
    per_domain: dict[str, int] = {}
    per_browser: dict[str, int] = {}
    per_day: dict[str, int] = {}
    total = 0
    first = last = ""
    for v in visits:
        total += 1
        per_browser[v.browser] = per_browser.get(v.browser, 0) + 1
        host = urlparse(v.url).netloc.lower() or "(无主机)"
        per_domain[host] = per_domain.get(host, 0) + 1
        day = (v.visited_at or "")[:10]
        if day:
            per_day[day] = per_day.get(day, 0) + 1
        if v.visited_at:
            if not first or v.visited_at < first:
                first = v.visited_at
            if not last or v.visited_at > last:
                last = v.visited_at
    top_domains = sorted(per_domain.items(), key=lambda kv: -kv[1])[:30]
    return {
        "total": total,
        "by_browser": per_browser,
        "top_domains": [{"域名": d, "次数": c} for d, c in top_domains],
        "by_day": dict(sorted(per_day.items())),
        "first": first,
        "last": last,
    }


def export_csv(visits: Iterable[Visit], path: str | os.PathLike, *, all_drives: bool = False) -> int:
    """导出 CSV（UTF-8-SIG，Excel 直接打开不乱码）。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(p, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        cols = ["浏览器", "Profile", "访问时间", "标题", "URL", "访问类型", "累计次数"]
        if all_drives:
            cols.append("来源盘")
        w.writerow(cols)
        for v in visits:
            row = [v.browser, v.profile, v.visited_at, v.title, v.url,
                   v.transition, v.visit_count]
            if all_drives:
                row.append(v.source)
            w.writerow(row)
            n += 1
    return n


def sources_report(*, all_drives: bool = False) -> list[dict[str, Any]]:
    """
    列出**能采集到什么**（不读内容，只探测存在性）。

    `all_drives=True` 时扫描 C–Z 所有盘符的常见浏览器目录（本机取证用：
    查"这台机器装过哪些浏览器 / 数据盘里藏了哪些历史"）。
    """
    rows: list[dict[str, Any]] = []
    for name, prof, db in (discover_all_drives() if all_drives else discover_all()):
        try:
            size = db.stat().st_size
        except OSError:
            size = 0
        rows.append({"browser": name, "profile": prof, "path": str(db),
                     "size_mb": round(size / 1048576, 2),
                     "kind": "firefox" if name == "Firefox" else "chromium",
                     "drive": _drive_of(db)})
    return rows


def _drive_of(p: Path) -> str:
    s = str(p)
    m = re.match(r"^([A-Za-z]):[\\/]", s)
    return m.group(1).upper() + ":" if m else ""