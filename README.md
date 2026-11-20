# MemLens · 内存取证工作台（v1.8.0 · 全栈 · 合规基座 + 五维判定 + 取证容器 + 检索引擎）

> 一个**独立实现**的取证工具：把内存镜像变成可查询、可复核、可报告的"证据"。
> 不是命令包装器的堆砌，而是**统一证据模型 + 多源交叉验证检测 + 情报提取 + 全栈工作台**。
>
> **v1.0 形态**：`MemLens.exe` → 起本地 Web 服务 → 自动开浏览器 → **打开证据即全量深度分析**。
> 无需安装 Python；UI 为浏览器内的取证控制台（概览 / 产物 / 时间线 / 发现项 / 情报 / 旗标 / 用户 / 日志）。
>
> **v1.1 形态**：**打开快了、不再"点了没反应"**。
> 端口占用自动分流（复用 / 换端口 / 弹框）、浏览器等服务真就绪才开、
> 端点全进线程池不再堵事件循环、建案只做 30 ms 的活其余全异步、
> **断网已实测可用**（拦截全部出网 socket 验证，0 次出网尝试）。
>
> **v1.2 形态**：**细粒度功能做成可点击按钮**（用户不再依赖"全量分析"顺带拿到单项结果）：
> 新增 Web「工具」页签——浏览器浏览记录（本机只读副本，点按钮才读）、
> 机器信息按需重取、用户/环境变量/未释放文件/字节快扫/进程内存导出 6 个单项操作按钮；
> 结果统一进证据模型（「产物」页可见），绝不随启动自动跑。
>
> **已可打包为独立 exe**：`dist\MemLens\MemLens.exe`，双击即用（冷启动 1.1 s）。
> **数据库**：SQLite（默认，零配置）↔ MySQL（可选，`MEMLENS_DB_URL`），**同一套模型两套方言**。
> **跨平台**：Windows / Linux / macOS 的内存镜像与取证容器（LiME / AVML / AFF4 / EWF / VMDK）。

版本：`1.5.0`（v1.3 全部能力 + **五维判定引擎**：违规跨境访问检测模块 FR-01~FR-07
—— 工具存在性 / 通道配置 / 运行痕迹 / 数据外联 / 访问方向五维打分分级，
规则包驱动、缺源即降级、两套结论体系不混用）
技术栈：Python 3.12 · FastAPI + uvicorn · 原生 JS/CSS 前端（无构建、无 CDN、离线可用）·
Volatility 3.2x · MemProcFS · SQLAlchemy 2.x（SQLite / MySQL）

---

## 0.0 v1.8：检索引擎（能查才能用）

## 为什么这是刚需

取证分析员的日常动作不是"看表"，而是**问问题**：

    这个 IP 在哪儿出现过？  这个域名跟哪个进程有关？  哪些记录提到了 xxx？

Volatility 有 `-f`/`--grep`，Wireshark 有 display filter。
**没有这些，看表就只能人肉 Ctrl+F** —— 一张表几千行根本翻不动，
于是"工具只能显示哈希和元数据、答案找不到"。

v1.8 把这件事变成**工具能力**。

## 覆盖范围

| scope | 内容 |
|---|---|
| `records` | 中间证据表（所有产物的每一行，**键 + 值**全字段可检索） |
| `findings` | 检测器结论 |
| `timeline` | 时间线事件 |
| `raw` | 产物原始文件内容（流式扫描，不整文件读进内存） |
| `container` | **加密容器 / 磁盘镜像内部**的文件内容（不落盘） |

## 检索式语法

| 写法 | 含义 |
|---|---|
| `cmd.exe` | 单词全文匹配（大小写不敏感） |
| `"net user"` | 精确短语 |
| `pid:1234` | 字段过滤（records 的列名） |
| `-flag` | 排除 |
| `/qianqianwoaini/i` | 正则 |

多个条件用空格分隔，AND 关系。

## 入口

    GUI    左栏「检索 → 跨产物检索」；工具页「🔐 在加密容器 / 镜像内部检索」
    CLI    python -m memlens.cli search <案件ID> <关键词> [--scope ...] [--regex]
           python -m memlens.cli search <案件ID> --container <容器> --password <口令> --keywords a,b
    Web    POST /api/search   {query, case_id, scopes, regex, limit}
           POST /api/search   {container, password, query, regex, limit}   ← 容器内检索

## 配套性能改进：批量 XTS 解密

逐扇区做 XTS 时，Python 层的 GF(2^128) 递推把吞吐压到 **~4 MB/s**
（读 15.9 GB 要 68 分钟）。改成：

    · tweak 种子用**一次** AES-ECB 批量算
    · GF 乘法用 numpy 向量化
    · 密文/tweak 的 XOR 用 numpy 整块做
    · 数据用**一次** AES-ECB 批量解密

**3.9 MB/s → 30 MB/s（~7 倍）**，且批量结果与逐扇区结果**逐字节相同**。

---

## 0.0 v1.7：取证容器引擎（非内存镜像检材通道）

取证现场的检材不只有内存镜像。v1.7 把"打开容器 → 列举内容 → 按需提取 → 解析"
做成**正式引擎能力**（`container`），不再是零散脚本。

### 覆盖的容器类型

| 容器 | 实现 | 能力 |
|---|---|---|
| **VeraCrypt 加密卷** | `core/veracrypt_volume.py` | **无需挂载、无需驱动、无需管理员**：离线校验卷头 → 提取主密钥 → AES-256-XTS 按扇区解密 |
| **exFAT** | `core/exfat.py` | 目录树枚举、单文件按需提取、NoFatChain 连续分配处理 |
| **EWF（E01 分段）** | `formats/ewf.py` | 分段表、chunk 头扫描、zlib/bzip2/lz4/xz 解压、按逻辑偏移读 |
| **VMDK 稀疏盘** | `formats/vmdk.py` | 描述符/grain 表解析、按虚拟盘偏移读（未分配 grain 返回全零） |
| **pcapng 抓包** | `formats/pcapng.py` | 完整逐包解析 + BLE 链路层 + USB HID 键盘 |
| **APK** | `formats/apk.py` | **AXML 树解析**（包名/权限/组件/label）+ DEX 字符串池 + 加固识别 + IOC |

### 引擎与入口

新增引擎 `container`，9 个插件：

    container.identify   容器类型识别（EWF/VMDK/ZIP/pcapng/APK/高熵加密体）
    container.files      卷内文件清单
    container.extract    按路径提取卷内文件
    container.crypto     VeraCrypt 卷头详情（算法/KDF/迭代/主密钥指纹）
    traffic.interfaces  pcapng 接口与链路类型
    traffic.bluetooth   BLE 设备表（地址/名称/厂商数据/出现时间）
    traffic.ble_rename  蓝牙改名事件（伪装设备的核心线索）
    traffic.hid         USB HID 键盘还原（含退格修正）
    mobile.apk          APK 属性（包名/权限/加固/IOC/flag 串）

    CLI : python -m memlens.cli container {identify|files|extract|crypto|traffic|apk} <文件>
    Web : POST /api/container/analyze  + 工具页「🧰 取证容器」卡片
    导航：左栏「文件分析 / 手动工作台」分组

### 实战验证：2025 平航杯检材容器

70 GiB 的 `平航杯题目`（VeraCrypt + exFAT），实测：

    容器口令  早起王的爱恋日记❤（西电取证 Wiki 公布）
    卷头      AES-256-XTS / PBKDF2-HMAC-SHA512 × 500000 / 主密钥指纹 fb9b1c95…
    内含      window.e01 (55 GB) / 20250415_181118.zip (1.93 GB) / BLE / USBPcap /
              export-disk0-000002.vmdk (15.9 GB)

**关键点：全程不需要 VeraCrypt 程序、不需要管理员、不需要加载驱动。**
按需提取 5.9 MB 的 BLE 抓包只花 0.5 秒。

### 解析格式时踩过的坑（都写进注释了）

1. **Nordic nRF Sniffer 私有封装不是标准 BLE**：linktype=272，21 字节私有头 +
   4 字节接入地址（D6BE898E）+ LL 包。按标准 BLE 解会满屏乱码**且不报错**。
2. **BLE 广播地址长度不能写死 6**：部分 ADV_IND 的 AdvData 少一字节，写死会让
   AD 结构整体错位 1 字节，设备名解成 `LE-YANG`QC\x135 Ei`。正解是按
   AD 序列能否自洽走完来反推长度（5/6/7）。
3. **USB 键盘报告不是 8 字节标准布局**：本例 37 字节复合 HID，第 0 字节是
   Report ID，真正的 boot 报告在 [1]/[3:9]。
4. **CapsLock 不产生字符**：不过滤会把 `abcdefghijkImn` 变成
   `abcdefghijkCapsLockiCapsLockmn`。
5. **AXML 字符串池切片只能跳 8 字节**（不是 headerSize=28，否则把池头整段跳过）；
   偏移数组在 body[20]；属性头字段在 body[16]；属性数组起点是 body[28]；
   命名空间的 prefix/uri 在 body[8]/body[12]。
   —— 只按字符串池猜"哪个是包名"必然误判（会把 `android.hardware.camera.autofocus`
   当成包名），**必须解析 XML 树**。
6. **EWF 的 chunk 不在文件开头**：文件头后还有若干 section，得全段查找 chunk 头
   再按 next_offset 跟链（顺序扫会在文件头处就 break）。

---

## 0.0 v1.6：分组导航栏（对标 LovelyMem V3）

顶部页签在分析类目变多后会横向挤爆，改成**左栏分组导航**——这是同类工作台
（LovelyMem V3 / StarMem）通行的做法，也是可扩展性上的必然选择。

### 结构

```
┌──────────┬──────────┬───────────────────────────────┐
│ 分组导航  │ 案件库    │ MemLens › 系统信息 › 结论速览   │ ← 面包屑
│ 206px    │ 262px    │                               │
│ 🔍 搜索…  │          │  卡片 / 表格 / 判定结果          │
│ ⓘ 系统信息 │ 分析流水线 │                               │
│ ▤ 进程分析 │          │                               │
│ ⊕ 网络分析 │          │                               │
│ …        │          │                               │
│ ⚖ 合规 33 │          │                               │
├──────────┴──────────┴───────────────────────────────┤
│ 控制台输出（可折叠）                                    │
├──────────────────────────────────────────────────────┤
│ 空闲 CPU 34.9% 内存 10.44/15.7GB  阶段… 引擎… v1.6.0   │
└──────────────────────────────────────────────────────┘
```

### 13 组 / 36 项，全部映射到真实能力

| 分组 | 子项示例 |
|---|---|
| 系统信息 | 结论速览 / 系统画像 / 机器信息重取 / 虚拟化检测 |
| 进程分析 | 进程列表 / 命令行 / 隐藏进程·注入 / 异常内存命中 |
| 网络分析 | 连接表 / DNS 缓存 / 浏览器记录 |
| 文件分析 | 全部产物 / 未释放文件 / 导出可疑进程内存 |
| 注册表 | 自启动项 / 代理配置 / 注册表配置单元 |
| 恶意分析 | 发现项 / IOC 情报 / 旗标候选 |
| 凭据与加密 | 用户与 SID / 环境变量 / 字节快扫 flag |
| 用户活动痕迹 | 时间线事件 / 字典命中 |
| 时间线分析 | 统一时间线（UTC） |
| 字符串搜索 | 内存字符串产物 / 产物记录检索 |
| 手动工作台 | 手动分析工作台 / **无符号分析（memstrings 兜底）** / 五维判定 |
| 合规与出证 | 五维判定 / 缺口清单 / 审计哈希链 / 规则包 |
| 日志 | 控制台日志 |

### 三个交互细节

- **搜索按插件名**，不只是中文名：输入 `filescan` → 内存字符串产物；
  `net` → 连接表 / DNS / 代理配置；`proxy` / `timeline` / `flag` / `strings` 同理。
  每个叶子都带英文与插件别名检索键（`mprocfs.net`、`registry_proxy`、`memstrings`…）。
  `/` 聚焦搜索框，`Esc` 清空。
- **子项直达三种动作**：切页签 / 开产物记录抽屉 / 触发取证工具——不用先想"这属于哪个页"。
- **窄屏（<1280px）自动收成 52px 图标条**，点图标浮出子菜单。

### 同步修的界面缺陷

- 案件详情浮层的暗化遮罩铺满视口却**没有 `pointer-events:none`**，
  把导航栏与顶栏的点击全部拦下 → 已修；
- 浮层 `left:12px` 正好压在导航栏上 → 改用 `--nav-w` 变量避让（窄屏跟随折叠宽度）；
- 点产物型子项后被页签级高亮同步**改回另一个叶子**（点「进程列表」显示「全部产物」）
  → 引入"手动钉住"标记，手动点过的叶子不被覆盖。

### 新增文件

- `memlens/web/static/style_nav.css` —— 导航栏样式（含窄屏折叠）
- `memlens/web/static/nav.js` —— 导航树 / 搜索 / 动作分发

---

## 0.0 v1.5：交互层重做（向导 / 控制台 / 状态栏 / 兼容降级 / 分析分组）

对标同类取证工作台（StarMem 等）的交互语言，把「能跑」提升到「好上手」。
后端判定逻辑一行没动，纯交互与可视化层。

### 五个新增

| 能力 | 说明 |
|---|---|
| **三步载入向导** | 选择镜像 → 选择兼容引擎 → 生成基础证据。步进器显示进度，支持拖拽、最近案件复用；不再是一堆平铺按钮 |
| **内联控制台** | 主区底部可折叠面板，时间戳 + 级别着色（ok/err/warn/step）；`log()` 自动镜像，不用切页签看日志 |
| **底部状态栏** | CPU / 内存 / 阶段 / 引擎 / 版本，2 秒轮询。CPU 走 `GetSystemTimes` 两次采样做差，内存走 `GlobalMemoryStatusEx`——**零第三方依赖**（无 psutil） |
| **兼容性 / 降级分析** | 引擎失败或数据源缺失时，给**可执行的下一步**（「启动兼容分析」「无符号兜底分析」「重试」「查看缺口清单」），而不是甩一屏报错 |
| **分析分组导航** | 8 个取证对象分组（进程与内存 / 网络与域名 / 持久化与注册表 / 凭据与用户 / 文件与产物 / 主机信息 / 时间线 / 合规判定），每组带真实产物计数与命中状态，点开直达对应分析 |

### 同步修的界面缺陷

- `#fileModal` 历史编辑残留**重复了一份**（重复 id，`getElementById` 只认第一个）→ 已删；
- 案件「完整分析信息」原挤在 262px 侧栏里，90 字符镜像路径被折断成竖排单字 →
  改为 **452px 浮层面板**，路径 4 行内可读，产物清单带行数；
- 五维判定控件曾放在会被渲染清空的容器里，**连点两次必崩** → 已移出；
- 补 `/favicon.ico` 路由（消掉浏览器自动请求产生的 404）。

### 新增文件

- `memlens/core/sysstat.py` —— Win32 状态采集（CPU / 内存 / 本进程工作集），非 Windows 自动降级；
- `memlens/web/static/style_v2.css` —— v2 组件层（设计令牌 + 向导 + 控制台 + 状态栏 + 降级卡 + 分组）；
- `memlens/web/static/app_v2.js` —— v2 交互层；
- 新端点 `GET /api/sysstat`。

### 验证

浏览器端到端（Chrome，1680×1020）实测：9 个页签全部可切换、
向导三步可达且引擎清单带可用性标记、分析分组计数正确、
降级卡片带 3 个可执行动作、**失败请求 0 / JS 错误 0**。

---

## 0.0 v1.4：五维判定引擎（违规跨境访问检测模块 FR-01~FR-07）

对应方案 4.2 节。五维按 **工具存在—通道配置—实际执行—数据外联—访问方向** 排列，
前一个是后一个的必要条件；但前一维不成立**不等于停止判定**——
外联证据若独立成立可反推前维，此时前维记为"痕迹已被清理"而非"不存在"。

### 五个维度

| 维度 | FR | 判定要点 | 内存域数据源 |
|---|---|---|---|
| 工具存在 | FR-01 | 三态（已安装/残留/便携运行）+ 强弱指纹分层 + 白名单**按安装路径**匹配 | 进程表、服务表、自启动项 |
| 通道配置 | FR-02 | 三个配置面（用户级/系统级/浏览器级）+ 四类异常面 + **自动配置脚本地址为高价值项** | 注册表 Internet Settings（新增收获）、DNS 缓存、连接表 |
| 实际执行 | FR-03 | 五源交叉 + 缺源按表 12 降级 + 缺 SRUM 时上限封顶 B | 进程创建时间、UserAssist（ROT13 还原）、服务表 |
| 数据外联 | FR-04 | 四类替代证据逐级收敛 + 量级比对双线（60%/30%，规则包可调） | 连接表、DNS 缓存、浏览器记录 |
| 访问方向 | FR-05 | 域名五类打标（学术/技术/新闻/社交/流媒体）+ **权限默认关闭** | DNS 缓存、浏览器记录 |

### 三条硬约定（方案 3.3）

1. **输出必须携带依据证据项编号** —— 无法回溯到证据项的结论视为无效；
2. **必须声明依赖的数据源**，缺源即走**降级分支**而非报错退出；
3. **阈值与权重全部来自规则包** —— 改阈值不改代码、不发版。

### 降级路径（方案表 12 落地）

内存镜像的硬边界是：**磁盘侧三源（Prefetch / AmCache / SRUM）与网络侧设备记录都不在镜像里**。
本实现**不假装判过**，而是：
- 明确写出未覆盖的面（浏览器独立配置、虚拟网卡、完整路由表）；
- 缺源 → 写入 `gaps` 表（缺失维度 / 原因 / **结论上限** / 建议补证）；
- 等级自动封顶（缺 SRUM ⇒ "启动过"不等于"用过" ⇒ 上限 B）。

### 两套结论体系（方案 1.5 / 4.2.5）

- **检查用法**：已确认 / 存在风险 / 记录备查（用"发现/存在/疑似"表述）；
- **取证用法**：A / B / C 级（用"证实/可采信"表述）；
- 定档规则：加权总分 ≥ 0.75 **且** 外联维 ≥ 0.5 → 已确认；
  0.40~0.75 → 存在风险；< 0.40 → 记录备查；
- **A 级的前提是"接入网络侧记录并完成三处交叉"**——主机侧来源再多也只是主机侧
  （早期用"外联维独立来源数"判定会误放行 A 级，已修正）。

### 新增能力

- 规则包扩展：五维权重、工具指纹库（15 个代理/隧道/VPN 工具，强弱指纹分层）、定档阈值；
- MemProcFS 新增收获项 `mprocfs.registry_proxy`（HKLM/HKU 的 Internet Settings）；
- 存储新增 `dimension_results` 表（维度得分 / 状态 / 等级上限 / 依据证据项集合 / 规则包版本）；
- CLI：`memlens.cli dimensions <case_id> [--usage forensic] [--allow-direction]`；
- Web：`POST /api/cases/{id}/dimensions`，概览页新增「🧭 五维判定」卡片；
- 新增 `tools/test_dimensions.py`（**70 项专项测试全通过**）。

---

## 0.0 v1.3：合规基座（方案 3.2 / 3.3 / 5.2 / 5.3 / 5.4 / FR-21）

按《计算机系统数字取证工作台开发方案（八章稿）》逐条对照后，先补齐**地基**——
这五项与后续的判定引擎、取证六环节共用，改晚了要返工。

### ① 统一时间基准（方案 5.3）

方案点名过一个真实的坑：

> 一份报告曾因把**设备本地时间当成协调世界时**直接与日志比对，
> 整整错了八小时，结论从"吻合"变成"完全对不上"，最后是复核时才发现。

新增 `memlens/core/timebase.py`（**全项目唯一的时间归一入口**）：

| 能力 | 说明 |
|---|---|
| 统一 UTC 存储 | 所有时间以 aware UTC 入库；`records.ts_utc` / `timeline_events.ts_utc` |
| 原始时区留存 | `tz_offset`（偏移秒数）、`tz_name`（UTC+08:00 等）、`ts_raw`（原始表示） |
| 换算留痕 | `tz_assumption`（utc/local/explicit_offset/explicit_tz/epoch_known）+ `tz_note` |
| 纪元显式声明 | 浏览器 1601 纪元、Firefox 1970 纪元、FILETIME 按**字段名**判定，不靠量级猜 |
| 可逆还原 | `to_local(utc, offset)` 能还原目标机本地时间 |

> **实测修掉的一个真 bug**：日期串 `2026-03-01 10:00:00` 里的 `-03`
> 会被偏移量正则误读成 "-3 小时"，导致朴素时间凭空偏 3 小时。
> 修正：偏移与时区名**只允许出现在时间部分之后**（`tail`），不再全文搜。

### ② 中间证据表五必填字段（方案 3.2）

方案规定中间证据表必须有五个字段，缺任一字段的记录不得进入分析层。现在：

| 字段 | 落点 |
|---|---|
| 证据编号 | `records.record_id` / `evidence_no` |
| 类别 | `artifacts.category` |
| 发生时间（UTC） | `records.ts_utc` + `ts_raw` + `tz_offset` + `tz_assumption` |
| 来源（文件路径与偏移或事件号） | `artifacts.output_path` + `records.source_offset` |
| 原始值哈希 | `records.raw_value_hash`（**可复现**：同一输入两次分析哈希相同） |

### ③ 规则包外置治理（方案 FR-21 / 1.5 / 3.4）

新增 `memlens/core/rulepack.py`。**判定阈值不再写死在代码里**：

- 规则包 = 版本号 + 发布日期 + 阈值集合 + 白名单 + 词表 + 变更记录；
- 检测器改为 `rulepack.current().threshold("hidden_process.w_pool_only")` 取值，
  **改阈值不用改代码、不用发版**；
- 离线导入 / 激活 / 回滚 / 导出（JSON 文件，全程不联网）；
- 导入前校验：缺版本号 → 拒绝；权重越界 [-1,1] → 拒绝；缺发布日期 → 拒绝；
- 报告首页写明所用规则包版本与 SHA-256（方案 1.5 硬要求）；
- CLI：`memlens.cli rulepack [--import|--activate|--export]`

> **实测修掉的两个真 bug**：
> ① `pack_id` 与 `version` 脱钩时，导入新版本会**覆盖同名旧版本文件**，
>    导致"回滚到基线"拿到的是被覆盖的假基线 → 改为文件名按 `pack_id@version` 派生；
> ② 审计链按案件过滤后校验会**误判断链**（链本��是全局的）→ 校验改为走全部记录。

### ④ 审计与保管链（方案 5.4 / FR-19）

新增 `audit_log` 表：操作人 / 动作 / 对象 / 时间 / 操作前后哈希 + **哈希链**
（每条记录的哈希包含前一条的哈希，任意一条被改动后续全部校验失败）。

- 四类重点操作（分析 / 导出报告 / 换规则包 / 建案）单独标记 `critical`；
- CLI：`memlens.cli audit [--verify]`（链校验）、`memlens.cli audit <case_id>`（留痕列表）；
- Web：`GET /api/cases/{id}/audit` 返回留痕 + 链校验结果；
- 专项测试里**故意篡改一条记录**，验证能检出并报出断点位置。

### ⑤ 缺口清单结构化（方案表 9 / FR-07）

方案要求："缺口本身是输出物，须结构化存储而非写在报告正文里"。新增 `gaps` 表：
缺失维度 / 数据源 / 缺失原因 / 影响 / **结论上限** / **建议补证**。

- 引擎失败、计划跳过、partial 产物全部转成缺口；
- **同根因自动合并**：一次镜像格式不匹配会让 MemProcFS 的 30+ 个产物报同一个错，
  合并成一条「65 个产物受同一根因影响」（实测 131 条 → 7 条）；
- 失败原因先经 `vol3.diagnose_failure()` **归一化成人话**
  （"未定位到 Windows 内核符号层"而不是一屏 stderr），才做合并与建议映射；
- 报告新增「缺口清单」章节 + **固定免责三句**（方案 5.7）：
  "主机侧未发现痕迹，不等于未使用" / "单机采集的结论等级存在上限" /
  "本报告不建议作为司法鉴定结论使用"；
- Web 概览页新增缺口卡片 + 新增「合规」页签（规则包 / 审计链 / 缺口清单）。

### 验证

新增 `tools/test_compliance_base.py`（**77 项专项测试，全通过**），
既有 `tools/regression_lite.py` 仍为 71/72（唯一失败项是改造前就存在的桌面 GUI 断言）。

---

## 0.0 v1.2：细粒度功能做成可点击按钮（"工具"页签）

用户反馈：**"没有可以点击的太多功能模块"**——浏览器记录、机器信息这些，
要用户**自己点按钮**才获取，而不是等全量分析顺带跑完。

本版新增 Web「工具」页签（`#panel-tools`），三类能力全部**按需触发**：

| 区块 | 按钮 | 走的链路 | 备注 |
|---|---|---|---|
| 🌐 浏览器浏览记录 | 「📥 采集浏览记录」「导出 CSV」 | `GET /api/browser-history*` → `core/browser_history` | **本机**历史（Chromium 系 + Firefox），只读副本，不联网；点按钮才读 |
| 💻 机器信息 | 「🔄 重新提取」「🖥 虚拟机扫描」 | `POST /api/tools/sysinfo` + `GET /api/vmscan` | 单机信息从镜像按需重取；VM 扫描走 `core/vmscan`（只读） |
| ⚙ 单项操作 | 机器信息 / 用户与 SID / 环境变量 / 未释放文件 / 字节快扫 / 导出可疑进程内存 | `POST /api/tools/{tool}` | 走 TaskRunner 同一套登记/落盘/入库，结果进「产物」页，绝不随启动自动跑 |

**v1.2 修复的两个"交付级"缺陷**（用户实测反馈）：

1. **案件库点不动**：侧栏案件条目从"纯展示"改为**点击 = 选中 + 输出该案件完整分析信息**
   （案件字段 / 产物记录数 / 发现项严重度 / IOC / 旗标 + 可点击的产物清单，见 `renderCaseDetail`）；
   每个案件条目还有「详情」按钮可展开/收起。
2. **未知/失败文件点不进去（"？？？"）**：「产物」页里失败、0 行、partial 的产物自动多一个
   **「详情」按钮** → 打开文件详情弹窗（`/api/cases/{id}/file-info`），里面**即使引擎失败也有**：
   容器探测结论 + 全部证据行、文件头 64 字节 hex（魔数）、static 画像（类型/哈希/熵/加壳/危险 API）、
   产物错误信息与原始输出。用户能据此**自己分辨这是什么文件、有无危险**；
   弹窗底部还有「🔍 用 static 引擎再分析一次」按钮一键补跑。

**后端端点**（`web/app.py`）：

```python
TOOL_PLUGINS = {
    "sysinfo":      ("memprocfs", "mprocfs.sysinfo"),
    "users":        ("memprocfs", "mprocfs.users"),
    "envs":         ("memprocfs", "mprocfs.envs"),
    "files":        ("memprocfs", "mprocfs.files"),
    "flag":         ("memstrings", "memstrings.flag"),
    "process_dump": ("memprocfs", "mprocfs.dump_process"),
}
```

- 每个工具都走**后台线程 + 事件总线**（`tool_done` / `tool_error`），
  前端按钮即时禁用、完成自动刷新「产物」页；
- 引擎不可用时返回 `state: unavailable` 而不是 500（前端弹 toast）；
- **跳过缓存**（`cache=False`）——用户点按钮就是要"现在再跑一次"。

**浏览器浏览记录**（`core/browser_history.py`）——三条硬规则：

1. **可选、按需**：没有导入即扫描的副作用，没有后台任务；
2. **只读 + 副本**：浏览器运行时锁着 `History`，先把库（含 `-wal`/`-shm`）
   复制到临时目录再 `file:...?mode=ro` 打开，原库一个字节不动；
3. **不联网、不上传**：纯本地解析，产物只落工作区。

支持 Edge / Chrome / Brave / Vivaldi / 360 极速 / QQ 浏览器（Chromium 系）
+ Firefox。时间戳按各自纪元（WebKit 自 1601 / Firefox 自 1970）换算。

**全盘扫描（`--all-drives` / 前端"全盘扫描"勾选框）**：
在 C–Z 所有驱动器上扫描"当前用户 AppData + 所有 `Users\<user>\AppData` +
盘根/ProgramData 便携版浏览器"，用于本机取证时查"这台机器装过哪些浏览器 /
其它用户 profile / 数据盘里藏了哪些历史"。只做**目录级**遍历（不递归进
历史库内部），500 GB 机器 < 1 秒。实测本机 4 个历史库（Edge/Chrome/Firefox×2）
**10,814 条访问记录** 0.2 秒采完，Top 域名按域名聚合（`nccsec.cn 402`、
`ctf.bugku.com 283`…）。

实测：本机 4 个历史库（Edge 14 MB / Chrome 0.3 MB / Firefox ×2 5 MB），
**10,814 条访问记录**一条不漏。

> 与 v1.1 的关系：v1.1 修的是"**打开快不快**"，v1.2 修的是"**单个功能能不能点**"。
> 深度分析（九阶段一键）保留为默认主路径；工具箱是它的**补充**，
> 不改变"打开即全量"的行为。

---

## 0. v1.1：打开慢 / "有时候根本打不开" —— 六类根因与实测对照

用户实测反馈：**"软件打开响应慢，并且还没验证过断网是否能打开，主要问题就是响应很慢，
甚至有时候根本打不开软件。"**

| 指标 | 修前 | 修后 |
|---|---|---|
| exe 冷启动 → 全部资源就绪 | 3.28 s | **1.09 s** |
| 双击 exe "没反应" | **端口占用即静默退出** | 自己占→开已有实例 / 别人占→**自动换端口** / 无解→**弹消息框** |
| 浏览器打开时机 | `sleep(1.5)`（服务器还没好）→ 白屏 | **轮询到 `/api/health` 返回 200 才开** |
| 首屏关键资源 | 800 ms（health 每次跑 `vol.py --help` 子进程） | **2–65 ms**（引擎自检改 60 s 缓存 + 启动后台预热） |
| 打开 2 GB 镜像（建案） | **3.6 s**（全文件 SHA-256 + 深度探测 + 512 MB 字节扫描） | **0.03 s**（其余全部异步） |
| 多案并发建案 | **越用越卡**（probe 1→241 ms） | **稳定 10–22 ms**（全局限 1 个补全任务） |
| 断网能不能打开 | 未验证 | **实测可用**（拦截全部出网 socket，0 次出网尝试） |

### 六类根因（每一类都有实测数据）

1. **端口占用 + windowed 打包 = 双击无反应**
   日志实证：`[Errno 10048] error while attempting to bind on address ('127.0.0.1', 8765)`。
   exe 没有控制台 ⇒ 异常只进日志 ⇒ 用户只看到"没反应"。
   → 端口占用**分流**（复用 / 换端口 / 弹框），**绝不静默退出**。
2. **Windows 的 `SO_REUSEADDR` 让端口探测永远返回 True**
   （Windows 允许第二个 socket 重复 bind 已监听端口 ⇒ 探测失效 ⇒ 真绑时才报错）
   → 不设 `SO_REUSEADDR`，且 bind 后**真的 `listen(1)`** 再关。
3. **FastAPI：`async def` 端点里调阻塞代码 = 堵死事件循环**
   24 个端点全是 `async def` 但内部是 SQLite 查询 / 文件读 / 子进程。
   → 阻塞端点一律改**同步 `def`**，FastAPI 自动放线程池（首屏 800 ms → 2 ms）。
4. **建案时不要同步做全文件哈希 / 大范围扫描**
   实测：深度探测 2.10 s + 全文件 SHA-256 3.06 s（16 GB 就是 ~25 s）+ 字节扫描 3.6 s。
   → 建案只做**魔数探测 + 前 8 MB 指纹**，其余**异步 + 限流**。
5. **异步 ≠ 无害**：每个建案起一个线程读整个镜像 ⇒ 几个案子叠在一起把请求拖慢一个数量级。
   → **全局信号量（同时最多 1 个）+ 同案去重 + 延迟 3 秒启动**。
6. **PyInstaller 6.x windowed 模式的 `sys.stdout` 是"假流"不是 `None`**
   → `if sys.stdout is None` 永不成立 ⇒ 日志文件建了却**永远 0 字节**（排障时什么都看不到）。
   → 改成按"有没有真实控制台"判定，并**无条件接管** stdout/stderr（行缓冲 + 轮转 + 跟随 `MEMLENS_HOME`）。

### 断网验证（新增命令）

```powershell
python -m memlens.cli offline-check
# 断网探针：通过 ✔
#    /  /static/app.js  /static/style.css  /api/health  /api/cases  全部 True
#    blocked_outbound_attempts    0        ← 启动路径一次都没尝试出网
```

方法：**运行时拦截全部出网 socket**（只放行回环），比拔网线更可控可重复，
能精确回答"启动路径到底有没有依赖外网"。

**结论（精确表述）**：
* UI 与全部只读 API 在**完全断网**下可用；
* 断网影响的是**分析阶段**：vol3 首次要下内核符号表，失败会**明确报错**而非静默
  （`symbol table requirement was not fulfilled`）；
  解法是把 ISF 预置到 `work/vol3/symbols/`（`memlens symbols --import-kernel <镜像>`）。

### 新增诊断能力

| 能力 | 位置 |
|---|---|
| 启动耗时 / 端口决策日志 | `main.py::_run_web` |
| 建案耗时分解（probe / create_case / total，毫秒） | `POST /api/cases` → `timing_ms` |
| 端口状态决策（复用 / 换端口 / 弹框） | `memlens/web/server.py` |
| 无控制台日志（行缓冲 + 轮转 + 跟随 `MEMLENS_HOME`） | `main.py::_fix_streams` |
| 断网自检 | `python -m memlens.cli offline-check` |

---

## 1. v1.0：从"能出日志"到"打开即全量深度分析 + 一屏看完系统信息"

### 1.1 用户反馈的三个问题，逐条对应

| 原话 | 根因 | v1.0 的做法 |
|---|---|---|
| "只能分析程序之后输出日志，很多内存取证的信息根本分析不出来，比如系统信息、版本、内存大小等" | 数据**散落在不同产物里、没人拼成一张表**；LovelyMem 那类工具也只把系统信息放在一个纯文本弹窗里，不结构化、不入库 | 新增 **系统画像合成器**：多来源（MemProcFS `sysinfo.txt` / vol3 `windows.statistics` / Linux `vmcoreinfo` / macOS `check_sysctl` / 镜像字节残留）→ **归一化成固定字段表**，每行带**来源**与**置信度**，交叉验证不一致时全部保留并标红 |
| "不要快速、深度分析这些选项，打开附件就是深度分析全部内容" | 传统做法是"上百个按钮，用户自己点"，分析深度取决于用户会不会点 | 删掉"快/深"概念，**只有一条路径**：探测 → 计划 → 全量执行 → 检测 → 情报 → 时间线 → 旗标 → 画像 → 报告。用户的干预点只剩"中途停止"与"按需补跑" |
| "UI 不够完整" | PySide6 桌面壳加一个"概览页"要几百行样板代码，甘特/时间线/关系图更是无从下手 | **全栈化**：FastAPI 后端 + 浏览器内取证控制台 SPA（8 个页签 + 产物记录抽屉 + 服务端文件浏览器 + WebSocket 实时进度） |

### 1.2 一键深度分析：九个阶段

| 阶段 | 产出 | 典型耗时（2 GiB Win7 镜像） |
|---|---|---|
| ① 探测 | 容器格式、操作系统、指纹证据 | 3–20 s |
| ② 计划 | **将要跑什么**（可解释，含"为什么跳过"） | < 1 s |
| ③ 引擎执行 | MemProcFS 全量产物 + vol3 平台插件族 + 字节扫描 + 静态分析 | 10–25 min |
| ④ 检测器 | 发现项（异常内存 / 隐藏进程 / 注入 / 可疑样本） | 1–30 s |
| ⑤ 情报 | IOC + 内置词典命中 | 1–3 min |
| ⑥ 时间线 | 统一时间线（进程/网络/注册表/文件/线程…） | 10–60 s |
| ⑦ 旗标 | 全量 flag 候选（跨所有产物） | 5–30 s |
| ⑧ **系统画像** | **版本 / 物理内存 / CPU / 开机时间 / 用户 / SID** | 1–10 s |
| ⑨ 报告 | Markdown + HTML | 1–5 s |

进度通过 **WebSocket** 实时推到前端：阶段条 + 百分比 + 逐插件状态 + 引擎输出日志。

### 1.3 系统画像：把"取不到"变成"一屏看完"

固定字段（`memlens/pipeline/sysprofile.py`）：

| 分组 | 字段 |
|---|---|
| 系统 | 操作系统、版本、构建号、架构、内核、计算机名、域/工作组 |
| 硬件 | CPU 型号、CPU 核心数、**物理内存**、可用内存、已用内存、系统盘 |
| 标识 | 机器 ID、安全 ID、产品 ID、注册所有者、组织 |
| 时间 | 开机时间、已运行时长、时区、安装日期、镜像采集时刻 |
| 用户 | 用户名 + SID + 用户目录（从 `users.txt` 与注册表交叉） |

**内存大小**取自三条独立通道并交叉验证：

1. `MemProcFS sys/sysinfo/sysinfo.txt` 的 `Physical Memory: 2 GB`
   → 必须用 `parse_size()` 换算（`2 GB` → `2147483648` 字节），
   否则界面会显示"2 B"，看起来就像"没分析出来"。
2. vol3 `windows.statistics` 的 `Total/Available Physical Memory`
3. 兜底：镜像字节里搜 `/proc/meminfo` 的 `MemTotal:`（Linux）、
   `hw.memsize`（macOS）、`Total Physical Memory`（Windows）
   —— 这条通道**不依赖任何引擎**，符号表拿不到时依然能给出内存大小。

### 1.4 数据库：SQLite 与 MySQL 同一套模型

存储层从"写死 sqlite3"换成 **SQLAlchemy Core**：

* `?` 占位符、`AUTOINCREMENT`、`executescript`、`TEXT`（MySQL 只有 64 KB）
  这些方言差异全部由 SQLAlchemy 编译，**代码里不再出现方言分支**。
* `records.data` 在 MySQL 上显式用 **`LONGTEXT`** ——
  一行记录的 JSON 很容易超过 64 KB（命令行、模块列表、YARA 命中），
  用普通 `TEXT` 会**静默截断**，症状是"换 MySQL 就丢数据"。
* **自动迁移**：`create_all()` 只会建缺失的表、**不会给旧表加列**。
  v1.0 补了 `ALTER TABLE ... ADD COLUMN` 迁移（SQLite / MySQL 通用），
  否则升级后的旧 `work/memlens.db` 一查就 `no such column: cases.state`。
* 新增 7 张表：`system_profile` / `timeline_events` / `iocs` / `dict_hits` /
  `flags` / `analysis_runs` / `notes` / `kv` —— **分析出来的所有信息都有地方落**。

```powershell
# 默认：SQLite（work/memlens.db）
MemLens.exe

# MySQL：环境变量指定即可（首次自动建表 + 迁移）
$env:MEMLENS_DB_URL = "mysql+pymysql://user:pw@127.0.0.1:3306/memlens?charset=utf8mb4"
MemLens.exe
```

实测：MySQL 8.0.23 + PyMySQL，13 张表全部就绪，20 万字节的单条记录完整往返。

### 1.5 跨平台：容器识别 + 插件族

| 证据类型 | 识别方式 | 分析路径 |
|---|---|---|
| Windows 裸内存 / `.vmem` / `.dmp` | 魔数 + 指纹投票 | MemProcFS（虚拟盘取证）+ vol3 `windows.*` |
| Linux（LiME / raw / ELF core / kdump / hiber） | `EMiL` 魔数 + 指纹 | vol3 `linux.*`（59 个插件）+ 字节扫描 |
| macOS（raw / AFF4 / EWF） | 指纹 + 容器魔数 | vol3 `mac.*`（22 个插件）+ 字节扫描 |
| **AVML**（Velociraptor 内存归档） | zip 头 + `lime.txt` | 归档内含 LiME 分段 |
| **AFF4 / EWF(E01) / VMDK** | `AFF4\r\n\x00` / `EVF\x09…` / `KDMV` | 标记为"需解包"并说明 |

> LovelyMem 的源码里**完全没有这一层**（grep `LiME|AVML|aff4|ewf|vmdk` 零命中），
> 它只把路径原样丢给外部工具碰运气。v1.0 补上了。

### 1.6 UI：浏览器内的取证控制台

| 页签 | 内容 |
|---|---|
| 概览 | 旗标横幅、KPI 条、**系统画像**（分组卡片 + 来源 + 置信度条）、案件信息、Top 发现项、用户表 |
| 产物 | 全部插件产物表（状态/行数/耗时/错误），点开 → **记录抽屉**（动态列、搜索、分页、导出 CSV） |
| 时间线 | 统一时间线，分类过滤 + 关键词搜索 + 正倒序 |
| 发现项 | 严重度分色卡片（含说明、来源、置信度） |
| 情报 | IOC 表 + 词典命中表（可切换） |
| 旗标 | 旗标候选，一键复制 |
| 用户 | 用户名 / SID / 用户目录 |
| 日志 | 实时引擎输出（WebSocket 推送） |

另有：**服务端文件浏览器**（工具跑在本机，可直接浏览本机磁盘挑证据）、
**案件库侧栏**、**引擎状态指示灯**、**数据库后端徽标**。

### 1.7 顺手修掉的真 bug

| Bug | 现象 | 根因 | 修复 |
|---|---|---|---|
| `sha256_file` 全文件哈希崩溃 | 案件 SHA-256 **静默为空**、所有产物原始输出无法落盘（证据保全失效） | `min(chunk, limit - read)` 在 `limit is None` 时抛 `TypeError` | 分支处理 `limit` |
| 旧库升级即 500 | Web 端 `/api/cases` 500、GUI 打不开 | `create_all()` 不 ALTER 旧表，缺 `cases.state` 等列 | `models.migrate()` 自动 `ADD COLUMN` |
| 内存大小被"可用内存"覆盖 | 总内存显示成 1 GB | `parse_vol3_statistics` 里 `"availablephysicalmemory"` 也含 `"physicalmemory"`，先判总量 | 调整判断顺序 |
| `Engine.tables` 不存在 | `/api/health` 500 | SQLAlchemy 2.x 移除了 `Engine.table_names()`，`engine.tables` 也没有 | 用 `metadata.tables` |
| 静态引擎 9 个插件全失败 | `analyze_file() takes 3 positional arguments but 4 were given` | `TaskRunner` 硬传 3 个位置参数，但 `static` 的签名没有 `params`（`memstrings` 有） | 按 `inspect.signature` 协商后再调用 |
| 系统版本显示成 "Windows 5.18" | 版本号被 MemProcFS 自己的版本覆盖 | `sysinfo.txt` 里 `Windows Information: Version` 与 `MemProcFS Information: Version` **同名**，扁平化时后者覆盖前者 | 扁平化改"首次出现优先"（`setdefault`） |
| 第一个用户整行丢失 | 用户表只剩一个半截路径 | MemProcFS 按第一个冒号切分键值，`C:\Users\…` 被拆成 key="C" / value="\Users\…" | 还原时对"含 SID 的行"特殊处理 |

---

## 1.8 快速上手

### 图形界面（Web 控制台，默认形态）

```powershell
# ① 双击 / 直接运行
dist\MemLens\MemLens.exe

# ② 或从源码
.venv\Scripts\python.exe main.py

# ③ 指定端口 / 拖文件进来
.venv\Scripts\python.exe main.py --port 9000
.venv\Scripts\python.exe main.py E:\cases\mem.raw
```

打开后：**「打开证据」→ 选文件 → 自动开始全量深度分析**（无需再点任何"开始"按钮）。

> **端口被占用怎么办？**（v1.1 起不再"双击没反应"）
> * 端口被**本工具自己**占 → 直接**打开已有实例的浏览器**并退出；
> * 端口被**别的程序**占 → **自动换端口**（8765→8766→…）并用新端口打开；
> * 实在起不来 → **弹 Windows 消息框**说明原因（同时写进 `work\memlens.log`）。
>
> **排障入口**：打包后的 exe 没有控制台，所有输出都在
> `<exe 同级目录>\work\memlens.log`（或 `MEMLENS_HOME\work\memlens.log`）。

### 命令行

```powershell
# ★ 一键深度分析（与 GUI 同一套流水线）
.venv\Scripts\python.exe -m memlens.cli deep E:\vol_easy.vmem

# 启动 Web 控制台
.venv\Scripts\python.exe -m memlens.cli serve --port 8765

# ★ 断网自检：拦截所有出网 socket，验证 UI/API 仍可用
.venv\Scripts\python.exe -m memlens.cli offline-check

# 数据库后端与数据表
.venv\Scripts\python.exe -m memlens.cli db --cases

# 旧命令仍在（逐插件精细控制）
.venv\Scripts\python.exe -m memlens.cli probe  E:\vol_easy.vmem
.venv\Scripts\python.exe -m memlens.cli plugins --search 进程
.venv\Scripts\python.exe -m memlens.cli analyze E:\vol_easy.vmem --engine vol3 --plugins pslist,netscan
```

### 目录结构（v1.0）

```
memlens/
  pipeline/           ★ 新增：一键深度分析
    plan.py             分析计划（按容器/OS 决定跑什么）
    sysprofile.py       系统画像合成器（版本/内存/CPU/开机时间）
    deep.py             九阶段编排器
  web/               ★ 新增：全栈 Web
    app.py              FastAPI 后端（REST + WebSocket + 服务端文件浏览）
    static/             前端 SPA（index.html / app.js / style.css，无构建无 CDN）
  storage/
    models.py         ★ 新增：SQLAlchemy Core 表定义（跨方言）+ 自动迁移
    db.py              ★ 改：DataStore 门面（SQLite / MySQL 通用）
  core/image_probe.py ★ 改：新增 AFF4 / EWF / VMDK / AVML 容器识别
  engines/ detectors/ intel/ tasks/ ui/    （v0.10 原样保留）
packaging/
  memlens.spec         PyInstaller 配置（已含 web 静态资源与新依赖）
  build.ps1            ★ 新增：一键打包（PyInstaller + 拷 MemProcFS）
```

### 打包成独立 exe

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build.ps1
# 产物：dist\MemLens\MemLens.exe   （167.5 MB，含 MemProcFS）
# 双击即用：起本地服务 → 自动开浏览器 → 打开证据即开始全量深度分析
```

> 打包脚本会**跳过 MemProcFS 自带的 `python\` 子目录（1.26 GB）**，
> 只拷 `memprocfs.exe` + DLL + `Symbols\`（28.6 MB）——
> 取证主流程用不到那个嵌入式 Python 运行时，不拷的话 dist 会变成 1.4 GB。
> 跳过拷贝的 exe 需要用环境变量 `MEMLENS_MEMPROCFS` 指向 `memprocfs.exe`。

### 实测基线（`E:\vol_easy.vmem`，2 GiB，Win7 SP1 x64）

| 指标 | 数值 |
|---|---|
| 产物 / 记录 | **110** 个产物 / **1,043,655** 条记录 |
| 发现项 | **57**（high 13 / medium 4 / low 40） |
| 时间线 | **8,586** 个事件 |
| 旗标 | `flag{ok!get_webshell_is_good_idea~}` |
| 系统画像 | Windows 7 · 6.1 (build 7601) · X64 · **物理内存 2,147,483,648 B (2 GB)** · i7-12700 · 开机 2025-07-23 03:56 UTC · 2 个用户（含 SID） |
| 全流程 | 20–25 min（重跑命中产物缓存，分钟级） |

---

## 0.10 v0.10.0：从"能出日志"到"一次收集、几十个产物、直接给结论"

### 0.1 为什么上一版仍然"没什么用"

上一版（v0.9）把 vol3 的符号预检、进度翻译、旗标扫描都补齐了，但它有一个**结构性**问题没解决：

**vol3 的模型是"一个插件一次、每次都重新解析镜像"**。于是：

| 现象 | 根因（实测） |
|---|---|
| 首跑要等 3-5 分钟（符号下载+页表重建），期间界面几乎只有日志 | vol3 每个插件都要重走：页映射扫描 → 内核定位 → 解析结构 |
| 拿不到注册表、事件日志、文件系统时间线 | vol3 需要 `dumpfiles`/`registry` 组合操作，散、慢、易失败 |
| 一旦符号表没就绪（离线/只读目录/杀软拦网），**27 个插件全失败**，界面只剩一屏 stderr | 全部产物都依赖同一个符号前提，没有第二条路 |
| 分析完成若没有发现项，界面停在「② 运行」页 —— 眼前就是程序日志 | 落地页逻辑没把"结果表"当成结果 |

### 0.2 本版的核心：接入 MemProcFS（虚拟盘取证）

MemProcFS 的模型完全不同：**常驻进程把镜像挂成一个盘（如 `Z:\`）**，内核符号与页表只解析一次，
之后所有取证数据都是**读文件**：

```
Z:\forensic\csv\process.csv     进程（PID/父进程/用户/完整性级别/命令行/PEB）
Z:\forensic\csv\net.csv         网络连接 + 归属进程与进程路径
Z:\forensic\csv\findevil.csv    异常检测（高熵可执行内存 = 注入/木马）
Z:\forensic\csv\timeline_*.csv  进程/线程/注册表/文件/网络 时间线
Z:\sys\sysinfo\sysinfo.txt      系统版本/启动时间/硬件
Z:\registry\HKLM\...            注册表**按文件系统读**（键=目录，值=文件）
Z:\registry\hive_files\*.reghive 原始配置单元（可离线解 SAM/LSA 凭据）
Z:\misc\eventlog\*.evtx         事件日志
Z:\pid\<PID>\memory.vmem        单进程完整内存 dump（CTF 常客）
```

MemLens 把它做成一个**一等引擎**，共 **34 类产物**（`mprocfs.*`）：

| 分组 | 产物 |
|---|---|
| 系统 | `harvest`（收集入口）`sysinfo` `productid` `procinfo` |
| 进程 | `process` `threads` `modules` `handles` `proc_view` `dump_process` |
| 网络 | `net` `netdns` |
| 恶意代码 | `findevil` `yara` `drivers` `unloaded_modules` |
| 注册表/凭据 | `registry_run` `registry_hives` `registry_key` `users` |
| 服务/文件/其他 | `services` `files` `devices` `virtualmachines` `eventlog` `bitlocker` |
| 时间线 | `timeline_process/net/registry/ntfs/thread/kernelobject/web/all` |

工程要点（都是踩坑换来的）：

* **工程目录隔离**：MemProcFS 运行在自己的副本 `tools/MemProcFS/` 下，日志与符号只写 MemLens
  的工作目录；**绝不写用户那份比赛工具包**（那份是只读红线）。
* **自动挑空闲盘符**（Z 往下找）：用户可能同时开着别的取证工具占着 `M:`，抢盘符会让两边都废。
* **收获即脱挂**：产物复制进工作目录后立刻杀掉进程、卸载盘符（否则留下常驻服务与占用的盘符）。
  会话带 **manifest + 收获版本号**，同镜像第二次分析毫秒级复用；格式升级会自动重收。
* **失败说真话**：进程提前退出/挂载点不出现/CSV 未落盘 → 明确报错，绝不返回"空结果 + 成功"。

### 0.3 配套检测器：`memprocfs_triage`

产物本身只是表，**结论**要另外给。新增的检测器把 MemProcFS 数据交叉成发现项：

* 异常内存（findevil 高熵页）→ 结合"是否系统进程"调置信度
* 可疑进程（工具名特征 / 从 Temp·AppData·公开目录运行 / 无镜像路径）
* 外部网络连接（内网判定 + 归属进程是否已被标记）
* 已卸载模块（无文件 DLL 注入线索）、可疑服务（用户可写目录/脚本宿主拉起）
* 自启动项（Run/RunOnce，指向可疑路径则高分）
* **凭据可用性**：抓到 SAM/SYSTEM/SECURITY hive 时明确提示"可离线解口令哈希"
* 多信号聚合：同一进程被 ≥3 类规则命中的，单独列成"重点排查对象"

实测（`E:\vol_easy.vmem`，2 GiB，Win7 SP1 x64，22 秒收集）：

```
[3/8] mprocfs.process  ✔ 35 行    mprocfs.net ✔ 33 行    mprocfs.findevil ✔ 3 行
[4/5] 检测器：memprocfs_triage 已执行：7 条发现项
      [HIGH] 82%  异常内存：AntSword.exe（PID 1456） — HIGH_ENTROPY
      [HIGH] 82%  异常内存：sppsvc.exe（PID 2000） — HIGH_ENTROPY
      [HIGH] 73%  可疑进程：AntSword.exe（PID 1456 / 1716 / 1952 / 260）
      [HIGH] 73%  可疑进程：notepad.exe（PID 2232）
      案件：8 个产物 / 108 条记录 / 7 条发现项 {'high': 7}
```

### 0.4 符号表：可查、可只读挂接、可离线

vol3 的成败几乎只取决于"内核 ISF 是否就绪"。新增 `memlens symbols`：

```powershell
# 查看现状（自有目录 + 只读引用源各有多少 ISF）
.\.venv\Scripts\python.exe -m memlens.cli symbols

# 把本机已有的符号目录**只读**挂接进来（零拷贝、离线秒出结果）
#   例：比赛工具包里自带的 volatility3\symbols
... symbols --add-dir "E:\某个工具包\Tools\volatility3\symbols"
... symbols --add-dir "<你的工具包>\Tools\volatility3\symbols"

# 或复制一份到 MemLens 工作目录（便携、可归档、可拷给别人）
... symbols --import "<上述目录>"
```

挂接后 vol3 的 `-s` 变成"自有可写目录;只读引用目录"（**可写目录永远排第一**，新 ISF 只写自己的）。
`analyze --offline` 可完全禁止联网。

> ⚠ 首次挂接大符号源（数千个 ISF）时 vol3 要重建一次索引（分钟级），之后就进缓存、秒级；
> 这是"离线可用"的一次性代价。

### 0.5 呈现层：结果页真的能翻结果

* 结果页新增**产物下拉框**：一次分析几十个产物，逐个翻看（默认停在进程表，而不是"最后一个跑完的插件"）。
* 分析完成的落地页改为：**旗标 > 发现项 > 结果表 > 运行状态** —— 没有结论时才落在运行页，
  不会再让用户"一眼只有日志"。
* MemProcFS 的收集过程信息（启动、取证阶段、收获产物数、耗时）实时回显到日志，长任务不再像卡死。

### 0.6 顺手修掉的真 bug

| Bug | 现象 | 修复 |
|---|---|---|
| 中文控制台编码 | `memlens engines` 在 GBK 控制台直接崩：`'gbk' codec can't encode character '\u2705'` —— 用户看到"跑了但啥都没输出" | 启动时把 stdio 的 `errors` 改成 `replace`（保留控制台编码，中文不乱码，符号降级为 `?`） |
| 收获路径两套映射 | 22 个 CSV 明明收获成功，上层却报"产物不存在"（复制到 `harvest/csv/`，查找走 `forensic/csv/`） | 统一**镜像挂载布局**：`harvest/<挂载内同路径>`，并加**收获版本号**让旧缓存自动失效 |
| vol3 并行 | `--parallelism processes` 会让插件全失败（0 行） | 默认不传，只有显式要求才加（上一版已修，本版补充回归测试） |

### 0.7 按需深入：单进程内存 dump 与任意注册表键

三个"在线产物"走**轻量挂载**（不跑 forensic，读完立刻卸载）：

```powershell
# 单进程内存 dump（CTF 里最常见的一步：把可疑进程的内存倒出来找 flag/凭据）
... analyze "E:\cases\mem.raw" --engine memprocfs --plugins mprocfs.dump_process --param pid=1456

# 不写 pid 时**自动挑选**：优先用 findevil.csv 标出的高熵进程，其次"工具名特征/用户可写目录"的进程（最多 3 个）
... analyze "E:\cases\mem.raw" --engine memprocfs --plugins mprocfs.dump_process

# 单进程视图：命令行 / 环境变量 / 当前目录 / 窗口标题 / 创建时间
... analyze "E:\cases\mem.raw" --engine memprocfs --plugins mprocfs.proc_view --param pid=1456

# 读任意注册表键（键=目录、值=文件）
... analyze "E:\cases\mem.raw" --engine memprocfs --plugins mprocfs.registry_key `
        --param "key=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

> 落盘位置：`work/mp/<镜像指纹>/dump/pid<PID>.vmem`，记录里带大小与 SHA-256。
> **dump 出来的东西只做静态分析与字符串提取，不要在本机运行。**


---

## 0.9 v0.9.0：为什么之前"纯纯摆设"，这次改了什么

现象（用户实测，`E:\vol_easy.vmem`，2 GiB，Win7 SP1 x64）：点「开始分析」→ 一个插件卡在
「(1/27) 系统类型探测（banners）」，日志里只有一屏 `Progress: … Updating caches for 110 files…`，
最后**什么都没出来**。逐条查下来是四个叠加问题，本版全部修掉：

| # | 真正的原因（实测证据） | 本版的做法 |
|---|---|---|
| 1 | **vol3 首次分析要先把内核符号表搞到手**：按镜像里的 PDB GUID 去下载 `ntkrnlmp.pdb`（约 10 MB）再转成 ISF，**实测 184 秒**；期间界面只有一个"0%"和进度刷屏 | 把这一步独立成**「符号预检」阶段**，把 vol3 的进度翻译成人话（符号索引 → 页映射扫描 → 内核定位 → 下载符号），配真实百分比与耗时；失败时给出可执行建议 |
| 2 | **缓存/符号表被写到安装目录**（`volatility3/symbols/…`）或 `%APPDATA%`，exe 装在只读盘/Program Files 时直接 `PermissionError: [WinError 5]`，插件最后以 `symbol table requirement was not fulfilled` 收场，却只埋在 stderr 里 | 一律 `--cache-path <work>/vol3/cache` + `-s <work>/vol3/symbols`（**自动创建**；目录不存在时 vol3 会报 `unable to open database file`）。下载的 ISF 落在这里 → 拷走 work 目录即可离线复用 |
| 3 | **0 行被当成"成功"**：`banners`/`windows.info` 之类返回空，界面只显示"0 行"，用户不知道是"镜像里没有"还是"引擎根本没跑通" | 每个插件都在**运行表**里显示：状态、行数、耗时、**为什么是 0 行**（从 stderr 里挑关键行 + 已知故障词典翻译），并可直接双击查看该插件的原始结果 |
| 4 | **必须等到插件阶段才有产出**，而插件阶段又依赖符号表 → 头几分钟必然"什么都没有" | 分析流程改成三段：**① 字节快扫（flag/IOC，不依赖符号表）→ ② 符号预检 → ③ 插件执行**。夺旗题常常在第①段几秒~几分钟内就出答案，并且 **`vol_easy.vmem` 实测直接命中 `flag{ok!get_webshell_is_good_idea~}`** |

另外新增/改进：
* **⚡ 找 flag（一键）**：整机字节多编码扫描 + 把所有已入库产物的命中汇总到「旗标」页（去重、计次、带镜像偏移与上下文），命中即在顶部大号显示并可一键复制；
* **宽松模式**（默认关）：`任意前缀{...}` 一起报——实测真实镜像里 `i18n{…}`/`mathit{…}`/`FileIdIndex-{GUID}` 这类模板噪声有几百条，会把真命中淹掉，故默认关闭并降级排序；
* **界面重做**：深色"取证控制台"主题（纯 QSS，零额外资源）、左栏改为会动态更新的卡片、新增「② 运行」页（阶段进度 + 插件运行表 + 结论条）、新增「⑤ 旗标」页；
* 预设里把 `windows.info` 提到第一位（它是**触发符号解析的那一步**，先跑它才能让后面的插件秒开）。

---

## 0.1 v0.8.0 新增：从"看得见结果"到"看得懂线索"

上一版能把 vol3 的结果收进库，但真正干活时还缺三样：**结果里哪些是要紧的**、
**这些现象说明什么**、**怎么写成一份能交出去的报告**。v0.8.0 补齐这三段：

| 新能力 | 解决的问题 | 入口 |
|---|---|---|
| **情报层 intel** | 几十万行结果里，IOC 与敏感特征要手工捞 | 工具栏「🔍 情报扫描」/ `cli intel` |
| **镜像字节扫描 memstrings** | flag、口令、C2 常是裸字符串，没有任何插件会主动告诉你 | 新引擎「镜像字节扫描」/ `--engine memstrings` |
| **取证知识库** | "psscan 有、pslist 无"说明什么、下一步查哪 | `cli knowledge` |
| **事件时间线** | 攻击链只有放到时间轴上才成立 | `cli timeline` |
| **报告生成** | 从"一堆 CSV"到"一份能交的报告" | 工具栏「📄 生成报告」/ `cli report` |

### 情报层：IOC 提取 + 词典扫描

```
      案件产物（records）
              │
              ▼
   ┌──────────────────────── intel/scan.py ────────────────────────┐
   │  ① IOC 自动提取  ioc.py   IP/URL/域名/邮箱/钱包/JWT/路径/注册表键 │
   │  ② 词典匹配      dict.py 7 本内置词典，关键词与正则              │
   │  ③ 聚合入库      按 (类型,值) 去重，带出处与次数                │
   └─────────────────────────────┬──────────────────────────────────┘
                                 ▼
        intel.ioc / intel.dict.<id> → 与 vol3 产物同表同源
```

**为什么要"聚合"而不是逐条命中入库**：一个外网 IP 会在几百条 netscan 行里重复出现，
逐条存会把证据表淹没。这里按 **(类型, 值)** 聚成一行，并记录 `sources`（出现在哪些插件里）
与 `count`（出现次数）——产出的是**线索清单**，不是匹配流水账。

**词典**（内容为本项目独立编写，可编辑扩展）：

| 词典 | 条目 | 覆盖 |
|---|---|---|
| `ctf` | 6 | flag 的明文/hex/base64/URL/HTML实体五种编码、解题痕迹 |
| `suspicious_process` | 6 | 远控、凭据工具、扫描器、**PowerShell 混淆**、关防护 |
| `suspicious_port` | 4 | 远管端口、C2 端口、数据库中间件、明文协议（只扫网络产物） |
| `persistence` | 6 | Run/RunOnce/Winlogon/AppInit_DLLs/**IFEO 劫持**、WMI 事件订阅、cron、`ld.so.preload` |
| `credentials` | 3 | 明文口令、JWT/AWS/GitHub/私钥、口令哈希格式 |
| `web_attack` | 3 | 一句话木马、SQL 注入语句、WebShell 家族标识 |
| `ransomware` | 3 | 赎金说明、`.onion` 与钱包、破坏恢复手段的命令 |

> 词典用 `file_globs` 做**路由**：敏感端口只喂 netscan/netstat/pcap，敏感程序只喂
> pslist/cmdline/services/memstrings。命中为 0 时会明确区分
> 「被路由挡掉了」与「扫了但没命中」——两者含义完全不同。

### 镜像字节扫描引擎（memstrings）

```
memstrings.flag    多编码 flag 直搜（明文/hex/base64/URL/HTML实体），命中即给解码结果
memstrings.ascii   ASCII 字符串提取（min_len 可调）
memstrings.utf16   UTF-16LE 字符串提取 —— ASCII 插件永远搜不到宽字符
memstrings.ioc     直接在原始字节上提 IOC
```

* **流式分块 + 重叠区**，几个 GB 的镜像不会读进内存；正则编译成 **bytes 模式**，
  绕开编码解码，GBK/UTF-8 解不开也不会作废整块。
* 每条命中带 **偏移 + 前后 hexdump/ASCII 上下文**——只看字符串本身看不出是不是垃圾数据。
* 对**任何容器**都可分析（不依赖 Volatility、不需要结构化解析），因此 `memfrag`/`other`
  这类"出不了进程表但字符串就在里面"的证据不会被误判为不可分析。

---

## 1. 它解决什么问题

同类工具通常停在"能跑 Volatility 插件、能把 CSV 弹出来"。真正干活时会缺三样东西：

| 痛点 | MemLens 的做法 |
|---|---|
| 结果散落在几十个 CSV 里，无法跨插件关联 | **统一证据模型**（案件 → 产物 → 记录 → 发现项），全部入 SQLite，可 SQL 查询 |
| 拿到一堆输出还得人工判断"哪个是恶意的" | **检测器**：多源交叉验证自动出"发现项"，带**置信度**与**证据链** |
| 换个镜像忘了清目录就串数据；重复跑浪费几十分钟 | **案件隔离 + 镜像 SHA-256 指纹 + 参数指纹缓存** |
| 镜像是什么格式、能不能分析，开跑才知道 | **镜像容器探测**：raw / LiME / Windows 崩溃转储 / minidump / VMware / ELF core / kdump / hiberfil / PE / 其它 |
| 工具自己崩了还假装一切正常 | **失败必须可见**：引擎返回码、解析异常、0 行结果全部明确标注 |

**三条分析域，同一套工作台**：

| 域 | 输入 | 引擎 | 能回答什么 |
|---|---|---|---|
| **内存取证** | `.raw .mem .dmp .vmem .lime .core`… | Volatility 3（运行时枚举 180 插件） | 机器上发生过什么：进程/网络/句柄/注册表/注入/隐藏进程 |
| **静态样本** | `.exe .sys .dll` / **ELF** / **任何二进制** | 内置标准库 PE+ELF 解析器 | 这个文件是什么、可不可疑：结构/导入导出/TLS/加壳/危险 API 组合 |
| **流量分析** | `.pcap` `.pcapng` | 内置 libpcap/pcapng 解析器 | 谁在通信、连去哪：会话对/Top IP/端口/DNS/HTTP、明文 flag |

**容器探测覆盖 15 类**（决定走哪条分析路线）：

`raw` · `lime` · `windmp`(PAGEDUMP/PAGEDU64) · `minidump` · `vmem/vmsn/sav/vmss`(VMware/Hyper-V) ·
`elfcore` · `kdump` · `hiber` · **`memfrag`(进程内存段)** · `exe`(PE) · `elf` ·
**`pcap`/`pcapng`(流量包)** · **`locked`(tag+长度+密文 加密容器)** · `other`

> `memfrag` / `locked` / `pcap` 都是拿**真实赛题样本**打出来的能力：
> 进程内存段里含 libc 代码页（开头就是 `\x7fELF`）会被误判成 ELF 样本；
> 赛题的 `LOCKED`+u64+密文 格式曾被归为 unknown；流量包此前也不在支持列表。

---

## 2. 快速开始

### 2.1 安装（依赖装在项目自己的虚拟环境里，不影响你其它 Python）

```powershell
cd D:\DSH\工作区\MemLens
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt

# 国内网络慢时用镜像：
.venv\Scripts\python.exe -m pip install -r requirements.txt `
    -i https://mirrors.aliyun.com/pypi/simple/
```

### 2.2 图形界面

```powershell
.venv\Scripts\python.exe main.py
```

界面流程：**打开证据 → 探测（自动推荐引擎）→ 选预设/勾插件 → 开始分析 → 看发现项 → 导出**。

探测结果会直接给出下一步建议，例如：

| 探测结论 | 工具给出的行动建议 |
|---|---|
| `raw` + windows 指纹 | 走内存域，跑 `windows-basic` 预设 |
| `exe` / `elf` | 自动切到 static 引擎（可手动改） |
| `memfrag` | 只能做 strings/正则/dumpfile，**出不了完整进程表** |
| `locked` | 自定义加密容器，需先逆出算法 |

### 2.3 命令行（适合批量与脚本化）

```powershell
# 两种等效启动方式
#   ① 进项目目录（推荐，最直观）：
cd D:\DSH\工作区\MemLens
.venv\Scripts\python.exe -m memlens.cli engines

#   ② 从任意目录（已建 ASCII 联接点 D:\MemLens 指向本目录）：
D:\MemLens\.venv\Scripts\python.exe -m memlens.cli engines
```

> 说明：`.venv\Lib\site-packages\memlens_dev.pth` 指向 ASCII 联接点 `D:\MemLens`，
> 因此 `import memlens` 在任意工作目录下都可用。
> （如果联接点被删，`cd` 到项目目录即可，功能不受影响。）

```powershell
$py = ".venv\Scripts\python.exe"

# ---- 引擎自检 ----
& $py -m memlens.cli engines

# ---- 只探测（自动判断是内存镜像还是样本）----
& $py -m memlens.cli probe   <文件>
& $py -m memlens.cli probe   <文件> --engine static    # 抑制不适用的提示

# ---- 内存镜像分析（默认引擎 vol3）----
& $py -m memlens.cli analyze <镜像> --plugins windows-basic
& $py -m memlens.cli analyze <镜像> --plugins windows-deep -v

# ---- 静态样本分析（exe/sys/任何二进制）----
& $py -m memlens.cli analyze C:\Windows\System32\notepad.exe --engine static
& $py -m memlens.cli analyze C:\suspect\evil.exe --engine static --case-name "样本A"

# ---- 结果消费 ----
& $py -m memlens.cli cases                       # 列出案件
& $py -m memlens.cli case    <case_id>           # 案件详情（产物清单）
& $py -m memlens.cli findings <case_id> -v       # 发现项（含证据）
& $py -m memlens.cli records <case_id> --plugin psscan   # 查记录
& $py -m memlens.cli export  <case_id> --plugin psscan --out psscan.csv
& $py -m memlens.cli records <case_id> --plugin static.pe   # 静态样本的结构记录
```

### 2.4 情报 / 字节扫描 / 时间线 / 报告

```powershell
# ---- 镜像字节扫描：任何容器都能跑，不依赖 Volatility ----
& $py -m memlens.cli analyze <镜像> --engine memstrings --plugins memstrings-full
& $py -m memlens.cli analyze <镜像> --engine memstrings --plugins memstrings.flag

# ---- 情报扫描：IOC + 词典，结果入库，可继续 records/export 查询 ----
& $py -m memlens.cli intel <case_id>
& $py -m memlens.cli intel <case_id> --show-ioc --limit 100
& $py -m memlens.cli intel <case_id> --dicts ctf,persistence      # 只跑指定词典

# ---- 词典清单与条目明细（内置内容可读、可扩展）----
& $py -m memlens.cli dict
& $py -m memlens.cli dict persistence

# ---- 时间线 ----
& $py -m memlens.cli timeline <case_id> --out timeline.csv

# ---- 报告（HTML 自包含可直接打印；Markdown 便于贴工单）----
& $py -m memlens.cli report <case_id> --format html
& $py -m memlens.cli report <case_id> --format md --out report.md

# ---- 知识库：给关键词查，或按本案已跑插件推荐 ----
& $py -m memlens.cli knowledge 隐藏进程
& $py -m memlens.cli knowledge --case <case_id>
```

**典型完整链路**：

```powershell
& $py -m memlens.cli probe  mem.raw
& $py -m memlens.cli analyze mem.raw --plugins windows-basic
& $py -m memlens.cli analyze mem.raw --engine memstrings --plugins memstrings-full
& $py -m memlens.cli intel    <case_id> --show-ioc
& $py -m memlens.cli timeline <case_id> --out timeline.csv
& $py -m memlens.cli report   <case_id> --format html
```

**内置预设**：`windows-quick`（6 插件）/ `windows-basic`（11）/ `windows-deep`（27）/
`只看进程与网络`；静态域 `static-full` / `static-quick`。

**静态样本 7 个分析维度**：

```powershell
& $py -m memlens.cli analyze C:\sample.exe --engine static    # 默认 static-full
# 维度：static.profile 画像 | static.pe PE结构 | static.elf ELF结构
#       static.strings 高危字符串 | static.packer 加壳检测 | static.deps 依赖与导入导出
#       static.pcap 流量包分析
</powershell>

ELF 解析产出（实测于真实赛题样本）：位数/类型(ET_EXEC·ET_DYN·ET_CORE)/机器/入口/解释器、
41 个节区（含熵与 W+X 标记）、**621 个本地函数**、动态符号导入导出、DT_NEEDED 依赖库、
重定位条数、build-id、是否剥离/静态链接。

pcap 解析产出（实测于真实赛题流量包，663 包）：全局头/会话对/Top 目的 IP/Top 端口/
TCP 标志分布/DNS 查询/HTTP Host 与 User-Agent/**明文 flag 特征**。

---

## 3. 架构

```
输入（内存镜像）
   │
   ▼
┌──────────────────────── ① 探测层 core/image_probe.py ────────────────────────┐
│ 容器识别（魔数 + 启发式 + 证据/置信度）  操作系统指纹投票  对齐/稀疏度  风险提醒 │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                ▼
┌──────────────────────── ② 引擎适配层 engines/ ───────────────────────────────┐
│ EngineAdapter（抽象）→ Volatility3Adapter                                    │
│  · 插件运行时枚举（不硬编码，上游升级不失效）                                  │
│  · 参数化命令（shell=False，无注入面）                                        │
│  · jsonl 解析（容错强，日志混入也不毁结果）                                    │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                ▼
┌──────────────────────── ③ 执行层 tasks/runner.py ────────────────────────────┐
│ 登记产物 → 落盘原始输出（SHA-256）→ 解析 → 批量入库 → 标记状态（含错误）        │
│ 可取消 / 可超时 / 同参数缓存                                                  │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                ▼
┌──────────────────────── ④ 证据模型 storage/（SQLite）────────────────────────┐
│ cases ──< artifacts ──< records >── findings        rules                   │
│ （案件）   （一次插件执行）  （结构化行）  （发现项）    （可启停规则）           │
│ 通用索引列：ts / pid / ppid / name / remote                                  │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                ▼
┌──────────────────────── ⑤ 检测层 detectors/ ─────────────────────────────────┐
│ hidden_process：psscan − pslist 差集 + 网络/白名单/psxview 加权 → 置信度       │
│ code_injection：malfind + 模块范围比对 + RWX + PE 头特征 → 置信度             │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                ▼
┌──────────────── ⑤' 情报层 intel/ （与检测器互补，不替代）───────────────────┐
│ ioc：15 类指标自动提取 + 公私网归类   dict：词典匹配 + file_globs 路由         │
│ 输出按 (类型,值) 聚合入库，带 sources 出处与 count → 可 SQL 查询 / 导出       │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                 ▼
┌──────────────── ⑥ 汇总层 report.py / timeline.py ───────────────────────────┐
│ timeline：异构时间归一化 → 事件线 CSV / Markdown                             │
│ report：证据 + 发现项 + 情报 + 时间线 + 知识 → Markdown / 自包含 HTML         │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                 ▼
┌──────────────────────── ⑦ 表现层 ui/ ────────────────────────────────────────┐
│ 主窗口：镜像指纹 │ 插件勾选（分组/搜索/预设）│ 结果表格（分页/过滤/导出）        │
│          │ 发现项（着色/详情）│ 情报页（IOC+词典，可按来源筛选）│ 日志          │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 目录结构

```
MemLens/
├── main.py                      GUI 入口
├── requirements.txt
├── memlens/
│   ├── cli.py                   命令行入口（核心链路的无 GUI 验证/批处理）
│   ├── report.py                ★ 报告生成（Markdown / 自包含 HTML）
│   ├── timeline.py              ★ 事件时间线（异构时间归一化 + CSV/Markdown）
│   ├── core/image_probe.py      ★ 镜像容器与系统探测（15 类容器 + 指纹投票 + 引擎分流）
│   ├── engines/
│   │   ├── base.py              EngineAdapter 抽象 / PluginMeta / RunSpec
│   │   ├── vol3.py              ★ Volatility 3 适配器（运行时枚举插件）
│   │   ├── memstrings.py        ★ 镜像字节级扫描（流式 strings / 多编码 flag / 原始 IOC）
│   │   ├── static.py            ★ 静态样本引擎（PE/ELF 手工解析 / 加密语言 / 字符串分类）
│   ├── elf.py               ★ ELF 结构解析（节区/动态符号/导入导出/依赖库/build-id/本地函数）
│   │   ├── _vol3_entry.py       薄入口（不依赖 vol.py.exe 文件名）
│   │   └── registry.py          引擎注册表（新增取证域只需注册）
│   ├── intel/
│   │   ├── ioc.py               ★ IOC 提取器（15 类 + 公私网归类 + 去噪）
│   │   ├── dictionary.py        ★ 词典模型（合并正则一趟扫描 + file_globs 路由）
│   │   ├── builtin.py           ★ 7 本内置词典（独立编写，带说明与处置建议）
│   │   ├── knowledge.py         ★ 取证知识库（征象→结论→下一步，可按结果检索）
│   │   └── scan.py              ★ 案例级扫描（按值聚合，写回统一证据模型）
│   ├── tasks/runner.py          ★ 执行器（落盘/入库/取消/超时/缓存；含"内置引擎"分支）
│   ├── storage/
│   │   ├── schema.sql           ★ 证据模型（四层 + 规则）
│   │   └── db.py                DataStore 门面（含二进制安全的 CSV 导出）
│   ├── detectors/
│   │   ├── base.py              检测器框架 + Detection + 白名单
│   │   ├── hidden_process.py    ★ 隐藏进程（多源差集 + 加权置信度）
│   │   ├── injection.py         ★ 代码注入（malfind 三层推理）
│   │   └── static_pe.py         ★ PE/ELF 可疑性研判（加壳/API组合/静态链接/WX节加权）
│   └── ui/
│       ├── main_window.py       主窗口装配（引擎切换 + 自动分流 + 情报页 + 报告）
│       ├── table.py             结果表格（服务端分页 + 过滤 + 排序 + 导出）
│       └── worker.py            后台线程（探测 / 分析 / 重检测）
├── tools/
│   ├── gen_samples.py           生成合成样本
│   ├── test_static_engine.py    静态引擎 × 本机真实文件
│   ├── test_detector_static.py  检测器双向验证（benign / 合成高危）
│   ├── test_intel_stack.py      ★ intel/memstrings/时间线/报告/知识库 端到端（37 项）
│   ├── diag_packer.py           加壳误报诊断
│   └── regression_lite.py       72 项回归（GUI/探测/表格/真实样本断言）
├── samples/                     合成样本（自测，不含真实数据）
└── work/                        运行目录：memlens.db + artifacts/（原始输出）
```

---

## 4. 目前验证到什么程度

**已实测通过**（本机 Windows + Python 3.12.9）：

| 项 | 结果 |
|---|---|
| 引擎自检 | ✅ vol3（Volatility 3.28.2）+ static（内置标准库 PE+ELF 解析器） |
| 插件运行时枚举 | ✅ vol3 **180 个**（14 分组、中文名）、static **6 个维度**；均非硬编码 |
| 容器探测 | ✅ raw / LiME / 崩溃转储(PAGEDU64) / minidump / **PE / ELF / 进程内存段 / 加密容器 / 垃圾文件归 other** 共 13 类 |
| 系统指纹投票 | ✅ 伪 Windows 镜像判 windows 98%、Linux 样本判 linux 正确 |
| 探测引擎分流 | ✅ PE/ELF 自动推荐 static；`--engine static` 时不再出现"请改用 static"的自相矛盾告警 |
| 内存域端到端 | ✅ 探测→建案(哈希)→执行→检测→汇总；**引擎失败时正确报告 partial/failed 而非假装成功** |
| **静态域端到端（真实赛题样本）** | ✅ solarsec_202603 全部 8 个文件跑通；15MB ELF 产出 **108 条记录** |
| **ELF 解析正确性** | ✅ 真实样本测得 **64bit / ET_EXEC / x86-64 / 入口 0x401320 / 41 节 / 12763 符号 / 621 本地函数 / 静态链接 / 已剥离=False** |
| PE 解析正确性 | ✅ notepad.exe MD5 `8a1d8175ccca97054cdb25acbb4cc07e`（与公开值吻合）；64bit/i386、驱动、DLL、签名、TLS 回调均正确 |
| **进程内存段识别** | ✅ `dumped_4053_*.bin` → `memfrag`；曾因"内存里含 libc ELF 代码页"被误判为 ELF 样本，已修正 |
| **自定义加密容器识别** | ✅ `LOCKED`+u64+密文 → `locked` 容器 + "需先逆出算法"提示 |
| **字符串去噪** | ✅ 修复前把 x86 代码字节（`D$ Hc@<H`）全判成"邮箱"；改用正则 + 字母占比过滤后归零 |
| **加壳检测误报治理** | ✅ 修复前**所有**系统 PE 被误报"Obsidium/VMProtect"；修复后 notepad/cmd/ntfs/kernel32 全部干净 |
| **检测器两级互证** | ✅ 早期把"反调试/文件遍历"当独立权重，导致 notepad.exe 拿 60% 误报；改为 Tier-1 罕见信号独立计分、Tier-2 常见信号仅在互证时按 0.05/项封顶后，**三个系统程序零误报** |
| 检测器双向验证 | ✅ benign（notepad/calc/mmc）**0 条误报**；**真实恶意 DLL TestDLL.dll → 48% MEDIUM**，权重可解释 |
| **流量包分析** | ✅ 真实赛题 pcap：663 包 / IPv4:663 / 会话对 / Top 端口 / **提取到明文 flag `flag{80892e26-...}`** |
| 检测器正面反馈 | ✅ 跑过但无命中时明确说"已执行：未产生发现项"，不静默 |
| **回归测试** | ✅ **45 项全通过**（GUI/探测/表格 + 22 项真实样本断言：ELF/memfrag/locked/恶意DLL/良性对照/pcap），0 失败 |
| CSV 导出 | ✅ 含 **NUL 字节安全清洗**（避开标准 csv 模块的 `need to escape` 陷阱） |
| **镜像字节扫描** | ✅ 4 插件（flag/ascii/utf16/ioc）；流式分块；**同一份 flag 的明文/hex/base64/UTF-16LE 四种形态全部命中**并还原出明文 |
| **flag 解码** | ✅ 候选打分择优，正确处理 `666c6167…` / `ZmxhZ…` 前缀（不会产出 `flagflag{...}`） |
| **IOC 提取去噪** | ✅ 机器码噪声 `D$ Hc@<H … fQh@2Z.QQ` **零误报**；公网/私网/回环/文档段分别归类 |
| **词典扫描** | ✅ 7 本词典 34 条目全部可编译；**合并正文字节模式可处理 `(?i)` 内联标志**；file_globs 路由生效且 0 命中时说明原因 |
| **情报聚合** | ✅ 按 (类型,值) 聚合，带 sources 出处；**派生字段（hexdump 上下文）不再被二次扫描**（修掉 URL 畸形变体） |
| **时间线** | ✅ Unix/毫秒/FILETIME/ISO 归一化；CSV + Markdown 导出 |
| **报告** | ✅ Markdown 2.3–4.5K 字符 / HTML 5.5–9K 字符自包含；含指纹、IOC、公网 IP、执行情况与局限 |
| **知识库** | ✅ 10 条征象条目；按关键词与按产物两种检索均命中 |
| **GUI 接入** | ✅ 新增「④ 情报」页（来源筛选 + 严重度排序）、工具栏「情报扫描」「生成报告」、引擎下拉 3 项 |
| **回归** | ✅ **72 项全通过**（GUI/探测/表格 + 真实样本断言），0 失败；新增 `test_intel_stack.py` 37 项全通过 |

**自测脚本**（可重跑）：
```powershell
.venv\Scripts\python.exe tools\gen_samples.py            # 生成合成样本
.venv\Scripts\python.exe tools\test_static_engine.py    # 静态引擎 × 本机真实 exe
.venv\Scripts\python.exe tools\test_detector_static.py  # 检测器双向验证
.venv\Scripts\python.exe tools\test_intel_stack.py      # 情报层端到端（37 项）
.venv\Scripts\python.exe tools\regression_lite.py       # 72 项回归（含真实样本断言）
.venv\Scripts\python.exe tools\gui_smoketest.py         # GUI offscreen 冒烟
```

**真实样本来源**（均已下载到 `work/attachments/`）：

| 样本 | 出处 | 检验了什么 |
|---|---|---|
| `03d44cc4…`(15MB ELF) | solar 应急响应赛 2025-06 | ELF 解析 / memfrag |
| `dumped_4053_*.bin` | 同上（ptrace 进程内存段） | memfrag 识别（不误判 ELF） |
| `flag.solarsec.locked` | 同上 | locked 加密容器识别 |
| `TestDLL.dll` (+flag.enc) | qsnctf 512「可疑文件」 | **真实恶意样本**：检测器出案 + 权重可解释 |
| `challenge.pcap` | qsnctf 1028「Traffic Analysis」 | pcap 解析 + flag 提取 |

**尚未做**：用**真实整机内存镜像**跑完整流程（当前内存域用合成样本 + 真实进程内存段验证，
静态域与流量域已用真实样本验证）。给一个 `.raw/.mem/.dmp/.vmem` 即可补上。

---

## 5. 与同类工具的关系

本项目的设计**受行业通用范式启发**（引擎编排 + 结果治理），但**代码完全独立实现**，并且在四处做了针对性改进：

| 维度 | 常见做法 | MemLens |
|---|---|---|
| 数据组织 | 结果散落为 CSV 文件 | 统一证据模型入库，可跨插件查询 |
| 检测 | 12 条硬编码正则 / 靠人翻表 | 检测器 + 多源交叉验证 + 置信度 |
| 情报 | 手工 grep，或关键词一没有出处 | IOC 自动提取 + 7 本词典，**每条命中带 sources 出处与次数** |
| 裸字符串 | 依赖某个 strings.exe 外部工具 | 内置流式扫描，**不依赖 Volatility 与符号表**，任何容器可跑 |
| 知识 | 每人一份笔记 | 结构化「征象→结论→下一步」，**按本案产物自动推荐** |
| 报告 | 纯文本 Markdown（无表格图片） | 自包含 HTML（可打印）+ Markdown，时间线与 IOC 同源 |
| 缓存 | "文件存在且非空" | 案件隔离 + 镜像 SHA-256 + 参数指纹 |
| 插件清单 | 硬编码 60 个字符串 | 运行时枚举（180 个），上游升级不失效 |
| 平台依赖 | 需装文件系统驱动、绑死盘符 | 纯用户态，零驱动、零挂载 |

---

## 6. 扩展路线（架构已预留）

新增一个取证域 = **实现一个 `EngineAdapter` + 注册**，UI 与数据层零改动：

| 阶段 | 域 | 扩展名 | 关键库（均需装进本项目 venv） |
|---|---|---|---|
| 2 | Windows 痕迹三件套 | `.evtx` `.prefetch` `.lnk` | `dissect.eventlog` / `pyscca` / `LnkParse3` |
| 3 | 注册表 hive | `.registry` / SAM / SYSTEM / NTUSER.DAT | `dissect.regf` 或 `python-registry` |
| 4 | PE / 驱动样本 | `.exe` `.sys` 裸二进制 | `pefile` / `capstone` / `yara-python` |
| 5 | 流量包 | `.pcap` `.pcapng` | `scapy` / `dpkt` / `pyshark` |
| 6 | Linux 内存 / core | `.core` `.lime` `.dump` | Volatility3 `linux.*` + ISF 符号表 |
| 7 | 报告增强 | — | `python-docx`（当前 Markdown/HTML 已可用，docx 为可选增强） |

> 阶段 2–4 有个前提：**先让内存里的文件落地**（`dumpfiles` / `memmap`），
> 再把落盘文件丢回 MemLens 分析——这正是统一证据模型的价值：所有域共用一条流水线。

---

## 7. 已知限制（诚实清单）

1. **虚拟化容器需先解包**：`.vmsn / .sav / .vmss / .hap` 是容器格式，当前只做**识别与提醒**，不能直接分析（需先提取内存段）。
   *例外*：`memstrings` 引擎对它们仍可直接做字节扫描（见 §0）。
2. **部分内存格式只能有限分析**：`.core`（进程级转储）、`.swap/.swp`、minidump 出不了完整进程表——工具会明确提示，不会假装能出。
3. **符号表首次使用需联网**：Volatility3 解析 Windows 内核需要 ISF 符号表，首次跑某个内核版本时会自动下载（约几十 MB）。离线环境需预置符号表。`memstrings` 不需要符号。
4. **检测器目前 3 个**：隐藏进程、代码注入、静态样本研判。持久化/凭据/时间线异常的**检测**在规划中；
   但 v0.8.0 的**情报层已能覆盖**持久化位置、凭据材料、勒索特征等（以"线索"而非"判定"形式给出）。
5. **知识库目前 10 条**：覆盖最常见的征象（隐藏进程、注入、公网外联、卸载模块、自启动、凭据、PowerShell、时间戳、Linux 隐藏、内存 flag），不是穷尽式参考手册。
6. **词典内容量有限**：7 本词典 / 34 条目是常用项，不是全量 IoC 库；且字典只能覆盖**已经入库的记录**，
   没有入库的数据（如未 dump 的文件）扫不到——先用 `dumpfiles`/`memmap` 导出再回扫。
7. **性能数据未采集**：需要真实镜像（数百 MB~数 GB）才能给出"探测耗时/单插件耗时/入库吞吐"。`memstrings` 在 8 MiB 分块下流式处理，实测小文件毫秒级，大镜像未系统压测。
8. **exe 未做代码签名**：无证书，Windows SmartScreen 首次运行会提示"未知发布者"。
9. **exe 只有 GUI**：`python -m memlens.cli` 那套 CLI 在 exe 里不可用（如需要可加 `--cli` 转发分支）。
10. **未做 Windows 痕迹解析**（evtx / prefetch / lnk / 注册表 hive / MFT）：内存里 dump 出来的这类文件目前只能靠
    `memstrings` 做字符串层面的扫描，解析器尚未内置（路线图 §6 阶段 2-3）。


---

## 7. 打包成独立 exe

产物：`dist\MemLens\MemLens.exe`（4.2 MiB）+ 同目录 `_internal\`（617 文件）＝ **整包 123.9 MiB**。双击即用，目标机**无需安装 Python**。

```powershell
cd D:\MemLens          # 必须是 ASCII 路径
.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean `
    --distpath D:\MemLens\dist --workpath D:\MemLens\build `
    D:\MemLens\packaging\memlens.spec
```

**为什么是 onedir 而不是单文件**：内存分析架构是"exe 起子进程跑 Volatility3"
（见 `main.py` 的 `--vol3-entry`）。单文件模式每次子进程调用都要把整包（含 300+ MB Qt）
解压一遍，一次分析要跑几十个插件＝解压几十遍，会慢到不可用。

**打包时踩过并已修的 6 个坑**（都有代码注释指向）：

| # | 问题 | 修法 |
|---|---|---|
| 1 | **vol3 子进程失效**：冻结后 `sys.executable` 指向 exe，`exe script.py` 不成立 | `main.py` 加 `--vol3-entry` 子进程模式；`vol3.py` 检测 `sys.frozen` 改用它 |
| 2 | vol3 插件运行时动态发现，静态分析抓不到 | spec 里 `collect_all("volatility3")`；本项目 `collect_submodules("memlens")` |
| 3 | `--windowed` 下 `sys.stdout/stderr` 为 `None`，任何 print 都崩 | `main.py` 开头替换为 `os.devnull` |
| 4 | 每次调 vol3 弹控制台黑窗 | `subprocess.run(creationflags=CREATE_NO_WINDOW)` |
| 5 | `schema.sql` 打包后找不到 | `--add-data` + `_find_schema()` 多路径回退 |
| 6 | exe 放进 `Program Files` 时 `work/` 不可写 | `_resolve_workdir()` 回退到 `%LOCALAPPDATA%\MemLens\work` |

> ⚠️ **改代码后必须 `--clean` 重建**：增量构建会复用旧的 PYZ 字节码归档。
> 实测改完版本号后不带 `--clean`，exe 标题仍是旧版本号。

**精简**：PySide6 原始 632 MiB → 打进包 120 MiB。UI 只用 `QtCore/QtGui/QtWidgets`，
spec 里排除了 `QtWebEngine*`、`QtQml/QtQuick*`、`Qt3D*`、`QtMultimedia*`、`QtCharts`、
`QtSql`（用的是标准库 sqlite3）等。

**验收**（`work/verify_exe.py`，9 项）：
产物结构 ✓ / `schema.sql`·图标·vol3 目录 ✓ / QtWebEngine 已排除 ✓ /
**`MemLens.exe --vol3-entry --help` 打印 `Volatility 3 Framework 2.28.2`** ✓ /
GUI offscreen 存活 18s ✓

**端到端实测**：`MemLens.exe --vol3-entry -f samples\synthetic_windows.raw banners`
→ rc=0 且输出 `Updating caches for 110 files`（110 个 vol3 插件文件确实被读取执行）。

---

## 8. 开发约定（给自己和协作者的规矩）

1. 引擎调用一律 `shell=False` + 参数数组；
2. 插件清单**运行时枚举**，禁止硬编码插件名；
3. 结果一律**结构化解析**（jsonl），禁止解析人类可读表格取数；
4. **失败要向上报**：`returncode != 0`、解析失败、0 行都要有明确状态，不许静默返回空；
5. 二进制内容进 CSV 必须转义（见 `storage/db.py::export_records_csv`）；
6. 所有耗时操作放工作线程，UI 只做信号回填。
