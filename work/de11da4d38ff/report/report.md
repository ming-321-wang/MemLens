# 内存取证分析报告 · base-test

> 由 MemLens 自动生成于 2026-11-13 21:55:38

## 一、案件基本信息

| 项 | 值 |
|---|---|
| 案件 ID | de11da4d38ff |
| 名称 | base-test |
| 证据文件 | `D:\MemLens\samples\synthetic_windows.raw` |
| 文件大小 | 8,388,608 字节 |
| SHA-256 | `144d8d52d7b1e7223699b4aad0ce650ebd631ac9b2054df9a04c734656141716` |
| 容器类型 | raw |
| 操作系统 | windows（置信度 0.98） |
| 建案时间 | 2026-11-13T21:54:38 |
| 产物数 / 记录数 / 发现项 | 108 / 812 / 0 |
| **规则包版本** | —（发布 —，SHA-256 ``） |
| **时间基准** | 协调世界时（UTC）存储；报告按记录的原时区偏移还原本地时间 |

## 二、发现项

_本次分析未产生发现项。_

## 三、情报指标（IOC）

| 类型 | 数量 | 示例 |
|---|---|---|
| domain | 1 | `vr.cO` |
| windows_path | 1 | `H:\tUL` |


## 四、词典命中

_无高危及以上命中。_

## 五、事件时间线

_本次分析未提取到带时间戳的记录。_


## 六、相关取证要点

> 以下条目依据本次实际运行的插件自动匹配，用于提示下一步核查方向。

**psscan 有、pslist 无：进程可能被隐藏**

- 征象：psscan 能扫到某 PID，但 pslist（活动 EPROCESS 链）里没有它；或反之（pslist 有而 psscan 扫不到）。
- 结论：双向差集都指向 DKOM（Direct Kernel Object Manipulation）：攻击者从活动链表里摘掉了进程，但对象还在池里；反向差集更多是残留对象或扫描窗口期问题。
- 下一步：跑 psxview 做多源交叉，确认隐藏性质；看该 PID 是否仍有句柄、模块或网络连接（有则进程仍存活）；检查 SSDT / callbacks / driverirp 是否有可疑钩子；对该 PID 做 memdump，看内部线程与模块
- 注意：仅差集不足以定案：进程正常退出时也可能只在一侧出现，必须靠 psxview 或句柄佐证。

**malfind 报出私有 RWX 区域且含 PE 头**

- 征象：malfind 发现 Private 的 RWX 页，Disassembly/PAGE 属性异常，Region 常以 MZ/PE 或可执行代码开头。
- 结论：高度怀疑进程内存在注入的代码（线程劫持、反射加载或 payload 落地）。
- 下一步：看 mdll 分布：正常进程的 RWX 页不应出现可执行节区；对照 ldrmodules，注入代码往往不在模块加载链里；看 threads 是否有起止异常的线程；对该 PID 做 memdump 并提取其中字符串（cmdline/URL/flag）
- 注意：JIT、浏览器、.NET 运行时会产生合法 RWX 区；必须结合「不在模块链里」这一点才能定性。

**存在公网 IP 的外联连接**

- 征象：netscan/netstat 中出现 scope=公网 的远端地址，且连接状态非 LISTEN。
- 结论：该机器曾主动向外通信，可能是 C2 回连、漏洞利用或数据外传。
- 下一步：按 PID 关联出进程，拿到 cmdline 判断是什么程序发起；把该 IP 与情报词典/威胁库比对；看是否有大量周期性短连接（典型 beacon 心跳）；查对应时间点的 DNS 记录，确认是否域名解析后直连
- 注意：浏览器、系统更新、Defender 云查杀都会产生公网外联，务必先看发起进程再下结论。

**已卸载模块/驱动里有可疑文件**

- 征象：unloadedmodules 或 modscan 出现路径在临时目录、用户可写目录的模块。
- 结论：动态加载后又卸载是隐藏手法；路径可写意味着攻击者已经取得落地能力。
- 下一步：核对该路径是否在 %TEMP% / %APPDATA% / C:\Users 下；在文件对象里找同名残留（filescan）；检查对应驱动的 IRP 表（driverirp）是否被钩

**注册表 Run 键指向非常规路径**

- 征象：printkey / registry.* 里 CurrentVersion\Run 的值指向 %TEMP%、用户目录，或指向非预期可执行文件。
- 结论：自启动持久化，且程序路径可写——说明攻击者已有落地文件。
- 下一步：取出目标文件路径与创建时间；确认是哪个用户的 hive（HKU\S-1-5-21-...）；在 filescan 里找该文件是否还在内存中；同时检查 RunOnce / Winlogon\Userinit / AppInit_DLLs / IFEO

**存在凭据材料（SAM/LSA/域缓存）**

- 征象：lsadump / hashdump / cachedump 产出了非空结果，或发现 mimikatz 痕迹。
- 结论：系统内存在可被直接利用的凭据材料；若有 mimikatz 痕迹则已被导出。
- 下一步：确认工具是否还在运行、是否有落盘副本；检查是否有对应的横向连接（445/3389/5985）；评估受影响账号范围并走应急轮换流程
- 注意：报告与导出物都应按敏感信息处理，不要把明文凭据写进公开报告。

**Linux：进程在 /proc 有残留但不在 task 链表**

- 征象：linux.pslist 缺进程，但 bash / proc / elfs 插件仍能取到其痕迹。
- 结论：Linux 侧的进程隐藏（内核模块摘链或用户态挂载伪造）。
- 下一步：跑 linux.check_modules / linux.check_ftrace 等内核完整性插件；检查是否有自定义内核模块；核对 mounts 与真实根文件系统是否一致

**镜像里直接存在 flag**

- 征象：memstrings.flag 命中，decoded 列给出明文。
- 结论：题目把答案放在内存里，通常藏在进程环境变量、命令行、剪贴板或文件内容中。
- 下一步：按 offset 反查落在哪个进程/区域；用 hit 的偏移去 windows.memmap 定位来源；若为 UTF-16LE 命中，说明是宽字符 API（注册表/路径）写入的

## 七、缺口清单

_本次分析未记录数据源缺口（所有计划内产物均已执行）。_

## 八、执行情况与局限

- 共执行 108 项，成功 3 项，异常 105 项。

| 引擎 | 插件 | 状态 | 说明 |
|---|---|---|---|
| memprocfs | `mprocfs.harvest` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.bitlocker` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.cmdlines` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.devices` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.drivers` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.envs` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.eventlog` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.files` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.findevil` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.flag_hits` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.handles` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.modules` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.net` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.netdns` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.process` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.procinfo` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.productid` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.registry_hives` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.registry_run` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.services` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.sysinfo` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.threads` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.timeline_all` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.timeline_kernelobject` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.timeline_net` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.timeline_ntfs` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.timeline_process` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.timeline_registry` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.timeline_thread` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.timeline_web` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.unloaded_modules` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.users` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.virtualmachines` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| memprocfs | `mprocfs.yara` | failed | 解析失败：MemProcFS 提前退出（返回码 1）：DEVICE OPEN: file \| DEVICE: ERROR: Failed opening file: 'D:\MemLens\samples\synthetic_windows.raw'. \| MemProcFS: Failed to connect  |
| vol3 | `windows.modules.Modules` | failed | 引擎返回码 1；stderr 末尾：ng FileLayer using PageMapScanner  Progress:   23.33		Scanning FileLayer using PageMapScanner  Progress:    0.00		Scanning FileLayer using Pag |
| vol3 | `windows.modscan.ModScan` | failed | 引擎返回码 1；stderr 末尾：ng FileLayer using PageMapScanner  Progress:   23.33		Scanning FileLayer using PageMapScanner  Progress:    0.00		Scanning FileLayer using Pag |
| vol3 | `windows.pslist.PsList` | failed | 引擎返回码 1；stderr 末尾：ning FileLayer using PageMapScanner  Progress:   23.33		Scanning FileLayer using PageMapScanner  Progress:    0.00		Scanning FileLayer using P |
| vol3 | `windows.psscan.PsScan` | failed | 引擎返回码 1；stderr 末尾：ning FileLayer using PageMapScanner  Progress:   23.33		Scanning FileLayer using PageMapScanner  Progress:    0.00		Scanning FileLayer using P |
| vol3 | `windows.pstree.PsTree` | failed | 引擎返回码 1；stderr 末尾：ning FileLayer using PageMapScanner  Progress:   23.33		Scanning FileLayer using PageMapScanner  Progress:    0.00		Scanning FileLayer using P |
| vol3 | `windows.netscan.NetScan` | failed | 引擎返回码 1；stderr 末尾：ng FileLayer using PageMapScanner  Progress:   23.33		Scanning FileLayer using PageMapScanner  Progress:    0.00		Scanning FileLayer using Pag |

> 上表中的失败项意味着**相应结论缺乏证据支撑**，请勿当作「已排除」。

### 复现信息

每个产物的原始命令行都完整留存在数据库 `artifacts.argv_json`，原始输出落盘于 `work/artifacts/` 且记录了 SHA-256，可逐条复现与校验。

### 免责与证明边界

1. 主机侧未发现痕迹，不等于未使用；路由级或虚拟机内代理不可见。
2. 单机采集的结论等级存在上限，上限已在前文标注。
3. 本报告不建议作为司法鉴定结论使用，如需鉴定请另行委托具备资质的机构。
