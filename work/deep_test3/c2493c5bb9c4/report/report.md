# 内存取证分析报告 · vol_easy.vmem

> 由 MemLens 自动生成于 2026-10-29 10:39:16

## 一、案件基本信息

| 项 | 值 |
|---|---|
| 案件 ID | c2493c5bb9c4 |
| 名称 | vol_easy.vmem |
| 证据文件 | `E:\vol_easy.vmem` |
| 文件大小 | 2,147,483,648 字节 |
| SHA-256 | `8b06551a860d0fab94a9f54414422103f022fa5a2606df4ac43204c439defdd4` |
| 容器类型 | vmem |
| 操作系统 | windows（置信度 0.48） |
| 建案时间 | 2026-10-29T10:04:17 |
| 产物数 / 记录数 / 发现项 | 110 / 1043655 / 57 |

## 二、发现项

| 严重度 | 置信度 | 标题 | 说明 |
|---|---|---|---|
| 高危 | 98% | 疑似代码注入：AntSword.exe（PID 1716，共 4 处可疑页） | malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。 |
| 高危 | 98% | 疑似代码注入：iexplore.exe（PID 1016，共 6 处可疑页） | malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。 |
| 高危 | 98% | 疑似代码注入：iexplore.exe（PID 1260，共 4 处可疑页） | malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。 |
| 高危 | 98% | 疑似代码注入：iexplore.exe（PID 1928，共 6 处可疑页） | malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。 |
| 高危 | 93% | 疑似代码注入：mmc.exe（PID 2992，共 2 处可疑页） | malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。 |
| 高危 | 93% | 疑似隐藏进程：AntSword.exe（PID 1432） | 该进程结构体存在于内存池中，但未出现在活动进程链表遍历结果里，符合「进程被摘链隐藏」的特征。注意：也可能是刚退出、内存尚未回收的进程残留，请结合命令行、网络连接与时间线复核。 |
| 高危 | 82% | 异常内存：AntSword.exe（PID 1456） — HIGH_ENTROPY | MemProcFS 异常检测在这些进程的内存里发现了非镜像页/高熵可执行段，常见于进程注入、加壳木马与内存马。需要用 memlens.dump_process 把该进程内存导出来做字符串与静态分析。 |
| 高危 | 82% | 异常内存：sppsvc.exe（PID 2000） — HIGH_ENTROPY | MemProcFS 异常检测在这些进程的内存里发现了非镜像页/高熵可执行段，常见于进程注入、加壳木马与内存马。需要用 memlens.dump_process 把该进程内存导出来做字符串与静态分析。 |
| 高危 | 73% | 可疑进程：AntSword.exe（PID 1456） | 进程名/命令行命中已知工具特征。 |
| 高危 | 73% | 可疑进程：AntSword.exe（PID 1716） | 进程名/命令行命中已知工具特征。 |
| 高危 | 73% | 可疑进程：AntSword.exe（PID 1952） | 进程名/命令行命中已知工具特征。 |
| 高危 | 73% | 可疑进程：AntSword.exe（PID 260） | 进程名/命令行命中已知工具特征。 |
| 高危 | 73% | 可疑进程：notepad.exe（PID 2232） | 从用户可写目录（Temp/AppData/公开目录）运行。 |
| 中危 | 90% | 注册表配置单元已收获（12 个可解凭据的 hive） | 内存里抓到了 SAM/SYSTEM/SECURITY（或用户 NTUSER）配置单元。用它们可以离线导出本地账户口令哈希 / LSA 机密 / 最近访问痕迹 —— 这是 CTF 内存取证与应急响应里最常出分的环节。 MemLens 已把它们复制到会话目录的 harvest/registry_hives/ 下。 |
| 中危 | 71% | 疑似代码注入：explorer.exe（PID 1656，共 4 处可疑页） | malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。 |
| 中危 | 60% | 已卸载模块：cryptsp.dll（进程 lsm.exe / PID 460） | 模块已从加载链卸载但内存痕迹还在，常见于无文件加载、反射式 DLL 注入。 |
| 中危 | 60% | 已卸载模块：cryptsp.dll（进程 msdtc.exe / PID 496） | 模块已从加载链卸载但内存痕迹还在，常见于无文件加载、反射式 DLL 注入。 |
| 低危 | 45% | 非系统目录的驱动/服务：ACPI | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：AFD | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：CLFS | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：CNG | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：Compbatt | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：DfsC | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：Disk | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：FltMgr | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：HTTP | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：KSecDD | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：KSecPkg | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：LSI_SAS | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：Msfs | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：Mup | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：NDIS | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：NetBIOS | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：NetBT | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：Npfs | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：Null | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：amdxata | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：atapi | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：blbdrive | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：bowser | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：cdrom | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：discache | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：hwpolicy | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：intelide | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：lltdio | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：luafv | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：mountmgr | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：mpsdrv | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：mrxsmb | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：mrxsmb10 | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：mrxsmb20 | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：msahci | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：msisadrv | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：mssmbios | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：nsiproxy | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：partmgr | 服务可执行体不在系统目录，建议核对数字签名与来源。 |
| 低危 | 45% | 非系统目录的驱动/服务：pci | 服务可执行体不在系统目录，建议核对数字签名与来源。 |

### 疑似代码注入：AntSword.exe（PID 1716，共 4 处可疑页）

- **严重度**：高危
- **置信度**：98%
- **证据源**：malfind, dlllist, netscan
- **说明**：malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。

### 疑似代码注入：iexplore.exe（PID 1016，共 6 处可疑页）

- **严重度**：高危
- **置信度**：98%
- **证据源**：malfind, dlllist, netscan
- **说明**：malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。

### 疑似代码注入：iexplore.exe（PID 1260，共 4 处可疑页）

- **严重度**：高危
- **置信度**：98%
- **证据源**：malfind, dlllist, netscan
- **说明**：malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。

### 疑似代码注入：iexplore.exe（PID 1928，共 6 处可疑页）

- **严重度**：高危
- **置信度**：98%
- **证据源**：malfind, dlllist, netscan
- **说明**：malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。

### 疑似代码注入：mmc.exe（PID 2992，共 2 处可疑页）

- **严重度**：高危
- **置信度**：93%
- **证据源**：malfind, dlllist, netscan
- **说明**：malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。

### 疑似隐藏进程：AntSword.exe（PID 1432）

- **严重度**：高危
- **置信度**：93%
- **证据源**：psscan, pslist, netscan, psxview
- **说明**：该进程结构体存在于内存池中，但未出现在活动进程链表遍历结果里，符合「进程被摘链隐藏」的特征。注意：也可能是刚退出、内存尚未回收的进程残留，请结合命令行、网络连接与时间线复核。

### 异常内存：AntSword.exe（PID 1456） — HIGH_ENTROPY

- **严重度**：高危
- **置信度**：82%
- **证据源**：mprocfs.findevil
- **说明**：MemProcFS 异常检测在这些进程的内存里发现了非镜像页/高熵可执行段，常见于进程注入、加壳木马与内存马。需要用 memlens.dump_process 把该进程内存导出来做字符串与静态分析。

### 异常内存：sppsvc.exe（PID 2000） — HIGH_ENTROPY

- **严重度**：高危
- **置信度**：82%
- **证据源**：mprocfs.findevil
- **说明**：MemProcFS 异常检测在这些进程的内存里发现了非镜像页/高熵可执行段，常见于进程注入、加壳木马与内存马。需要用 memlens.dump_process 把该进程内存导出来做字符串与静态分析。

### 可疑进程：AntSword.exe（PID 1456）

- **严重度**：高危
- **置信度**：73%
- **证据源**：mprocfs.process
- **说明**：进程名/命令行命中已知工具特征。

### 可疑进程：AntSword.exe（PID 1716）

- **严重度**：高危
- **置信度**：73%
- **证据源**：mprocfs.process
- **说明**：进程名/命令行命中已知工具特征。

### 可疑进程：AntSword.exe（PID 1952）

- **严重度**：高危
- **置信度**：73%
- **证据源**：mprocfs.process
- **说明**：进程名/命令行命中已知工具特征。

### 可疑进程：AntSword.exe（PID 260）

- **严重度**：高危
- **置信度**：73%
- **证据源**：mprocfs.process
- **说明**：进程名/命令行命中已知工具特征。


## 三、情报指标（IOC）

| 类型 | 数量 | 示例 |
|---|---|---|
| registry_key | 4806 | `HKLM\SOFTWARE\Classes\Interface\`, `HKLM\SOFTWARE\Classes\Wow6432Node\Interface\`, `HKLM\SOFTWARE\Classes\CLSID\` |
| url | 148 | `https://msdl.microsoft.com/download/symbols/ntdll.pdb/6192BFDB9F04442995FFCB0BE95172E12/ntdll.pdb`, `https://msdl.microsoft.com/download/symbols/kernelbase.pdb/FF31C2F3216C4621A7F009584AC0D68F2/kernelbase.pdb`, `https://msdl.microsoft.com/download/symbols/rpcrt4.pdb/7D748DA6D7454C9EA38C8CEF1C9E75F22/rpcrt4.pdb` |
| bitcoin | 21 | `173DAEF86B2548DBA6134EB74C4D2F23`, `173DAEF86B2548DBA6134EB74C4D2F232`, `1F9BBFCBF7A9451B89A51771CA4C47DB` |
| domain | 16 | `msdl.microsoft.com`, `System.IO`, `www.microsoft.com` |
| ipv4 | 9 | `6.1.0.0`, `8.0.0.0`, `6.0.0.0` |

**公网 IP（优先核查出网行为）**

| IP | 出现次数 | 来源插件 |
|---|---|---|
| `6.1.0.0` | 512 | mprocfs.timeline_registry×256, mprocfs.timeline_all×256 |
| `8.0.0.0` | 106 | mprocfs.timeline_registry×53, mprocfs.timeline_all×53 |
| `6.0.0.0` | 16 | mprocfs.timeline_registry×8, mprocfs.timeline_all×8 |
| `7.0.0.0` | 11 | mprocfs.modules×11 |
| `192.228.79.201` | 5 | windows.netscan.NetScan×5 |
| `2.5.29.32` | 4 | mprocfs.timeline_registry×2, mprocfs.timeline_all×2 |


## 四、词典命中

| 词典 | 条目 | 命中值 | 次数 | 处置建议 |
|---|---|---|---|---|
| 敏感端口 | 默认远程管理端口 | `23` | 32 | 核对发起方 IP 与进程；外网直连 3389/445 需立即处置 |
| 持久化位置 | 注册表自启动项 | `CurrentVersion\Run` | 7 | 逐项取出指向的可执行文件路径，判断是否异常；IFEO Debugger 是经典持久化 |
| 持久化位置 | 注册表自启动项 | `CurrentVersion\RunOnce` | 4 | 逐项取出指向的可执行文件路径，判断是否异常；IFEO Debugger 是经典持久化 |
| Web 攻击与后门 | WebShell 落地痕迹 | `antsword` | 5 | 定位 Web 根目录并全量查同名/同特征文件 |
| Web 攻击与后门 | WebShell 落地痕迹 | `behinder` | 4 | 定位 Web 根目录并全量查同名/同特征文件 |

## 五、事件时间线

| 时间 | 来源 | 事件 |
|---|---|---|
| 2009-06-10 20:30:41 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:30:42 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:30:43 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:30:50 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:30:52 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:31:00 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:31:01 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:31:08 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:31:11 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:31:15 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:31:31 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:31:36 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:33:59 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:34:15 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:34:23 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:34:28 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:34:33 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:34:37 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:34:48 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:35:09 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:35:18 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:35:23 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:35:30 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:35:36 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:36:23 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:36:24 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:36:45 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:36:49 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:37:14 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:37:19 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:37:35 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:37:36 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:37:40 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:37:58 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:38:02 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:38:27 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:38:51 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:38:56 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:38:57 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:39:10 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:39:26 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:39:32 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:39:34 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:40:38 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:42:03 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:43:13 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:43:14 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:43:16 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:43:20 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:43:38 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:43:46 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:43:47 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:43:51 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:44:02 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:44:03 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:44:04 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:44:05 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:44:06 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:44:08 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:44:10 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:44:13 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:44:29 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:44:35 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:44:36 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:45:28 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:46:20 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:46:43 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:47:05 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:47:07 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:47:08 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:47:09 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:47:25 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:47:40 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:47:41 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:47:57 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:47:59 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:48:43 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:49:20 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:49:41 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:49:45 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:49:50 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:49:51 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:51:25 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:51:48 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:51:58 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:52:01 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:52:46 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:53:31 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:53:32 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:53:48 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:53:53 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:56:53 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:57:11 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:57:32 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:58:19 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:58:34 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:59:12 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:59:13 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:59:19 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:59:55 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 20:59:56 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:00:03 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:00:14 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:00:23 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:00:26 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:00:28 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:00:40 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:00:54 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:01:01 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:01:05 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:01:06 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:01:15 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:01:18 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:01:22 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:01:24 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:01:25 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:01:37 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:01:39 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:01:55 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| 2009-06-10 21:02:23 | `mprocfs.timeline_ntfs` | [mprocfs.timeline_ntfs] 记录 |
| … | | 另有 4880 条（见 CSV 导出） |


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

## 七、执行情况与局限

- 共执行 110 项，成功 81 项，异常 29 项。

| 引擎 | 插件 | 状态 | 说明 |
|---|---|---|---|
| memprocfs | `mprocfs.netdns` | partial | 未解析出任何记录（该产物为空，或镜像里没有对应数据） |
| memprocfs | `mprocfs.yara` | partial | 未解析出任何记录（该产物为空，或镜像里没有对应数据） |
| memprocfs | `mprocfs.registry_run` | partial | 未解析出任何记录（该产物为空，或镜像里没有对应数据） |
| memprocfs | `mprocfs.virtualmachines` | partial | 未解析出任何记录（该产物为空，或镜像里没有对应数据） |
| memprocfs | `mprocfs.timeline_web` | partial | 未解析出任何记录（该产物为空，或镜像里没有对应数据） |
| vol3 | `windows.hollowprocesses.HollowProcesses` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.svclist.SvcList` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.svcdiff.SvcDiff` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.crashinfo.Crashinfo` | failed | 引擎返回码 1；stderr 末尾：ite-packages\volatility3\cli\__init__.py", line 942, in main     CommandLine().run()   File "D:\MemLens\.venv\Lib\site-packages\volatility3\cl |
| vol3 | `windows.consoles.Consoles` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.strings.Strings` | failed | 引擎返回码 2；stderr 末尾：usage: _vol3_entry.py windows.strings.Strings [-h] [--pid [PID ...]]                                               --strings-file STRINGS_FILE |
| vol3 | `windows.amcache.Amcache` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.cmdscan.CmdScan` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.debugregisters.DebugRegisters` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.deskscan.DeskScan` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.desktops.Desktops` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.etwpatch.EtwPatch` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.malware.hollowprocesses.HollowProcesses` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.malware.processghosting.ProcessGhosting` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.malware.suspicious_threads.SuspiciousThreads` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.malware.svcdiff.SvcDiff` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.orphan_kernel_threads.Threads` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.pe_symbols.PESymbols` | failed | 引擎返回码 2；stderr 末尾：                                               {kernel,processes} --module                                                    MODULE           |
| vol3 | `windows.pedump.PEDump` | failed | 引擎返回码 2；stderr 末尾：usage: _vol3_entry.py windows.pedump.PEDump [-h] [--pid [PID ...]] --base BASE                                             [--kernel-module] _ |
| vol3 | `windows.registry.amcache.Amcache` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.truecrypt.Passphrase` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.virtmap.VirtMap` | failed | 引擎返回码 1；stderr 末尾：r  Progress:   41.02		Scanning layer_name using PdbSignatureScanner  Progress:  100.00		PDB scanning finished                         Volatili |
| vol3 | `windows.windows.Windows` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |
| vol3 | `windows.windowstations.WindowStations` | partial | 引擎执行成功但未解析出任何记录（可能镜像不含该数据结构） |

> 上表中的失败项意味着**相应结论缺乏证据支撑**，请勿当作「已排除」。

### 复现信息

每个产物的原始命令行都完整留存在数据库 `artifacts.argv_json`，原始输出落盘于 `work/artifacts/` 且记录了 SHA-256，可逐条复现与校验。
