r"""
MemLens · 内置词典

**内容为本项目独立编写**，参考的是公开的取证/应急通用知识，而非任何第三方词库文件。

设计取舍：
  * 每个条目都写清 `note`（这是什么）与 `advice`（命中后该做什么）——
    没有处置建议的关键词命中等于噪声，使用者根本不知道下一步；
  * 用 `file_globs` 做路由：敏感端口只喂给 netscan/netstat/pcap，
    敏感程序只喂给 pslist/cmdline/services，避免在无关产物上做全量 grep；
  * 注册表路径条目一律 `whole_word=False`（词边界对含 `\` 的模式必然失效）。
"""

from __future__ import annotations

from memlens.intel.dictionary import Dictionary, Entry

# 常见插件名（用于 file_globs 路由）
#
# ⚠ memstrings.* 必须一并路由进来：镜像里的裸字符串正是"进程名 / 命令行 /
#   可疑路径"最常见的出处，把它排除在外，等于让敏感程序词典在最该生效的地方失效。
_PROC_GLOBS = ("*pslist*", "*psscan*", "*pstree*", "*psaux*", "*cmdline*",
               "*dlllist*", "*services*", "*svclist*", "*svcscan*",
               "*modules*", "*ldrmodules*", "*handles*", "*threads*",
               "*envars*", "*consoles*", "*cmd*", "*process*",
               "memstrings.*", "*strings*")
_NET_GLOBS = ("*netscan*", "*netstat*", "*net*", "*pcap*", "*sockets*", "*connections*")


# ==================================================================== CTF / 夺旗
CTF = Dictionary(
    id="ctf",
    name="CTF 夺旗",
    description="Flag 的各种编码形态与解题常见痕迹。命中即高价值线索。",
    builtin=True,
    entries=[
        Entry(
            name="Flag 明文", severity="critical",
            patterns=[r"flag\{[^\}\r\n]{1,300}\}", r"ctf\{[^\}\r\n]{1,300}\}",
                      r"key\{[^\}\r\n]{1,300}\}", r"flag[:=][^\s\"',;]{4,120}"],
            note="最常见的 flag 形态，形如 flag{...}",
            advice="直接作为答案提交；记入报告的结论区",
            tags=["flag", "答案"],
        ),
        Entry(
            name="Flag 十六进制编码", severity="critical",
            patterns=[r"666c6167[0-9a-fA-F]{6,300}", r"\\x66\\x6c\\x61\\x67[0-9a-fA-F]{6,300}"],
            note="'flag' 四字节的十六进制（66 6c 61 67）",
            advice="从 hex 串右起按 2 字符解码，即可还原 flag 明文",
            tags=["flag", "编码", "hex"],
        ),
        Entry(
            name="Flag Base64 编码", severity="critical",
            patterns=[r"ZmxhZ[A-Za-z0-9+/=]{6,300}"],
            note="'flag' 的 Base64 编码（ZmxhZ）",
            advice="对命中串做 Base64 解码；memstrings.flag 插件会直接给出解码结果",
            tags=["flag", "编码", "base64"],
        ),
        Entry(
            name="疑似 Base64 长串", severity="low",
            # ⚠ 这里刻意**不用** `[A-Za-z0-9+/]{12,}` 这种宽泛写法。
            #   那样会把 AKIAIOSFODNN7EXAMPLE、CurrentVersion、exeTeamViewer
            #   全判成命中——实测踩过，噪声一大，整本词典就没人信了。
            #   改为要求：长度 4 的倍数 + 至少含一个大写、小写、数字三类中的两类。
            patterns=[r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])"],
            note="较长且形似 Base64 的串，未匹配已知 flag 前缀",
            advice="尝试解码；能解出可读文本才有意义，否则多半是普通标识符",
            tags=["编码", "base64", "候选"],
        ),
        Entry(
            name="Flag URL / HTML 编码", severity="high",
            patterns=[r"f%6[cC]%61%67", r"&#102;?\s*l?a?g?\{", r"&#[0-9]{2,3};?"],
            note="'flag' 的 URL 百分号编码与 HTML 实体编码",
            advice="URL 解码 / HTML 实体解码后重搜 flag",
            tags=["flag", "编码"],
        ),
        Entry(
            name="通用花括号令牌", severity="medium",
            patterns=[r"\b[A-Za-z0-9_\-]{2,12}\{[A-Za-z0-9_\-+/=]{10,200}\}"],
            note="形如 xxx{...} 的令牌，未匹配已知 flag 前缀",
            advice="CTF 有时自定义前缀；结合上下文的文件名与进程名判断",
            tags=["flag", "候选"],
        ),
        Entry(
            name="解题痕迹", severity="low",
            patterns=[r"\bnc\s+-?[a-z]*\s*[lv]\s*-?\d", r"/bin/(?:sh|bash)\b.{0,40}cat\s+/flag",
                      r"docker\s+run\b.{0,60}challenge", r"ropper|ROPgadget|pwntools"],
            note="解题者在镜像/样本里留下的操作痕迹",
            advice="常能反推题目原本的利用方式",
            tags=["痕迹"],
        ),
    ],
)


# ==================================================================== 远控/工具
SUSPICIOUS_PROCESS = Dictionary(
    id="suspicious_process",
    name="敏感程序",
    description="远控、凭据窃取、横向移动、扫描与破解类程序。命中不等于恶意，需结合路径与签名。",
    builtin=True,
    file_globs=_PROC_GLOBS,
    entries=[
        Entry(
            name="远控软件", severity="high",
            patterns=["TeamViewer.exe", "AnyDesk.exe", "Ammyy.exe", "SunloginClient.exe",
                      "ToDesk.exe", "RustDesk.exe", "向日葵.exe", "Parsec.exe",
                      "VNC Server.exe", "TightVNC.exe", "Splashtop.exe", "ScreenConnect.exe"],
            note="商业远控软件；企业环境合法，但出现在服务器/取证机上是重点",
            advice="核对安装时间、服务项与外联记录，确认是否未授权",
            tags=["远控", "C2"],
        ),
        Entry(
            name="凭据与哈希工具", severity="critical",
            patterns=["mimikatz.exe", "sekurlsa::logonpasswords", "lsadump.exe", "procdump.exe",
                      "psexec.exe", "wce.exe", "hashcat.exe", "john.exe", "ophcrack.exe",
                      "LaZagne.exe", "BrowserPass.exe", "SharpDPAPI.exe"],
            note="凭据导出与离线破解工具，入侵后的典型痕迹",
            advice="重点看是谁在什么时间运行的；关联其后续网络活动",
            tags=["凭据", "横向"],
        ),
        Entry(
            name="扫描与后渗透", severity="high",
            patterns=["nmap.exe", "mimikatz", "cobaltstrike", "beacon.exe", "npscan",
                      "netscan.exe", "advanced_ip_scanner", "BloodHound.exe", "AdFind.exe"],
            note="攻击者常用的侦察与 C2 工具",
            advice="结合内存中的 beacon 配置定位 C2 地址",
            tags=["后渗透"],
        ),
        Entry(
            name="PowerShell 可疑用法", severity="high",
            patterns=[r"powershell[^\n]{0,40}-[eE]nc(odedcommand)?\b",
                      r"powershell[^\n]{0,40}-[eE]xec\s+bypass",
                      r"\-[eE]xecutionpolicy\s+bypass",
                      r"powershell[^\n]{0,60}\bnop\b",
                      r"IEX\s*\(\s*(New-Object|iwr|Invoke-WebRequest)",
                      r"FromBase64String", r"DownloadString", r"DownloadFile",
                      r"Reflection\.Assembly", r"VirtualAlloc", r"Set-MpPreference"],
            note="PowerShell 混淆 / 内存加载 / 关闭防护",
            advice="这是经典免杀手法，直接判高危；解出 -enc 的 base64 看真实命令",
            tags=["powershell", "免杀"],
        ),
        Entry(
            name="安全软件与关闭防护", severity="medium",
            patterns=["MsMpEng.exe", "avp.exe", "avgui.exe", "360tray.exe",
                      r"netsh\s+firewall\s+set", r"sc\s+stop\s+\w+", r"bcdedit.{0,40}recoveryenabled\s+no"],
            note="安全进程本身正常；这里关注的是'关闭防护'类命令",
            advice="命令行为比进程名单更值得关注",
            tags=["防护"],
        ),
        Entry(
            name="批量执行痕迹", severity="medium",
            patterns=[r"for\s+/[fFiI]\s+", r"wmic\s+process\s+call\s+create",
                      r"schtasks\s+/create", r"reg\s+add\s+", r"certutil\s+-urlcache"],
            note="一次性批量拉起/落盘/建任务的典型命令",
            advice="按命令反查落盘路径与下载 URL",
            tags=["执行", "批处理"],
        ),
    ],
)


# ==================================================================== 敏感端口
SUSPICIOUS_PORT = Dictionary(
    id="suspicious_port",
    name="敏感端口",
    description="非常规或具备横向移动/回连含义的端口。只扫网络相关产物。",
    builtin=True,
    file_globs=_NET_GLOBS,
    entries=[
        Entry(
            name="默认远程管理端口", severity="high",
            patterns=[r"\b22\b", r"\b23\b", r"\b3389\b", r"\b5900\b", r"\b5985\b", r"\b445\b"],
            note="SSH / Telnet / RDP / VNC / WinRM / SMB",
            advice="核对发起方 IP 与进程；外网直连 3389/445 需立即处置",
            tags=["横向", "远控"],
        ),
        Entry(
            name="常见 C2 / 后门端口", severity="critical",
            patterns=[r"\b4444\b", r"\b5555\b", r"\b12345\b", r"\b8888\b",
                      r"\b9001\b", r"\b6666\b", r"\b31337\b", r"\b1234\b"],
            note="Metasploit 默认 4444、经典后门高位端口等",
            advice="命中的连接若为出站，优先按此追 C2",
            tags=["C2"],
        ),
        Entry(
            name="数据库与中间件", severity="medium",
            patterns=[r"\b3306\b", r"\b5432\b", r"\b1433\b", r"\b1521\b", r"\b27017\b",
                      r"\b6379\b", r"\b9200\b", r"\b11211\b"],
            note="MySQL / PostgreSQL / SQLServer / Oracle / MongoDB / Redis / ES / Memcached",
            advice="6379、11211、27017 无认证暴露属高危",
            tags=["数据", "未授权"],
        ),
        Entry(
            name="明文协议端口", severity="medium",
            patterns=[r"\b21\b", r"\b23\b", r"\b25\b", r"\b80\b", r"\b110\b", r"\b143\b",
                      r"\b161\b", r"\b389\b", r"\b636\b", r"\b2049\b"],
            note="FTP / Telnet / SMTP / HTTP / POP3 / IMAP / SNMP / LDAP / LDAPS / NFS",
            advice="明文传输的凭据可被直接嗅探",
            tags=["明文"],
        ),
    ],
)


# ==================================================================== 持久化
PERSISTENCE = Dictionary(
    id="persistence",
    name="持久化位置",
    description="开机自启、服务、计划任务、驱动加载等持久化落点。内存域与静态域通用。",
    builtin=True,
    entries=[
        Entry(
            name="注册表自启动项", severity="high",
            patterns=[r"CurrentVersion\\Run(Once)?\b", r"CurrentVersion\\RunServices\b",
                      r"Winlogon\\Userinit\b", r"Winlogon\\Shell\b", r"AppInit_DLLs\b",
                      r"CurrentVersion\\Explorer\\Shell Folders\\Startup",
                      r"CurrentVersion\\Explorer\\User Shell Folders\\Startup",
                      r"Image File Execution Options\\[^\\]+\\Debugger"],
            note="Run / RunOnce / Winlogon / AppInit_DLLs / 启动文件夹 / IFEO 劫持",
            advice="逐项取出指向的可执行文件路径，判断是否异常；IFEO Debugger 是经典持久化",
            tags=["自启", "劫持"],
        ),
        Entry(
            name="WMI 事件订阅持久化", severity="high",
            patterns=[r"Win32_ProcessStartupCommand", r"__EventFilter", r"CommandLineEventConsumer",
                      r"__EventConsumer", r"ActiveScriptEventConsumer", r"ExecQuery\s*\(\s*\"select"],
            note="WMI 事件订阅型无文件持久化，单纯查 Run 查不到",
            advice="对比 FilterToConsumerBinding 与实际命令行",
            tags=["无文件"],
        ),
        Entry(
            name="计划任务", severity="medium",
            patterns=[r"\\Tasks\\", r"schtasks", r"Schedule\\TaskCache",
                      r"0F87369F-A4E5-4CFC-BD3E-73E6154572DD"],
            note="任务计划持久化；最后一个是 Microsoft 的 UpdateOrchestrator 任务 CLSID",
            advice="重点看 Action 里的命令行是否指向临时目录或用户可写路径",
            tags=["自启"],
        ),
        Entry(
            name="服务与驱动", severity="medium",
            patterns=[r"CurrentControlSet\\Services\\", r"\\drivers\\", r"\\DriverStore\\"],
            note="服务/驱动型持久化",
            advice="核对服务 ImagePath 是否指向签名异常的二进制",
            tags=["服务"],
        ),
        Entry(
            name="Linux 持久化", severity="high",
            patterns=[r"/etc/rc\.local", r"/etc/cron\.(d|daily|hourly)/", r"~/\.bashrc",
                      r"~/\.profile", r"/etc/systemd/system/", r"/usr/lib/systemd/system/",
                      r"authorized_keys", r"/etc/ld\.so\.preload"],
            note="Shell 启动脚本 / cron / systemd unit / SSH 公钥 / 动态链接预加载",
            advice="ld.so.preload 属于高阶 rootkit 手法，出现即重点核查",
            tags=["linux"],
        ),
        Entry(
            name="SSH 密钥与配置", severity="high",
            patterns=[r"ssh-rsa\s+AAAA", r"ssh-ed25519\s+AAAA", r"StrictHostKeyChecking\s+no",
                      r"UserKnownHostsFile\s+/dev/null"],
            note="植入的 SSH 公钥，或关闭主机校验的配置",
            advice="公钥即持久化凭据，务必视为入侵已成立的证据",
            tags=["凭据", "linux"],
        ),
    ],
)


# ==================================================================== 凭据
CREDENTIALS = Dictionary(
    id="credentials",
    name="凭据线索",
    description="明文凭据、令牌与认证材料。只提示存在性，不鼓励导出明文口令。",
    builtin=True,
    entries=[
        Entry(
            name="明文口令模式", severity="high",
            patterns=[r"(?i)password\s*[=:]\s*\S{4,}", r"(?i)passwd\s*[=:]\s*\S{4,}",
                      r"(?i)pwd\s*=\s*\S{4,}", r"(?i)用户.{0,6}密码\s*[：:=]\s*\S{2,}"],
            note="配置或脚本中出现的明文口令赋值",
            advice="确认是否为测试账号；真实凭据应走应急响应流程轮换",
            tags=["凭据"],
        ),
        Entry(
            name="令牌与密钥", severity="high",
            patterns=[r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}",
                      r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{20,}",
                      r"sk-[A-Za-z0-9]{20,}", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                      r"AIza[0-9A-Za-z_\-]{35}"],
            note="JWT / AWS AccessKey / GitHub Token / OpenAI Key / 私钥 / Google API Key",
            advice="按应急流程作废并轮换",
            tags=["凭据", "密钥"],
        ),
        Entry(
            name="凭据文件与数据库口令哈希", severity="medium",
            patterns=[r"\$NT\$", r"\$1\$", r"\$2[aby]?\$", r"\$5\$", r"\$6\$",
                      r"sam\b.{0,40}hash", r"sekurlsa", r"kerberos", r"wdigest",
                      r"CredentialManager", r"Login Data"],
            note="口令哈希格式与凭据提取相关痕迹",
            advice="涉及他人凭据时注意合规边界",
            tags=["哈希"],
        ),
    ],
)


# ==================================================================== Web / Webshell
WEB_ATTACK = Dictionary(
    id="web_attack",
    name="Web 攻击与后门",
    description="WebShell、注入语句与一句话木马特征。",
    builtin=True,
    entries=[
        Entry(
            name="一句话木马", severity="critical",
            patterns=[r"eval\s*\(\s*\$_(?:POST|GET|REQUEST)", r"assert\s*\(\s*\$_(?:POST|GET|REQUEST)",
                      r"system\s*\(\s*\$_(?:POST|GET|REQUEST)",
                      r"`\$_GET\[.*\]`", r"\beval\s*\(\s*base64_decode", r"assert\s*\(\s*base64_decode"],
            note="PHP 一句话木马最典型的形态",
            advice="属确证入侵；立即隔离并全网排查同源文件",
            tags=["webshell"],
        ),
        Entry(
            name="注入语句", severity="high",
            patterns=[r"(?i)union\s+(?:all\s+)?select\b", r"(?i)\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1",
                      r"(?i)sleep\s*\(\s*\d+\s*\)", r"(?i)waitfor\s+delay\b",
                      r"(?i)benchmark\s*\(", r"(?i)information_schema\b", r"(?i)xp_cmdshell\b"],
            note="SQL 注入探测语句",
            advice="说明该主机正被扫描或已被利用；查 WAF/应用日志定位来源",
            tags=["注入"],
        ),
        Entry(
            name="WebShell 落地痕迹", severity="high",
            patterns=[r"jspxcrt", r"behinder", r"godzilla", r"antsword", r"c99shell",
                      r"eval\(gzinflate", r"assert\(gzinflate", r"base64_decode\(gzinflate"],
            note="常见 WebShell 家族的标识",
            advice="定位 Web 根目录并全量查同名/同特征文件",
            tags=["webshell"],
        ),
    ],
)


# ==================================================================== 勒索
RANSOMWARE = Dictionary(
    id="ransomware",
    name="勒索软件",
    description="加密扩展名、赎金说明与暗网联系方式。",
    builtin=True,
    entries=[
        Entry(
            name="赎金说明", severity="critical",
            patterns=[r"README[_-]?(?:DECRYPT|RECOVER|RESTORE)", r"HOW[_-]?TO[_-]?DECRYPT",
                      r"YOUR[_-]?FILES[_-]?ARE[_-]?ENCRYPTED", r"恢复说明", r"解密说明"],
            note="勒索软件留下的恢复指引文件",
            advice="保留原文件不要删除；评估是否有解密工具",
            tags=["勒索"],
        ),
        Entry(
            name="暗网联系方式", severity="critical",
            patterns=[r"onion[:\s][a-z2-7]{16,56}\.onion", r"\.onion\b",
                      r"monero wallet", r"bitcoin address", r"your personal decryption key"],
            note="Tor 站点与钱包地址",
            advice="据此关联同源勒索家族与批次",
            tags=["勒索"],
        ),
        Entry(
            name="加密行为指令", severity="high",
            patterns=[r"vssadmin\s+delete\s+shadows", r"wmic\s+shadowcopy\s+delete",
                      r"bcdedit[^\n]{0,60}recoveryenabled\s+no", r"wbadmin\s+delete\s+catalog",
                      r"CryptEncrypt", r"AES-\d{3}", r"CipherMode\s*=\s*CTR"],
            note="加密前破坏恢复手段的典型命令",
            advice="说明勒索已进入执行阶段",
            tags=["勒索"],
        ),
    ],
)


# ==================================================================== 注册表
ALL_DICTIONARIES: list[Dictionary] = [
    CTF, SUSPICIOUS_PROCESS, SUSPICIOUS_PORT, PERSISTENCE,
    CREDENTIALS, WEB_ATTACK, RANSOMWARE,
]


def get(dictionary_id: str) -> Dictionary | None:
    for d in ALL_DICTIONARIES:
        if d.id == dictionary_id:
            return d
    return None


def all_ids() -> list[str]:
    return [d.id for d in ALL_DICTIONARIES]
