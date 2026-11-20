# -*- coding: utf-8 -*-
"""导出 TestDLL.dll 的完整导入表，人工核对密码学/反调试 API。"""
import sys
from pathlib import Path

ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))
from memlens.engines.static import profile_file

prof = profile_file(r"D:\MemLens\work\attachments\512_512_可疑文件\TestDLL.dll")
pe = prof.pe
print("PE:", pe.bits, pe.machine, "DLL=", pe.is_dll, "节=", len(pe.sections),
      "签名=", pe.digital_signature, "Rich=", pe.rich_header)
for imp in pe.imports:
    print(f"\n=== {imp['dll']}  ({imp['count']} 函数)")
    fns = imp["functions"]
    for i in range(0, len(fns), 4):
        print("   " + ", ".join(f.ljust(26) for f in fns[i:i+4]))

# 分类
allf = {f for imp in pe.imports for f in imp["functions"]}
print("\n=== 关键 API 命中 ===")
CRYPTO = ("Crypt", "BCrypt", "NCrypt", "AES", "RC4", "MD5", "SHA", "RtlGenRandom", "CryptGenKey")
ANTI = ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
        "GetSystemTimeAsFileTime", "NtSetInformationThread", "CloseHandle")
INJECT = ("VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
          "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext", "NtMapViewOfSection",
          "OpenProcess", "ReadProcessMemory", "VirtualProtect")
FILE = ("CreateFile", "WriteFile", "ReadFile", "DeleteFile", "MoveFile", "CopyFile",
        "FindFirstFile", "SetFilePointer", "SetEndOfFile", "GetFileSize", "FlushFileBuffers")
PROC = ("CreateProcess", "ShellExecute", "WinExec", "OpenProcess", "CreateToolhelp32Snapshot",
        "Process32First", "Process32Next", "TerminateProcess")
REG = ("RegOpenKey", "RegSetValue", "RegCreateKey", "RegQueryValue", "RegDeleteKey",
       "RegCloseKey", "RegEnumKey")
NET = ("InternetOpen", "InternetConnect", "HttpSendRequest", "URLDownloadToFile",
       "WSAStartup", "socket", "connect", "send", "recv", "gethostbyname", "inet_addr",
       "WinHttpOpen", "WinHttpConnect")
LIB = ("LoadLibrary", "GetProcAddress", "LoadLibraryEx", "FreeLibrary", "LdrLoadDll")
for name, pats in (("密码学", CRYPTO), ("反调试/反分析", ANTI), ("注入/内存操作", INJECT),
                   ("文件操作", FILE), ("进程操作", PROC), ("注册表", REG),
                   ("网络", NET), ("动态加载", LIB)):
    hits = sorted(f for f in allf if any(p.lower() in f.lower() for p in pats))
    print(f"{name:<12} {len(hits):>3} 个: {', '.join(hits[:30])}")
