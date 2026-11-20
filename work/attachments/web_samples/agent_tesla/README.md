# MEMORY-FORENSICS-INVESTIGATION-OF-AN-AGENT-TESLA-MALWARE-INFECTION-USING-VOLATILITY-3
Hands-on memory forensics investigation using Volatility 3 — process analysis, injection detection, registry artefacts, SMTP exfiltration strings, and C2 IOC recovery from a raw memory image.
# Memory Forensics Investigation of an AgentTesla Malware Infection Using Volatility 3

A hands-on memory forensics investigation of a Windows 10 virtual machine infected with an AgentTesla infostealer, packaged using PyInstaller. The analysis was conducted using Volatility 3 on an Ubuntu host, working through process analysis, injection detection, DLL inspection, network artefacts, registry persistence, and string-level IOC recovery.

---

##  Disclaimer

This repository is for **educational and research purposes only**. The malware sample used in this investigation was sourced from [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch), a public malware repository. All analysis was conducted in an isolated, air-gapped virtual environment.

- The malware sample is provided as a password-protected zip following standard InfoSec practice
- **File name:** `AgentTesla.zip`
- **Password:** `infected`
- The zip must be **downloaded locally** to extract — it cannot be opened directly on GitHub
- Only open inside an **isolated, air-gapped virtual environment**
- Never execute malware on a host machine or production system
- The author takes no responsibility for misuse of any materials in this repository

---

## Project Overview

This investigation demonstrates a full memory forensics workflow applied to a live infected machine:

1. **Memory Acquisition** — Capturing a raw memory image from the infected Windows 10 VM using WinPmem while the malware was actively running
2. **Image Transfer & Verification** — Moving the 7.06 GB dump to an Ubuntu analysis host and verifying it with `windows.info`
3. **Process Analysis** — Using `pslist`, `pstree`, `psscan`, and `cmdline` to identify the malicious `internet_detector.exe` process and its self-spawned child
4. **Injection Detection** — Running `malfind` to check for injected memory regions, uncovering suspected AV tampering in `MsMpEng.exe`
5. **DLL Inspection** — Identifying `python310.dll` and `ucrtbase.dll` loaded from a PyInstaller `_MEI` temp directory, confirming the packaging method
6. **Network Artefacts** — Using `netscan` to examine connection records in memory
7. **Registry Analysis** — Enumerating hives and reading Run keys, discovering a suspicious `ransomware.exe` persistence entry with null bytes
8. **String Extraction** — Running GNU `strings` across the raw dump and grepping for SMTP addresses, C2 URLs, and keylogger identifiers

---

## Skills Demonstrated

- Live memory acquisition using WinPmem
- Memory image transfer and verification
- Process analysis and hidden process detection with Volatility 3
- Code injection detection using `malfind`
- DLL inspection for non-standard load paths
- Registry artefact analysis from memory
- IOC recovery through raw string extraction
- PyInstaller malware packaging identification
- Incident response recommendations

---

## Key Findings

| Finding | Detail |
|---------|--------|
| Malicious Process | `internet_detector.exe` running from `C:\Tools\internet_detector\` |
| Self-Replication | PID 2824 spawned child PID 4740 within 25 seconds |
| PyInstaller Packaging | `python310.dll` loaded from `AppData\Local\Temp\_MEI28242` |
| C2 Infrastructure | `185.234.72.230`, `gate.php` endpoint, disguised as Google storage path |
| SMTP Exfiltration | `admin@smtp.rambler.ru`, `admin@smtp.yandex.ru` found in memory strings |
| AV Tampering | `MsMpEng.exe` had 14 flagged `PAGE_EXECUTE_READWRITE` regions |
| Registry Persistence | `ransomware.exe` entry in HKCU Run key with null bytes |
| VirusTotal Detection | 59/72 vendors flagged the sample as malicious |

---

## Repository Contents

| File | Description |
|------|-------------|
| `report.pdf` | Full investigation report |
| `AgentTesla.zip` | Password-protected malware sample — must be **downloaded** to access. Password: `infected` |
| `iocs.txt` | All Indicators of Compromise extracted from the investigation |
| `volatility_commands.txt` | Every Volatility 3 command used, with explanations |
| `memory_strings.txt` | Key strings recovered from the raw memory dump |

---

## Tools & Environment

| Category | Tools |
|----------|-------|
| Infected VM | Windows 10 x64, VMware Workstation 17.5 |
| Analysis Host | Ubuntu 24 |
| Memory Acquisition | WinPmem |
| Memory Analysis | Volatility 3 (v2.28.0) |
| String Extraction | GNU strings |
| Process Monitoring | Process Explorer (Sysinternals) |
| Threat Intelligence | VirusTotal, MalwareBazaar |

---

## Investigation Walkthrough

### Step 1 — Environment Setup
- Configured Windows 10 VM with Host-Only network adapter to prevent real C2 communication
- Installed and verified Volatility 3 on the Ubuntu analysis host
- Took a clean VM snapshot before introducing the malware sample

### Step 2 — Malware Execution & Memory Capture
- Executed the AgentTesla sample inside the isolated VM
- Observed `internet_detector.exe` appear under PID 2732 via Process Explorer
- Left the malware running for ~3 hours to allow full persistence setup
- Captured a 7.06 GB raw memory image using WinPmem
- Transferred the image to the Ubuntu host via Python HTTP server at ~193 MB/s

### Step 3 — Process Analysis
- `pslist` returned 133 processes — two entries named `internet_detec` stood out
- `pstree` revealed the full path `C:\Tools\internet_detector\internet_detector.exe`
- PID 2824 had `svchost.exe` (PID 1268) as parent — unusual for a user-run process
- PID 4740 was spawned by PID 2824 ~25 seconds later — confirmed self-replication
- `psscan` matched `pslist` exactly — malware was not using rootkit hiding techniques

### Step 4 — Injection Detection
- `malfind` on PID 2824 and PID 4740 returned no flagged regions
- Full system scan flagged `MsMpEng.exe` with 14 `PAGE_EXECUTE_READWRITE` regions — consistent with AgentTesla's known AV interference behaviour

### Step 5 — DLL Inspection
- PID 2824 had a clean DLL list — all from `C:\Windows\System32\`
- PID 4740 loaded `python310.dll` and `ucrtbase.dll` from `AppData\Local\Temp\_MEI28242\`
- `_MEI` naming pattern confirms PyInstaller — malware was a Python script compiled into a standalone executable

### Step 6 — Network & Registry Analysis
- `netscan` found no active connections to C2 — expected given Host-Only network isolation
- `hivelist` provided hive offsets for Run key queries
- HKLM Run key contained only legitimate entries
- HKCU Run key contained a `ransomware.exe` entry with null bytes — leftover from a prior session on the same VM

### Step 7 — String Extraction & IOC Recovery
- `strings -n 8` extracted all printable sequences from the 7 GB dump
- SMTP grep returned `admin@smtp.rambler.ru`, `admin@smtp.yandex.ru`, and keylogger identifier strings
- C2 grep returned `185.234.72.230`, `gate.php` URLs, and a disguised Google storage path
- `dumpfiles` returned no output for either PID — expected with PyInstaller's temp-extract execution model

---

*Author: Damoah Bashiru*
