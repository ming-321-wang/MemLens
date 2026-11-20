<#
    MemLens · 一键打包脚本（Windows / PowerShell 5.1 兼容）

    用法：
        powershell -ExecutionPolicy Bypass -File packaging\build.ps1
        powershell -ExecutionPolicy Bypass -File packaging\build.ps1 -NoTools   # 不带 MemProcFS
        powershell -ExecutionPolicy Bypass -File packaging\build.ps1 -WithSymbols  # 连符号表一起拷（+10 GB）

    产物：
        dist\MemLens\MemLens.exe      （双击即用：PySide6 取证工作台）
        dist\MemLens\tools\MemProcFS\ （MemProcFS 可执行文件 + DLL，约 14 MB）

    ⚠ 为什么 MemProcFS 不整个塞进 _internal：
        MemProcFS 自带的 `python\` 子目录有 **1.26 GB**（它的插件/gradio 运行时），
        而取证主流程只用得到 `memprocfs.exe` + DLL（**13.6 MB**）。
        整个复制会让 dist 变成 1.4 GB；这里只拷必要部分。
    ⚠ 为什么**默认不拷 Symbols**：
        符号表 10.5 GB，是"所有历史镜像的内核"合集；实际只需要当前镜像那一个内核
        （MemProcFS 首次运行会自动从微软符号服务器下载，约 40 MB，落 exe 同级目录）。
        真要离线用：`memlens symbols --import-kernel <镜像>` 精确取一个 ISF。
#>
param([switch]$NoTools, [switch]$NoClean, [switch]$WithSymbols)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

# ⚠ 必须先结束正在运行的 MemLens：它**持有 work\memlens.log 的文件句柄**，
#    而日志文件就在 exe 同级目录下 → PyInstaller 删除 dist 时报
#    `PermissionError: [WinError 32] 另一个程序正在使用此文件`
#    （实测踩过：构建静默失败，exe 还是旧版本，排查了半天才发现）。
Write-Host "[0/3] 结束正在运行的 MemLens…" -ForegroundColor Cyan
Get-Process MemLens -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

Write-Host "[1/3] PyInstaller 打包…" -ForegroundColor Cyan
& $py -m PyInstaller --noconfirm $(if ($NoClean) { "" } else { "--clean" }) `
    (Join-Path $root "packaging\memlens.spec")
if ($LASTEXITCODE -ne 0) { Write-Host "打包失败" -ForegroundColor Red; exit 1 }

if (-not $NoTools) {
    Write-Host "[2/3] 复制 MemProcFS 运行时（不含 1.26GB python 子目录、不含 10.5GB 符号表）…" -ForegroundColor Cyan
    $src = Join-Path $root "tools\MemProcFS"
    $dst = Join-Path $root "dist\MemLens\tools\MemProcFS"
    if (Test-Path $src) {
        if (Test-Path $dst) { Remove-Item -LiteralPath $dst -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Force -Path $dst | Out-Null
        Get-ChildItem $src -File | ForEach-Object { Copy-Item $_.FullName $dst -Force }
        foreach ($sub in @("plugins")) {
            $s = Join-Path $src $sub
            if (Test-Path $s) { Copy-Item $s $dst -Recurse -Force }
        }
        if ($WithSymbols) {
            $sym = Join-Path $src "Symbols"
            if (Test-Path $sym) { Copy-Item $sym $dst -Recurse -Force }
            Write-Host "      已连符号表一起复制（+10 GB，离线可用）" -ForegroundColor Green
        } else {
            # ★ 默认不拷 Symbols（10.5 GB），但如果源里是 junction（→ E 盘全量符号表），
            #   为 dist 也建同款 junction —— 这样打包后 exe 依然能离线用全量符号。
            $srcSym = Join-Path $src "Symbols"
            $dstSym = Join-Path $dst "Symbols"
            if ((Test-Path $srcSym) -and (-not (Test-Path $dstSym))) {
                $t = @((Get-Item $srcSym -Force).Target)[0]
                if (-not $t) { $t = $srcSym }
                New-Item -ItemType Junction -Path $dstSym -Target $t | Out-Null
                Write-Host "      Symbols junction 已建 → $t" -ForegroundColor Green
            }
        }
        $sz = (Get-ChildItem $dst -Recurse -File | Measure-Object -Property Length -Sum)
        Write-Host ("      MemProcFS 就位：{0}（{1:N1} MB）" -f $dst, ($sz.Sum / 1MB)) -ForegroundColor Green
    } else {
        Write-Warning "找不到 $src —— 打包的 exe 将无法使用 MemProcFS（可用环境变量 MEMLENS_MEMPROCFS 指定）"
    }
} else {
    Write-Host "[2/3] 跳过 MemProcFS 复制" -ForegroundColor Yellow
}

Write-Host "[3/3] 统计产物体积…" -ForegroundColor Cyan
$exe = Join-Path $root "dist\MemLens\MemLens.exe"
if (-not (Test-Path $exe)) { Write-Host "没有生成 exe" -ForegroundColor Red; exit 1 }
$sz = (Get-ChildItem (Join-Path $root "dist\MemLens") -Recurse -File | Measure-Object -Property Length -Sum)
Write-Host ""
Write-Host "完成：" -ForegroundColor Green
Write-Host "  可执行文件 : $exe"
Write-Host ("  总体积     : {0:N1} MB" -f ($sz.Sum / 1MB))
Write-Host ""
Write-Host "用法：双击 MemLens.exe → 打开内存镜像 → 引擎选「MemProcFS 虚拟盘」→ ⚡ 一键分析"
Write-Host "     自检    ：MemLens.exe --selftest（输出 work\selftest.json）"
Write-Host "     命令行  ：MemLens.exe <镜像路径>"
