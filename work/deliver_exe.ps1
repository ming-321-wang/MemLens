# Deliver MemLens.exe to the Desktop: shortcut + portable zip
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$exe   = 'D:\MemLens\dist\MemLens\MemLens.exe'
$dist  = 'D:\MemLens\dist\MemLens'
$desk  = [Environment]::GetFolderPath('Desktop')
$lnk   = Join-Path $desk 'MemLens.lnk'
$zip   = Join-Path $desk 'MemLens-v0.7.0-portable.zip'

if (-not (Test-Path -LiteralPath $exe)) { throw "exe not found: $exe" }
Write-Output "desktop = $desk"

# ---- 1. shortcut (instant launch) ----
try {
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut($lnk)
    $sc.TargetPath        = $exe
    $sc.WorkingDirectory  = $dist
    $sc.IconLocation      = "$exe,0"
    $sc.Description       = 'MemLens Memory Forensics Workbench'
    $sc.Save()
    Write-Output "shortcut OK -> $lnk  ($((Get-Item -LiteralPath $lnk).Length) bytes)"
} catch {
    Write-Output "shortcut FAILED: $($_.Exception.Message)"
}

# ---- 2. portable zip (for copying to another machine) ----
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Write-Output "zipping $dist ..."
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $dist, $zip,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false)
    $sw.Stop()
    $zi = Get-Item -LiteralPath $zip
    Write-Output ("zip OK -> {0}  {1:N1} MiB  ({2:N1}s)" -f $zi.FullName, ($zi.Length/1MB), $sw.Elapsed.TotalSeconds)
} catch {
    Write-Output "zip FAILED: $($_.Exception.Message)"
}

# ---- 3. verify what landed on the desktop ----
Write-Output ""
Write-Output "=== desktop contents (MemLens*) ==="
Get-ChildItem -LiteralPath $desk -Filter 'MemLens*' -ErrorAction SilentlyContinue |
    ForEach-Object { "  {0,-34} {1,10:N1} MiB" -f $_.Name, ($_.Length/1MB) }
