# Verify the portable zip actually runs from a clean (ASCII) location
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$zip  = Join-Path ([Environment]::GetFolderPath('Desktop')) 'MemLens-v0.7.0-portable.zip'
$dest = 'D:\MemLens_portable_test'

Write-Output "=== 1. extract to a clean dir ==="
if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
New-Item -ItemType Directory -Path $dest -Force | Out-Null
if (-not (Test-Path -LiteralPath $zip)) { Write-Output "zip missing: $zip"; exit 1 }
[System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $dest)
$exe = Join-Path $dest 'MemLens.exe'
Write-Output "  extracted exe exists = $(Test-Path -LiteralPath $exe)"
Write-Output "  files = $((Get-ChildItem -LiteralPath $dest -Recurse -File).Count)"

Write-Output ""
Write-Output "=== 2. vol3 entry mode from the unzipped copy ==="
$r = & $exe --vol3-entry --help 2>&1 | Out-String
$ver = ($r -split "`n" | Where-Object { $_ -match 'Volatility 3 Framework' } | Select-Object -First 1)
Write-Output "  $($ver.Trim())"
Write-Output "  windows.pslist present = $($r -match 'windows\.pslist')"

Write-Output ""
Write-Output "=== 3. real plugin run (banners) ==="
$img = 'D:\MemLens\samples\synthetic_windows.raw'
if (Test-Path -LiteralPath $img) {
    $o = & $exe --vol3-entry -f $img banners 2>&1 | Out-String
    $hit = $o -match 'Updating caches for'
    Write-Output "  plugin executed (cache scan seen) = $hit"
    Write-Output "  exit code = $LASTEXITCODE"
} else {
    Write-Output "  sample image missing, skip"
}

Write-Output ""
Write-Output "=== 4. GUI launch from unzipped copy ==="
$env:QT_QPA_PLATFORM = 'offscreen'
$p = Start-Process -FilePath $exe -PassThru
Start-Sleep -Seconds 16
$p.Refresh()
if ($p.HasExited) {
    Write-Output "  FAILED: exited early, code=$($p.ExitCode)"
} else {
    Write-Output "  OK: still running after 16s (PID $($p.Id))"
    $p.Kill()
    $p.WaitForExit(5000)
}
Remove-Item Env:\QT_QPA_PLATFORM -ErrorAction SilentlyContinue

Write-Output ""
Write-Output "=== 5. cleanup ==="
Start-Sleep -Seconds 2
try { Remove-Item -LiteralPath $dest -Recurse -Force; Write-Output "  test dir removed" }
catch { Write-Output "  cleanup skipped: $($_.Exception.Message)" }
