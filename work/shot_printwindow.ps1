# Capture MemLens window content via PrintWindow (works even when occluded)
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Drawing;
using System.Runtime.InteropServices;
public class PW {
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public delegate bool EnumProc(IntPtr h, IntPtr lp);
  public struct R { public int L, T, Rr, B; }
}
"@

$out = 'D:\MemLens\work\exe_ui_clean.png'

# find MemLens window by process name
$targets = @()
$cb = [PW+EnumProc]{
    param($h, $lp)
    $pid2 = 0
    [void][PW]::GetWindowThreadProcessId($h, [ref]$pid2)
    if ($pid2 -gt 0) {
        $pr = Get-Process -Id $pid2 -ErrorAction SilentlyContinue
        if ($pr -and $pr.ProcessName -eq 'MemLens') {
            $sb = New-Object System.Text.StringBuilder 512
            [void][PW]::GetWindowText($h, $sb, 512)
            $t = $sb.ToString()
            if ($t.Length -gt 0 -and [PW]::IsWindowVisible($h)) {
                $script:targets += [pscustomobject]@{ H = $h; Title = $t; PID = $pid2 }
            }
        }
    }
    return $true
}
[void][PW]::EnumWindows($cb, [IntPtr]::Zero)

Write-Output "found windows: $($targets.Count)"
foreach ($t in $targets) { Write-Output "  hwnd=$($t.H) pid=$($t.PID) title=$($t.Title)" }

if ($targets.Count -eq 0) {
    Write-Output "no MemLens window found - is it still running?"
    exit 1
}

$win = $targets[0].H
$r = New-Object PW+R
[void][PW]::GetWindowRect($win, [ref]$r)
$w = $r.Rr - $r.L
$h = $r.B - $r.T
Write-Output "rect ${w}x${h}"

$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
# PW_RENDERFULLCONTENT = 2 (needed for DirectComposition / Qt windows)
$ok = [PW]::PrintWindow($win, $hdc, 2)
$g.ReleaseHdc($hdc)
$g.Dispose()
if (-not $ok) {
    Write-Output "PrintWindow flag=2 failed, retry flag=0"
    $g2 = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc2 = $g2.GetHdc()
    $ok = [PW]::PrintWindow($win, $hdc2, 0)
    $g2.ReleaseHdc($hdc2)
    $g2.Dispose()
}
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "PrintWindow ok=$ok saved=$out bytes=$((Get-Item -LiteralPath $out).Length)"
