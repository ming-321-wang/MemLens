# Launch the rebuilt exe WITH a PE sample on the command line, then screenshot.
# This reproduces the user's exact flow and proves the fix in the real GUI.
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class PW2 {
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public delegate bool EnumProc(IntPtr h, IntPtr lp);
  public struct R { public int L, T, Rr, B; }
}
"@

$exe = 'D:\MemLens\dist\MemLens\MemLens.exe'
$pe  = 'E:\附件原件\solar题库\逆向\simple_re\simple_re.exe'
$out = 'D:\MemLens\work\exe_ui_after_fix.png'

Get-Process -Name 'MemLens' -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill(); $_.WaitForExit(3000) }
Start-Sleep -Seconds 1

Write-Output "launching with sample: $pe"
$p = Start-Process -FilePath $exe -ArgumentList "`"$pe`"" -PassThru
Write-Output "  PID = $($p.Id)"

# wait for window, then give the probe time to finish
$hwnd = [IntPtr]::Zero
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 700
    $p.Refresh()
    if ($p.HasExited) { Write-Output "  exited code=$($p.ExitCode)"; break }
    if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $hwnd = $p.MainWindowHandle; break }
}
Write-Output "  hwnd = $hwnd"
Start-Sleep -Seconds 12   # let probe + auto-engine-switch settle

if ($hwnd -ne [IntPtr]::Zero) {
    $sb = New-Object System.Text.StringBuilder 512
    [void][PW2]::GetWindowText($hwnd, $sb, 512)
    Write-Output "  title = $($sb.ToString())"
    $r = New-Object PW2+R
    [void][PW2]::GetWindowRect($hwnd, [ref]$r)
    $w = $r.Rr - $r.L; $h = $r.B - $r.T
    $bmp = New-Object System.Drawing.Bitmap $w, $h
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    $ok = [PW2]::PrintWindow($hwnd, $hdc, 2)
    $g.ReleaseHdc($hdc); $g.Dispose()
    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output "  PrintWindow ok=$ok saved=$out bytes=$((Get-Item -LiteralPath $out).Length)"
    Write-Output "  window still running (left open for user): PID=$($p.Id)"
} else {
    Write-Output "  no window found"
}
