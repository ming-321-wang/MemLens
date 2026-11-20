# Launch packaged MemLens.exe, bring window to front, capture screenshot
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class W {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
  public struct R { public int L, T, Rr, B; }
}
"@

$exe = 'D:\MemLens\dist\MemLens\MemLens.exe'
$out = 'D:\MemLens\work\exe_ui_screenshot.png'

Write-Output "launching $exe"
$p = Start-Process -FilePath $exe -PassThru
Write-Output "  PID = $($p.Id)"

$hwnd = [IntPtr]::Zero
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 700
    $p.Refresh()
    if ($p.HasExited) { Write-Output "  process exited code=$($p.ExitCode)"; break }
    $h = $p.MainWindowHandle
    if ($h -ne [IntPtr]::Zero -and $h -ne 0) { $hwnd = $h; break }
}
Write-Output "  hwnd = $hwnd"

if ($hwnd -ne [IntPtr]::Zero) {
    $sb = New-Object System.Text.StringBuilder 512
    [void][W]::GetWindowText($hwnd, $sb, 512)
    Write-Output "  title = $($sb.ToString())"
    Start-Sleep -Seconds 7
    [void][W]::ShowWindow($hwnd, 9)
    [void][W]::SetForegroundWindow($hwnd)
    Start-Sleep -Seconds 3

    $r = New-Object W+R
    if ([W]::GetWindowRect($hwnd, [ref]$r)) {
        $w = $r.Rr - $r.L
        $h = $r.B - $r.T
        Write-Output "  rect = ${w}x${h} at ($($r.L),$($r.T))"
        if ($w -gt 100 -and $h -gt 100) {
            $bmp = New-Object System.Drawing.Bitmap $w, $h
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            $g.CopyFromScreen($r.L, $r.T, 0, 0, (New-Object System.Drawing.Size $w, $h))
            $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
            $g.Dispose()
            $bmp.Dispose()
            Write-Output "  saved $out bytes=$((Get-Item -LiteralPath $out).Length)"
        } else {
            Write-Output "  window too small, skip"
        }
    }
} else {
    Write-Output "  no hwnd, fallback fullscreen"
    Start-Sleep -Seconds 7
    $b = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Left, $b.Top, 0, 0, (New-Object System.Drawing.Size $b.Width, $b.Height))
    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
    Write-Output "  saved fullscreen $out"
}
Write-Output "  MemLens.exe left running PID=$($p.Id)"
