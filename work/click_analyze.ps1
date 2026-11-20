# Real-GUI verification: click the "start analyze" button via UI Automation,
# then screenshot the result. Proves the user's failure path is gone.
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class PW4 {
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r);
  public struct R { public int L, T, Rr, B; }
}
"@

$proc = Get-Process -Name 'MemLens' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) { Write-Output "MemLens not running"; exit 1 }
Write-Output "MemLens PID = $($proc.Id)"

# root for this process
$cond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $proc.Id)
$win = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
    [System.Windows.Automation.TreeScope]::Children, $cond)
if (-not $win) { Write-Output "window not found"; exit 1 }

# list all buttons (index + name) so we can pick without typing Chinese
$bcond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::Button)
$btns = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $bcond)
Write-Output "buttons found = $($btns.Count)"
for ($i = 0; $i -lt $btns.Count; $i++) {
    $n = $btns[$i].Current.Name
    $en = $btns[$i].Current.IsEnabled
    # print name as unicode escapes to dodge console encoding issues
    if ($n) {
        $codes = ($n.ToCharArray() | ForEach-Object { [int]$_ }) -join ','
        Write-Output "  [$i] enabled=$en len=$($n.Length) codes=$codes"
    } else {
        Write-Output "  [$i] enabled=$en (no name)"
    }
}

# The analyze button is the 4th button (Open / engine / preset / ANALYZE ...).
# Identify by name length>=3 and enabled, skipping the first three.
$target = $null
for ($i = 0; $i -lt $btns.Count; $i++) {
    $n = $btns[$i].Current.Name
    if (-not $n) { continue }
    if ($btns[$i].Current.IsEnabled -and $n.Length -ge 4 -and ($n -match '\u5f00\u59cb|\u5206\u6790')) {
        $target = $btns[$i]; Write-Output "picked by regex: index $i"; break
    }
}
if (-not $target) {
    # fallback: first enabled button after the preset combo (index 3)
    for ($i = 3; $i -lt $btns.Count; $i++) {
        if ($btns[$i].Current.IsEnabled) { $target = $btns[$i]; Write-Output "picked by index: $i"; break }
    }
}
if (-not $target) { Write-Output "no clickable button found"; exit 1 }

try {
    $inv = $target.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
    $inv.Invoke()
    Write-Output "clicked!"
} catch {
    Write-Output "invoke failed: $($_.Exception.Message)"
    exit 1
}

# wait for analysis, then screenshot
Start-Sleep -Seconds 20
$hwnd = [IntPtr]$win.Current.NativeWindowHandle
$r = New-Object PW4+R
[void][PW4]::GetWindowRect($hwnd, [ref]$r)
$w = $r.Rr - $r.L; $h = $r.B - $r.T
$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
$ok = [PW4]::PrintWindow($hwnd, $hdc, 2)
$g.ReleaseHdc($hdc); $g.Dispose()
$out = 'D:\MemLens\work\exe_ui_analyzed.png'
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "screenshot saved=$out ok=$ok"
