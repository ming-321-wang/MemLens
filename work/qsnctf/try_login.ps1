param([string]$Captcha = 'UmyB', [string]$User = '冥', [string]$Pass = 'wzh211955')
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$base = 'https://www.qsnctf.com'
$work = 'D:\MemLens\work\qsnctf'

$ids = @()
Get-ChildItem -LiteralPath $work -Filter 'code?.txt' | Sort-Object Name | ForEach-Object {
    $ids += (Get-Content -LiteralPath $_.FullName -Raw).Trim()
}
Write-Output "待试 codeId 数量: $($ids.Count)"

foreach ($cid in $ids) {
    $sess = $null
    try { Invoke-WebRequest -Uri "$base/" -UseBasicParsing -TimeoutSec 25 -SessionVariable sess | Out-Null } catch {}
    $body = @{ username = $User; password = $Pass; captcha = $Captcha; code = $cid } | ConvertTo-Json -Compress
    Write-Output "--- try code=$($cid.Substring(0,8))... captcha=$Captcha"
    try {
        $r = Invoke-WebRequest -Uri "$base/api/login" -Method POST -WebSession $sess `
            -ContentType 'application/json' -Body $body -UseBasicParsing -TimeoutSec 40 `
            -Headers @{ Referer = "$base/" }
        Write-Output "  HTTP $($r.StatusCode)  len=$($r.Content.Length)"
        Write-Output "  body: $($r.Content.Substring(0,[Math]::Min(500,$r.Content.Length)))"
        Set-Content -LiteralPath (Join-Path $work 'login_ok.txt') -Value "$cid`n$Captcha`n$($r.Content)" -Encoding UTF8
        Write-Output "  *** 登录成功 ***"
        break
    } catch {
        $code = $null; if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        $msg = ""
        if ($_.Exception.Response) {
            try { $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream()); $msg = $sr.ReadToEnd() } catch {}
        }
        Write-Output "  HTTP $code  $msg"
    }
    Start-Sleep -Milliseconds 400
}
