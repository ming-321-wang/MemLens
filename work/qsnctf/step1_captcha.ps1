# qsnctf 登录第一步：建会话 + 取验证码图片（authorized by account owner）
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$base = 'https://www.qsnctf.com'
$work = 'D:\DSH\工作区\MemLens\work\qsnctf'
New-Item -ItemType Directory -Force -Path $work | Out-Null

$sess = $null
$r0 = Invoke-WebRequest -Uri "$base/" -UseBasicParsing -TimeoutSec 30 -SessionVariable sess
Write-Output "首页 $($r0.StatusCode)"

$codeId = [guid]::NewGuid().ToString()
Write-Output "codeId = $codeId"
$script:CodeId = $codeId
$script:Sess = $sess

# 先试 /api/captcha/{id}
foreach ($u in @("$base/api/captcha/$codeId", "$base/captcha/$codeId")) {
    try {
        $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 30 -WebSession $sess -Headers @{ Referer = "$base/" }
        $ct = $r.Headers['Content-Type']
        Write-Output "$u -> $($r.StatusCode)  ct=$ct  len=$($r.RawContentLength)"
        if ($r.RawContentLength -gt 200) {
            $p = Join-Path $work 'captcha.png'
            [IO.File]::WriteAllBytes($p, $r.Content)
            Write-Output "SAVED $p"
            $script:CaptchaUrl = $u
            break
        }
    } catch {
        Write-Output "$u -> FAIL $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
            Write-Output ("   body: " + $sr.ReadToEnd().Substring(0, [Math]::Min(300, $sr.ReadToEnd().Length)))
        }
    }
}
Write-Output "CodeId=$script:CodeId"
$script:Sess | Export-Clixml -Path (Join-Path $work 'session.clixml')
Write-Output "session 已保存"
