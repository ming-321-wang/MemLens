$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$base = 'https://www.qsnctf.com'
$work = 'D:\MemLens\work\qsnctf'
New-Item -ItemType Directory -Force -Path $work | Out-Null

$sess = $null
$r0 = Invoke-WebRequest -Uri "$base/" -UseBasicParsing -TimeoutSec 30 -SessionVariable sess
Write-Output "home $($r0.StatusCode)"

$codeId = [guid]::NewGuid().ToString()
$png = Join-Path $work 'captcha.png'
Invoke-WebRequest -Uri "$base/api/captcha/$codeId" -UseBasicParsing -TimeoutSec 30 `
    -WebSession $sess -Headers @{ Referer = "$base/" } -OutFile $png
$fi = Get-Item -LiteralPath $png
Write-Output "captcha saved: $($fi.Length) bytes"
Write-Output "codeId=$codeId"
$codeId | Set-Content -LiteralPath (Join-Path $work 'codeId.txt') -Encoding ASCII
$sess | Export-Clixml -Path (Join-Path $work 'session.clixml')
Write-Output "OK"
