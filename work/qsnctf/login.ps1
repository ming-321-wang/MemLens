param(
    [Parameter(Mandatory=$true)][string]$User = '冥',
    [Parameter(Mandatory=$true)][string]$Pass = 'wzh211955',
    [Parameter(Mandatory=$true)][string]$Code,
    [string]$CodeId
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$base = 'https://www.qsnctf.com'
$work = 'D:\MemLens\work\qsnctf'

if (-not $CodeId) { $CodeId = Get-Content -LiteralPath (Join-Path $work 'codeId.txt') -Raw; $CodeId = $CodeId.Trim() }

$sess = Import-Clixml -Path (Join-Path $work 'session.clixml')

$body = @{ username = $User; password = $Pass; captcha = $Code; codeId = $CodeId } | ConvertTo-Json -Compress
Write-Output "POST /api/login  codeId=$CodeId  captcha=$Code"

$r = Invoke-WebRequest -Uri "$base/api/login" -Method POST -WebSession $sess `
    -ContentType 'application/json' -Body $body -UseBasicParsing -TimeoutSec 40 `
    -Headers @{ Referer = "$base/" }

Write-Output "status=$($r.StatusCode)"
$txt = $r.Content
Write-Output "response: $($txt.Substring(0,[Math]::Min(600,$txt.Length)))"

# 保存 token / cookie
try {
    $j = $r.Content | ConvertFrom-Json
    if ($j.data.token) {
        Set-Content -LiteralPath (Join-Path $work 'token.txt') -Value $j.data.token -Encoding ASCII
        Write-Output "TOKEN SAVED (len=$($j.data.token.Length))"
    }
    if ($j.data.user) { Write-Output "user: $($j.data.user | ConvertTo-Json -Compress -Depth 3)" }
} catch {
    Write-Output "parse json failed: $($_.Exception.Message)"
}
$sess | Export-Clixml -Path (Join-Path $work 'session.clixml')
Write-Output "session exported"
