$ErrorActionPreference = 'Stop'
$wgaCheckout = Split-Path -Parent $PSScriptRoot
$wgaLocalPython = Join-Path $wgaCheckout '.venv\Scripts\python.exe'
$wgaPrivatePython = Join-Path $env:LOCALAPPDATA 'WeChatGroupAudit\runtime\Scripts\python.exe'
if ($env:WGA_PYTHON) {
    & $env:WGA_PYTHON -m wechat_group_audit @args
} elseif (Test-Path -LiteralPath $wgaLocalPython) {
    & $wgaLocalPython -m wechat_group_audit @args
} elseif (Test-Path -LiteralPath $wgaPrivatePython) {
    & $wgaPrivatePython -m wechat_group_audit @args
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3.12 -m wechat_group_audit @args
} else {
    throw 'Install Python 3.12 and follow the README setup steps, or set WGA_PYTHON.'
}
exit $LASTEXITCODE
