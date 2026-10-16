# Removes ss, ip, ifconfig installed by install.ps1 and cleans the user PATH.
param(
    [string]$Dir = (Join-Path $env:LOCALAPPDATA 'Programs\net-tools-windows')
)
$ErrorActionPreference = 'Stop'
foreach ($t in 'ss.exe', 'ip.exe', 'ifconfig.exe') {
    $p = Join-Path $Dir $t
    if (Test-Path $p) { Remove-Item -Force $p }
}
if ((Test-Path $Dir) -and -not (Get-ChildItem $Dir -Force)) { Remove-Item -Force $Dir }

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath) {
    $parts = $userPath -split ';' | Where-Object { $_ -and $_ -ne $Dir }
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
}
Write-Host "Uninstalled from $Dir"
