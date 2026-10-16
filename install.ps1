# Installs ss, ip, ifconfig for the current user and adds them to PATH.
# Usage:  powershell -ExecutionPolicy Bypass -File install.ps1 [-Dir <path>]
param(
    [string]$Dir = (Join-Path $env:LOCALAPPDATA 'Programs\net-tools-windows')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$tools = 'ss.exe', 'ip.exe', 'ifconfig.exe'

$src = Join-Path $root 'bin'
$missing = $tools | Where-Object { -not (Test-Path (Join-Path $src $_)) }
if ($missing) {
    Write-Host 'Binaries not found, building with MSVC...'
    & cmd.exe /c "`"$root\build.bat`""
    if ($LASTEXITCODE -ne 0) { throw 'Build failed. Install Visual Studio Build Tools (C++) or download a release.' }
}

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
foreach ($t in $tools) { Copy-Item -Force (Join-Path $src $t) (Join-Path $Dir $t) }

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$parts = @()
if ($userPath) { $parts = $userPath -split ';' | Where-Object { $_ } }
if ($parts -notcontains $Dir) {
    [Environment]::SetEnvironmentVariable('Path', (($parts + $Dir) -join ';'), 'User')
    Write-Host "Added to user PATH: $Dir"
}
if (($env:Path -split ';') -notcontains $Dir) { $env:Path = "$env:Path;$Dir" }

Write-Host "Installed to $Dir"
Write-Host 'Open a new terminal, then try:  ip -br a   |   ss -tulpn   |   ifconfig'
