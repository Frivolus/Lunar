param([string]$Config = "Release")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$candidates = @(
    "$env:LOCALAPPDATA\Microsoft\WinGet\Links\cmake.exe",
    "C:\Program Files\CMake\bin\cmake.exe"
)
$cmake = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $cmake) { $cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source }
if (-not $cmake) { throw "cmake introuvable" }

& $cmake -B build -G "Visual Studio 17 2022" -A x64
if ($LASTEXITCODE -ne 0) { throw "configuration echouee" }

& $cmake --build build --config $Config
if ($LASTEXITCODE -ne 0) { throw "compilation echouee" }

Write-Host "`nBuild OK" -ForegroundColor Green
