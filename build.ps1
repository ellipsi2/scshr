# Configure + build with MSVC (VS 2026 or 2022) + Ninja. Usage: .\build.ps1 [-Config Release|Debug] [-Clean]
param([string]$Config = "Release", [switch]$Clean)
$ErrorActionPreference = "Stop"
$vs = @("C:\Program Files\Microsoft Visual Studio\18\Community", "C:\Program Files\Microsoft Visual Studio\2022\Community") |
  Where-Object { Test-Path "$_\VC\Auxiliary\Build\vcvars64.bat" } | Select-Object -First 1
if (-not $vs) { throw "Visual Studio with C++ tools not found" }
$root = $PSScriptRoot
$bld = Join-Path $root "build\$Config"
if ($Clean -and (Test-Path $bld)) { Remove-Item -Recurse -Force $bld }
New-Item -ItemType Directory -Force $bld | Out-Null
$cmd = "call `"$vs\VC\Auxiliary\Build\vcvars64.bat`" >nul && cmake -S `"$root`" -B `"$bld`" -G Ninja -DCMAKE_BUILD_TYPE=$Config && cmake --build `"$bld`" --parallel"
cmd /c $cmd
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
Write-Host "built: $bld"
