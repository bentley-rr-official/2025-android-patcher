# Windows entry point for the Android PHONE build: runs scripts/build-phone.sh inside WSL.
# Usage:  .\build-phone.ps1 C:\path\to\RecRoom.xapk
# Needs in WSL: JDK, python3 + `pip install lief`, Android NDK r27c (ANDROID_NDK), zipalign +
# apksigner (in tools/ or on PATH). One-time: scripts/make-keystore.sh and copy 2025.cfg.example.
param([Parameter(Mandatory=$true)][string]$Xapk)
$ErrorActionPreference = "Stop"
if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) { throw "WSL is required (wsl --install -d Ubuntu)" }
$Xapk  = (Resolve-Path $Xapk).Path
$Repo  = $PSScriptRoot
$wX    = (wsl wslpath -a "$Xapk").Trim()
$wRepo = (wsl wslpath -a "$Repo").Trim()
wsl bash -lc "cd '$wRepo' && ANDROID_NDK=`${ANDROID_NDK:-`$HOME/x/ndk/android-ndk-r27c} scripts/build-phone.sh '$wX'"
if ($LASTEXITCODE -ne 0) { throw "phone build failed" }
Write-Host "Done: $Repo\build\phone\signed  (connect the phone, then run install.ps1 from that folder)"
