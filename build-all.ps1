param(
  [string]$BackendBuildDir = "backend\build"
)

$ErrorActionPreference = "Stop"

Write-Host "[Frontend] Installing dependencies"
Push-Location "frontend"
if (-not (Test-Path "node_modules")) {
  npm install
}
Write-Host "[Frontend] Building"
npm run build
Pop-Location

Write-Host "[Backend] Configuring (MinGW Makefiles)"
Push-Location "backend"
cmake -S . -B $BackendBuildDir -G "MinGW Makefiles"
Write-Host "[Backend] Building"
cmake --build $BackendBuildDir
Pop-Location

Write-Host "Build complete."
