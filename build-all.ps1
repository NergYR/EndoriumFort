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

Write-Host "[Agent] Building EndoriumFortAgent"
Push-Location "agent"
$goPath = Get-Command go -ErrorAction SilentlyContinue
if ($goPath) {
  $env:GOOS = "windows"
  $env:GOARCH = "amd64"
  go build -o endoriumfort-agent.exe .
  Write-Host "[Agent] Built: agent\endoriumfort-agent.exe"
} else {
  Write-Host "[Agent] Go not found - skipping agent build"
}
Pop-Location

Write-Host "Build complete."
