param(
  [string]$BuildDir = "build"
)

$ErrorActionPreference = "Stop"

cmake -S . -B $BuildDir -G "MinGW Makefiles"
cmake --build $BuildDir
