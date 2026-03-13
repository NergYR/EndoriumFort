$ErrorActionPreference = "Stop"

$baseKey = "HKCU:\Software\Classes\endoriumfort"
if (Test-Path $baseKey) {
  Remove-Item -Path $baseKey -Recurse -Force
  Write-Host "Protocol endoriumfort:// supprimé (HKCU)." -ForegroundColor Yellow
} else {
  Write-Host "Aucune installation HKCU trouvée." -ForegroundColor Yellow
}
