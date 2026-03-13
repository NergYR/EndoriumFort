param(
  [string]$AgentPath = ""
)

$ErrorActionPreference = "Stop"

if (-not $AgentPath) {
  $root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
  $candidate = Join-Path $root "endoriumfort-agent.exe"
  if (Test-Path $candidate) {
    $AgentPath = $candidate
  }
}

if (-not $AgentPath -or -not (Test-Path $AgentPath)) {
  throw "Agent introuvable. Passez -AgentPath vers endoriumfort-agent.exe"
}

$AgentPath = (Resolve-Path $AgentPath).Path
$baseKey = "HKCU:\Software\Classes\endoriumfort"
$commandKey = "$baseKey\shell\open\command"

New-Item -Path $baseKey -Force | Out-Null
Set-ItemProperty -Path $baseKey -Name "(default)" -Value "URL:EndoriumFort Agent Protocol" -Force
Set-ItemProperty -Path $baseKey -Name "URL Protocol" -Value "" -Force

New-Item -Path "$baseKey\DefaultIcon" -Force | Out-Null
Set-ItemProperty -Path "$baseKey\DefaultIcon" -Name "(default)" -Value "\"$AgentPath\",0" -Force

New-Item -Path $commandKey -Force | Out-Null
$command = "\"$AgentPath\" open-link \"%1\""
Set-ItemProperty -Path $commandKey -Name "(default)" -Value $command -Force

Write-Host "Protocol endoriumfort:// installé pour l'utilisateur courant." -ForegroundColor Green
Write-Host "Commande associée: $command"