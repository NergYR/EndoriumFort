param(
  [string]$Version = "",
  [string]$BinaryPath = "",
  [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
if (-not $Version) {
  $versionFile = Join-Path $root "agent\VERSION"
  if (Test-Path $versionFile) {
    $Version = (Get-Content $versionFile -Raw).Trim()
  }
}
if (-not $Version) {
  throw "Version is required (use -Version 1.2.3)"
}

if (-not $BinaryPath) {
  $BinaryPath = Join-Path $root "release\endoriumfort-agent-windows-amd64.exe"
}
if (-not (Test-Path $BinaryPath)) {
  throw "Binary not found: $BinaryPath"
}

if (-not $OutputDir) {
  $OutputDir = Join-Path $root "release\packages\windows"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) {
  throw "WiX CLI not found. Install with: dotnet tool install --global wix"
}

$work = Join-Path $env:TEMP ("endoriumfort-msi-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
  Copy-Item $BinaryPath (Join-Path $work "endoriumfort-agent.exe") -Force

  $wxsPath = Join-Path $work "EndoriumFortAgent.wxs"
  @"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="EndoriumFort Agent"
           Manufacturer="EndoriumFort"
           Version="$Version"
           UpgradeCode="A6D3D8AC-5E00-4A58-A704-208A4E572901"
           Language="1033"
           Scope="perUser">

    <StandardDirectory Id="ProgramFilesFolder">
      <Directory Id="INSTALLFOLDER" Name="EndoriumFort Agent" />
    </StandardDirectory>

    <Feature Id="MainFeature" Title="EndoriumFort Agent" Level="1">
      <ComponentRef Id="AgentExe" />
      <ComponentRef Id="ProtocolRegistry" />
    </Feature>

    <Component Id="AgentExe" Directory="INSTALLFOLDER" Guid="*">
      <File Id="AgentExeFile" Source="$($work.Replace('\','\\'))\\endoriumfort-agent.exe" KeyPath="yes" />
    </Component>

    <Component Id="ProtocolRegistry" Directory="INSTALLFOLDER" Guid="*">
      <RegistryKey Root="HKCU" Key="Software\\Classes\\endoriumfort">
        <RegistryValue Type="string" Value="URL:EndoriumFort Agent Protocol" KeyPath="yes" />
        <RegistryValue Name="URL Protocol" Type="string" Value="" />
      </RegistryKey>
      <RegistryKey Root="HKCU" Key="Software\\Classes\\endoriumfort\\DefaultIcon">
        <RegistryValue Type="string" Value="[#AgentExeFile],0" />
      </RegistryKey>
      <RegistryKey Root="HKCU" Key="Software\\Classes\\endoriumfort\\shell\\open\\command">
        <RegistryValue Type="string" Value="&quot;[#AgentExeFile]&quot; open-link &quot;%1&quot;" />
      </RegistryKey>
    </Component>
  </Package>
</Wix>
"@ | Set-Content -Path $wxsPath -Encoding UTF8

  $msiOut = Join-Path $OutputDir "EndoriumFortAgent-$Version-windows-amd64.msi"
  & wix build $wxsPath -o $msiOut
  Write-Host "MSI created: $msiOut"
}
finally {
  Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
}
