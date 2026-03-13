param(
  [string]$Version = "",
  [string]$BinaryPath = "",
  [string]$OutputDir = "",
  [string]$BannerPath = ""
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

if (-not $BannerPath) {
  $bannerCandidates = @(
    (Join-Path $root "assets\installer-banner.png"),
    (Join-Path $root "assets\installer-banner.jpg"),
    (Join-Path $root "assets\installer-banner.jpeg")
  )
  foreach ($candidate in $bannerCandidates) {
    if (Test-Path $candidate) {
      $BannerPath = $candidate
      break
    }
  }
}

$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) {
  throw "WiX CLI not found. Install with: dotnet tool install --global wix"
}

function Ensure-WixUiExtension {
  $listOutput = (& wix extension list 2>$null | Out-String)
  if ($LASTEXITCODE -eq 0 -and $listOutput -match "WixToolset.UI.wixext") {
    return $true
  }

  $wixVersion = ((& wix --version 2>$null | Select-Object -First 1) -as [string]).Trim()
  if ($wixVersion) {
    & wix extension add "WixToolset.UI.wixext/$wixVersion" 2>$null
  }
  if ($LASTEXITCODE -ne 0) {
    & wix extension add WixToolset.UI.wixext 2>$null
  }
  if ($LASTEXITCODE -ne 0) {
    if ($wixVersion) {
      & wix extension add -g "WixToolset.UI.wixext/$wixVersion" 2>$null
    }
  }
  if ($LASTEXITCODE -ne 0) {
    & wix extension add -g WixToolset.UI.wixext 2>$null
  }

  $listOutput = (& wix extension list 2>$null | Out-String)
  return ($LASTEXITCODE -eq 0 -and $listOutput -match "WixToolset.UI.wixext")
}

$work = Join-Path $env:TEMP ("endoriumfort-msi-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work -Force | Out-Null

function Convert-ImageToBmp {
  param(
    [Parameter(Mandatory = $true)][string]$SourcePath,
    [Parameter(Mandatory = $true)][string]$DestinationPath,
    [Parameter(Mandatory = $true)][int]$Width,
    [Parameter(Mandatory = $true)][int]$Height
  )

  Add-Type -AssemblyName System.Drawing

  $src = [System.Drawing.Image]::FromFile($SourcePath)
  try {
    $bmp = New-Object System.Drawing.Bitmap($Width, $Height)
    try {
      $graphics = [System.Drawing.Graphics]::FromImage($bmp)
      try {
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $graphics.Clear([System.Drawing.Color]::White)

        $scaleX = [double]$Width / [double]$src.Width
        $scaleY = [double]$Height / [double]$src.Height
        $scale = [Math]::Min($scaleX, $scaleY)

        $drawWidth = [int][Math]::Round($src.Width * $scale)
        $drawHeight = [int][Math]::Round($src.Height * $scale)
        $offsetX = [int][Math]::Floor(($Width - $drawWidth) / 2)
        $offsetY = [int][Math]::Floor(($Height - $drawHeight) / 2)

        $graphics.DrawImage($src, $offsetX, $offsetY, $drawWidth, $drawHeight)
      }
      finally {
        $graphics.Dispose()
      }
      $bmp.Save($DestinationPath, [System.Drawing.Imaging.ImageFormat]::Bmp)
    }
    finally {
      $bmp.Dispose()
    }
  }
  finally {
    $src.Dispose()
  }
}

try {
  Copy-Item $BinaryPath (Join-Path $work "endoriumfort-agent.exe") -Force
  $logoIconPng = Join-Path $root "assets\logo-icon-dark.png"
  $logoFullPng = Join-Path $root "assets\logo-full-blue.png"
  if (-not (Test-Path $logoIconPng)) {
    throw "Logo not found: $logoIconPng"
  }
  if (-not (Test-Path $logoFullPng)) {
    throw "Logo not found: $logoFullPng"
  }
  Copy-Item $logoIconPng (Join-Path $work "logo-icon-dark.png") -Force
  Copy-Item $logoFullPng (Join-Path $work "logo-full-blue.png") -Force

  $uiBlock = ""
  $wixBuildExtArgs = @()
  if ($BannerPath) {
    if (-not (Test-Path $BannerPath)) {
      throw "Banner not found: $BannerPath"
    }

    $bannerBmp = Join-Path $work "installer-banner.bmp"
    $dialogBmp = Join-Path $work "installer-dialog.bmp"
    Convert-ImageToBmp -SourcePath $BannerPath -DestinationPath $bannerBmp -Width 493 -Height 58
    Convert-ImageToBmp -SourcePath $BannerPath -DestinationPath $dialogBmp -Width 493 -Height 312

    if (Ensure-WixUiExtension) {
      $uiBlock = @"
    <ui:WixUI Id="WixUI_Minimal" />
    <WixVariable Id="WixUIBannerBmp" Value="$($bannerBmp.Replace('\\','\\\\'))" />
    <WixVariable Id="WixUIDialogBmp" Value="$($dialogBmp.Replace('\\','\\\\'))" />
"@
      $wixBuildExtArgs = @("-ext", "WixToolset.UI.wixext")
    }
    else {
      Write-Warning "WixToolset.UI.wixext not available; installer UI branding is skipped for this build."
    }
  }

  $wxsPath = Join-Path $work "EndoriumFortAgent.wxs"
  function Write-WixSource {
    param([string]$UiBlockContent)

    @"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs" xmlns:ui="http://wixtoolset.org/schemas/v4/wxs/ui">
  <Package Name="EndoriumFort Agent"
           Manufacturer="EndoriumFort"
           Version="$Version"
           UpgradeCode="A6D3D8AC-5E00-4A58-A704-208A4E572901"
           Language="1033"
           Scope="perUser">

    <MediaTemplate EmbedCab="yes" />
${UiBlockContent}

    <StandardDirectory Id="ProgramFilesFolder">
      <Directory Id="INSTALLFOLDER" Name="EndoriumFort Agent" />
    </StandardDirectory>

    <StandardDirectory Id="ProgramMenuFolder">
      <Directory Id="ProgramMenuDir" Name="EndoriumFort Agent" />
    </StandardDirectory>

    <Feature Id="MainFeature" Title="EndoriumFort Agent" Level="1">
      <ComponentRef Id="AgentExe" />
      <ComponentRef Id="BrandAssets" />
      <ComponentRef Id="ProtocolRegistry" />
      <ComponentRef Id="StartMenuShortcut" />
    </Feature>

    <Component Id="AgentExe" Directory="INSTALLFOLDER" Guid="*">
      <File Id="AgentExeFile" Source="$($work.Replace('\','\\'))\\endoriumfort-agent.exe" KeyPath="yes" />
    </Component>

    <Component Id="BrandAssets" Directory="INSTALLFOLDER" Guid="*">
      <File Id="LogoIconPng" Source="$($work.Replace('\\','\\\\'))\\logo-icon-dark.png" />
      <File Id="LogoFullPng" Source="$($work.Replace('\\','\\\\'))\\logo-full-blue.png" />
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

    <Component Id="StartMenuShortcut" Directory="ProgramMenuDir" Guid="*">
      <Shortcut Id="StartMenuAgentShortcut"
                Name="EndoriumFort Agent"
                Target="[#AgentExeFile]"
                WorkingDirectory="INSTALLFOLDER"
                Description="EndoriumFort local agent" />
      <RemoveFolder Id="ProgramMenuDirCleanup" On="uninstall" />
      <RegistryValue Root="HKCU" Key="Software\\EndoriumFort\\Agent" Name="StartMenuShortcut" Type="integer" Value="1" KeyPath="yes" />
    </Component>
  </Package>
</Wix>
"@ | Set-Content -Path $wxsPath -Encoding UTF8
  }

  Write-WixSource -UiBlockContent $uiBlock

  $msiOut = Join-Path $OutputDir "EndoriumFortAgent-$Version-windows-amd64.msi"
  if (Test-Path $msiOut) {
    Remove-Item -Path $msiOut -Force
  }
  $wixBuildOutput = (& wix build $wxsPath -o $msiOut @wixBuildExtArgs 2>&1 | Out-String)
  $wixExitCode = $LASTEXITCODE

  if ($wixBuildOutput) {
    Write-Host $wixBuildOutput
  }

  if ($wixBuildExtArgs.Count -gt 0 -and $wixBuildOutput -match "WIX0144") {
    Write-Warning "WixToolset.UI.wixext could not be resolved at build time; retrying MSI build without UI branding."
    $uiBlock = ""
    $wixBuildExtArgs = @()
    Write-WixSource -UiBlockContent $uiBlock

    if (Test-Path $msiOut) {
      Remove-Item -Path $msiOut -Force
    }

    $wixBuildOutput = (& wix build $wxsPath -o $msiOut 2>&1 | Out-String)
    $wixExitCode = $LASTEXITCODE
    if ($wixBuildOutput) {
      Write-Host $wixBuildOutput
    }
  }

  if ($wixExitCode -ne 0) {
    throw "wix build failed with exit code $wixExitCode"
  }
  if (-not (Test-Path $msiOut)) {
    throw "wix build completed without generating MSI: $msiOut"
  }
  Write-Host "MSI created: $msiOut"
}
finally {
  Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
}
