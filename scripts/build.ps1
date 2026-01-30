param(
  [Parameter(Position = 0)]
  [ValidateSet('Win32', 'x64')]
  [string]$Platform = 'Win32',

  [Parameter(Position = 1)]
  [ValidateSet('Debug', 'Release')]
  [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$solution = Join-Path $root 'PEInfo.sln'

if (-not (Test-Path -LiteralPath $solution)) {
  throw "Solution not found: $solution"
}

function Find-MSBuild {
  $cmd = Get-Command msbuild.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Path }

  $candidates = @(
    Join-Path $env:ProgramFiles 'Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe'
    Join-Path $env:ProgramFiles 'Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe'
    Join-Path $env:ProgramFiles 'Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
    Join-Path $env:ProgramFiles 'Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe'
    Join-Path $env:ProgramFiles 'Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe'
  )

  foreach ($p in $candidates) {
    if (Test-Path -LiteralPath $p) { return $p }
  }

  $vsRoot2022 = Join-Path $env:ProgramFiles 'Microsoft Visual Studio\2022'
  if (Test-Path -LiteralPath $vsRoot2022) {
    $found = Get-ChildItem -Path $vsRoot2022 -Recurse -Filter MSBuild.exe -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -match '\\MSBuild\\Current\\Bin\\MSBuild\.exe$' } |
      Select-Object -First 1
    if ($found) { return $found.FullName }
  }

  return $null
}

$msbuild = Find-MSBuild
if (-not $msbuild) {
  throw 'msbuild.exe not found. Install Visual Studio (with C++ toolchain) or run from a Developer Command Prompt.'
}

Write-Host "MSBuild: $msbuild"
Write-Host "Solution: $solution"
Write-Host "Config/Platform: $Configuration/$Platform"

& $msbuild $solution /t:Clean /p:Configuration=$Configuration /p:Platform=$Platform | Write-Host
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $msbuild $solution /m /p:Configuration=$Configuration /p:Platform=$Platform | Write-Host
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$outDir = if ($Platform -eq 'x64') { Join-Path $root "x64\$Configuration" } else { Join-Path $root $Configuration }
$exePath = Join-Path $outDir 'PEInfo.exe'
$pdbPath = Join-Path $outDir 'PEInfo.pdb'

if (-not (Test-Path -LiteralPath $exePath)) {
  throw "Output not found: $exePath"
}

$staging = Join-Path $root "dist\$Platform\$Configuration"
New-Item -ItemType Directory -Force -Path $staging | Out-Null

Copy-Item -LiteralPath $exePath -Destination (Join-Path $staging 'PEInfo.exe') -Force
if (Test-Path -LiteralPath $pdbPath) {
  Copy-Item -LiteralPath $pdbPath -Destination (Join-Path $staging 'PEInfo.pdb') -Force
}

$zipPath = Join-Path $root "dist\PEInfo_${Platform}_${Configuration}.zip"
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zipPath -Force

Write-Host "Done: $zipPath"
