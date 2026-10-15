# The Chocolatey channel (CLOUD-2298): install the MSI this package carries,
# through Chocolatey's own MSI installer, then drop the embedded copy.
$ErrorActionPreference = 'Stop'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'msi'
  file64         = Join-Path $toolsDir 'batten-x86_64-pc-windows-gnu.msi'
  silentArgs     = '/qn /norestart'
  validExitCodes = @(0, 3010, 1641)
}
Install-ChocolateyInstallPackage @packageArgs
Remove-Item -Force -ErrorAction SilentlyContinue $packageArgs.file64
