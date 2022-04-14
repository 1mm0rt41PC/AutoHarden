################################################################################
# Installation de choco
#
if( !(Get-Command "choco" -errorAction SilentlyContinue) ){
	Write-Host "==============================================================================="
	Write-Host "Install: choco"
    mywget https://chocolatey.org/install.ps1 | Out-String | iex
}
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\ProgramData\chocolatey\bin"
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\ProgramData\chocolatey\lib"
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\ProgramData\chocolatey\tools"
Add-MpPreference -ExclusionPath "C:\ProgramData\chocolatey\bin"
Add-MpPreference -ExclusionPath "C:\ProgramData\chocolatey\lib"
Add-MpPreference -ExclusionPath "C:\ProgramData\chocolatey\tools"

################################################################################
# Installation des soft de base
#
function chocoInstall( $pk )
{
	if( "$global:chocoList" -Match "$pk" ){
		return ;
	}
	Write-Host "==============================================================================="
	Write-Host "Install: $pk"
	choco install $pk -y
}
$global:chocoList = & choco list -localonly
choco upgrade all -y
