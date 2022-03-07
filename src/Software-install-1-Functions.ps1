################################################################################
# Installation de choco
#
if( !(Get-Command "choco" -errorAction SilentlyContinue) ){
	Write-Host "==============================================================================="
	Write-Host "Install: choco"
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Disable-NetFirewallRule
    iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Enable-NetFirewallRule
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
