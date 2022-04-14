# @brief This script is used to auto link all rules in all role with the exception of the following listed options.

# For all servers, do not apply the following scripts
$servers = @'
	'1.4-Firewall-BlockOutgoingSNMP',
	'2-Hardening-HardDriveEncryption',
	'Hardening-AccountRename',
	'Hardening-DisableMimikatz__CredentialsGuard',
	'Hardening-DisableMimikatz__Mimikatz-DomainCredAdv',
	'Hardening-DLLHijacking',
	'Optimiz-DisableAutoReboot',
	'Optimiz-DisableAutoUpdate',
	'Optimiz-DisableDefender',
	'Optimiz-DisableReservedStorageState',
	'Software-install',
	'Software-install-notepad++',
	'Optimiz-CleanUpWindowFolder-MergeUpdate'
'@

# For each role do not apply theses rules
$rules = @"
{
	'Pentester': [
		'1.4-Firewall-BlockOutgoingSNMP',
		'Crapware-Onedrive',
		'Crapware-RemoveUseLessSoftware__Uninstall-OneNote',
		'Crapware-RemoveUseLessSoftware__Uninstall-Skype',
		'Optimiz-ClasicExplorerConfig',
		'1.5-Firewall-DisableNotification'
	],
	'Home': [
		'1.4-Firewall-BlockOutgoingSNMP',
		'2-Hardening-HardDriveEncryption',
		'Crapware-Onedrive',
		'Crapware-RemoveUseLessSoftware__Uninstall-OneNote',
		'Crapware-RemoveUseLessSoftware__Uninstall-Skype',
		'Optimiz-DisableAutoUpdate',
		'Optimiz-DisableDefender'
	],
	'Corp-Workstations': [
		'1.4-Firewall-BlockOutgoingSNMP',
		'Crapware-Onedrive',
		'Crapware-RemoveUseLessSoftware__Uninstall-OneNote',
		'Crapware-RemoveUseLessSoftware__Uninstall-Skype',
		'Hardening-AccountRename',
		'Hardening-DisableMimikatz__Mimikatz-DomainCredAdv',
		'Optimiz-ClasicExplorerConfig',
		'Optimiz-DisableAutoUpdate',
		'Optimiz-DisableDefender',
		'Optimiz-DisableReservedStorageState',
		'Optimiz-CleanUpWindowFolder-MergeUpdate',
		'Hardening-DLLHijacking',
		'Optimiz-DisableAutoReboot'
	],
	'Corp-Servers': [
		$servers
	],
	'Corp-DomainControllers': [
		$servers,
		'Hardening-DisableSMBServer',
		'1.6-Firewall-AvoidSMBOnInternet',
		'2-Hardening-RPCFiltering'
	],
	'Corp-FileServers': [
		$servers,
		'Hardening-DisableSMBServer',
		'2-Hardening-RPCFiltering'
	],
	'RELEASE': []
}
"@ | ConvertFrom-Json

$MyDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)

function logInfo( $msg )
{
	Write-Host -NoNewline -Background 'Blue' '[i]'
	Write-Host " $msg"
}
function logError( $msg )
{
	Write-Host -NoNewline -Background 'Red' '[X]'
	Write-Host " $msg"
}

Get-ChildItem $MyDir\..\src\*.ps1 | foreach {
	$ps1Rule=$_.Name
	$FullName=$_.FullName
	Get-ChildItem -Directory $MyDir | foreach {
		$tragetFolder=$_.FullName;
		$tragetFolderName=$_.Name;
		if( -not [System.IO.File]::Exists("$tragetFolder\$ps1Rule") ){
			if( -not ($rules."$tragetFolderName").Contains($ps1Rule.Replace('.ps1','')) ){
				logInfo "Create $tragetFolder\$ps1Rule"
				New-Item -Path $tragetFolder\$ps1Rule -ItemType SymbolicLink -Value $FullName | Out-Null
			}else{
				logError "Ignore $tragetFolder\$ps1Rule"
				Remove-Item $tragetFolder\$ps1Rule -ErrorAction SilentlyContinue | Out-Null
			}
		}
	}
}
