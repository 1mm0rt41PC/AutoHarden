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
	]
}
"@ | ConvertFrom-Json


# Recreate all rules for each role
$rules | Get-Member -MemberType NoteProperty  | foreach {
	$key=$_.Name;
	Get-ChildItem -Attribute ReparsePoint $key\* | Remove-Item
	Get-ChildItem RELEASE\*.ps1 | foreach {
		$Name=$_.Name
		$FullName=$_.FullName
		New-Item -Path $key\$Name -ItemType SymbolicLink -Value $FullName
	}
	$rules."$key" | foreach {
		Remove-Item $key\$_.ps1
	}
}