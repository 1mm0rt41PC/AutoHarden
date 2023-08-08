# @brief This script is used to auto link all rules in all role with the exception of the following listed options.
$MyDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
Get-ChildItem -Recurse -Force $MyDir\*\*.ps1 |where { $_.LinkType } | Remove-Item
Get-ChildItem -Recurse -Force $MyDir\*\*.ask |where { $_.LinkType } | Remove-Item

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
	'Optimiz-CleanUpWindowFolder-MergeUpdate',
	'Harden-AppData',
	'Hardening-UAC-credz'
'@

# For each role do not apply theses rules
$blacklist = @"
{
	'Pentester': [
		'1.4-Firewall-BlockOutgoingSNMP',
		'Crapware-Onedrive',
		'Crapware-RemoveUseLessSoftware__Uninstall-OneNote',
		'Crapware-RemoveUseLessSoftware__Uninstall-Skype',
		'Optimiz-ClasicExplorerConfig',
		'Hardening-AccountRename',
		'1.5-Firewall-DisableNotification',
		'Hardening-Co-Installers',
		'Hardening-DLLHijacking',
		'Harden-AppData',
		'Hardening-UAC-credz'
	],
	'Home': [
		'1.4-Firewall-BlockOutgoingSNMP',
		'2-Hardening-HardDriveEncryption',
		'Crapware-Onedrive',
		'Crapware-RemoveUseLessSoftware__Uninstall-OneNote',
		'Crapware-RemoveUseLessSoftware__Uninstall-Skype',
		'Optimiz-DisableAutoUpdate',
		'Optimiz-DisableDefender',
		'Hardening-Co-Installers',
		'Harden-AppData',
		'Hardening-UAC-credz'
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
		'Optimiz-DisableAutoReboot',
		'Harden-AppData',
		'Hardening-UAC-credz'
	],
	'Corp-Servers': [
		$servers
	],
	'RELEASE': []
}
"@ | ConvertFrom-Json

$whitelist = @"
{
	'Corp-Workstations-LightST': [
		'0.0__init__0',
		'0.0__init__1-Conf',
		'0.0__init__2-Functions-Const',
		'0.0__init__2-Functions-logs',
		'0.0__init__2-Functions-RPC',
		'0.0__init__2-Functions',
		'0.0__init__3-IsAdmin',
		'0.0__init__4-MigrateLogs',
		'0.1-AutoScheduledTask',
		'1.0-Firewall-Functions',
		'1.1-Firewall-BasicRules',
		'1.1-Firewall-Malware',
		'1.4-Firewall-RPC',
		'1.5-Firewall-DisableNotification',
		'1.6-Firewall-AvoidSMBOnInternet',
		'1.6-Firewall-StealtMode',
		'2-Hardening-ADIDNS',
		'2-Hardening-HardDriveEncryption',
		'2-Hardening-Powershell',
		'Crapware-Cortana',
		'Crapware-DisableTelemetry-and-ADS',
		'Crapware-RemoveUseLessSoftware',
		'Crapware-Windows10UpgradeOldFolder',
		'Fix-CVE-2020-16898',
		'Fix-CVE-2022-30910-Follina',
		'Fix-HiveNightmare',
		'Fix-PetitPotam',
		'Harden-Adobe',
		'Harden-DisableShortPath',
		'Harden-Office',
		'Harden-VMWareWorkstation',
		'Harden-VoiceControl',
		'Harden-WindowsDefender',
		'Hardening-BlockAutoDiscover',
		'Hardening-BlockUntrustedFonts',
		'Hardening-CertPaddingCheck',
		'Hardening-Disable-C-FolderCreation',
		'Hardening-DisableCABlueCoat',
		'Hardening-DisableIPv6',
		'Hardening-DisableLLMNR',
		'Hardening-DisableMimikatz',
		'Hardening-DisableNetbios',
		'Hardening-DisableRemoteServiceManagement',
		'Hardening-DisableSMBServer',
		'Hardening-DisableWPAD',
		'Hardening-DNSCache',
		'Hardening-FileExtension',
		'Hardening-LDAP',
		'Hardening-Navigator',
		'Hardening-RemoteAssistance',
		'Hardening-SMB',
		'Hardening-UAC',
		'Hardening-Wifi-RemoveOpenProfile',
		'Hardening-Wifi',
		'Log-Activity',
		'Optimiz-CleanUpWindowFolder-MergeUpdate',
		'Optimiz-CleanUpWindowFolder',
		'Optimiz-CleanUpWindowsName',
		'Optimiz-cmd-color',
		'Optimiz-DisableAutoReboot',
		'Optimiz-DisableReservedStorageState',
		'Software-install-1-Functions',
		'Software-install-Logs',
		'ZZZ-10.Asks-Cleanup',
		'ZZZ-20.Firewall-Cleanup',
		'ZZZ-30.__END__'
	]
}
"@ | ConvertFrom-Json


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

$blacklist.PSObject.Properties | Select Name | foreach {
	$tragetFolderName=$_.Name;
	mkdir -Force $MyDir\$tragetFolderName | Out-Null
	New-Item -Force -ItemType file $MyDir\$tragetFolderName\.gitkeep
}


$symLinkList = New-Object -TypeName "System.Text.StringBuilder"
$symLinkList.AppendLine(".gitignore") | Out-Null
Get-ChildItem $MyDir\..\src\*.ps1 | foreach {
	$ps1Rule=$_.Name
	$FullName=$_.FullName
	$symLinkList.AppendLine("*/$ps1Rule") | Out-Null
	$blacklist.PSObject.Properties | Select Name | foreach {
		$tragetFolder=(Get-Item $_.Name).FullName;
		$tragetFolderName=$_.Name;
		if( -not ($blacklist."$tragetFolderName").Contains($ps1Rule.Replace('.ps1','')) ){
			if( -not [System.IO.File]::Exists("$tragetFolder\$ps1Rule") ){
				logInfo "[Blacklist] Create $tragetFolder\$ps1Rule"
				New-Item -Path $tragetFolder\$ps1Rule -ItemType SymbolicLink -Value $FullName | Out-Null
			}
			$askFullpath = $FullName.Replace('.ps1','.ask')
			$askName = $ps1Rule.Replace('.ps1','.ask')
			if( [System.IO.File]::Exists($askFullpath) -and -not [System.IO.File]::Exists("$tragetFolder\$askName") ){
				logInfo "[Blacklist] Create $tragetFolder\$askName"
				New-Item -Path "$tragetFolder\$askName" -ItemType SymbolicLink -Value $askFullpath | Out-Null
			}
		}
	}
	$whitelist.PSObject.Properties | Select Name | foreach {
		$tragetFolder=(Get-Item $_.Name).FullName;
		$tragetFolderName=$_.Name;
		if( -not [System.IO.File]::Exists("$tragetFolder\$ps1Rule") ){
			if( ($whitelist."$tragetFolderName").Contains($ps1Rule.Replace('.ps1','')) ){
				logInfo "[Whitelist]Create $tragetFolder\$ps1Rule"
				New-Item -Path $tragetFolder\$ps1Rule -ItemType SymbolicLink -Value $FullName | Out-Null
				$askFullpath = $FullName.Replace('.ps1','.ask')
				$askName = $ps1Rule.Replace('.ps1','.ask')
				if( [System.IO.File]::Exists($askFullpath) -and -not [System.IO.File]::Exists("$tragetFolder\$askName") ){
					logInfo "[Blacklist] Create $tragetFolder\$askName"
					New-Item -Path "$tragetFolder\$askName" -ItemType SymbolicLink -Value $askFullpath | Out-Null
				}
			}
		}
	}
}



Write-Host "Applying exception..."
$rules.PSObject.Properties | foreach {
	$webdomain=$_.Name
	Write-Host "Applying exception on $webdomain"
	$_.Value | foreach {
		logError "Ignore $MyDir\$webdomain\$_"
		Remove-Item $MyDir\$webdomain\${_}.* -ErrorAction SilentlyContinue | Out-Null
	}
}

$symLinkList.ToString() | Out-File -Encoding UTF8 "$MyDir\.gitignore"
Write-Host "All link established"
$host.SetShouldExit(0)
exit 0