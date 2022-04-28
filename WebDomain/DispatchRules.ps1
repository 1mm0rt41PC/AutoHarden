# @brief This script is used to auto link all rules in all role with the exception of the following listed options.
$MyDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
Get-ChildItem -Recurse -Force $MyDir\*\*.ps1 |where { $_.LinkType } | Remove-Item

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
		'Hardening-AccountRename',
		'1.5-Firewall-DisableNotification',
		'Hardening-Co-Installers',
		'Hardening-DLLHijacking'
	],
	'Home': [
		'1.4-Firewall-BlockOutgoingSNMP',
		'2-Hardening-HardDriveEncryption',
		'Crapware-Onedrive',
		'Crapware-RemoveUseLessSoftware__Uninstall-OneNote',
		'Crapware-RemoveUseLessSoftware__Uninstall-Skype',
		'Optimiz-DisableAutoUpdate',
		'Optimiz-DisableDefender',
		'Hardening-Co-Installers'
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
	'Corp-Workstations-LightST': [
		'1.4-Firewall-BlockOutgoingSNMP',
		'1.2-Firewall-Office',
		'1.3-Firewall-IE',
		'Crapware-Onedrive',		
		'Crapware-RemoveUseLessSoftware__Uninstall-OneNote',
		'Crapware-RemoveUseLessSoftware__Uninstall-Skype',
		'Hardening-AccountRename',
		'Hardening-DisableMimikatz__Mimikatz-DomainCredAdv',
		'Hardening-DisableMimikatz__CredentialsGuard',
		'Optimiz-ClasicExplorerConfig',
		'Optimiz-DisableAutoUpdate',
		'Optimiz-DisableDefender',		
		'Hardening-DLLHijacking',
		'Software-install-notepad++',
		'Harden-RDP-Credentials'
	],
	'Corp-Servers': [
		$servers
	],
	'RELEASE': []
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
$symLinkList = New-Object -TypeName "System.Text.StringBuilder"
$symLinkList.AppendLine(".gitignore") | Out-Null
Get-ChildItem $MyDir\..\src\*.ps1 | foreach {
	$ps1Rule=$_.Name
	$FullName=$_.FullName
	$symLinkList.AppendLine("*/$ps1Rule") | Out-Null
	Get-ChildItem -Directory $MyDir | foreach {
		$tragetFolder=$_.FullName;
		$tragetFolderName=$_.Name;
		if( -not [System.IO.File]::Exists("$tragetFolder\$ps1Rule") ){
			if( -not ($rules."$tragetFolderName").Contains($ps1Rule.Replace('.ps1','')) ){
				logInfo "Create $tragetFolder\$ps1Rule"
				New-Item -Path $tragetFolder\$ps1Rule -ItemType SymbolicLink -Value $FullName | Out-Null
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