# AutoHarden - A simple script that automates Windows Hardening
#
# Filename: AutoHarden_Corp-Workstations.ps1
# Author: 1mm0rt41PC - immortal-pc.info - https://github.com/1mm0rt41PC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# Update: 2021-09-17-20-45-33
$AutoHarden_version="2021-09-17-20-45-33"
$global:AutoHarden_boradcastMsg=$true
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
Add-Type -AssemblyName System.Windows.Forms
$AutoHarden_Folder='C:\Windows\AutoHarden'
$AutoHarden_Logs="${AutoHarden_Folder}\logs"
$AutoHarden_AsksFolder="${AutoHarden_Folder}\asks"
$AutoHarden_Group='Corp-Workstations'
$AutoHarden_Asks=($AutoHarden_Group -eq 'RELEASE')
$AutoHarden_WebDomain="https://raw.githubusercontent.com/1mm0rt41PC/HowTo/master/Harden/Windows/AutoHarden_${AutoHarden_Group}.ps1"
$AutoHarden_IP4Admins=@()
$AutoHarden_IP4Users=@()
$AutoHarden_IP4VPN=@()
###############################################################################
# FUNCTIONS
$askMigration = ConvertFrom-StringData -StringData @'
0.1-AutoUpdate.ask = 0-AutoUpdate.ask
1.2-Firewall-Office.ask = block-communication-for-excel,word.ask
1.3-Firewall-IE.ask = block-communication-for-InternetExplorer.ask
1.1-Firewall-Malware.ask = block-communication-for-powershell,eviltools.ask
Hardening-DisableMimikatz__CredentialsGuard.ask = CredentialsGuard.ask
1.4-Firewall-BlockOutgoingSNMP.ask = Hardening-BlockOutgoingSNMP.ask
Hardening-DisableMimikatz__Mimikatz-DomainCredAdv.ask = Mimikatz-DomainCred.ask
Crapware-RemoveUseLessSoftware__Uninstall-OneNote.ask = Uninstall-OneNote.ask
Crapware-RemoveUseLessSoftware__Uninstall-Skype.ask = Uninstall-Skype.ask
'@

$isLaptop = (Get-WmiObject -Class win32_systemenclosure | Where-Object { $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 -or $_.chassistypes -eq 14}).Count -gt 0 -And (Get-WmiObject -Class win32_battery).Name -ne ''

$getRole = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
$getRole = @{
	"WinNT"     = "WorkStation";
	"LanmanNT"  = "Domain Controller";
	"ServerNT"  = "Server";
}[$getRole.ProductType];

$isDomainLinked = ( "\\$($env:COMPUTERNAME)" -eq $env:LOGONSERVER -And  $getRole -eq "Domain Controller" ) -Or "\\$($env:COMPUTERNAME)" -ne $env:LOGONSERVER
###############################################################################
# FUNCTIONS
function logInfo( $msg )
{
	Write-Host -NoNewline -Background 'Blue' '[i]'
	Write-Host " $msg"
}
function logSuccess( $msg )
{
	Write-Host -NoNewline -Background 'Green' '[v]'
	Write-Host " $msg"
}
function logError( $msg )
{
	Write-Host -NoNewline -Background 'Red' '[X]'
	Write-Host " $msg"
}
###############################################################################
# FUNCTIONS
$RpcRules = (netsh rpc filter show filter).Replace(' ','')

function addRpcAcl( $name='', $uuid=@(), $acl='' )
{
	if( $uuid.Count -gt 0 -Or $uuid -ne '' ){
		$acl = $uuid | foreach {
			return RpcRuleCreator $_ $name
		}
	}
	if( $acl -eq '' ){
		return $null;
	}
	$acl = @"
rpc
filter
$acl
quit
"@
	netsh -f (createTempFile $acl)
	netsh rpc filter show filter
}


# Add a rule to drop access to EFS for non DA
# From: https://twitter.com/tiraniddo/status/1422223511599284227
# From: https://gist.github.com/tyranid/5527f5559041023714d67414271ca742
function RpcRuleCreator( $uuid, $name )
{
	$1st_uuid=$uuid.Split('-')[0]
	if( $RpcRules -Like "*$uuid*" -Or $RpcRules -Like "*$1st_uuid*" ){
		logSuccess "RpcRules is already applied for $name => $uuid"
		return '';
	}
	$ret = '';
	if( $isDomainLinked ){
		logSuccess "RpcRules applied for $name with DOMAIN support => $uuid"
		$ret = @"
add rule layer=um actiontype=permit
add condition field=if_uuid matchtype=equal data=$uuid
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;DA)
add filter

"@
	}else{
		logSuccess "RpcRules applied for $name withOUT DOMAIN support => $uuid"
	}
	return $ret+@"
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=$uuid
add filter

"@
}
###############################################################################
# FUNCTIONS

function ask( $query, $config )
{
	if( [System.IO.File]::Exists("${AutoHarden_AsksFolder}\${config}") ){
		Write-Host "# [${AutoHarden_AsksFolder}\${config}] Exist => Using the new file location"
		return _ask $query $config $AutoHarden_AsksFolder
	}
	if( [System.IO.File]::Exists("${AutoHarden_Folder}\${config}") ){
		Write-Host "# [${AutoHarden_Folder}\${config}] The new 'ask' location doesn't exist but the old one exist => Using the old file location"
		$ret = _ask $query $config $AutoHarden_Folder
		[System.IO.File]::WriteAllLines("${AutoHarden_AsksFolder}\${config}", "$ret", (New-Object System.Text.UTF8Encoding $False));
		Remove-Item -Force "${AutoHarden_Folder}\${config}" -ErrorAction Ignore;
		return $ret;
	}
	if( $askMigration.Contains($config) ){
		if( [System.IO.File]::Exists("${AutoHarden_Folder}\$($askMigration[$config])") ){
			Write-Host "# [${AutoHarden_AsksFolder}\${config}] Not found but the old configuration exist ${AutoHarden_Folder}\$($askMigration[$config])"
			$ret=cat "${AutoHarden_Folder}\$($askMigration[$config])" -ErrorAction Ignore;
			if( $config -eq 'Hardening-DisableMimikatz__Mimikatz-DomainCredAdv.ask' ){
				if( $ret -eq 'Yes' ){
					$ret = 'No'
				}else{
					$ret = 'Yes'
				}
			}
			[System.IO.File]::WriteAllLines("${AutoHarden_AsksFolder}\${config}","$ret", (New-Object System.Text.UTF8Encoding $False));
			Remove-Item -Force $AutoHarden_Folder\$askMigration[$config] -ErrorAction Ignore;
			return $ret -eq 'Yes';
		}
	}	
	Write-Host "# [${AutoHarden_AsksFolder}\${config}] This parameter is new and doesn't exist at all"
	return _ask $query $config $AutoHarden_AsksFolder
}


function _ask( $query, $config, $folder )
{
	$ret=cat "${folder}\${config}" -ErrorAction Ignore;
	logInfo "[${folder}\${config}] Checking..."
	try{
		if( [string]::IsNullOrEmpty($ret) ){
			logInfo "[${folder}\${config}] Undefined... Asking"
			if( $AutoHarden_Asks ){
				$ret = 'No'
				if( -not [Environment]::UserInteractive ){
					throw 'UserNotInteractive'
				}
				Write-Host ""
				do{
					$ret = (Read-Host "${query}? (Y/n)").substring(0,1).toupper()
				}while( $ret -ne 'Y' -and $ret -ne 'N' -and $ret -ne '' );
				if( $ret -eq 'Y' ){
					$ret = 'Yes'
				}else{
					$ret = 'No'
				}				
				logInfo "[${folder}\${config}] Admin said >$ret<"
			}else{
				logInfo "[${folder}\${config}] AutoManagement ... NOASKING => YES"
				$ret = 'Yes'
			}
			[System.IO.File]::WriteAllLines("${AutoHarden_AsksFolder}\${config}","$ret", (New-Object System.Text.UTF8Encoding $False));
		}
		logSuccess "[${folder}\${config}] is >$ret<"
		return $ret -eq 'Yes' -Or $ret -eq 'True';
	}catch{
		logError "[${folder}\${config}][WARN] An update of AutoHarden require an action from the administrator."
		if( $global:AutoHarden_boradcastMsg -And $AutoHarden_Asks ) {
			$global:AutoHarden_boradcastMsg=$false
			msg * "An update of AutoHarden require an action from the administrator. Please run ${AutoHarden_Folder}\AutoHarden.ps1"
		}
		return $false;
	}
}


function createTempFile( $data, [Parameter(Mandatory=$false)][string]$ext='' )
{
	$tmpFileName = -join ((65..90) + (97..122) | Get-Random -Count 25 | % {[char]$_});
	$tmpFileName = "${AutoHarden_Folder}\${tmpFileName}${ext}"
	[System.IO.File]::WriteAllLines($tmpFileName, $data, (New-Object System.Text.UTF8Encoding $False));
	return $tmpFileName;
}
if( ![bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") ){  Write-Host -BackgroundColor Red -ForegroundColor White "Administrator privileges required ! This terminal has not admin priv. This script ends now !"; pause;exit;}
mkdir $AutoHarden_Folder -Force -ErrorAction Continue | Out-Null
mkdir $AutoHarden_Logs -Force -ErrorAction Continue | Out-Null
mkdir $AutoHarden_AsksFolder -Force -ErrorAction Continue | Out-Null
Move-Item -ErrorAction SilentlyContinue -Force ${AutoHarden_Folder}\*.log ${AutoHarden_Logs}
Move-Item -ErrorAction SilentlyContinue -Force ${AutoHarden_Folder}\*.7z ${AutoHarden_Logs}
$AutoHardenTransScriptLog = "${AutoHarden_Logs}\Activities_${AutoHarden_Group}_"+(Get-Date -Format "yyyy-MM-dd")+".log"
Start-Transcript -Force -IncludeInvocationHeader -Append ($AutoHardenTransScriptLog)
#$DebugPreference = "Continue"
#$VerbosePreference = "Continue"
$InformationPreference = "Continue"
####################################################################################################
logInfo "Asking questions for the configuration"
ask "Execute AutoHarden every day at 08h00 AM" "0.1-AutoUpdate.ask"
ask "Block Internet communication for evil tools ? This filtering prevents viruses from downloading the payload." "1.1-Firewall-Malware.ask"
ask "Block Internet communication for Word and Excel ? Excel and Word will still be able to access files on local network shares. This filtering prevents viruses from downloading the payload." "1.2-Firewall-Office.ask"
ask "Block Internet communication for 'Internet Explorer' ? 'Internet Explorer' will still be able to access web server on local network. This filtering prevents viruses from downloading the payload." "1.3-Firewall-IE.ask"
ask "Avoid sending notification to Users about the firewall" "1.5-Firewall-DisableNotification.ask"
ask "Encrypt the HardDrive C:" "2-Hardening-HardDriveEncryption.ask"
ask "Disable Cortana in Windows search bar" "Crapware-Cortana.ask"
ask "Disable voice control" "Harden-VoiceControl.ask"
ask "Do you want to enable 'Credentials Guard' and disable VMWare/VirtualBox" "Hardening-DisableMimikatz__CredentialsGuard.ask"
ask "Disable Remote Assistance on this computer" "Hardening-RemoteAssistance.ask"
ask "Replace notepad with notepad++" "Software-install-notepad++.ask"
logSuccess "All asks have been processed"
####################################################################################################
echo "####################################################################################################"
echo "# 0.1-AutoUpdate"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "0.1-AutoUpdate" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 0.1-AutoUpdate"
if( ask "Execute AutoHarden every day at 08h00 AM" "0.1-AutoUpdate.ask" ){
# Install cert to avoid git takeover
$AutoHardenCert = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"
[IO.File]::WriteAllBytes($AutoHardenCert, [Convert]::FromBase64String("MIIFGTCCAwGgAwIBAgIQlPiyIshB45hFPPzNKE4fTjANBgkqhkiG9w0BAQ0FADAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBMB4XDTE5MTAyOTIxNTUxNVoXDTM5MTIzMTIzNTk1OVowFTETMBEGA1UEAxMKQXV0b0hhcmRlbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALrMv49xZXZjF92Xi3cWVFQrkIF+yYNdU3GSl1NergVq/3WmT8LDpaZ0XSpExZ7soHR3gs8eztnfe07r+Fl+W7l6lz3wUGFt52VY17WCa53tr5dYRPzYt2J6TWT874tqZqlo+lUl8ONK1roAww2flcDajm8VUXM0k0sLM17H9NLykO3DeBuh2PVaXUxGDej+N8PsYF3/7Gv2AW0ZHGflrondcXb2/eh8xwbwRENsGaMXvnGr9RWkufC6bKq31J8BBnP+/65M6541AueBoH8pLbANPZgHKES+8V9UWlYKOeSoeBhtL1k3Rr8tfizRWx1zg/pBNL0WTOLcusmuJkdHkdHbHaW6Jc/vh06Cs6xqz9/Dkg+K3BvOmfwZfAjl+qdgzM8dUU8/GWhswngwLAz64nZ82mZv/Iw6egC0rj5MYV0tpEjIgtVVgHavUfyXoIETNXFQR4SoK6PfeVkEzbRh03xhU65MSgBgWVv1YbOtdgXK0MmCs3ngVPJdVaqBjgcrK++X3Kxasb/bOkcfQjff/EK+BPb/xs+pXEqryYbtbeX0v2rbV9cugPUj+mneucZBLFjuRcXhzVbXLrwXVne7yTD/sIKfe7dztzchg19AY6/qkkRkroaKLASpfCAVx2LuCgeFGn//QaEtCpFxMo2dcnW2a+54pkzrCRTRg1N2wBQFAgMBAAGjYjBgMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEkGA1UdAQRCMECAEPp+TbkVy9u5igk2CqcX2OihGjAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBghBrxVMud93NnE/XjEko2+2HMA0GCSqGSIb3DQEBDQUAA4ICAQAQLtHeMr2qJnfhha2x2aCIApPjfHiHT4RNPI2Lq71jEbTpzdDFJQkKq4R3brGcpcnuU9VjUwz/BgKer+SFpkwFwTHyJpEFkbGavNo/ez3bqoehvqlTYDJO/i2mK0fvKmShfne6dZT+ftLpZCP4zngcANlp+kHy7mNRMB+LJv+jPc0kJ2oP4nIsLejyfxMj0lXuTJJRhxeZssdh0tq4MZP5MjSeiE5/AMuKT12uJ6klNUFS+OlEpZyHkIpgy4HxflXSvhchJ9U1YXF2IQ47WOrqwCXPUinHKZ8LwB0b0/35IlRCpub5KdRf803+4Okf9fL4rfc1cg9ZbLxuK9neFg1+ESL4aPyoV03TbN7Cdsd/sfx4mJ8jXJD+AXZ1ZofAAapYf9J5C71ChCZlhIGBvVc+dTUCWcUYgNOD9Nw+NiV6mARmVHl9SFL7yEtNYFgo0nWiNklqMqBLDxmrrD27sgBpFUwbMZ52truQwaaSHD7hFb4Tb1B0JVaGoog3QfNOXaFeez/fAt5L+yo78cDm7Q2tXvy2g0xDAL/TXn7bhtDzQunltBzdULrJEQO4zI0h8YgmF88a0zYZ9HRkDUn6dR9+G8TlZuUsWSOdvLdEvad9RqiHKeSrL6qgLBT5kqVt6AFsEtmFNz1s7xpsw/zPZvIXtQTmb4h+GcE/b2sUFZUkRA=="))
Import-Certificate -Filepath $AutoHardenCert -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
$AutoHardenCertCA = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"
[IO.File]::WriteAllBytes($AutoHardenCertCA, [Convert]::FromBase64String("MIIFHDCCAwSgAwIBAgIQa8VTLnfdzZxP14xJKNvthzANBgkqhkiG9w0BAQ0FADAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBMB4XDTE5MTAyOTIxNTUwOVoXDTM5MTIzMTIzNTk1OVowGDEWMBQGA1UEAxMNQXV0b0hhcmRlbi1DQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANlm8tv2IqVairIP90RnIsNlQYPMAvUwRcC6Nw+0Qlv56tWczvMl9IF0+h2vUF5+lnSEkJMGBqeLFaJgSo9lNyHeTfjjqpEcMVBw1nXl6VSfNiirD7fJTkyZ3rl63PsOwbfWCPDW1AvLufYhBiijPlK1k4RJFkiFZbZkpe5ys0uY4QVFj+ZTaW0EA0MncX2YZ775QnX7HJO0HfMcHGGTxOPhAqJ7Pp+IBrs75laaASekJSTVub7jqs5aeApQkUWgKel1fmK0tBv35deE1P5ABXi+KnuzWCZDU8znIDAnj1qz+6c21KKhslEdzYlRSlq4kPcF964GECxRtgq0z1pzhV/WvBJjWjNp3G5e8jUfjuAg2utF/xd/j7GNU8vllDAXFjl4czc1saGZDcU8a/uaweKMjqR4WfyUp/H/mB7JFJlOHBGTRszWaAU/4E0V+bICXNI5augkV29ci0HouBG3WFcQiA5q+1U2vY/scVyMPm8ZecCe2b+SD/ipPtFspcOPStRm5EQgL4CWdVpSmm8+JRO0NcrSnQtNPCwPBT3c7OLOwYLBl8WHcJG1yOJtQvLjv1koMmJkHR0djODx8Ig9fqAFLH0c694E6VJbojDVGp/LRR9LnJnzYlWAYoT3ScPQ9uesgr4x8VSnrM6cMG3ASQD92RVXKCDep/Rq29IXtvjpAgMBAAGjYjBgMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEkGA1UdAQRCMECAEPp+TbkVy9u5igk2CqcX2OihGjAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBghBrxVMud93NnE/XjEko2+2HMA0GCSqGSIb3DQEBDQUAA4ICAQDBiDwoVi2YhWzlMUTE5JHUUUkGkTaMVKfjYBFiUHeQQIaUuSq3dMRPlfpDRSzt3TW5mfwcPdwwatE0xeGN3r3zyQgnzEG/vMVrxwkgfFekVYvE4Ja551MSkwAA2fuTHGsRB9tEbTrkbGr35bXZYxOpGHpZIifFETFCT6rOpheDdxOEU6YyLeIYgGdGCmKStJ3XSkvqBh7oQ45M0+iqX9yjJNGoUg+XMLnk4K++7rxIk/SGtUBuIpsB3ksmIsXImelUxHw3xe6nGkkncAm9yX7rTU1M1fqrxaoBiGvx9jlqxDVMIzzDga7vKXDsP/iUmb4feeTIoy7+SgqGWsSvRiLt6A5CeIQ5XaTrhWN+mbGq6vvFTZuctY6LzdufwhlbZXFmfU/LnsRprM2EzYfba8VZmmfMBBpnYrw5q/3d5f9OSmNkRQjs0HfVab9b44hWNUd2QJ6yvjM5gdB367ekVagLpVdb/4mwzKOlspDULSlT7rAeuOc1njylu80pbBFCNiB72AmWNbqEK48ENloUr75NhuTKJ74llj+Nt6g9zDzsXuFICyJILvgE8je87GQXp+712aSGqJBLiGTFjuS3UctJ8qdlf5zkXw6mMB52/M3QYg6vI+2AYRc2EQXRvm8ZSlDKYidp9mZF43EcXFVktnK87x+TKYVjnfTGomfLfAXpTg=="))
Import-Certificate -Filepath $AutoHardenCertCA -CertStoreLocation Cert:\LocalMachine\AuthRoot | Out-Null
	
$Trigger = New-ScheduledTaskTrigger -At 08:00am -Daily
#$Action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec AllSigned -nop -File C:\Windows\AutoHarden\AutoHarden.ps1 > C:\Windows\AutoHarden\ScheduledTask.log"
$Action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec ByPass -nop -File ${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1 > ${AutoHarden_Logs}\ScheduledTask_${AutoHarden_Group}.log"
$Setting = New-ScheduledTaskSettingsSet -RestartOnIdle -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)
Register-ScheduledTask -TaskName "AutoHarden_${AutoHarden_Group}" -Trigger $Trigger -User "NT AUTHORITY\SYSTEM" -Action $Action -RunLevel Highest -Settings $Setting -Force | Out-Null
if( ask "Auto update AutoHarden every day at 08h00 AM" "0-AutoUpdateFromWeb.ask" ){
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Disable-NetFirewallRule
	$tmpPS1 = -join ((65..90) + (97..122) | Get-Random -Count 25 | % {[char]$_})
	$tmpPS1 = "${AutoHarden_Folder}\${tmpPS1}.ps1"
	Invoke-WebRequest -Uri $AutoHarden_WebDomain -OutFile $tmpPS1 | Out-Null
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Enable-NetFirewallRule
	if( (Get-AuthenticodeSignature $tmpPS1).Status -eq [System.Management.Automation.SignatureStatus]::Valid ){
		logSuccess 'The downloaded PS1 has a valid signature !'
		move -force $tmpPS1 ${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1 | Out-Null
	}else{
		logError 'The downloaded PS1 has an invalid signature !'
	}
}
}
else{
Unregister-ScheduledTask -TaskName "AutoHarden" -Confirm:$False -ErrorAction SilentlyContinue
}
Write-Progress -Activity AutoHarden -Status "0.1-AutoUpdate" -Completed
echo "####################################################################################################"
echo "# 1.0-Firewall-Functions"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "1.0-Firewall-Functions" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 1.0-Firewall-Functions"
# Ref: https://en.wikipedia.org/wiki/Reserved_IP_addresses
$IPForInternet=@('1.0.0.0-9.255.255.255',
'11.0.0.0-100.63.255.255',
'100.128.0.0-126.255.255.255',
'128.0.0.0-169.253.255.255',
'169.255.0.0-172.15.255.255',
'172.32.0.0-191.255.255.255',
'192.0.1.0-192.0.1.255',
'192.0.3.0-192.167.255.255',
'192.169.0.0-198.17.255.255',
'198.20.0.0-198.51.99.255',
'198.51.101.0-203.0.112.255',
'203.0.114.0-255.255.255.254')
$IPForIntranet=@(
'0.0.0.0–0.255.255.255',
'10.0.0.0–10.255.255.255',
'100.64.0.0–100.127.255.255',
'127.0.0.0–127.255.255.255',
'169.254.0.0–169.254.255.255',
'172.16.0.0–172.31.255.255',
'192.0.0.0–192.0.0.255',
'192.168.0.0–192.168.255.255',
'198.18.0.0–198.19.255.255')
# From: https://docs.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
$IPForOffice365 = (@"
104.146.128.0/17, 104.42.230.91/32, 104.47.0.0/17, 13.107.128.0/22,
13.107.136.0/22, 13.107.140.6/32, 13.107.18.10/31, 13.107.6.152/31,
13.107.6.156/31, 13.107.6.171/32, 13.107.64.0/18, 13.107.7.190/31,
13.107.9.156/31, 13.80.125.22/32, 13.91.91.243/32, 131.253.33.215/32,
132.245.0.0/16, 150.171.32.0/22, 150.171.40.0/22, 157.55.145.0/25,
157.55.155.0/25, 157.55.227.192/26, 20.190.128.0/18, 204.79.197.215/32,
23.103.160.0/20, 40.104.0.0/15, 40.107.0.0/16, 40.108.128.0/17,
40.126.0.0/18, 40.81.156.154/32, 40.90.218.198/32, 40.92.0.0/15,
40.96.0.0/13, 52.100.0.0/14, 52.104.0.0/14, 52.108.0.0/14,
52.112.0.0/14, 52.120.0.0/14, 52.120.0.0/14, 52.174.56.180/32,
52.183.75.62/32, 52.184.165.82/32, 52.238.106.116/32, 52.238.119.141/32,
52.238.78.88/32, 52.244.160.207/32, 52.244.203.72/32,
52.244.207.172/32, 52.244.223.198/32, 52.244.37.168/32,
52.247.150.191/32, 52.247.150.191/32, 52.96.0.0/14
"@).replace("`n","").replace("`r","").replace(" ","").split(",")

$utf8 = new-object -TypeName System.Text.UTF8Encoding
function getHash( $str )
{
	$stream = New-Object System.IO.MemoryStream -ArgumentList @(,$utf8.GetBytes($str))
	return Get-FileHash -Algorithm MD5 -InputStream $stream | Select-Object -ExpandProperty Hash	
}


$G_fwRule = New-Object System.Collections.ArrayList
function fwRule( $opt )
{
	$opt['Enabled'] = 'True';
	if( $opt.ContainsKey('blockExe') ){
		$opt['blockExe'] = ($opt['blockExe'] | get-item -ErrorAction Continue)
	}
	if( $opt['Action'] -eq 'Block' ){
		if( $opt['AllowO365'] -and $opt['AllowIntranet'] ){
			$opt2 = $opt.clone();
			$opt2.Remove('AllowIntranet');
			$opt2['Action'] = 'Allow';
			$opt.Remove('AllowO365');
			$G_fwRule.Add($opt2);
		}
	}
	$G_fwRule.Add($opt);
}



function _applyFwRules_filtering( $param, $name )
{
	$param = $param.clone();
	$route=($param | ConvertTo-Json -Compress)
	$action=$param['Action']
	if( $name[0] -ne '[' ){
		$name = " $name"
	}
	$param['Name'] = "[AutoHarden-$AutoHarden_version]$name";
	$param['DisplayName'] = $param['Name'];

	if( $param['Direction'] -eq '*' ){
		@('Inbound','Outbound') | foreach {
			$param['Direction'] = $_;
			Write-Host "[*] ADD $action firewall rule `"$name`" >$route<"
			$param.remove('AllowIntranet');
			$param.remove('AllowO365');	
			_applyFwRules_updateOrInsert $param
		}
		return $null;
	}
	if( ($param.ContainsKey('RemotePort') -And -Not $param.ContainsKey('Protocol')) -Or $param['Protocol'] -eq '*' ){
		@('tcp','udp') | foreach {
			$param['Protocol'] = $_;
			$param['Name'] += (' ('+$_+')');
			$param['DisplayName'] = $param['Name'];
			Write-Host "[*] ADD $action firewall rule `"$name`" >$route<"
			$param.remove('AllowIntranet');
			$param.remove('AllowO365');
			_applyFwRules_updateOrInsert $param
		}
		return $null;
	}
	Write-Host "[*] ADD $action firewall rule `"$name`" >$route<"
	$param.remove('AllowIntranet');
	$param.remove('AllowO365');	
	_applyFwRules_updateOrInsert $param
}


function _applyFwRules_updateOrInsert( $param )
{
	$param = $param.clone()
	$hash = getHash $param['Name'];
	$param['DisplayName'] = $param['Name']+" ($hash)";
	$nb = (Get-NetFirewallRule -DisplayName "*$hash*" | foreach {
		logInfo "UPDATING the rule $($param|convertTo-Json)"
		$tmp = $param.clone();
		$tmp.remove('Name');
		$tmp['NewDisplayName'] = $tmp['DisplayName'];
		$tmp.remove('DisplayName');
		$tmp.remove('Group');
		$_ | Set-NetFirewallRule @tmp -ErrorAction Continue
		$_
	}).Count
	if( $nb -eq 0 ){
		logInfo 'ADDING the rule'
		New-NetFirewallRule @param -ErrorAction Continue | Out-Null
	}
}


function _applyFwRules_updateTargetIP( [ref] $param )
{
	$tag = '';
	if( $param.Value.ContainsKey('AllowIntranet') -And $param.Value['AllowIntranet'] ){
		$tag = '[Except Intranet]';
		$param.Value['RemoteAddress'] = $IPForInternet;

	}elseif( $param.Value.ContainsKey('AllowO365') -And $param.Value['AllowO365'] ){
		$tag = '[Except O365]';
		$param.Value['RemoteAddress'] = $IPForOffice365;
	}
	return $tag;
}


function applyFwRules()
{
	$G_fwRule | where { $_.Action -eq 'Allow' -Or ( $_.Action -eq 'Block' -And $_.AllowO365 -eq $true -And $_.AllowIntranet -eq $true ) } | foreach {
		$param = $_.Clone()			
		$param['Group'] = ('AutoHarden-'+$param['Group']);
		$param['Action'] = 'Allow';
		$name = $param['Name'];
		$param.remove('Name');
		$tag = _applyFwRules_updateTargetIP ([ref]$param);

		if( $_.ContainsKey('blockExe') ){
			$exe = $param['blockExe'];
			$param.remove('blockExe');
			$exe | get-item -ErrorAction Continue | foreach {
				$bin = $_.Fullname
				$param['Program'] = $bin;
				_applyFwRules_filtering $param "$tag ByPass $name : $bin"
			}
		}else{
			_applyFwRules_filtering $param "$tag $name"
		}
	}
	
	
	$G_fwRule | where { $_.Action -eq 'Block' } | foreach {
		$param = $_.Clone()			
		$param['Group'] = ('AutoHarden-'+$param['Group']);
		$name = $param['Name'];
		$param.remove('Name');
		if( $_.ContainsKey('blockExe') ){
			$exe = $param['blockExe'];
			$param.remove('blockExe');
			$tag = _applyFwRules_updateTargetIP ([ref]$param);
			$exe | get-item -ErrorAction Continue | foreach {
				$bin = $_.Fullname
				$param['Program'] = $bin;
				_applyFwRules_filtering $param "$tag $name : $bin"
			}
		}else{
			$tag = _applyFwRules_updateTargetIP ([ref]$param);
			_applyFwRules_filtering $param "$tag $name"
		}
	}
}
Write-Progress -Activity AutoHarden -Status "1.0-Firewall-Functions" -Completed
echo "####################################################################################################"
echo "# 1.1-Firewall-BasicRules"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "1.1-Firewall-BasicRules" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 1.1-Firewall-BasicRules"
### Snort & Suricata signatures for:
### https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6
##
##alert udp fe80::/12 [546,547] -> fe80::/12 [546,547] (msg:"FOX-SRT - Policy - DHCPv6 advertise"; content:"|02|"; offset:48; depth:1; reference:url,blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/; threshold:type limit, track by_src, count 1, seconds 3600; classtype:policy-violation; sid:21002327; rev:2;)
##alert udp ::/0 53 -> any any (msg:"FOX-SRT - Suspicious - WPAD DNS reponse over IPv6"; byte_test:1,&,0x7F,2; byte_test:2,>,0,6; content:"|00 04|wpad"; nocase; fast_pattern; threshold: type limit, track by_src, count 1, seconds 1800; reference:url,blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/; classtype:attempted-admin; priority:1; sid:21002330; rev:1;)

fwRule @{
	Name='NMAP'
	Group='Pentest'
	Direction='*'
	Action='Allow'
	blockExe="C:\Program Files*\Nmap\nmap.exe"
}
fwRule @{
	Name='VMWare'
	Group='Pentest'
	Direction='*'
	Action='Allow'
	blockExe="C:\Program Files*\VMware\*\vmnat.exe"
}
# Note about 135/TCP => https://superuser.com/questions/669199/how-to-stop-listening-at-port-135/1012382#1012382
# Port 135/TCP can be killed in 100% of server and workstation if CreateObject("Excel.Application", RemoteMachine) is not used
Write-Progress -Activity AutoHarden -Status "1.1-Firewall-BasicRules" -Completed
echo "####################################################################################################"
echo "# 1.1-Firewall-Malware"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "1.1-Firewall-Malware" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 1.1-Firewall-Malware"
if( ask "Block Internet communication for evil tools ? This filtering prevents viruses from downloading the payload." "1.1-Firewall-Malware.ask" ){
#	blockExe "Windows Defender" "C:\ProgramData\Microsoft\Windows Defender\platform\*\MpCmdRun.exe",# Fixed in the latest version of Defender
#	https://malware.news/t/a-deep-dive-into-rundll32-exe/43840
#	blockExe "Rundll32" "C:\Windows\System32\rundll32.exe",

@(
	@{ Name='Intel Graphics Control Panel'; blockExe="C:\Windows\System32\driverstore\filerepository\*\GfxDownloadWrapper.exe" },
	@{ Name='Presentationhost'; blockExe="C:\Windows\Sys*\Presentationhost.exe" },
	@{ Name='Dfsvc'; blockExe="C:\Windows\Microsoft.NET\*\*\Dfsvc.exe" },
	@{ Name='IEexec'; blockExe="C:\Windows\Microsoft.NET\*\*\ieexec.exe" },
	@{ Name='HH'; blockExe=@("C:\Windows\*\hh.exe","C:\Windows\hh.exe") },
	@{ Name='CertUtil'; blockExe="C:\Windows\System32\certutil.exe" },
	@{ Name='Mshta'; blockExe="C:\Windows\system32\mshta.exe" },
	@{ Name='BitsAdmin'; blockExe="C:\Windows\system32\BitsAdmin.exe" },
	@{ Name='CScript'; blockExe="C:\Windows\system32\cscript.exe" },
	@{ Name='WScript'; blockExe="C:\Windows\system32\wscript.exe" },
	@{ Name='Powershell'; blockExe=@(
		"C:\Windows\WinSxS\*\powershell.exe",
		"C:\Windows\WinSxS\*\PowerShell_ISE.exe",
		"C:\Windows\*\WindowsPowerShell\v1.0\powershell.exe",
		"C:\Windows\*\WindowsPowerShell\v1.0\PowerShell_ISE.exe"
	) }
) | foreach {
	fwRule @{
		Name=$_.Name
		Group='LOLBAS'
		Direction='Outbound'
		Action='Block'
		blockExe=$_.blockExe
		AllowIntranet=$true
	}
}

}
else{
Get-NetFirewallRule -Group "AutoHarden-LOLBAS" | Remove-NetFirewallRule
}
Write-Progress -Activity AutoHarden -Status "1.1-Firewall-Malware" -Completed
echo "####################################################################################################"
echo "# 1.2-Firewall-Office"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "1.2-Firewall-Office" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 1.2-Firewall-Office"
if( ask "Block Internet communication for Word and Excel ? Excel and Word will still be able to access files on local network shares. This filtering prevents viruses from downloading the payload." "1.2-Firewall-Office.ask" ){
@(
	@{Name='Word'; blockExe=@(
		"C:\Program Files*\Microsoft Office*\root\*\winword.exe",
		"C:\Program Files*\Microsoft Office*\*\root\*\winword.exe",
		"C:\Program Files*\Microsoft Office*\*\winword.exe"
	)},
	@{Name='Excel'; blockExe=@(
		"C:\Program Files*\Microsoft Office*\root\*\EXCEL.EXE",
		"C:\Program Files*\Microsoft Office*\*\root\*\EXCEL.EXE",
		"C:\Program Files*\Microsoft Office*\*\EXCEL.EXE",
		"C:\Program Files*\Microsoft Office*\*\excelcnv.exe",
		"C:\Program Files*\Microsoft Office*\*\*\excelcnv.exe"
	)},
	@{Name='PowerPoint'; blockExe=@(
		"C:\Program Files*\Microsoft Office*\root\*\Powerpnt.exe",
		"C:\Program Files*\Microsoft Office*\*\root\*\Powerpnt.exe",
		"C:\Program Files*\Microsoft Office*\*\Powerpnt.exe"
	)},	
	@{Name='Teams'; blockExe=@(
		"C:\Users\*\AppData\Local\Microsoft\Teams\*\Squirrel.exe",
		"C:\Users\*\AppData\Local\Microsoft\Teams\update.exe"
	)}	
) | foreach {
	fwRule @{
		Name=$_.Name
		Group='Office'
		Direction='Outbound'
		Action='Block'
		blockExe=$_.blockExe
		AllowIntranet=$true
		AllowO365=$true
	}
}
}
else{
Get-NetFirewallRule -Group '*AutoHarden*Office*' | Remove-NetFirewallRule
}
Write-Progress -Activity AutoHarden -Status "1.2-Firewall-Office" -Completed
echo "####################################################################################################"
echo "# 1.3-Firewall-IE"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "1.3-Firewall-IE" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 1.3-Firewall-IE"
if( ask "Block Internet communication for 'Internet Explorer' ? 'Internet Explorer' will still be able to access web server on local network. This filtering prevents viruses from downloading the payload." "1.3-Firewall-IE.ask" ){
fwRule @{
	Name='InternetExplorer'
	Group='InternetExplorer'
	Direction='Outbound'
	Action='Block'
	blockExe=@(
		"C:\Program Files*\Internet Explorer\iexplore.exe"
	)
	AllowIntranet=$true
}
}
else{
Get-NetFirewallRule -Name '*AutoHarden*InternetExplorer*' | Remove-NetFirewallRule
}
Write-Progress -Activity AutoHarden -Status "1.3-Firewall-IE" -Completed
echo "####################################################################################################"
echo "# 1.5-Firewall-DisableNotification"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "1.5-Firewall-DisableNotification" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 1.5-Firewall-DisableNotification"
if( ask "Avoid sending notification to Users about the firewall" "1.5-Firewall-DisableNotification.ask" ){
Set-NetFirewallProfile -All -Enabled True -NotifyOnListen False
}
else{
Set-NetFirewallProfile -All -Enabled True -NotifyOnListen True
}
Write-Progress -Activity AutoHarden -Status "1.5-Firewall-DisableNotification" -Completed
echo "####################################################################################################"
echo "# 1.6-Firewall-AvoidSMBOnInternet"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "1.6-Firewall-AvoidSMBOnInternet" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 1.6-Firewall-AvoidSMBOnInternet"
if( $getRole -ne 'Domain Controller' ){
	# This rule avoid users use SMB on internet
	# This rule is incompactible with PetiPotam fix which allows SMB outbound to only other DC
	fwRule @{
		Name='SMB'
		Group='Harding'
		Direction='Outbound'
		Action='Block'
		RemotePort=445
		Protocol='tcp'
		AllowIntranet=$true
	}
}
Write-Progress -Activity AutoHarden -Status "1.6-Firewall-AvoidSMBOnInternet" -Completed
echo "####################################################################################################"
echo "# 1.6-Firewall-StealtMode"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "1.6-Firewall-StealtMode" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 1.6-Firewall-StealtMode"
# Force Windows Firewall to block packets instead of just dropping them.
# 0x00000000 (default – StealthMode enabled)
# 0x00000001 (StealthMode disabled)
$value=0x00000000
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile'
Write-Progress -Activity AutoHarden -Status "1.6-Firewall-StealtMode" -Completed
echo "####################################################################################################"
echo "# 2-Hardening-HardDriveEncryption"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "2-Hardening-HardDriveEncryption" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 2-Hardening-HardDriveEncryption"
if( ask "Encrypt the HardDrive C:" "2-Hardening-HardDriveEncryption.ask" ){
# AES 256-bit 
reg add 'HKLM\SOFTWARE\Policies\Microsoft\FVE' /v EncryptionMethod  /t REG_DWORD /d 4 /f

try{
	(Get-BitLockerVolume -MountPoint 'C:').KeyProtector |foreach {
		logSuccess ('C: is protected with: '+$_.KeyProtectorType)
	}
	# Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -TpmProtector -RecoveryKeyProtector -RecoveryKeyPath "C:\"
}catch{
	Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly -TpmProtector -ErrorAction Continue
	if( ((Get-BitLockerVolume -MountPoint 'C:').KeyProtector | where { $_.KeyProtectorType -eq "RecoveryPassword" }).Count -eq 0 ){
		Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly -RecoveryPasswordProtector -ErrorAction Continue
	}
	(Get-BitLockerVolume -MountPoint 'C:').KeyProtector | foreach {
		if( -not [string]::IsNullOrEmpty($_.RecoveryPassword) ){
			Add-Type -AssemblyName System.Windows.Forms
			[System.Windows.Forms.MessageBox]::Show("Please keep a note of this RecoveryPassword $($_.RecoveryPassword)");
		}
	}
}
}
else{
Disable-BitLocker -MountPoint 'C:'  -ErrorAction SilentlyContinue | Out-Null
manage-bde -off C: >$null
}
Write-Progress -Activity AutoHarden -Status "2-Hardening-HardDriveEncryption" -Completed
echo "####################################################################################################"
echo "# 2-Hardening-Powershell"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "2-Hardening-Powershell" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 2-Hardening-Powershell"
# Disable Powershellv2
DISM /Online /Disable-Feature:MicrosoftWindowsPowerShellV2Root /NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
Write-Progress -Activity AutoHarden -Status "2-Hardening-Powershell" -Completed
echo "####################################################################################################"
echo "# 2-Hardening-RPCFiltering"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "2-Hardening-RPCFiltering" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 2-Hardening-RPCFiltering"
# Script from https://raw.githubusercontent.com/craigkirby/scripts/main/RPC_Filters.bat
# List of UUIDs
# https://vulners.com/openvas/OPENVAS:1361412562310108044
# https://github.com/p33kab00/dcerpc-pipe-scan/blob/master/dcerpc-pipe-scan.py

# Services
$rules = RpcRuleCreator '367abb81-9844-35f1-ad32-98f038001003' 'Services'
# Also Services as listed on Internet but might be a typo
$rules += RpcRuleCreator '367aeb81-9844-35f1-ad32-98f038001003' 'Service bis'
# Task Scheduler
$rules += RpcRuleCreator '378e52b0-c0a9-11cf-822d-00aa0051e40f' 'Task Scheduler 1'
$rules += RpcRuleCreator '0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53' 'Task Scheduler 2'
$rules += RpcRuleCreator '86d35949-83c9-4044-b424-db363231fd0c' 'Task Scheduler 3'
# AT Scheduler
$rules += RpcRuleCreator '1ff70682-0a51-30e8-076d-740be8cee98b' 'AT Scheduler'
# Security Configuration Editor Engine
$rules += RpcRuleCreator '93149ca2-973b-11d1-8c39-00c04fb984f9' 'Security Configuration Editor Engine'
# Remote Registry
$rules += RpcRuleCreator '338cd001-2244-31f1-aaaa-900038001003' 'Remote Registry'

# See PetitPotam fix
## Encrypting File System Remote (EFSRPC) Protocol
#$rules += RpcRuleCreator 'c681d488-d850-11d0-8c52-00c04fd90f7e' 'EFS'
#$rules += RpcRuleCreator 'df1941c5-fe89-4e79-bf10-463657acf44d' 'EFS'

# Print Spooler
$rules += RpcRuleCreator '12345678-1234-abcd-ef00-0123456789ab' 'Print Spooler'

addRpcAcl -acl $rules
Write-Progress -Activity AutoHarden -Status "2-Hardening-RPCFiltering" -Completed
echo "####################################################################################################"
echo "# Crapware-Cortana"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-Cortana" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-Cortana"
if( ask "Disable Cortana in Windows search bar" "Crapware-Cortana.ask" ){
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowCortana /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowCortana /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowSearchToUseLocation /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowCortanaAboveLock /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v DisableWebSearch /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v ConnectedSearchUseWeb /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /t REG_DWORD /v BingSearchEnabled /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v PublishUserActivities /d 0 /f
# From: Fireice
# https://www.winhelponline.com/blog/disable-web-results-windows-10-start-menu/
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /t REG_DWORD /v DisableSearchBoxSuggestions /d 1 /f
Get-appxpackage -allusers *Microsoft.549981C3F5F10* | Remove-AppxPackage
}
else{
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowCortana /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowCortana /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowSearchToUseLocation /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowCortanaAboveLock /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v DisableWebSearch /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v ConnectedSearchUseWeb /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /t REG_DWORD /v BingSearchEnabled /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v PublishUserActivities /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /t REG_DWORD /v DisableSearchBoxSuggestions /d 0 /f
}
Write-Progress -Activity AutoHarden -Status "Crapware-Cortana" -Completed
echo "####################################################################################################"
echo "# Crapware-DisableTelemetry-and-ADS"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-DisableTelemetry-and-ADS" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-DisableTelemetry-and-ADS"
# Disable Windows telemetry
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowDeviceNameInTelemetry /t REG_DWORD /d 0 /f
schtasks.exe /Change /TN "\Microsoft\Windows\Device Information\Device" /Disable

sc.exe stop DiagTrack
sc.exe config DiagTrack "start=" disabled
sc.exe stop dmwappushservice
sc.exe config dmwappushservice "start=" disabled

# Disable Wifi sense telemetry
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0  /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
# Disable “Suggested Apps” in Windows 10
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RemediationRequired /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContentEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-310093Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-314563Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
# Disable notifications/ads in File Explorer
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f

# Start Menu: Disable Bing Search Results
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f

# Privacy - Disable Microsoft Help feedback.
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoImplicitFeedback" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoOnlineAssist" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d 1 /f

# Privacy - Disable feedback in Office.
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\common\feedback" /v "enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\common\feedback" /v "includescreenshot" /t REG_DWORD /d 0 /f




#https://github.com/crazy-max/WindowsSpyBlocker/raw/master/data/hosts/spy.txt
Write-Progress -Activity AutoHarden -Status "Crapware-DisableTelemetry-and-ADS" -Completed
echo "####################################################################################################"
echo "# Crapware-RemoveUseLessSoftware"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-RemoveUseLessSoftware" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-RemoveUseLessSoftware"
Get-AppxPackage -Name king.com.CandyCrushSaga
Get-AppxPackage *3dbuilder* | Remove-AppxPackage
Get-AppxPackage *officehub* | Remove-AppxPackage
Get-AppxPackage *getstarted* | Remove-AppxPackage
Get-AppxPackage *zunemusic* | Remove-AppxPackage
Get-AppxPackage *bingfinance* | Remove-AppxPackage
Get-AppxPackage *zunevideo* | Remove-AppxPackage
Get-AppxPackage *people* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *windowsphone* | Remove-AppxPackage
Get-AppxPackage *bingsports* | Remove-AppxPackage
Get-AppxPackage *xboxapp* | Remove-AppxPackage

reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main /v AllowPrelaunch /d 0 /t REG_DWORD /f

# List: Get-AppxPackage
Write-Progress -Activity AutoHarden -Status "Crapware-RemoveUseLessSoftware" -Completed
echo "####################################################################################################"
echo "# Crapware-Windows10UpgradeOldFolder"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-Windows10UpgradeOldFolder" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-Windows10UpgradeOldFolder"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 'C:\$Windows.~BT' | Out-Null
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 'C:\Windows.old' | Out-Null
Write-Progress -Activity AutoHarden -Status "Crapware-Windows10UpgradeOldFolder" -Completed
echo "####################################################################################################"
echo "# Fix-CVE-2020-16898"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Fix-CVE-2020-16898" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Fix-CVE-2020-16898"
# Protection against CVE-2020-16898: “Bad Neighbor”
netsh int ipv6 show int | foreach { $p=$_.trim().split(' ')[0]; [int]::TryParse($p,[ref]$null) -and (netsh int ipv6 set int $p rabaseddnsconfig=disable) -and (write-host "int >$p<") }
Write-Progress -Activity AutoHarden -Status "Fix-CVE-2020-16898" -Completed
echo "####################################################################################################"
echo "# Fix-HiveNightmare"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Fix-HiveNightmare" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Fix-HiveNightmare"
# https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
icacls $env:windir\system32\config\*.* /inheritance:e
Write-Progress -Activity AutoHarden -Status "Fix-HiveNightmare" -Completed
echo "####################################################################################################"
echo "# Fix-PetitPotam"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Fix-PetitPotam" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Fix-PetitPotam"
###############################################################################
# Fix for DC
if( $getRole -eq 'Domain Controller' ){
	# Avoid the usage of the HTTP2SMB convertor (WebClient)
	# WebClient is not installed by default on DC
	sc.exe config webclient start= disabled 2>$null >$null
	
	
	# Filter SMB communication to allow only SMB <=> SMB between DC
	$domainDontrollerList = (Get-DnsClientGlobalSetting).SuffixSearchList | foreach {
		Resolve-DnsName -Type ALL -Name _ldap._tcp.dc._msdcs.$_
	} | foreach {
		$_.IP4Address
	} | sort -unique
	
	fwRule @{
		Name='DC2DC'
		Group='PetitPotam'
		Direction='*'
		Action='Allow'
		RemoteAddress=$domainDontrollerList
	}
	fwRule @{
		Name='DC2DC'
		Group='PetitPotam'
		Direction='Outbound'
		Action='Block'
		Protocol='tcp'
		RemotePort=445
	}
}

# Add a rule to drop access to EFS for non DA
# From: https://twitter.com/tiraniddo/status/1422223511599284227
# From: https://gist.github.com/tyranid/5527f5559041023714d67414271ca742
addRpcAcl -name 'EFS' -uuid @('c681d488-d850-11d0-8c52-00c04fd90f7e', 'df1941c5-fe89-4e79-bf10-463657acf44d')
Write-Progress -Activity AutoHarden -Status "Fix-PetitPotam" -Completed
echo "####################################################################################################"
echo "# Harden-DisableShortPath"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Harden-DisableShortPath" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Harden-DisableShortPath"
fsutil.exe 8dot3name set 1
Write-Progress -Activity AutoHarden -Status "Harden-DisableShortPath" -Completed
echo "####################################################################################################"
echo "# Harden-RDP-Credentials"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Harden-RDP-Credentials" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Harden-RDP-Credentials"
Get-Item "HKCU:\Software\Microsoft\Terminal Server Client\Servers\*" -ErrorAction Ignore | Remove-Item -Force -Recurse
Write-Progress -Activity AutoHarden -Status "Harden-RDP-Credentials" -Completed
echo "####################################################################################################"
echo "# Harden-VMWareWorkstation"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Harden-VMWareWorkstation" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Harden-VMWareWorkstation"
# Disable VM Sharing (free the port 443/TCP)
sc.exe config VMwareHostd start= disabled
Write-Progress -Activity AutoHarden -Status "Harden-VMWareWorkstation" -Completed
echo "####################################################################################################"
echo "# Harden-VoiceControl"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Harden-VoiceControl" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Harden-VoiceControl"
if( ask "Disable voice control" "Harden-VoiceControl.ask" ){
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /t REG_DWORD /v AgentActivationEnabled /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /t REG_DWORD /v AgentActivationOnLockScreenEnabled /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization" /t REG_DWORD /v AllowInputPersonalization /d 0 /f
}
else{
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v AgentActivationEnabled /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v AgentActivationOnLockScreenEnabled /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization" /v AllowInputPersonalization /f
}
Write-Progress -Activity AutoHarden -Status "Harden-VoiceControl" -Completed
echo "####################################################################################################"
echo "# Harden-WindowsDefender"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Harden-WindowsDefender" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Harden-WindowsDefender"
if( -not (ask "Disable WindowsDefender" "Optimiz-DisableDefender.ask") -and (ask "Harden Windows Defender" "Harden-WindowsDefender.ask") ){
	# From https://gist.github.com/decay88/5bd6b2c9ebf681324847e541ba1fb191
	# From https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
	################################################################################################################
	# Windows Defender Device Guard - Exploit Guard Policies (Windows 10 Only)
	# Enable ASR rules in Win10 ExploitGuard (>= 1709) to mitigate Office malspam
	# Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
	# Note these only work when Defender is your primary AV
	# Sources:
	# https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office
	# https://www.darkoperator.com/blog/2017/11/8/windows-defender-exploit-guard-asr-obfuscated-script-rule
	# https://www.darkoperator.com/blog/2017/11/6/windows-defender-exploit-guard-asr-vbscriptjs-rule
	# https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction
	# https://demo.wd.microsoft.com/Page/ASR2
	# https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSettings/1.2/Content/WindowsDefender_InternalEvaluationSettings.ps1
	# ---------------------
	#%programfiles%\"Windows Defender"\MpCmdRun.exe -RestoreDefaults
	#
	# Block Office applications from creating child processes
	Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block Office applications from injecting code into other processes
	Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block Win32 API calls from Office macro
	Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block Office applications from creating executable content
	Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block execution of potentially obfuscated scripts
	Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block executable content from email client and webmail
	Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block JavaScript or VBScript from launching downloaded executable content
	Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block executable files from running unless they meet a prevalence, age, or trusted list criteria
	Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
	#
	# Use advanced protection against ransomware
	Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
	
	if( (Get-Item "C:\Program Files*\VMware\*\vmnat.exe") -eq $null ){
		# Block credential stealing from the Windows local security authority subsystem (lsass.exe)
		Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
	}else{
		Remove-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2
	}
	#
	# Block untrusted and unsigned processes that run from USB
	#A TEST#########Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
	#
	# Enable Controlled Folder
	#Set-MpPreference -EnableControlledFolderAccess Enabled
	#
	# Enable Cloud functionality of Windows Defender
	#A TEST#########Set-MpPreference -MAPSReporting Advanced
	#A TEST#########Set-MpPreference -SubmitSamplesConsent Always
	#
	# Enable Network protection
	# Enabled - Users will not be able to access malicious IP addresses and domains
	# Disable (Default) - The Network protection feature will not work. Users will not be blocked from accessing malicious domains
	# AuditMode - If a user visits a malicious IP address or domain, an event will be recorded in the Windows event log but the user will not be blocked from visiting the address.
	Set-MpPreference -EnableNetworkProtection Enabled 
	#
	################################################################################################################
	# Enable exploit protection (EMET on Windows 10)
	# Sources:
	# https://www.wilderssecurity.com/threads/process-mitigation-management-tool.393096/
	# https://blogs.windows.com/windowsexperience/2018/03/20/announcing-windows-server-vnext-ltsc-build-17623/
	# ---------------------
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Disable-NetFirewallRule
	Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/ProcessMitigation.xml -OutFile $env:temp\ProcessMitigation.xml
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Enable-NetFirewallRule
	Set-ProcessMitigation -PolicyFilePath $env:temp\ProcessMitigation.xml
	rm $env:temp\ProcessMitigation.xml
}else{
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 2>$null
	Set-MpPreference -EnableNetworkProtection Disabled 2>$null
}
Write-Progress -Activity AutoHarden -Status "Harden-WindowsDefender" -Completed
echo "####################################################################################################"
echo "# Hardening-BlockUntrustedFonts"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-BlockUntrustedFonts" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-BlockUntrustedFonts"
# https://adsecurity.org/?p=3299
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v MitigationOptions /t REG_QWORD /d 0x2000000000000 /f
Write-Progress -Activity AutoHarden -Status "Hardening-BlockUntrustedFonts" -Completed
echo "####################################################################################################"
echo "# Hardening-CertPaddingCheck"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-CertPaddingCheck" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-CertPaddingCheck"
# To inject shellcode inside signed binaries : https://github.com/med0x2e/SigFlip
# MS13-098 - Vulnerability in Windows Could Allow Remote Code Execution - https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2013/ms13-098?redirectedfrom=MSDN
#
# IMPACT: Impact of enabling the functionality changes included in the MS13-098 update. Non-conforming binaries will appear unsigned and, therefore, be rendered untrusted.
#
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\Wintrust\Config" /t REG_DWORD /v EnableCertPaddingCheck /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /t REG_DWORD /v EnableCertPaddingCheck /d 1 /f
Write-Progress -Activity AutoHarden -Status "Hardening-CertPaddingCheck" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableCABlueCoat"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableCABlueCoat" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableCABlueCoat"
# See http://blogs.msmvps.com/alunj/2016/05/26/untrusting-the-blue-coat-intermediate-ca-from-windows/
#Invoke-WebRequest -Uri "https://crt.sh/?id=19538258" -OutFile "${env:temp}/Hardening-DisableCABlueCoat.crt"
echo @'
-----BEGIN CERTIFICATE-----
MIIGTDCCBTSgAwIBAgIQUWMOvf4tj/x5cQN2PXVSwzANBgkqhkiG9w0BAQsFADCB
yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp
U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW
ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5IC0gRzUwHhcNMTUwOTI0MDAwMDAwWhcNMjUwOTIzMjM1OTU5WjCBhDEL
MAkGA1UEBhMCVVMxIDAeBgNVBAoTF0JsdWUgQ29hdCBTeXN0ZW1zLCBJbmMuMR8w
HQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTIwMAYDVQQDEylCbHVlIENv
YXQgUHVibGljIFNlcnZpY2VzIEludGVybWVkaWF0ZSBDQTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAJ/Go2aR50MoHttT0E7g9bDUUzKomaIkCRy5gI8A
BRkAed7v1mKUk/tn7pKxOvYHnd8BG3iT+eQ2P1ha2oB+vymj4b35gOAcYQIEEYCO
vH35pSqRKlmflrI5RwjX/+l9O+YUn2cK0uYeJBXNMfTse6/azxksNQjK1CFqFcWz
XIK12+THFiFQuuCc5lON6nkhpBkGJSCN43nevFigNhW3YWZG/Z1l86Y9Se0Sf96o
fL7VnV2Ri0kSwJuxNYH7ei5ZBG8GVuNFuqPhmfE2YD2yjbXMnnn4hKOWsM8Oe0xL
ocjPgMTGVgvgeqZo8tV2gvaAycPO4PcJ+yHlgXtdyV7qztECAwEAAaOCAnAwggJs
MBIGA1UdEwEB/wQIMAYBAf8CAQAwLwYDVR0fBCgwJjAkoCKgIIYeaHR0cDovL3Mu
c3ltY2IuY29tL3BjYTMtZzUuY3JsMA4GA1UdDwEB/wQEAwIBBjAuBggrBgEFBQcB
AQQiMCAwHgYIKwYBBQUHMAGGEmh0dHA6Ly9zLnN5bWNkLmNvbTCCAVkGA1UdIASC
AVAwggFMMFwGBmeBDAECAjBSMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LnN5bWF1
dGguY29tL2NwczAoBggrBgEFBQcCAjAcGhpodHRwOi8vd3d3LnN5bWF1dGguY29t
L3JwYTB1BgorBgEEAfElBAIBMGcwZQYIKwYBBQUHAgIwWRpXSW4gdGhlIGV2ZW50
IHRoYXQgdGhlIEJsdWVDb2F0IENQUyBhbmQgU3ltYW50ZWMgQ1BTIGNvbmZsaWN0
LCB0aGUgU3ltYW50ZWMgQ1BTIGdvdmVybnMuMHUGCisGAQQB8SUEAgIwZzBlBggr
BgEFBQcCAjBZGldJbiB0aGUgZXZlbnQgdGhhdCB0aGUgQmx1ZUNvYXQgQ1BTIGFu
ZCBTeW1hbnRlYyBDUFMgY29uZmxpY3QsIHRoZSBTeW1hbnRlYyBDUFMgZ292ZXJu
cy4wHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMCkGA1UdEQQiMCCkHjAc
MRowGAYDVQQDExFTeW1hbnRlY1BLSS0yLTIxNDAdBgNVHQ4EFgQUR5UKC6ehgqJt
yZuczT7zkELkb5kwHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJ
KoZIhvcNAQELBQADggEBAJjsKAGzmIEavosNMHxJVCidIGF1r3+vmGBoSVU5iT9R
1DKnrQc8KO5l+LgMuyDUMmH5CxbLbOWT/GtEC/ZvyiVTfn2xNE9SXw46zNUz1oOO
DMJLyvTMuRt7LsExqqsg3KZo6esNW5gmCYbLyfcjn7dKbtjkHvOdxJJ7VrDDayeC
Z5rBgiTj1+l09Uxo+2rwfEvHXzVtWSQyuqxRc8DVwCgFGrnJNGJS1coOQdQ91i6Q
zij5S/djgP1rVHH+MkgJcUQ/2km9GC6B6Y3yMGq6XLVjLvi73Ch2G5mUWkeoZibb
yQSxTBWG6GJjyDY7543ZK3FH4Ctih/nFgXrjuY7Ghrk=
-----END CERTIFICATE-----
'@ > $env:temp/Hardening-DisableCABlueCoat.crt
Import-Certificate -Filepath "${env:temp}/Hardening-DisableCABlueCoat.crt" -CertStoreLocation Cert:\LocalMachine\Disallowed | out-null
Write-Progress -Activity AutoHarden -Status "Hardening-DisableCABlueCoat" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableIPv6"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableIPv6" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableIPv6"
# Block IPv6
@(
	@{Name='IPv6'       ;Protocol=41},
	@{Name='IPv6-Route' ;Protocol=43},
	@{Name='IPv6-Frag'  ;Protocol=44},
	@{Name='ICMPv6'     ;Protocol=58},
	@{Name='IPv6-NoNxt' ;Protocol=59},
	@{Name='IPv6-Opts'  ;Protocol=60}
) | foreach {
	fwRule @{
		Name=$_.Name
		Protocol=$_.Protocol
		Group='IPv6'
		Direction='Outbound'
		Action='Block'
	}
}
fwRule @{
	Name='DHCPv6'
	Protocol='udp'
	RemotePort=547
	Group='IPv6'
	Direction='Outbound'
	Action='Block'
}


# reg add "HKLM\SYSTEM\CurrentControlSet\services\tcpip6\parameters" /v DisabledComponents /t REG_DWORD /d 0xFF /f
# Netsh int ipv6 set int 12 routerdiscovery=disabled
# Netsh int ipv6 set int 12 managedaddress=disabled
Write-Progress -Activity AutoHarden -Status "Hardening-DisableIPv6" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableLLMNR"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableLLMNR" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableLLMNR"
# Disable LLMNR
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /t REG_DWORD /v EnableMulticast /d 0 /f
nbtstat.exe /n
fwRule @{
	Name='LLMNR'
	Protocol='udp'
	RemotePort=5355
	Group='Multicast'
	Direction='Outbound'
	Action='Block'
}
fwRule @{
	Name='MBNS'
	Protocol='udp'
	RemotePort=5353
	Group='Multicast'
	Direction='Outbound'
	Action='Block'
}
Write-Progress -Activity AutoHarden -Status "Hardening-DisableLLMNR" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableMimikatz"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableMimikatz" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableMimikatz"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL /t REG_DWORD /d 1 /f

# This sets up your RDP session to NOT store credentials in the memory of the target host.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 1 /f
Write-Progress -Activity AutoHarden -Status "Hardening-DisableMimikatz" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableMimikatz__CredentialsGuard"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableMimikatz__CredentialsGuard" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableMimikatz__CredentialsGuard"
if( ask "Do you want to enable 'Credentials Guard' and disable VMWare/VirtualBox" "Hardening-DisableMimikatz__CredentialsGuard.ask" ){
if( (Get-Item "C:\Program Files*\VMware\*\vmnat.exe") -eq $null ){
	# Credentials Guard
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags /t REG_DWORD /d 1 /f
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlagsDefault /t REG_DWORD /d 1 /f
	# Credentials Guard bloque VMWare...
	# En cas de blocage, il faut désactive CG via DG_Readiness.ps1 -Disable
	# cf https://stackoverflow.com/questions/39858200/vmware-workstation-and-device-credential-guard-are-not-compatible
	# cf https://www.microsoft.com/en-us/download/details.aspx?id=53337
}
}
else{
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlagsDefault /t REG_DWORD /d 0 /f
}
Write-Progress -Activity AutoHarden -Status "Hardening-DisableMimikatz__CredentialsGuard" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableNetbios"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableNetbios" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableNetbios"
$(
	@{Port=135; proto='tcp'},
	@{Port=137; proto='UDP'},
	@{Port=138; proto='UDP'},
	@{Port=139; proto='tcp'}
) | foreach {
	$port=$_.port
	$proto=$_.proto
	fwRule @{
		Name="NetBios $port/$proto"
		Group='NetBios'
		Direction='Inbound'
		Action='Block'
		LocalPort=$port
		Protocol=$proto
	}
	fwRule @{
		Name="NetBios $port/$proto"
		Group='NetBios'
		Direction='Outbound'
		Action='Block'
		RemotePort=$port
		Protocol=$proto
	}
}


# https://twitter.com/PythonResponder/status/1379251124985851904
# Did you know? You can anonymously overwrite any NetBIOS name registered on a Windows network, with  a NTB Name Overwrite Demand Request, even today... 😛
# http://ubiqx.org/cifs/NetBIOS.html
# Fix => Disable NetBios on all interfaces
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip* -Name NetbiosOptions -Value 2
Write-Progress -Activity AutoHarden -Status "Hardening-DisableNetbios" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableRemoteServiceManagement"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableRemoteServiceManagement" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableRemoteServiceManagement"
# From: https://twitter.com/JohnLaTwC/status/802218490404798464?s=19
# Empeche la création de service via les RPC/SMB distant. => psexec upload ok mais exec fail
$tmp=(sc.exe sdshow scmanager).split("`r`n")[1].split(":")[1]
if( -not $tmp.Contains("(D;;GA;;;NU)") -and -not $tmp.Contains("(D;;KA;;;NU)") ){
	sc.exe sdset scmanager "D:(D;;GA;;;NU)$tmp"
}else{
	echo "Already patched"
}
Write-Progress -Activity AutoHarden -Status "Hardening-DisableRemoteServiceManagement" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableSMBServer"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableSMBServer" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableSMBServer"
# Désactivation des partages administratifs
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f

# Block CobaltStrike from using \\evil.kali\tmp$\becon.exe
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f

#Set-SmbServerConfiguration -AnnounceServer $false -Force
#Get-SmbServerConfiguration

sc.exe config lanmanserver start= disabled
Write-Progress -Activity AutoHarden -Status "Hardening-DisableSMBServer" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableSMBv1"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableSMBv1" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableSMBv1"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Rdr\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Rdr\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
Write-Progress -Activity AutoHarden -Status "Hardening-DisableSMBv1" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableWPAD"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableWPAD" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableWPAD"
# Disable wpad service
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /t REG_DWORD /v Start /d 4 /f

reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v "DefaultConnectionSettings" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v "SavedLegacySettings" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /t REG_DWORD /v WpadOverride /d 0 /f
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8
ipconfig /flushdns
$_wpad=Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern "0.0.0.0 wpad"
if( [string]::IsNullOrEmpty($_wpad) ){
	[System.IO.File]::AppendAllText("C:\Windows\System32\drivers\etc\hosts", "`r`n0.0.0.0 wpad", (New-Object System.Text.UTF8Encoding $False));
}
$_wpad=Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern "0.0.0.0 ProxySrv"
if( [string]::IsNullOrEmpty($_wpad) ){
	[System.IO.File]::AppendAllText("C:\Windows\System32\drivers\etc\hosts", "`r`n0.0.0.0 ProxySrv", (New-Object System.Text.UTF8Encoding $False));
}
Write-Progress -Activity AutoHarden -Status "Hardening-DisableWPAD" -Completed
echo "####################################################################################################"
echo "# Hardening-DNSCache"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DNSCache" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DNSCache"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v MaxCacheTtl /t REG_DWORD /d 10 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v MaxNegativeCacheTtl /t REG_DWORD /d 10 /f
Write-Progress -Activity AutoHarden -Status "Hardening-DNSCache" -Completed
echo "####################################################################################################"
echo "# Hardening-FileExtension"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-FileExtension" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-FileExtension"
# assoc .txt
# .hta
cmd /c ftype  htafile="C:\Windows\notepad.exe" "%1"
# .js
cmd /c ftype  JSFile="C:\Windows\notepad.exe" "%1"
# .jse
cmd /c ftype  JSEFile="C:\Windows\notepad.exe" "%1"
# .vbe
cmd /c ftype VBEFile="C:\Windows\notepad.exe" "%1"
# .vbs
cmd /c ftype VBSFile="C:\Windows\notepad.exe" "%1"
# .wsf
cmd /c ftype WSFFile="C:\Windows\notepad.exe" "%1"
# .wsh
cmd /c ftype WSHFile="C:\Windows\notepad.exe" "%1"
# .reg
cmd /c ftype regfile="C:\Windows\notepad.exe" "%1"
# .inf
cmd /c ftype inffile="C:\Windows\notepad.exe" "%1"
# .scf 
cmd /c ftype SHCmdFile="C:\Windows\notepad.exe" "%1"
# .wsc
cmd /c ftype scriptletfile="C:\Windows\notepad.exe" "%1"
# .scr
cmd /c ftype scrfile="C:\Windows\notepad.exe" "%1"
# .pif
cmd /c ftype piffile="C:\Windows\notepad.exe" "%1"
# .ps1
cmd /c ftype Microsoft.PowerShellScript.1="C:\Windows\notepad.exe" "%1"
cmd /c ftype Microsoft.PowerShellXMLData.1="C:\Windows\notepad.exe" "%1"
cmd /c ftype Microsoft.PowerShellConsole.1="C:\Windows\notepad.exe" "%1"
# .xml
cmd /c ftype "XML Script Engine"="C:\Windows\notepad.exe" "%1"
Write-Progress -Activity AutoHarden -Status "Hardening-FileExtension" -Completed
echo "####################################################################################################"
echo "# Hardening-RemoteAssistance"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-RemoteAssistance" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-RemoteAssistance"
if( ask "Disable Remote Assistance on this computer" "Hardening-RemoteAssistance.ask" ){
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /t REG_DWORD /v fAllowToGetHelp /d 0 /f
}
else{
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /f
}
Write-Progress -Activity AutoHarden -Status "Hardening-RemoteAssistance" -Completed
echo "####################################################################################################"
echo "# Hardening-Wifi-RemoveOpenProfile"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-Wifi-RemoveOpenProfile" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-Wifi-RemoveOpenProfile"
netsh wlan export profile folder=C:\Windows\Temp
get-item C:\Windows\temp\Wi-Fi-*.xml | foreach {
	$xml=[xml] (cat $_.FullName)
	Write-Host "[*] Lecture du profile wifi $($_.Name)"
	if( $xml.WLANProfile.MSM.security.authEncryption.authentication.ToLower() -eq "open" ){
		$p=$xml.WLANProfile.SSIDConfig.SSID.name.Replace('"','')
		Write-Host "[*] Suppression du profile wifi $p"		
		netsh wlan delete profile name="$p" interface=*
	}
}
rm C:\Windows\temp\Wi-Fi-*.xml | Out-Null
Write-Progress -Activity AutoHarden -Status "Hardening-Wifi-RemoveOpenProfile" -Completed
echo "####################################################################################################"
echo "# Hardening-Wifi"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-Wifi" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-Wifi"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v DontDisplayNetworkSelectionUI /d 1 /f

# WiFi Sense: Shared HotSpot Auto-Connect: Disable
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /t REG_DWORD /v value /d 0 /f
Write-Progress -Activity AutoHarden -Status "Hardening-Wifi" -Completed
echo "####################################################################################################"
echo "# Log-Activity"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Log-Activity" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Log-Activity"
# Log powershell activity
# https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5ba3dc87e79c703f9bfff29a/1537465479833/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2018+v2.2.pdf
# https://www.malwarearchaeology.com/cheat-sheets
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableInvocationHeader /t REG_DWORD /d 1 /f
reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v OutputDirectory /t REG_SZ /d "${AutoHarden_Logs}\Powershell.log" /f
reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
# This is VERY noisy, do not set in most environments, or seriously test first (4105 & 4106)
#reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockInvocationLogging
#WevtUtil gl "Windows PowerShell"
#WevtUtil gl "Microsoft-Windows-PowerShell/Operational"

# Log DHCP
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcp-Client/Operational" /v Enabled /t REG_DWORD /d 1 /f

# Log DHCPv6
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcpv6-Client/Operational" /v Enabled /t REG_DWORD /d 1 /f

# Log DNS
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" /v Enabled /t REG_DWORD /d 1 /f

Move-Item -ErrorAction SilentlyContinue -Force ${AutoHarden_Folder}\AuditPol_BEFORE.* ${AutoHarden_Logs}\AuditPol_BEFORE.log
if( -not [System.IO.File]::Exists("${AutoHarden_Logs}\AuditPol_BEFORE.log") ){
	Auditpol /get /category:* > $AutoHarden_Logs\AuditPol_BEFORE.log
}


# From
#	https://github.com/rkovar/PowerShell/blob/master/audit.bat
#	https://forensixchange.com/posts/19_05_07_dns_investigation/

# SET THE LOG SIZE - What local size they will be
# ---------------------
#
# 540100100 will give you 7 days of local Event Logs with everything logging (Security and Sysmon)
# 1023934464 will give you 14 days of local Event Logs with everything logging (Security and Sysmon)
# Other logs do not create as much quantity, so lower numbers are fine
#
wevtutil sl Security /ms:540100100
wevtutil sl Application /ms:256000100
wevtutil sl Setup /ms:256000100
wevtutil sl System /ms:256000100
wevtutil sl "Windows Powershell" /ms:256000100
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:540100100


# PS C:\> auditpol /list /subcategory:* /r
#
# Catégorie/Sous-catégorie,GUID
# Système,{69979848-797A-11D9-BED3-505054503030}
#   Modification de l’état de la sécurité,{0CCE9210-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9210-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Extension système de sécurité,{0CCE9211-69AE-11D9-BED3-505054503030}
#   Intégrité du système,{0CCE9212-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9212-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Pilote IPSEC,{0CCE9213-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9213-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
#   Autres événements système,{0CCE9214-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9214-69AE-11D9-BED3-505054503030}" /success:disable /failure:enable
# Ouverture/Fermeture de session,{69979849-797A-11D9-BED3-505054503030}
#   Ouvrir la session,{0CCE9215-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Fermer la session,{0CCE9216-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Verrouillage du compte,{0CCE9217-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9217-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Mode principal IPsec,{0CCE9218-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9218-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
#   Mode rapide IPsec,{0CCE9219-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9219-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
#   Mode étendu IPsec,{0CCE921A-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921A-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
#   Ouverture de session spéciale,{0CCE921B-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Autres événements d’ouverture/fermeture de session,{0CCE921C-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Serveur NPS,{0CCE9243-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9243-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Revendications utilisateur/de périphérique,{0CCE9247-69AE-11D9-BED3-505054503030}
#   Appartenance à un groupe,{0CCE9249-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9249-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# Accès aux objets,{6997984A-797A-11D9-BED3-505054503030}
#   Système de fichiers,{0CCE921D-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Registre,{0CCE921E-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921E-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Objet de noyau,{0CCE921F-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   SAM,{0CCE9220-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9220-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Services de certification,{0CCE9221-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9221-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Généré par application,{0CCE9222-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9222-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Manipulation de handle,{0CCE9223-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Partage de fichiers,{0CCE9224-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9224-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Rejet de paquet par la plateforme de filtrage,{0CCE9225-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9225-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Connexion de la plateforme de filtrage,{0CCE9226-69AE-11D9-BED3-505054503030}
#   Autres événements d’accès à l’objet,{0CCE9227-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Partage de fichiers détaillé,{0CCE9244-69AE-11D9-BED3-505054503030}
#   Stockage amovible,{0CCE9245-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9245-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Stratégie centralisée intermédiaire,{0CCE9246-69AE-11D9-BED3-505054503030}
# Utilisation de privilège,{6997984B-797A-11D9-BED3-505054503030}
#   Utilisation de privilèges sensibles,{0CCE9228-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9228-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Utilisation de privilèges non sensibles,{0CCE9229-69AE-11D9-BED3-505054503030}
#   Autres événements d’utilisation de privilèges,{0CCE922A-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922A-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
# Suivi détaillé,{6997984C-797A-11D9-BED3-505054503030}
#   Création du processus,{0CCE922B-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
# Log process activity
reg.exe add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
#   Fin du processus,{0CCE922C-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922C-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Activité DPAPI,{0CCE922D-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922D-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Événements RPC,{0CCE922E-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922E-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Événements Plug-and-Play,{0CCE9248-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9248-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Événements de jeton ajustés à droite,{0CCE924A-69AE-11D9-BED3-505054503030}
# Changement de stratégie,{6997984D-797A-11D9-BED3-505054503030}
#   Modification de la stratégie d’audit,{0CCE922F-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Modification de la stratégie d’authentification,{0CCE9230-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9230-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Modification de la stratégie d’autorisation,{0CCE9231-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9231-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Modification de la stratégie de niveau règle MPSSVC,{0CCE9232-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9232-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
#   Modification de la stratégie de plateforme de filtrage,{0CCE9233-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9233-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Autres événements de modification de stratégie,{0CCE9234-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9234-69AE-11D9-BED3-505054503030}" /success:disable /failure:enable
# Gestion des comptes,{6997984E-797A-11D9-BED3-505054503030}
#   Gestion des comptes d’utilisateur,{0CCE9235-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Gestion des comptes d’ordinateur,{0CCE9236-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9236-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Gestion des groupes de sécurité,{0CCE9237-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Gestion des groupes de distribution,{0CCE9238-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9238-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Gestion des groupes d’applications,{0CCE9239-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9239-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Autres événements de gestion des comptes,{0CCE923A-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE923A-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# Accès DS,{6997984F-797A-11D9-BED3-505054503030}
#   Accès au service d’annuaire,{0CCE923B-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE923B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Modification du service d’annuaire,{0CCE923C-69AE-11D9-BED3-505054503030}
#   Réplication du service d’annuaire,{0CCE923D-69AE-11D9-BED3-505054503030}
#   Réplication du service d’annuaire détaillé,{0CCE923E-69AE-11D9-BED3-505054503030}
# Connexion de compte,{69979850-797A-11D9-BED3-505054503030}
#   Validation des informations d’identification,{0CCE923F-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Opérations de ticket du service Kerberos,{0CCE9240-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9240-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Autres événements d’ouverture de session,{0CCE9241-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9241-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Service d’authentification Kerberos,{0CCE9242-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9242-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable


##############################################################################
# Log all autoruns to detect malware
# From: https://github.com/palantir/windows-event-forwarding/
$autorunsc7z = ("${AutoHarden_Logs}\autorunsc_"+(Get-Date -Format "yyyy-MM-dd"))
start-job -Name LogActivity -scriptblock {
	autorunsc -nobanner /accepteula -a "*" -c -h -s -v -vt "*" > "${autorunsc7z}.csv"
	7z a -t7z "${autorunsc7z}.7z" "${autorunsc7z}.csv"
	if( [System.IO.File]::Exists("${autorunsc7z}.7z") ){
		rm -Force "${autorunsc7z}.csv"
	}
}
Write-Progress -Activity AutoHarden -Status "Log-Activity" -Completed
echo "####################################################################################################"
echo "# Optimiz-CleanUpWindowFolder"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-CleanUpWindowFolder" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-CleanUpWindowFolder"
# https://www.malekal.com/comment-reduire-la-taille-du-dossier-windows-de-windows-10/

# Réduire la taille du dossier WinSxS
Dism.exe /online /Cleanup-Image /StartComponentCleanup

# Réparation des DLL et drivers
DISM /Online /Cleanup-image /Restorehealth
sfc /SCANNOW
Write-Progress -Activity AutoHarden -Status "Optimiz-CleanUpWindowFolder" -Completed
echo "####################################################################################################"
echo "# Optimiz-CleanUpWindowsName"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-CleanUpWindowsName" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-CleanUpWindowsName"
$finalUser='Administrateur'
try{
	if( -Not (New-Object System.Security.Principal.NTAccount($finalUser)).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
		$finalUser='Invité'
	}
}catch{
	$finalUser='Administrator'
	if( -Not (New-Object System.Security.Principal.NTAccount($finalUser)).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
		$finalUser='Guest'
	}
}


function killfakename( $file ){
	echo "$file ========="
	#takeown.exe /f $file
	icacls.exe "$file" /setowner $env:username
	remove-item -Force $file | Out-Null
	echo '' | Out-File $file
	icacls.exe "$file" /setowner $finalUser
	attrib +s +h $file
	(Get-Acl $file).Owner
	#(Get-Acl $file).Access
}


killfakename 'C:\Users\desktop.ini'
killfakename 'C:\Program Files\desktop.ini'
killfakename 'C:\Program Files (x86)\desktop.ini'
Write-Progress -Activity AutoHarden -Status "Optimiz-CleanUpWindowsName" -Completed
echo "####################################################################################################"
echo "# Software-install-notepad++"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Software-install-notepad++" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Software-install-notepad++"
if( ask "Replace notepad with notepad++" "Software-install-notepad++.ask" ){
$npp_path=(Get-Item "C:\Program Files*\Notepad++\notepad++.exe").FullName.Replace('.exe','.vbs')
@'
'// DISCLAIMER
'// THIS COMES WITH NO WARRANTY, IMPLIED OR OTHERWISE. USE AT YOUR OWN RISK
'// IF YOU ARE NOT COMFORTABLE EDITING THE REGISTRY THEN DO NOT USE THIS SCRIPT
'//
'// NOTES:
'// This affects all users.
'// This will prevent ANY executable named notepad.exe from running located anywhere on this computer!!
'//
'// Save this text to your notepad++ folder as a text file named npp.vbs (some AV don't like vbs, get a different AV :-P )
'//
'// USAGE
'// 1)
'// Navigate to registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
'//
' // 2)
'// Add new subkey called notepad.exe
'// This step is what tells windows to use the notepad++ exe, to undo simply delete this key
'//
'// 3)
'// Create new Sting Value called Debugger
'//
'// 4)
'// Modify value and enter wscript.exe "path to npp.vbs" e.g. wscript.exe "C:\Program Files\Notepad++\npp.vbs"

Option Explicit
Dim sCmd, x
sCmd = """" & LeftB(WScript.ScriptFullName, LenB(WScript.ScriptFullName) - LenB(WScript.ScriptName)) & "notepad++.exe" & """ """
For x = 1 To WScript.Arguments.Count - 1
   sCmd = sCmd & WScript.Arguments(x) & " "
Next
sCmd = sCmd & """"
CreateObject("WScript.Shell").Exec(sCmd)
WScript.Quit
'@ | out-file -encoding ASCII $npp_path

if( [System.IO.File]::Exists($npp_path) ){
	# Create sub folder
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d x /f
	# Create key
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Name Debugger -Value ('wscript.exe "'+$npp_path+'"') -PropertyType String -Force | Out-Null
}
}
else{
$npp_path=(Get-Item "C:\Program Files*\Notepad++\notepad++.exe")
if( $npp_path -ne $null ){
	$npp_path = $npp_path.FullName.Replace('.exe','.vbs')
	rm $npp_path
	reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /f
}
}
Write-Progress -Activity AutoHarden -Status "Software-install-notepad++" -Completed
echo "####################################################################################################"
echo "# Software-install"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Software-install" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Software-install"
Write-Progress -Activity AutoHarden -Status "Software-install" -Completed
echo "####################################################################################################"
echo "# ZZZ-10.Asks-Cleanup"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "ZZZ-10.Asks-Cleanup" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running ZZZ-10.Asks-Cleanup"
Remove-Item -Force -ErrorAction SilentlyContinue $AutoHarden_Folder\*.ask
Write-Progress -Activity AutoHarden -Status "ZZZ-10.Asks-Cleanup" -Completed
echo "####################################################################################################"
echo "# ZZZ-20.Firewall-Cleanup"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "ZZZ-20.Firewall-Cleanup" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running ZZZ-20.Firewall-Cleanup"
# Apply all rules
logInfo 'Apply all rules'
applyFwRules

# Enable rules
logInfo 'Enable rules'
Get-NetFirewallRule -DisplayName '*AutoHarden*' | Enable-NetFirewallRule

# Remove all rules that are not tagged
logInfo 'Remove all rules that are not tagged'

# This version doesn't remove hidden rules. Hidden rules can only be removed via registry...
#Get-NetFirewallRule | where {
#	-not ($_.DisplayName -like "*[AutoHarden]*" -or $_.DisplayName -like "*AutoHarden*$AutoHarden_version*")
#} | Remove-NetFirewallRule -ErrorAction Continue | Out-Null
#Get-NetFirewallRule -all -policystore configurableservicestore | where {
#	-not ($_.DisplayName -like "*[AutoHarden]*" -or $_.DisplayName -like "*AutoHarden*$AutoHarden_version*")
#} | Remove-NetFirewallRule -ErrorAction Continue | Out-Null


# Following Registry-Keys store the Rules: "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices"
# and all Subfolders. "Static" are only configurable by Registry, "Configurable" by command-line and Registry, "FirewallRules" are the rules you can see in
# WF.msc. If you take the rights of FirewallRules too, you can not modify by mmc.exe/wf.msc anymore.
#
# 1. HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules
# Windows Firewall rules are stored here. These are available through Windows Firewall API and these are visible and editable in WFC.
# 
# 2. HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules
# Here are stored Windows Store rules that are defined for specific user accounts. These rules can be removed.
# 
# 3. HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System
# Here are stored default service based rules, meaning some services may accept connections only on certain ports, other services may not
# receive or initiate any connection. These can't be deleted. They are loaded and applied before the ones from 1. Windows Firewall API does
# not allow access to these, therefore WFC does not display them. Anyway, these should not be modified by the user.
@('HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System', 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules', 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules') | foreach {
	$Path=$_
	Get-Item -PipelineVariable key $Path | ForEach-Object Property | ForEach-Object { 
		$keyName=$_
		$value=$key.GetValue($keyName)
		if( $value -notmatch ".*\[AutoHarden\].*" -and $value -notmatch ".*AutoHarden-$AutoHarden_version.*" ){
			echo "Removing $keyName"
			#$_ | Remove-ItemProperty
			Remove-ItemProperty -Path $Path -Name $keyName -Force
		}
	}
};


logInfo 'Checking rules priorities'
$NetFirewallRule = Get-NetFirewallRule
$nbAllow = (Get-NetFirewallRule -Action Allow -ErrorAction Ignore).Count
$nbAllowAtTop = ($NetFirewallRule | Select -First $nbAllow | where { $_.Action -eq 'Allow' }).Count
if( $nbAllow -ne $nbAllowAtTop ){
	logInfo 'Rules are not correctly ordered...'
	# Dump the FW and rearange
	logInfo 'Dump the FW and rearange'
	$allRules = Get-NetFirewallRule | Sort-Object 'Action'  | foreach {
		$NetFirewallPortFilter=$_ | Get-NetFirewallPortFilter
		$NetFirewallAddressFilter=$_ | Get-NetFirewallAddressFilter
		$NetFirewallApplicationFilter=$_ | Get-NetFirewallApplicationFilter
		$NetFirewallSecurityFilter=$_ | Get-NetFirewallSecurityFilter
		$NetFirewallServiceFilter=$_ | Get-NetFirewallServiceFilter
		@{
			Name=$_.Name;
			DisplayName=$_.DisplayName;
			Group=$_.Group;
			Enabled=$_.Enabled;
			Direction=$_.Direction;
			Action=$_.Action;
			Program=$NetFirewallApplicationFilter.Program;
			
			LocalAddress=$NetFirewallAddressFilter.LocalAddress;
			RemoteAddress=$NetFirewallAddressFilter.RemoteAddress;
			
			Protocol=$NetFirewallPortFilter.Protocol;
			LocalPort=$NetFirewallPortFilter.LocalPort;
			RemotePort=$NetFirewallPortFilter.RemotePort;
			IcmpType=$NetFirewallPortFilter.IcmpType;
			DynamicTarget=$NetFirewallPortFilter.DynamicTarget;
			
			Authentication=$NetFirewallSecurityFilter.Authentication;
			Encryption=$NetFirewallSecurityFilter.Encryption;
			OverrideBlockRules=$NetFirewallSecurityFilter.OverrideBlockRules;
			LocalUser=$NetFirewallSecurityFilter.LocalUser;
			RemoteUser=$NetFirewallSecurityFilter.RemoteUser;
			RemoteMachine=$NetFirewallSecurityFilter.RemoteMachine;
			
			Service=$NetFirewallServiceFilter.Service
		}
	}
	# Full Open the firewall to avoid connections lost
	logInfo 'Full Open the firewall to avoid connections lost'
	Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False -DefaultInboundAction Allow
	# Cleaning rules
	logInfo 'Cleaning rules'
	Get-NetFirewallRule | Remove-NetFirewallRule
	# Reinsert rules with correct order
	logInfo 'Reinsert rules with correct order'
	$allRules | foreach {
		$param = $_
		New-NetFirewallRule @param -ErrorAction Continue | Out-Null
	}
	# Harden the firewall
	logInfo 'Reenable the firewall'
}

# Enabling firewall
Get-NetFirewallProfile | foreach {
	$Name=$_.Name
	$DefaultInboundAction=$_.DefaultInboundAction
	if( $_.Enabled -eq $false ){
		Write-Host -BackgroundColor Red -ForegroundColor White "    [!] ${Name} firewall profile was disabled"
	}
	if( $_.DefaultInboundAction -ne "Block" ){
		Write-Host -BackgroundColor Red -ForegroundColor White "    [!] ${Name} firewall profile was DefaultInboundAction=${DefaultInboundAction}"
	}
	$_
} | Set-NetFirewallProfile -Enabled True -DefaultOutboundAction Allow -DefaultInboundAction Block -AllowInboundRules True -AllowLocalFirewallRules True -AllowLocalIPsecRules True -AllowUnicastResponseToMulticast True -LogAllowed True -LogBlocked True -LogIgnored True -LogFileName "%windir%\system32\logfiles\firewall\pfirewall.log" -LogMaxSizeKilobytes 32767

Write-Progress -Activity AutoHarden -Status "ZZZ-20.Firewall-Cleanup" -Completed
###############################################################################
# Cleaning the script...
###############################################################################
logInfo 'Waiting for the job autoruns...'
Wait-Job -Name LogActivity
Stop-Transcript
7z a -t7z "${AutoHardenTransScriptLog}.7z" $AutoHardenTransScriptLog
if( [System.IO.File]::Exists("${AutoHardenTransScriptLog}.7z") ){
	rm -Force $AutoHardenTransScriptLog
}
