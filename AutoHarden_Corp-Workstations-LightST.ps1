# AutoHarden - A simple script that automates Windows Hardening
#
# Filename: AutoHarden_Corp-Workstations-LightST.ps1
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
# Update: 2022-06-01-01-36-12
$AutoHarden_version="2022-06-01-01-36-12"
$global:AutoHarden_boradcastMsg=$true
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
Add-Type -AssemblyName System.Windows.Forms

$AutoHarden_Folder='C:\Windows\AutoHarden'
$AutoHarden_Logs="${AutoHarden_Folder}\logs"
$AutoHarden_AsksFolder="${AutoHarden_Folder}\asks"
$AutoHarden_Group='Corp-Workstations-LightST'
$AutoHarden_Asks=($AutoHarden_Group -eq 'RELEASE')
$AutoHarden_WebDomain="https://raw.githubusercontent.com/1mm0rt41PC/AutoHarden/master/AutoHarden_${AutoHarden_Group}.ps1"
#$AutoHarden_SysmonUrl="https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
$AutoHarden_SysmonUrl="https://raw.githubusercontent.com/1mm0rt41PC/AutoHarden/master/sysmonconfig.xml"

###############################################################################
# FUNCTIONS - Const var
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
# FUNCTIONS - Logs
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
# FUNCTIONS - RPC
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
	$file=createTempFile $acl
	netsh -f $file
	$global:RpcRules = (netsh rpc filter show filter)
	echo $global:RpcRules
	$global:RpcRules = ($global:RpcRules).Replace(' ','')
	rm $file
}


# Add a rule to drop access to EFS for non DA
# From: https://twitter.com/tiraniddo/status/1422223511599284227
# From: https://gist.github.com/tyranid/5527f5559041023714d67414271ca742
function RpcRuleCreator( $uuid, $name )
{
	$1st_uuid=$uuid.Split('-')[0]
	if( $RpcRules -Like "*$uuid*" -Or $RpcRules -Like "*$1st_uuid*" ){
		logInfo "RpcRules is already applied for $name => $uuid"
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
# FUNCTIONS - Global
$global:asks_cache = @{}

function ask( $query, $config )
{
	if( $global:asks_cache.ContainsKey($config) ){
		Write-Host ("# [${AutoHarden_AsksFolder}\${config}] In cache => {0}" -f $global:asks_cache[$config])
		return $global:asks_cache[$config];
	}
	if( [System.IO.File]::Exists("${AutoHarden_AsksFolder}\${config}") ){
		Write-Host "# [${AutoHarden_AsksFolder}\${config}] Exist => Using the new file location"
		$ret = _ask $query $config $AutoHarden_AsksFolder
		$global:asks_cache[$config] = $ret
		return $ret;
	}
	if( [System.IO.File]::Exists("${AutoHarden_Folder}\${config}") ){
		Write-Host "# [${AutoHarden_Folder}\${config}] The new 'ask' location doesn't exist but the old one exist => Using the old file location"
		$ret = _ask $query $config $AutoHarden_Folder
		[System.IO.File]::WriteAllLines("${AutoHarden_AsksFolder}\${config}", "$ret", (New-Object System.Text.UTF8Encoding $False));
		Remove-Item -Force "${AutoHarden_Folder}\${config}" -ErrorAction Ignore;
		$global:asks_cache[$config] = $ret
		return $ret;
	}
	if( $askMigration.Contains($config) ){
		if( [System.IO.File]::Exists("${AutoHarden_Folder}\$($askMigration[$config])") ){
			$ret=cat "${AutoHarden_Folder}\$($askMigration[$config])" -ErrorAction Ignore;
			if( $config -eq 'Hardening-DisableMimikatz__Mimikatz-DomainCredAdv.ask' ){
				if( $ret -eq 'Yes' ){
					$ret = 'No'
				}else{
					$ret = 'Yes'
				}
			}
			Write-Host ("# [${AutoHarden_AsksFolder}\${config}] Not found but the old configuration exist ${AutoHarden_Folder}\$($askMigration[$config]) with the value ${ret} => {0}" -f ($ret -eq 'Yes'))
			[System.IO.File]::WriteAllLines("${AutoHarden_AsksFolder}\${config}","$ret", (New-Object System.Text.UTF8Encoding $False));
			Remove-Item -Force $AutoHarden_Folder\$askMigration[$config] -ErrorAction Ignore;
			$global:asks_cache[$config] = $ret -eq 'Yes'
			return $global:asks_cache[$config];
		}
	}
	Write-Host "# [${AutoHarden_AsksFolder}\${config}] This parameter is new and doesn't exist at all"
	$ret = _ask $query $config $AutoHarden_AsksFolder
	$global:asks_cache[$config] = $ret
	return $ret;
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
					$ret = (Read-Host "${query}? (Y/n)").toupper()
					if( $ret.Length -gt 0 ){
						$ret = $ret.substring(0,1)
					}else{
						$ret = 'Y'
					}
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
		logSuccess ("[${folder}\${config}] is >$ret< => parsed={0}" -f ($ret -eq 'Yes' -Or $ret -eq 'True'))
		return $ret -eq 'Yes' -Or $ret -eq 'True';
	}catch{
		logError "[${folder}\${config}][WARN] An update of AutoHarden require an action from the administrator."
		if( $global:AutoHarden_boradcastMsg -And $AutoHarden_Asks ) {
			$global:AutoHarden_boradcastMsg=$false
			msg * "An update of AutoHarden require an action from the administrator.`r`n`r`n${query}?`r`nPlease run ${AutoHarden_Folder}\AutoHarden.ps1"
		}
		return $null;
	}
}


function createTempFile( $data, [Parameter(Mandatory=$false)][string]$ext='' )
{
	$tmpFileName = -join ((65..90) + (97..122) | Get-Random -Count 25 | % {[char]$_});
	$tmpFileName = "${AutoHarden_Folder}\${tmpFileName}${ext}"
	[System.IO.File]::WriteAllLines($tmpFileName, $data, (New-Object System.Text.UTF8Encoding $False));
	return $tmpFileName;
}


# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v PublishUserActivities /d 0 /f
function reg()
{
	$action = $args[0].ToLower()
	$hk = $args[1].Replace('HKLM','HKLM:').Replace('HKCR','HKCR:').Replace('HKCU','HKCU:')
	$hk = $hk.Replace('HKEY_LOCAL_MACHINE','HKLM:').Replace('HKEY_CLASSES_ROOT','HKCR:').Replace('HKEY_CURRENT_USER','HKCU:')

	$type = 'REG_DWORD'
	$key = '???'
	$value = '???'

	for( $i=2; $i -lt $args.Count; $i+=2 )
	{
		if( $args[$i] -eq '/t' ){
			$type=$args[$i+1]
		}elseif( $args[$i] -eq '/v' ){
			$key=$args[$i+1]
		}elseif( $args[$i] -eq '/d' ){
			$value=$args[$i+1]
		}elseif( $args[$i] -eq '/f' ){
			$i-=1
			# Pass
		}
	}

	if( $action -eq 'add' ){
		try {
			if( (Get-ItemPropertyValue $hk -Name $key -ErrorAction Stop) -eq $value ){
				logInfo "[${hk}:$key] is OK ($value)"
			}else{
				logSuccess "[${hk}:$key] is now set to $value"
				reg.exe $args
			}
		}catch{
			logSuccess "[${hk}:$key] is now set to $value"
			reg.exe $args
		}
	}elseif( $action -eq 'delete' ){
		try {
			Get-ItemPropertyValue $hk -Name $key -ErrorAction Stop
			logSuccess "[${hk}:$key] is now DELETED"
			reg.exe $args
		}catch{
			logInfo "[${hk}:$key] is NOT present"
		}
	}
}

function mywget( $Uri, $OutFile=$null )
{
	$ret = $null
	Get-NetFirewallRule -DisplayName '*AutoHarden*Powershell*' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
	try{
		if( $OutFile -eq $null ){
			$ret=Invoke-WebRequest -UseBasicParsing -Uri $Uri
		}else{
			Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile | Out-Null
		}
	}catch{
		if( $OutFile -eq $null ){
			$ret=curl.exe $Uri
		}else{
			curl.exe $Uri --output $OutFile | Out-Null
		}

	}
	Get-NetFirewallRule -DisplayName '*AutoHarden*Powershell*' -ErrorAction SilentlyContinue | Enable-NetFirewallRule
	return $ret;
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

Get-ChildItem -File $AutoHarden_Folder\*.log | foreach {
	$name = $_.Name
	$_ | Compress-Archive -CompressionLevel "Optimal" -DestinationPath ${AutoHarden_Logs}\${name}.zip -ErrorAction SilentlyContinue
}

####################################################################################################
logInfo "Asking questions for the configuration"
ask "Fetch the latest version of AutoHarden from Github every day at 08h00 AM" "0-AutoUpdateFromWeb.ask" | Out-Null
ask "Execute AutoHarden every day at 08h00 AM" "0.1-AutoUpdate.ask" | Out-Null
ask "Block Internet communication for evil tools ?
This filtering prevents viruses from downloading the payload." "1.1-Firewall-Malware.ask" | Out-Null
ask "Block Internet communication for Word and Excel ?
Excel and Word will still be able to access files on local network shares.
This filtering prevents viruses from downloading the payload.

Block Internet communication for Word and Excel" "1.2-Firewall-Office.ask" | Out-Null
ask "Block Internet communication for 'Internet Explorer' ?
'Internet Explorer' will still be able to access web server on local network.
This filtering prevents viruses from downloading the payload.

Block Internet communication for 'Internet Explorer'" "1.3-Firewall-IE.ask" | Out-Null
ask "Disable SNMP communication (can break printers)" "1.4-Firewall-BlockOutgoingSNMP.ask" | Out-Null
ask "Avoid sending notification to Users about the firewall" "1.5-Firewall-DisableNotification.ask" | Out-Null
ask "Disable Cortana in Windows search bar" "Crapware-Cortana.ask" | Out-Null
ask "Remove OneDrive" "Crapware-Onedrive.ask" | Out-Null
ask "Uninstall OneNote" "Crapware-RemoveUseLessSoftware__Uninstall-OneNote.ask" | Out-Null
ask "Uninstall Skype" "Crapware-RemoveUseLessSoftware__Uninstall-Skype.ask" | Out-Null
ask "Disable voice control" "Harden-VoiceControl.ask" | Out-Null
ask "Harden Windows Defender" "Harden-WindowsDefender.ask" | Out-Null
ask "Invert the administrator and guest accounts" "Hardening-AccountRename.ask" | Out-Null
ask "Deny auto installation of vendor's application/drivers by the user" "Hardening-Co-Installers.ask" | Out-Null
ask "Do you want to enable 'Credentials Guard' and disable VMWare/VirtualBox" "Hardening-DisableMimikatz__CredentialsGuard.ask" | Out-Null
ask "Harden domain credential against hijacking ?
WARNING If this Windows is a mobile laptop, this configuration will break this Windows !!!

Harden domain credential against hijacking" "Hardening-DisableMimikatz__Mimikatz-DomainCredAdv.ask" | Out-Null
ask "Block DLL from SMB share and WebDav Share" "Hardening-DLLHijacking.ask" | Out-Null
ask "Disable Remote Assistance on this computer" "Hardening-RemoteAssistance.ask" | Out-Null
ask "Show file extension and show windows title in the taskbar" "Optimiz-ClasicExplorerConfig.ask" | Out-Null
ask "Disable auto Windows Update during work time" "Optimiz-DisableAutoUpdate.ask" | Out-Null
ask "Disable WindowsDefender" "Optimiz-DisableDefender.ask" | Out-Null
ask "Replace notepad with notepad++" "Software-install-notepad++.ask" | Out-Null
$global:asks_cache | Format-Table -Autosize
logSuccess "All asks have been processed"
####################################################################################################
echo "####################################################################################################"
echo "# 0.1-AutoUpdate"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "0.1-AutoUpdate" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 0.1-AutoUpdate"
$q=ask "Execute AutoHarden every day at 08h00 AM" "0.1-AutoUpdate.ask"
if( $q -eq $true ){
$ps1TestSign = "${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1"
if( -not [System.IO.File]::Exists($ps1TestSign) ){
	$ps1TestSign = "${AutoHarden_Folder}\AutoHarden.ps1"
}
if( -not [System.IO.File]::Exists($ps1TestSign) ){
	$ps1TestSign = $null
}
for( $i=3; $i -gt 0; $i-- )
{
	# Install cert to avoid git takeover
	$AutoHardenCert = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"
	while( -not [System.IO.File]::Exists($AutoHardenCert) )
	{
		[IO.File]::WriteAllBytes($AutoHardenCert, [Convert]::FromBase64String("MIIFGTCCAwGgAwIBAgIQlPiyIshB45hFPPzNKE4fTjANBgkqhkiG9w0BAQ0FADAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBMB4XDTE5MTAyOTIxNTUxNVoXDTM5MTIzMTIzNTk1OVowFTETMBEGA1UEAxMKQXV0b0hhcmRlbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALrMv49xZXZjF92Xi3cWVFQrkIF+yYNdU3GSl1NergVq/3WmT8LDpaZ0XSpExZ7soHR3gs8eztnfe07r+Fl+W7l6lz3wUGFt52VY17WCa53tr5dYRPzYt2J6TWT874tqZqlo+lUl8ONK1roAww2flcDajm8VUXM0k0sLM17H9NLykO3DeBuh2PVaXUxGDej+N8PsYF3/7Gv2AW0ZHGflrondcXb2/eh8xwbwRENsGaMXvnGr9RWkufC6bKq31J8BBnP+/65M6541AueBoH8pLbANPZgHKES+8V9UWlYKOeSoeBhtL1k3Rr8tfizRWx1zg/pBNL0WTOLcusmuJkdHkdHbHaW6Jc/vh06Cs6xqz9/Dkg+K3BvOmfwZfAjl+qdgzM8dUU8/GWhswngwLAz64nZ82mZv/Iw6egC0rj5MYV0tpEjIgtVVgHavUfyXoIETNXFQR4SoK6PfeVkEzbRh03xhU65MSgBgWVv1YbOtdgXK0MmCs3ngVPJdVaqBjgcrK++X3Kxasb/bOkcfQjff/EK+BPb/xs+pXEqryYbtbeX0v2rbV9cugPUj+mneucZBLFjuRcXhzVbXLrwXVne7yTD/sIKfe7dztzchg19AY6/qkkRkroaKLASpfCAVx2LuCgeFGn//QaEtCpFxMo2dcnW2a+54pkzrCRTRg1N2wBQFAgMBAAGjYjBgMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEkGA1UdAQRCMECAEPp+TbkVy9u5igk2CqcX2OihGjAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBghBrxVMud93NnE/XjEko2+2HMA0GCSqGSIb3DQEBDQUAA4ICAQAQLtHeMr2qJnfhha2x2aCIApPjfHiHT4RNPI2Lq71jEbTpzdDFJQkKq4R3brGcpcnuU9VjUwz/BgKer+SFpkwFwTHyJpEFkbGavNo/ez3bqoehvqlTYDJO/i2mK0fvKmShfne6dZT+ftLpZCP4zngcANlp+kHy7mNRMB+LJv+jPc0kJ2oP4nIsLejyfxMj0lXuTJJRhxeZssdh0tq4MZP5MjSeiE5/AMuKT12uJ6klNUFS+OlEpZyHkIpgy4HxflXSvhchJ9U1YXF2IQ47WOrqwCXPUinHKZ8LwB0b0/35IlRCpub5KdRf803+4Okf9fL4rfc1cg9ZbLxuK9neFg1+ESL4aPyoV03TbN7Cdsd/sfx4mJ8jXJD+AXZ1ZofAAapYf9J5C71ChCZlhIGBvVc+dTUCWcUYgNOD9Nw+NiV6mARmVHl9SFL7yEtNYFgo0nWiNklqMqBLDxmrrD27sgBpFUwbMZ52truQwaaSHD7hFb4Tb1B0JVaGoog3QfNOXaFeez/fAt5L+yo78cDm7Q2tXvy2g0xDAL/TXn7bhtDzQunltBzdULrJEQO4zI0h8YgmF88a0zYZ9HRkDUn6dR9+G8TlZuUsWSOdvLdEvad9RqiHKeSrL6qgLBT5kqVt6AFsEtmFNz1s7xpsw/zPZvIXtQTmb4h+GcE/b2sUFZUkRA=="))
		Import-Certificate -Filepath $AutoHardenCert -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
	}

	$AutoHardenCertCA = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"
	while( -not [System.IO.File]::Exists($AutoHardenCertCA) )
	{
		[IO.File]::WriteAllBytes($AutoHardenCertCA, [Convert]::FromBase64String("MIIFHDCCAwSgAwIBAgIQa8VTLnfdzZxP14xJKNvthzANBgkqhkiG9w0BAQ0FADAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBMB4XDTE5MTAyOTIxNTUwOVoXDTM5MTIzMTIzNTk1OVowGDEWMBQGA1UEAxMNQXV0b0hhcmRlbi1DQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANlm8tv2IqVairIP90RnIsNlQYPMAvUwRcC6Nw+0Qlv56tWczvMl9IF0+h2vUF5+lnSEkJMGBqeLFaJgSo9lNyHeTfjjqpEcMVBw1nXl6VSfNiirD7fJTkyZ3rl63PsOwbfWCPDW1AvLufYhBiijPlK1k4RJFkiFZbZkpe5ys0uY4QVFj+ZTaW0EA0MncX2YZ775QnX7HJO0HfMcHGGTxOPhAqJ7Pp+IBrs75laaASekJSTVub7jqs5aeApQkUWgKel1fmK0tBv35deE1P5ABXi+KnuzWCZDU8znIDAnj1qz+6c21KKhslEdzYlRSlq4kPcF964GECxRtgq0z1pzhV/WvBJjWjNp3G5e8jUfjuAg2utF/xd/j7GNU8vllDAXFjl4czc1saGZDcU8a/uaweKMjqR4WfyUp/H/mB7JFJlOHBGTRszWaAU/4E0V+bICXNI5augkV29ci0HouBG3WFcQiA5q+1U2vY/scVyMPm8ZecCe2b+SD/ipPtFspcOPStRm5EQgL4CWdVpSmm8+JRO0NcrSnQtNPCwPBT3c7OLOwYLBl8WHcJG1yOJtQvLjv1koMmJkHR0djODx8Ig9fqAFLH0c694E6VJbojDVGp/LRR9LnJnzYlWAYoT3ScPQ9uesgr4x8VSnrM6cMG3ASQD92RVXKCDep/Rq29IXtvjpAgMBAAGjYjBgMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEkGA1UdAQRCMECAEPp+TbkVy9u5igk2CqcX2OihGjAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBghBrxVMud93NnE/XjEko2+2HMA0GCSqGSIb3DQEBDQUAA4ICAQDBiDwoVi2YhWzlMUTE5JHUUUkGkTaMVKfjYBFiUHeQQIaUuSq3dMRPlfpDRSzt3TW5mfwcPdwwatE0xeGN3r3zyQgnzEG/vMVrxwkgfFekVYvE4Ja551MSkwAA2fuTHGsRB9tEbTrkbGr35bXZYxOpGHpZIifFETFCT6rOpheDdxOEU6YyLeIYgGdGCmKStJ3XSkvqBh7oQ45M0+iqX9yjJNGoUg+XMLnk4K++7rxIk/SGtUBuIpsB3ksmIsXImelUxHw3xe6nGkkncAm9yX7rTU1M1fqrxaoBiGvx9jlqxDVMIzzDga7vKXDsP/iUmb4feeTIoy7+SgqGWsSvRiLt6A5CeIQ5XaTrhWN+mbGq6vvFTZuctY6LzdufwhlbZXFmfU/LnsRprM2EzYfba8VZmmfMBBpnYrw5q/3d5f9OSmNkRQjs0HfVab9b44hWNUd2QJ6yvjM5gdB367ekVagLpVdb/4mwzKOlspDULSlT7rAeuOc1njylu80pbBFCNiB72AmWNbqEK48ENloUr75NhuTKJ74llj+Nt6g9zDzsXuFICyJILvgE8je87GQXp+712aSGqJBLiGTFjuS3UctJ8qdlf5zkXw6mMB52/M3QYg6vI+2AYRc2EQXRvm8ZSlDKYidp9mZF43EcXFVktnK87x+TKYVjnfTGomfLfAXpTg=="))
		Import-Certificate -Filepath $AutoHardenCertCA -CertStoreLocation Cert:\LocalMachine\AuthRoot | Out-Null
	}
	try{
		Remove-Item -ErrorAction SilentlyContinue -Force $AutoHardenCert $AutoHardenCertCA
	}catch{}

	if( $ps1TestSign -ne $null -and (Get-AuthenticodeSignature $ps1TestSign).Status -eq [System.Management.Automation.SignatureStatus]::Valid ){
		$i=0;
	}
}

$Trigger = New-ScheduledTaskTrigger -At 08:00am -Daily
#$Action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec AllSigned -nop -File C:\Windows\AutoHarden\AutoHarden.ps1 > C:\Windows\AutoHarden\ScheduledTask.log"
$Action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec ByPass -nop -File ${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1"
$Setting = New-ScheduledTaskSettingsSet -RestartOnIdle -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)
Register-ScheduledTask -TaskName "AutoHarden_${AutoHarden_Group}" -Trigger $Trigger -User "NT AUTHORITY\SYSTEM" -Action $Action -RunLevel Highest -Settings $Setting -Force | Out-Null
if( ask "Auto update AutoHarden every day at 08h00 AM" "0-AutoUpdateFromWeb.ask" ){
	$tmpPS1 = -join ((65..90) + (97..122) | Get-Random -Count 25 | % {[char]$_})
	$tmpPS1 = "${AutoHarden_Folder}\${tmpPS1}.ps1"
	mywget -Uri $AutoHarden_WebDomain -OutFile $tmpPS1 | Out-Null
	if( (Get-AuthenticodeSignature $tmpPS1).Status -eq [System.Management.Automation.SignatureStatus]::Valid ){
		logSuccess 'The downloaded PS1 has a valid signature !'
		Move-Item -force $tmpPS1 ${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1 | Out-Null
	}else{
		logError 'The downloaded PS1 has an invalid signature !'
	}
}
if( [System.IO.File]::Exists("${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1") -And (Get-ScheduledTask -TaskName "AutoHarden_${AutoHarden_Group}" -ErrorAction SilentlyContinue) -ne $null ){
	Unregister-ScheduledTask -TaskName "AutoHarden" -Confirm:$False -ErrorAction SilentlyContinue
}

}elseif($q -eq $false){
Unregister-ScheduledTask -TaskName "AutoHarden_${AutoHarden_Group}" -Confirm:$False -ErrorAction SilentlyContinue

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


###############################################################################
# FW creation
function FWRule( $param )
{
	$param = $param.clone()
	if( -Not $param.ContainsKey('Direction') -or $param['Direction'] -eq '*' ){
		#Write-Host "Applying Direction"
		$param['Direction'] = 'Outbound'
		FWRule $param
		$param['Direction'] = 'Inbound'
		FWRule $param
		return $null
	}
	if( $param.ContainsKey('blockExe') ){
		#Write-Host "Applying blockExe"
		$blockExe = $param['blockExe']
		$param.remove('blockExe')
		$blockExe | Get-Item -ErrorAction Continue | foreach {
			$opt = $param.clone()
			$opt['Program'] = $_.Fullname
			$opt['Name'] = ('{0} - {1}' -f $opt['Name'], $opt['Program'])
			FWRule $opt
		}
		return $null
	}
	if( ($param.ContainsKey('RemotePort') -And -Not $param.ContainsKey('Protocol')) -Or $param['Protocol'] -eq '*' ){
		#Write-Host "Applying Protocol"
		@('tcp','udp') | foreach {
			$opt = $param.clone()
			$opt['Protocol'] = $_;
			$opt['Name'] += (' ('+$_+')');
			FWRule $opt
		}
		return $null;
	}

	$param['DisplayName'] = ('[AutoHarden-{0}] {1}' -f $AutoHarden_version,$param['Name']) -replace '\] \[', ']['
	if( $param.ContainsKey('Group') -and $param['Group'] -ne '' ){
		$param['Group'] = ('AutoHarden-{0}' -f $param['Group'])
	}
	$param['Name'] = ('[AutoHarden-{0}][{1}] {2}' -f $AutoHarden_version,$param['Direction'],$param['Name'])
	if( $param.ContainsKey('RemotePort') ){
		$param['Name'] += (' '+$param['RemotePort'])
	}
	if( $param.ContainsKey('LocalPort') ){
		$param['Name'] += (' '+$param['LocalPort'])
	}
	if( $param.ContainsKey('Protocol') ){
		$param['Name'] += (' /'+$param['Protocol'])
	}
	if( (Get-NetFirewallRule -Group $param['Group'] -ErrorAction Ignore | where {$_.Name -eq $param['Name']}).Count -eq 0 ){
		logInfo ("Create new FW rule: {0}" -f ($param | ConvertTo-Json))
		New-NetFirewallRule -Enabled True -Profile Any @param -ErrorAction Continue | Out-Null
	}else{
		logSuccess ("FW rule is in place: {0}" -f ($param | ConvertTo-Json))
	}
}

###############################################################################
# Remove invalid or old rule
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
function FWRemoveBadRules
{
	$date = ('[AutoHarden-{0}]' -f $AutoHarden_version)
	@(
		'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules',
		'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System',
		'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules'
	) | foreach {
		Write-Host ('Working on {0}' -f $_) ;
		$hive = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(($_ -Replace 'HKLM\:\\', ''), $true);
		if( $hive -eq $null ){
			continue;
		} ;
		$hive.GetValueNames() | where {
			-not $hive.GetValue($_).Contains('[AutoHarden]') -and
			-not $hive.GetValue($_).Contains($date)
		} | foreach {
			$v = $hive.GetValue($_) ;
			Write-Host ('Delete {0} => {1}' -f $_,$v) ;
			$hive.DeleteValue($_) ;
		} ;
	}
}


###############################################################################
###############################################################################
###############################################################################
# Windows7 functions in degraded compactibility mode
###############################################################################
###############################################################################
###############################################################################
if( -not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) ){
	###############################################################################
	# Degraded compactibility mode of the function New-NetFirewallRule
	function New-NetFirewallRule{
	[cmdletbinding()]
	Param (
		[string] $Enabled,
		[string] $Action,
		[string] $Name,
		[string] $DisplayName,
		[string] $Profile,
		[string] $Direction,
		[string] $Group,
		[string] $Description,
		[string] $Program,
		[string] $Protocol,
		$RemotePort,
		$LocalPort,
		$RemoteAddress
	)
		$Direction = $Direction -replace 'bound', ''
		if( [string]::IsNullOrEmpty($RemotePort) ){
			$RemotePort=''
		}else{
			if( $RemotePort -is [array] ){
				$RemotePort = $RemotePort -join ','
			}
			$RemotePort="remoteport=`"$RemotePort`""
		}
		if( [string]::IsNullOrEmpty($LocalPort) ){
			$LocalPort=''
		}else{
			if( $LocalPort -is [array] ){
				$LocalPort = $LocalPort -join ','
			}
			$LocalPort="localport=`"$LocalPort`""
		}
		if( [string]::IsNullOrEmpty($RemoteAddress) ){
			$RemoteAddress=''
		}else{
			if( $RemoteAddress -is [array] ){
				$RemoteAddress = $RemoteAddress -join ','
			}
			$RemoteAddress="remoteip=`"$RemoteAddress`""
		}
		if( [string]::IsNullOrEmpty($Program) ){
			$Program=''
		}else{
			$Program="program=`"$Program`""
		}
		if( [string]::IsNullOrEmpty($Protocol) ){
			$Protocol=''
		}else{
			$Protocol="protocol=$Protocol"
		}
		if( [string]::IsNullOrEmpty($Description) ){
			$Description=''
		}else{
			$Description="description=$Description"
		}
		netsh advfirewall firewall add rule enable=yes name="$DisplayName" action=$Action dir=$Direction $Description $Protocol $RemoteAddress $RemotePort $LocalPort $Program
	}


	###############################################################################
	# Degraded compactibility mode of the function ConvertTo-Json
	function ConvertTo-Json{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline=$true)][object] $item
    )
		add-type -assembly system.web.extensions
		$ps_js=new-object system.web.script.serialization.javascriptSerializer
		return $ps_js.Serialize($item)
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

FWRule @{
	Name='NMAP'
	Group='Pentest'
	Direction='*'
	Action='Allow'
	blockExe="C:\Program Files*\Nmap\nmap.exe"
}
FWRule @{
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
$q=ask "Block Internet communication for evil tools ?
This filtering prevents viruses from downloading the payload." "1.1-Firewall-Malware.ask"
if( $q -eq $true ){
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
	@{ Name='Mshta'; blockExe="C:\Windows\System32\mshta.exe" },
	@{ Name='BitsAdmin'; blockExe="C:\Windows\System32\BitsAdmin.exe" },
	@{ Name='CScript'; blockExe="C:\Windows\System32\cscript.exe" },
	@{ Name='WScript'; blockExe="C:\Windows\System32\wscript.exe" },
	@{ Name='Cmdl32'; blockExe="C:\Windows\System32\Cmdl32.exe" },# https://twitter.com/ElliotKillick/status/1455897435063074824?t=5m5_Y1SRhLnd_UN6YktuVQ&s=09
	@{ Name='Powershell'; blockExe=@(
		"C:\Windows\WinSxS\*\powershell.exe",
		"C:\Windows\WinSxS\*\PowerShell_ISE.exe",
		"C:\Windows\*\WindowsPowerShell\v1.0\powershell.exe",
		"C:\Windows\*\WindowsPowerShell\v1.0\PowerShell_ISE.exe"
	) }
) | foreach {
	FWRule @{
		Name=('[Deny Internet] {0}' -f $_.Name)
		Group='LOLBAS'
		Direction='Outbound'
		Action='Block'
		blockExe=$_.blockExe
		RemoteAddress=$IPForInternet
	}
}

}elseif($q -eq $false){
Get-NetFirewallRule -Group "AutoHarden-LOLBAS" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

}
Write-Progress -Activity AutoHarden -Status "1.1-Firewall-Malware" -Completed
echo "####################################################################################################"
echo "# 1.4-Firewall-RPC"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "1.4-Firewall-RPC" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 1.4-Firewall-RPC"
reg add "HKLM\SOFTWARE\Microsoft\Rpc\Internet" /v Ports /t REG_MULTI_SZ /f /d "60000-65000"
reg add "HKLM\SOFTWARE\Microsoft\Rpc\Internet" /v PortsInternetAvailable /t REG_SZ /f /d N
reg add "HKLM\SOFTWARE\Microsoft\Rpc\Internet" /v UseInternetPorts /t REG_SZ /f /d N
netsh int ipv4 set dynamicport tcp start=60000 num=5000 | Out-Null
netsh int ipv4 set dynamicport udp start=60000 num=5000 | Out-Null
netsh int ipv6 set dynamicport tcp start=60000 num=5000 | Out-Null
netsh int ipv6 set dynamicport udp start=60000 num=5000 | Out-Null

function testNetshRPCPort ($ipversion, $proto)
{
	$ret=netsh int $ipversion show dynamicport $proto | Out-String
	if( $ret.Contains('60000') -and $ret.Contains('5000') ){
		logSuccess "$ipversion on $proto use the correct RPC range"
	}else{
		logError "$ipversion on $proto DO NOT USE the correct RPC range"
	}
}

testNetshRPCPort 'ipv4' 'udp'
testNetshRPCPort 'ipv4' 'tcp'
testNetshRPCPort 'ipv6' 'udp'
testNetshRPCPort 'ipv6' 'tcp'

Write-Progress -Activity AutoHarden -Status "1.4-Firewall-RPC" -Completed
echo "####################################################################################################"
echo "# 1.5-Firewall-DisableNotification"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "1.5-Firewall-DisableNotification" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 1.5-Firewall-DisableNotification"
$q=ask "Avoid sending notification to Users about the firewall" "1.5-Firewall-DisableNotification.ask"
if( $q -eq $true ){
Set-NetFirewallProfile -All -Enabled True -NotifyOnListen False

}elseif($q -eq $false){
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
	FWRule @{
		Name='SMB'
		Group='Harding'
		Direction='Outbound'
		Action='Block'
		RemotePort=445
		Protocol='tcp'
		RemoteAddress=$IPForInternet
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
reg add "HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"   /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"   /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"                                /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"                               /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"                                /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"                              /d $value /v DisableStealthMode /t REG_DWORD /f

Write-Progress -Activity AutoHarden -Status "1.6-Firewall-StealtMode" -Completed
echo "####################################################################################################"
echo "# 2-Hardening-ADIDNS"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "2-Hardening-ADIDNS" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 2-Hardening-ADIDNS"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableReverseAddressRegistrations /d 1 /t REG_DWORD /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableDynamicUpdate /d 1 /t REG_DWORD /f

Write-Progress -Activity AutoHarden -Status "2-Hardening-ADIDNS" -Completed
echo "####################################################################################################"
echo "# 2-Hardening-HardDriveEncryption"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "2-Hardening-HardDriveEncryption" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 2-Hardening-HardDriveEncryption"
# AES 256-bit
reg add 'HKLM\SOFTWARE\Policies\Microsoft\FVE' /v EncryptionMethod  /t REG_DWORD /d 4 /f
try{
	(Get-BitLockerVolume -MountPoint 'C:').KeyProtector | foreach {
		logSuccess ('C: is protected with: {0}' -f $_.KeyProtectorType)
	}

	if( (Get-BitLockerVolume -MountPoint 'C:').KeyProtector.Count -eq 0 ){
		logError 'C: is not encrypted !'
	}
}catch{
	logError 'C: is not encrypted !'
}
# Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -TpmProtector -RecoveryKeyProtector -RecoveryKeyPath "C:\"

Write-Progress -Activity AutoHarden -Status "2-Hardening-HardDriveEncryption" -Completed
echo "####################################################################################################"
echo "# 2-Hardening-Powershell"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "2-Hardening-Powershell" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 2-Hardening-Powershell"
# Disable Powershellv2
DISM /Online /Disable-Feature:MicrosoftWindowsPowerShellV2Root /NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null

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
$q=ask "Disable Cortana in Windows search bar" "Crapware-Cortana.ask"
if( $q -eq $true ){
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

}elseif($q -eq $false){
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
schtasks.exe /Change /TN "\Microsoft\Windows\Device Information\Device" /Disable | Out-Null

@("DiagTrack","dmwappushservice") | foreach {
	$srv = Get-Service -ErrorAction SilentlyContinue $_
	if( $srv -eq $null -or $srv.Count -eq 0 ){
		logInfo "Service >$_< is not INSTALLED"
	}elseif( (Get-Service -ErrorAction SilentlyContinue $_).StartType -eq "Disabled" ){
		logInfo "Service >$_< is already disabled"
	}else{
		Stop-Service -ErrorAction SilentlyContinue -Force -Name $_
		Set-Service -ErrorAction SilentlyContinue -Name $_ -Status Stopped -StartupType Disabled
		logSuccess "Service >$_< has been disabled"
	}
}

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
Get-NetIPInterface -AddressFamily ipv6 | foreach{
	$rfc = (& netsh int ipv6 show int $_.ifIndex) -match '(RFC 6106)'
	if($rfc -like "*enabled"){
		logSuccess 'CVE-2020-16898 - "Bad Neighbor" fixed'
		netsh int ipv6 set int $_.ifIndex rabaseddnsconfig=disable
	}else{
		logInfo 'Already fixed against CVE-2020-16898 - "Bad Neighbor"'
	}
}

Write-Progress -Activity AutoHarden -Status "Fix-CVE-2020-16898" -Completed
echo "####################################################################################################"
echo "# Fix-CVE-2022-30910-Follina"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Fix-CVE-2022-30910-Follina" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Fix-CVE-2022-30910-Follina"
# https://twitter.com/gentilkiwi/status/1531384447219781634
# https://twitter.com/MalwareJake/status/1531427953967607810
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnostics" /t REG_DWORD /v EnableDiagnostics /d 0 /f

Write-Progress -Activity AutoHarden -Status "Fix-CVE-2022-30910-Follina" -Completed
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
echo "# Harden-Adobe"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Harden-Adobe" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Harden-Adobe"
try{
Get-Item -errorAction SilentlyContinue -Force "HKCU:\SOFTWARE\Adobe\Acrobat Reader\*" | foreach {
	$name=$_.PSPath
	New-Item -Force -Path $name -Name JSPrefs | Out-Null
	New-Item -Force -Path $name -Name Originals | Out-Null
	New-Item -Force -Path $name -Name Privileged | Out-Null
	New-Item -Force -Path $name -Name TrustManager | Out-Null
}
}catch{}
# AdobePDFJS hardens Acrobat JavaScript.
# bEnableJS possible values:
# 0 - Disable AcroJS
# 1 - Enable AcroJS
Set-ItemProperty "HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\JSPrefs" -Name bEnableJS -Value 0 -errorAction SilentlyContinue

# Disables Acrobat Reader embedded objects
# AdobePDFObjects hardens Adobe Reader Embedded Objects.
# bAllowOpenFile set to 0 and
# bSecureOpenFile set to 1 to disable
# the opening of non-PDF documents
Set-ItemProperty "HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\Originals" -Name bAllowOpenFile -Value 0 -errorAction SilentlyContinue
Set-ItemProperty "HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\Originals" -Name bSecureOpenFile -Value 1 -errorAction SilentlyContinue

# AdobePDFProtectedMode switches on the Protected Mode setting under
# "Security (Enhanced)" (enabled by default in current versions).
# (HKEY_LOCAL_USER\Software\Adobe\Acrobat Reader<version>\Privileged -> DWord „bProtectedMode“)
# 0 - Disable Protected Mode
# 1 - Enable Protected Mode
Set-ItemProperty "HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\Privileged" -Name bProtectedMode -Value 1 -errorAction SilentlyContinue

# AdobePDFProtectedView switches on Protected View for all files from
# untrusted sources.
# (HKEY_CURRENT_USER\SOFTWARE\Adobe\Acrobat Reader\<version>\TrustManager -> iProtectedView)
# 0 - Disable Protected View
# 1 - Enable Protected View
Set-ItemProperty "HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\TrustManager" -Name iProtectedView -Value 1 -errorAction SilentlyContinue

# AdobePDFEnhancedSecurity switches on Enhanced Security setting under
# "Security (Enhanced)".
# (enabled by default in current versions)
# (HKEY_CURRENT_USER\SOFTWARE\Adobe\Acrobat Reader\DC\TrustManager -> bEnhancedSecurityInBrowser = 1 & bEnhancedSecurityStandalone = 1)
Set-ItemProperty "HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\TrustManager" -Name bEnhancedSecurityInBrowser -Value 1 -errorAction SilentlyContinue
Set-ItemProperty "HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\TrustManager" -Name bEnhancedSecurityStandalone -Value 1 -errorAction SilentlyContinue

Write-Progress -Activity AutoHarden -Status "Harden-Adobe" -Completed
echo "####################################################################################################"
echo "# Harden-DisableShortPath"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Harden-DisableShortPath" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Harden-DisableShortPath"
fsutil.exe 8dot3name set 1

Write-Progress -Activity AutoHarden -Status "Harden-DisableShortPath" -Completed
echo "####################################################################################################"
echo "# Harden-Office"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Harden-Office" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Harden-Office"
try{
Get-Item -errorAction SilentlyContinue -Force "HKCU:\SOFTWARE\Microsoft\Office\*\*\" | foreach {
	$name=$_.PSPath
	Write-Host "Create $name\Security"
	New-Item -Force -Path $name -Name Security | Out-Null
}
}catch{}
try{
Get-Item -errorAction SilentlyContinue -Force "HKCU:\SOFTWARE\Microsoft\Office\*\" | foreach {
	$name=$_.PSPath
	Write-Host "Create $name\Security"
	New-Item -Force -Path $name -Name Security | Out-Null
}
}catch{}

# OfficeOLE hardens Office Packager Objects.
# 0 - No prompt from Office when user clicks, object executes.
# 1 - Prompt from Office when user clicks, object executes.
# 2 - No prompt, Object does not execute.
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name PackagerPrompt -Value 2 -errorAction SilentlyContinue

# OfficeMacros contains Macro registry keys.
# 1 - Enable all.
# 2 - Disable with notification.
# 3 - Digitally signed only.
# 4 - Disable all.
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name VBAWarnings -Value 3 -errorAction SilentlyContinue

# OfficeActiveX contains ActiveX registry keys.
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\Security" -Name DisableAllActiveX -Value 1 -errorAction SilentlyContinue
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name DisableAllActiveX -Value 1 -errorAction SilentlyContinue

# AllowDDE: part of Update ADV170021
# disables DDE for Word (default setting after installation of update)
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name AllowDDE -Value 0 -errorAction SilentlyContinue

# If you enable this policy setting, macros are blocked from running, even if "Enable all macros" is selected in the Macro Settings section of the Trust Center. Also, instead of having the choice to "Enable Content," users will receive a notification that macros are blocked from running. If the Office file is saved to a trusted location or was previously trusted by the user, macros will be allowed to run.
#Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name BlockContentExecutionFromInternet -Value 1 -errorAction SilentlyContinue

Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Options" -Name DontUpdateLinks -Value 1 -errorAction SilentlyContinue
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Options\WordMail" -Name DontUpdateLinks -Value 1 -errorAction SilentlyContinue

Write-Progress -Activity AutoHarden -Status "Harden-Office" -Completed
echo "####################################################################################################"
echo "# Harden-VMWareWorkstation"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Harden-VMWareWorkstation" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Harden-VMWareWorkstation"
# Disable VM Sharing (free the port 443/TCP)
@("VMwareHostd") | foreach {
	$srv = Get-Service -ErrorAction SilentlyContinue $_
	if( $srv -eq $null -or $srv.Count -eq 0 ){
		logInfo "Service >$_< is not INSTALLED"
	}elseif( (Get-Service -ErrorAction SilentlyContinue $_).StartType -eq "Disabled" ){
		logInfo "Service >$_< is already disabled"
	}else{
		Stop-Service -ErrorAction SilentlyContinue -Force -Name $_
		Set-Service -ErrorAction SilentlyContinue -Name $_ -Status Stopped -StartupType Disabled
		logSuccess "Service >$_< has been disabled"
	}
}

Write-Progress -Activity AutoHarden -Status "Harden-VMWareWorkstation" -Completed
echo "####################################################################################################"
echo "# Harden-VoiceControl"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Harden-VoiceControl" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Harden-VoiceControl"
$q=ask "Disable voice control" "Harden-VoiceControl.ask"
if( $q -eq $true ){
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /t REG_DWORD /v AgentActivationEnabled /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /t REG_DWORD /v AgentActivationOnLockScreenEnabled /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization" /t REG_DWORD /v AllowInputPersonalization /d 0 /f

}elseif($q -eq $false){
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
$q=ask "Harden Windows Defender" "Harden-WindowsDefender.ask"
if( $q -eq $true ){
if( -not (ask "Disable WindowsDefender" "Optimiz-DisableDefender.ask") ){
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
	$ProcessMitigation = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".xml"
	mywget -Uri https://demo.wd.microsoft.com/Content/ProcessMitigation.xml -OutFile $ProcessMitigation
	Set-ProcessMitigation -PolicyFilePath $ProcessMitigation
	rm -Force $ProcessMitigation
}

}elseif($q -eq $false){
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
echo "# Hardening-BlockAutoDiscover"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-BlockAutoDiscover" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-BlockAutoDiscover"
# Avoid credentials leak https://www.guardicore.com/labs/autodiscovering-the-great-leak/
$autodicover=Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern "127.0.0.1 autodicover"
if( [string]::IsNullOrEmpty($autodicover) ){
	$tlds = mywget -Uri 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
	$domains = $tlds.Content.ToLower().Replace("`r","").Replace("\r","").Split("`n") | where { -not [string]::IsNullOrEmpty($_) -and -not $_.StartsWith('#') } | foreach {
		echo "127.0.0.1 autodicover.$_"
	}
	$domains = $domains -join "`r`n"
	[System.IO.File]::AppendAllText("C:\Windows\System32\drivers\etc\hosts", "`r`n# [AutoHarden] Block Autodiscover`r`n$domains", (New-Object System.Text.UTF8Encoding $False));
	RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8
	ipconfig /flushdns
}

Write-Progress -Activity AutoHarden -Status "Hardening-BlockAutoDiscover" -Completed
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
echo "# Hardening-Co-Installers"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-Co-Installers" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-Co-Installers"
$q=ask "Deny auto installation of vendor's application/drivers by the user" "Hardening-Co-Installers.ask"
if( $q -eq $true ){
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" /t REG_DWORD /v DisableCoInstallers /d 1 /f

}
Write-Progress -Activity AutoHarden -Status "Hardening-Co-Installers" -Completed
echo "####################################################################################################"
echo "# Hardening-Disable-C-FolderCreation"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-Disable-C-FolderCreation" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-Disable-C-FolderCreation"
icacls C:\ /remove:g "NT AUTHORITY\Utilisateurs authentifiés"
icacls C:\ /remove:g "Utilisateurs authentifiés"
icacls C:\ /remove:g "NT AUTHORITY\Authenticated Users"
icacls C:\ /remove:g "Authenticated Users"

Write-Progress -Activity AutoHarden -Status "Hardening-Disable-C-FolderCreation" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableCABlueCoat"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableCABlueCoat" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableCABlueCoat"
# See http://blogs.msmvps.com/alunj/2016/05/26/untrusting-the-blue-coat-intermediate-ca-from-windows/
#Invoke-WebRequest -Uri "https://crt.sh/?id=19538258" -OutFile "${env:temp}/Hardening-DisableCABlueCoat.crt"
$CABlueCoat = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"
@'
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
'@ > $CABlueCoat
Import-Certificate -Filepath $CABlueCoat -CertStoreLocation Cert:\LocalMachine\Disallowed | out-null
Remove-Item -Force $CABlueCoat -ErrorAction Ignore

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

# https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/
# https://en.hackndo.com/pass-the-hash/
# Affects Windows Remoting (WinRM) deployments
# 18.3.1 Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
# 0=This value builds a filtered token. It's the default value. The administrator credentials are removed.
# 1=This value builds an elevated token.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
# 2.3.17.1 UAC - Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f

Write-Progress -Activity AutoHarden -Status "Hardening-DisableMimikatz" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableNetbios"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableNetbios" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableNetbios"
@(
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

# https://admx.help/?Category=KB160177M
# This secures the machine by telling Windows to treat itself as a NetBIOS P-node (point-to-point system).
# These systems will only resolve NBT-NS queries using WINS – no broadcasts will take place. Success!
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NodeType /t REG_DWORD /d 2 /f

Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip* -Name NetbiosOptions -Value 2

wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2

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
	logSuccess "Patched"
}else{
	logInfo "Already patched"
}

# https://twitter.com/olamotte33/status/1429386553562963970?s=09
# https://twitter.com/olamotte33/status/1429484420000534530?s=20
addRpcAcl -name 'SCManager' -uuid '367abb81-9844-35f1-ad32-98f038001003'
# https://twitter.com/tiraniddo/status/1429525321414369281?s=20
addRpcAcl -name 'WMI' -uuid '8bc3f05e-d86b-11d0-a075-00c04fb68820'

Write-Progress -Activity AutoHarden -Status "Hardening-DisableRemoteServiceManagement" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableSMBServer"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableSMBServer" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableSMBServer"
# Désactivation des partages administratifs
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f

# Block CobaltStrike from using \\evil.kali\tmp$\becon.exe
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f

#Set-SmbServerConfiguration -AnnounceServer $false -Force
#Get-SmbServerConfiguration

sc.exe config lanmanserver start= disabled

Write-Progress -Activity AutoHarden -Status "Hardening-DisableSMBServer" -Completed
echo "####################################################################################################"
echo "# Hardening-DisableWPAD"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-DisableWPAD" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-DisableWPAD"
# Disable wpad service
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /t REG_DWORD /v Start /d 4 /f

# https://web.archive.org/web/20160301201733/http://blog.raido.be/?p=426M
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /t REG_DWORD /v AutoDetect /d 0 /fM

reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v "DefaultConnectionSettings" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v "SavedLegacySettings" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /t REG_DWORD /v WpadOverride /d 0 /f
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8 | Out-Null
ipconfig /flushdns | Out-Null
$_wpad=Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern "0.0.0.0 wpad"
if( [string]::IsNullOrEmpty($_wpad) ){
	[System.IO.File]::AppendAllText("C:\Windows\System32\drivers\etc\hosts", "`r`n# [AutoHarden] Block WPAD`r`n0.0.0.0 wpad", (New-Object System.Text.UTF8Encoding $False)) | Out-Null
}
$_wpad=Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern "0.0.0.0 ProxySrv"
if( [string]::IsNullOrEmpty($_wpad) ){
	[System.IO.File]::AppendAllText("C:\Windows\System32\drivers\etc\hosts", "`r`n# [AutoHarden] Block WPAD`r`n0.0.0.0 ProxySrv", (New-Object System.Text.UTF8Encoding $False)) | Out-Null
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
# .mht
cmd /c ftype mhtmlfile="C:\Windows\notepad.exe" "%1"
# .ps1
cmd /c ftype Microsoft.PowerShellScript.1="C:\Windows\notepad.exe" "%1"
cmd /c ftype Microsoft.PowerShellXMLData.1="C:\Windows\notepad.exe" "%1"
cmd /c ftype Microsoft.PowerShellConsole.1="C:\Windows\notepad.exe" "%1"
# .xml
cmd /c ftype "XML Script Engine"="C:\Windows\notepad.exe" "%1"
cmd /c ftype sctfile="%systemroot%\system32\notepad.exe" "%1"
cmd /c ftype urlfile="%systemroot%\system32\notepad.exe" "%1"
# https://www.trustwave.com/Resources/SpiderLabs-Blog/Firework--Leveraging-Microsoft-Workspaces-in-a-Penetration-Test/
cmd /c ftype wcxfile="%systemroot%\system32\notepad.exe" "%1"
# https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
#ftype mscfile="%systemroot%\system32\notepad.exe" "%1"

# https://rinseandrepeatanalysis.blogspot.com/2018/09/dde-downloaders-excel-abuse-and.html
cmd /c ftype slkfile="%systemroot%\system32\notepad.exe" "%1"
cmd /c ftype iqyfile="%systemroot%\system32\notepad.exe" "%1"
cmd /c ftype prnfile="%systemroot%\system32\notepad.exe" "%1"
cmd /c ftype diffile="%systemroot%\system32\notepad.exe" "%1"

# CVE-2020-0765 impacting Remote Desktop Connection Manager (RDCMan) configuration files - MS won't fix
cmd /c ftype rdgfile="%systemroot%\system32\notepad.exe" "%1"

Write-Progress -Activity AutoHarden -Status "Hardening-FileExtension" -Completed
echo "####################################################################################################"
echo "# Hardening-LDAP"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-LDAP" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-LDAP"
# 1- Negotiated; 2-Required

# LDAP client
# 2.3.11.8 Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f


# LDAP Server
# Domain controller LDAP server signing requirements
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f
# 18.3.5 (L1) Ensure 'Extended Protection for LDAP Authentication (Domain Controllers only)' is set to 'Enabled: Enabled, always (recommended)' (DC Only) (Scored)
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f

# Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
# Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
# Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f

Write-Progress -Activity AutoHarden -Status "Hardening-LDAP" -Completed
echo "####################################################################################################"
echo "# Hardening-Navigator"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-Navigator" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-Navigator"
@(
	'PasswordManagerEnabled',
	'AutofillAddressEnabled',
	'AutofillCreditCardEnabled',
	'ImportAutofillFormData'
) | foreach {
	reg add HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome /v $_ /d 0 /f
	reg add HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave /v $_ /d 0 /f
	reg add HKEY_LOCAL_MACHINE\Software\Policies\Chromium /v $_ /d 0 /f
}
# Enable support for chromecast
reg add HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome /v EnableMediaRouter /d 1 /f
reg add HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave /v EnableMediaRouter /d 1 /f
reg add HKEY_LOCAL_MACHINE\Software\Policies\Chromium /v EnableMediaRouter /d 1 /f

Write-Progress -Activity AutoHarden -Status "Hardening-Navigator" -Completed
echo "####################################################################################################"
echo "# Hardening-RemoteAssistance"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-RemoteAssistance" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-RemoteAssistance"
$q=ask "Disable Remote Assistance on this computer" "Hardening-RemoteAssistance.ask"
if( $q -eq $true ){
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /t REG_DWORD /v fAllowToGetHelp /d 0 /f

}elseif($q -eq $false){
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /f

}
Write-Progress -Activity AutoHarden -Status "Hardening-RemoteAssistance" -Completed
echo "####################################################################################################"
echo "# Hardening-SMB"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-SMB" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-SMB"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\Rdr\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Rdr\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol

Write-Progress -Activity AutoHarden -Status "Hardening-SMB" -Completed
echo "####################################################################################################"
echo "# Hardening-UAC"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-UAC" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-UAC"
# Enable UAC
# This key is called EnableLUA because User Access Control was previously called Limited User Account (LUA).
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableLUA /d 1 /f

Write-Progress -Activity AutoHarden -Status "Hardening-UAC" -Completed
echo "####################################################################################################"
echo "# Hardening-Wifi-RemoveOpenProfile"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Hardening-Wifi-RemoveOpenProfile" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Hardening-Wifi-RemoveOpenProfile"
netsh wlan export profile folder=C:\Windows\Temp | Out-Null
Get-Item C:\Windows\temp\Wi-Fi-*.xml | foreach {
	$xml=[xml] (Get-Content $_.FullName)
	Write-Host "[*] Lecture du profile wifi $($_.Name)"
	if( $xml.WLANProfile.MSM.security.authEncryption.authentication.ToLower() -eq "open" ){
		$p=$xml.WLANProfile.SSIDConfig.SSID.name.Replace('"','')
		logSuccess "[*] Suppression du profile wifi $p"
		netsh wlan delete profile name="$p" interface=*
	}
}
Remove-Item C:\Windows\temp\Wi-Fi-*.xml | Out-Null

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

if( -not [System.IO.File]::Exists("${AutoHarden_Logs}\AuditPol_BEFORE.log.zip") ){
	Auditpol /get /category:* | Out-File -Encoding UTF8 $AutoHarden_Logs\AuditPol_BEFORE.log
	Compress-Archive -Path "${AutoHarden_Logs}\AuditPol_BEFORE.log" -CompressionLevel "Optimal" -DestinationPath "${AutoHarden_Logs}\AuditPol_BEFORE.log.zip"
}


# From
#	https://github.com/rkovar/PowerShell/blob/master/audit.bat
#	https://forensixchange.com/posts/19_05_07_dns_investigation/
#	https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d

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
#   Rejet de paquet par la plateforme de filtrage,{0CCE9225-69AE-11D9-BED3-505054503030} == "Filtering Platform Packet Drop"
auditpol /set /subcategory:"{0CCE9225-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Connexion de la plateforme de filtrage,{0CCE9226-69AE-11D9-BED3-505054503030} == "Filtering Platform Connection"
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
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
reg add "HKLM\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
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

Write-Progress -Activity AutoHarden -Status "Log-Activity" -Completed
echo "####################################################################################################"
echo "# Optimiz-CleanUpWindowFolder-MergeUpdate"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-CleanUpWindowFolder-MergeUpdate" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-CleanUpWindowFolder-MergeUpdate"
# https://www.malekal.com/comment-reduire-la-taille-du-dossier-windows-de-windows-10/

# En appliquant ces deux commandes, vous ne pourrez plus désinstaller les mises à jour Windows.
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
Dism.exe /online /Cleanup-Image /SPSuperseded

Write-Progress -Activity AutoHarden -Status "Optimiz-CleanUpWindowFolder-MergeUpdate" -Completed
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
	icacls.exe "$file" /setowner $env:username | Out-Null
	remove-item -Force $file | Out-Null
	echo '' | Out-File $file
	icacls.exe "$file" /setowner $finalUser | Out-Null
	attrib +s +h $file | Out-Null
	#(Get-Acl $file).Owner
	#(Get-Acl $file).Access
}

killfakename 'C:\Users\desktop.ini'
killfakename 'C:\Program Files\desktop.ini'
killfakename 'C:\Program Files (x86)\desktop.ini'

Write-Progress -Activity AutoHarden -Status "Optimiz-CleanUpWindowsName" -Completed
echo "####################################################################################################"
echo "# Optimiz-cmd-color"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-cmd-color" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-cmd-color"
# https://ss64.com/nt/syntax-ansi.html
reg add HKEY_CURRENT_USER\Console /v VirtualTerminalLevel /d 1 /t REG_DWORD /f

Write-Progress -Activity AutoHarden -Status "Optimiz-cmd-color" -Completed
echo "####################################################################################################"
echo "# Optimiz-DisableAutoReboot"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-DisableAutoReboot" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-DisableAutoReboot"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /t REG_DWORD /v NoAutoRebootWithLoggedOnUsers /d 1 /f
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /Disable
if( !(Test-Path -PathType Container "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot") ){
	schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Reboot" /Disable
	Rename-Item "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot" "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot.bak"
	mkdir "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot"
}
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /t REG_DWORD /v ActiveHoursStart /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /t REG_DWORD /v ActiveHoursEnd /d 23 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /t REG_DWORD /v IsActiveHoursEnabled /d 1 /f

Write-Progress -Activity AutoHarden -Status "Optimiz-DisableAutoReboot" -Completed
echo "####################################################################################################"
echo "# Optimiz-DisableReservedStorageState"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-DisableReservedStorageState" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-DisableReservedStorageState"
# From: https://www.windowslatest.com/2020/03/15/windows-10-will-finally-allow-you-to-reclaim-reserved-storage/
DISM.exe /Online /Set-ReservedStorageState /State:Disabled

Write-Progress -Activity AutoHarden -Status "Optimiz-DisableReservedStorageState" -Completed
echo "####################################################################################################"
echo "# Soft-LSA-Control"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Soft-LSA-Control" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Soft-LSA-Control"
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableDomainCreds /f 2>$null
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v TokenLeakDetectDelaySecs /f 2>$null

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictReceivingNTLMTraffic /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictReceivingNTLMTraffic /t REG_DWORD /d 0 /f

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 0x20080000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 0x20080000 /f

Write-Progress -Activity AutoHarden -Status "Soft-LSA-Control" -Completed
echo "####################################################################################################"
echo "# Software-install-1-Functions"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Software-install-1-Functions" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Software-install-1-Functions"
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

Write-Progress -Activity AutoHarden -Status "Software-install-1-Functions" -Completed
echo "####################################################################################################"
echo "# Software-install-2-GlobalPackages"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Software-install-2-GlobalPackages" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Software-install-2-GlobalPackages"
chocoInstall vcredist-all
chocoInstall 7zip.install
chocoInstall greenshot
chocoInstall vlc
chocoInstall sysinternals
chocoInstall keepassxc

Write-Progress -Activity AutoHarden -Status "Software-install-2-GlobalPackages" -Completed
echo "####################################################################################################"
echo "# Software-install-Logs"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Software-install-Logs" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Software-install-Logs"
##############################################################################
# Enable sysmon
if( -not (Get-Command sysmon -errorAction SilentlyContinue) ){
	chocoInstall sysmon
	$sysmonconfig = curl.exe $AutoHarden_SysmonUrl
	if( -not [String]::IsNullOrWhiteSpace($sysmonconfig) ){
		$sysmonconfig | Out-File -Encoding ASCII C:\Windows\sysmon.xml
		sysmon.exe -accepteula -i C:\Windows\sysmon.xml
		sysmon.exe -accepteula -c C:\Windows\sysmon.xml
	}
}


##############################################################################
# Log all autoruns to detect malware
# From: https://github.com/palantir/windows-event-forwarding/
if( Get-Command autorunsc -errorAction SilentlyContinue ){
	$autorunsc7z = ("${AutoHarden_Logs}\autorunsc_"+(Get-Date -Format "yyyy-MM-dd"))
	start-job -Name LogActivity_autoruns -scriptblock {
		autorunsc -nobanner /accepteula -a "*" -c -h -s -v -vt "*" | Out-File -Encoding UTF8 "${autorunsc7z}.csv"
		Compress-Archive -Path "${autorunsc7z}.csv" -CompressionLevel "Optimal" -DestinationPath "${autorunsc7z}.csv.zip"
		if( [System.IO.File]::Exists("${autorunsc7z}.csv.zip") ){
			Remove-Item -Force "${autorunsc7z}.csv"
		}
	}
}

Write-Progress -Activity AutoHarden -Status "Software-install-Logs" -Completed
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
# Enable rules
logInfo 'Enable rules'
Get-NetFirewallRule -DisplayName '*AutoHarden*' | Enable-NetFirewallRule

# Remove all rules that are not tagged
logInfo 'Remove all rules that are not tagged'
FWRemoveBadRules

# Enable all rules
Enable-NetFirewallRule -Name '*'

try{
	mkdir -Force $env:windir\system32\logfiles\firewall | Out-Null
}catch{}

# Enabling firewall
Get-NetFirewallProfile | foreach {
	$Name=$_.Name
	$DefaultInboundAction=$_.DefaultInboundAction
	if( $_.Enabled -eq $false ){
		logError "${Name} firewall profile was disabled"
	}else{
		logInfo "${Name} firewall profile is enable"
	}
	if( $_.DefaultInboundAction -ne "Block" ){
		logError "${Name} firewall profile was DefaultInboundAction=${DefaultInboundAction}"
	}else{
		logInfo "${Name} firewall profile is well configured"
	}
	$_
} | Set-NetFirewallProfile -Enabled True -DefaultOutboundAction Allow -DefaultInboundAction Block -AllowInboundRules True -AllowLocalFirewallRules True -AllowLocalIPsecRules True -AllowUnicastResponseToMulticast True -LogAllowed True -LogBlocked True -LogIgnored True -LogFileName "%windir%\system32\logfiles\firewall\pfirewall.log" -LogMaxSizeKilobytes 32767

Write-Progress -Activity AutoHarden -Status "ZZZ-20.Firewall-Cleanup" -Completed
echo "####################################################################################################"
echo "# ZZZ-30.__END__"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "ZZZ-30.__END__" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running ZZZ-30.__END__"
###############################################################################
# Cleaning the script...
###############################################################################
logInfo 'Waiting for the job autoruns...'
Wait-Job -Name LogActivity_autoruns -ErrorAction SilentlyContinue
Stop-Transcript
Compress-Archive -Path $AutoHardenTransScriptLog -CompressionLevel "Optimal" -DestinationPath "${AutoHardenTransScriptLog}.zip" -ErrorAction SilentlyContinue
if( [System.IO.File]::Exists("${AutoHardenTransScriptLog}.zip") ){
	Remove-Item -Force $AutoHardenTransScriptLog
}

Write-Progress -Activity AutoHarden -Status "ZZZ-30.__END__" -Completed


# SIG # Begin signature block
# MIINoAYJKoZIhvcNAQcCoIINkTCCDY0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOp+VqprizhEhV1P+w/ByypJT
# ipagggo9MIIFGTCCAwGgAwIBAgIQlPiyIshB45hFPPzNKE4fTjANBgkqhkiG9w0B
# AQ0FADAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBMB4XDTE5MTAyOTIxNTUxNVoX
# DTM5MTIzMTIzNTk1OVowFTETMBEGA1UEAxMKQXV0b0hhcmRlbjCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBALrMv49xZXZjF92Xi3cWVFQrkIF+yYNdU3GS
# l1NergVq/3WmT8LDpaZ0XSpExZ7soHR3gs8eztnfe07r+Fl+W7l6lz3wUGFt52VY
# 17WCa53tr5dYRPzYt2J6TWT874tqZqlo+lUl8ONK1roAww2flcDajm8VUXM0k0sL
# M17H9NLykO3DeBuh2PVaXUxGDej+N8PsYF3/7Gv2AW0ZHGflrondcXb2/eh8xwbw
# RENsGaMXvnGr9RWkufC6bKq31J8BBnP+/65M6541AueBoH8pLbANPZgHKES+8V9U
# WlYKOeSoeBhtL1k3Rr8tfizRWx1zg/pBNL0WTOLcusmuJkdHkdHbHaW6Jc/vh06C
# s6xqz9/Dkg+K3BvOmfwZfAjl+qdgzM8dUU8/GWhswngwLAz64nZ82mZv/Iw6egC0
# rj5MYV0tpEjIgtVVgHavUfyXoIETNXFQR4SoK6PfeVkEzbRh03xhU65MSgBgWVv1
# YbOtdgXK0MmCs3ngVPJdVaqBjgcrK++X3Kxasb/bOkcfQjff/EK+BPb/xs+pXEqr
# yYbtbeX0v2rbV9cugPUj+mneucZBLFjuRcXhzVbXLrwXVne7yTD/sIKfe7dztzch
# g19AY6/qkkRkroaKLASpfCAVx2LuCgeFGn//QaEtCpFxMo2dcnW2a+54pkzrCRTR
# g1N2wBQFAgMBAAGjYjBgMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEkGA1UdAQRCMECA
# EPp+TbkVy9u5igk2CqcX2OihGjAYMRYwFAYDVQQDEw1BdXRvSGFyZGVuLUNBghBr
# xVMud93NnE/XjEko2+2HMA0GCSqGSIb3DQEBDQUAA4ICAQAQLtHeMr2qJnfhha2x
# 2aCIApPjfHiHT4RNPI2Lq71jEbTpzdDFJQkKq4R3brGcpcnuU9VjUwz/BgKer+SF
# pkwFwTHyJpEFkbGavNo/ez3bqoehvqlTYDJO/i2mK0fvKmShfne6dZT+ftLpZCP4
# zngcANlp+kHy7mNRMB+LJv+jPc0kJ2oP4nIsLejyfxMj0lXuTJJRhxeZssdh0tq4
# MZP5MjSeiE5/AMuKT12uJ6klNUFS+OlEpZyHkIpgy4HxflXSvhchJ9U1YXF2IQ47
# WOrqwCXPUinHKZ8LwB0b0/35IlRCpub5KdRf803+4Okf9fL4rfc1cg9ZbLxuK9ne
# Fg1+ESL4aPyoV03TbN7Cdsd/sfx4mJ8jXJD+AXZ1ZofAAapYf9J5C71ChCZlhIGB
# vVc+dTUCWcUYgNOD9Nw+NiV6mARmVHl9SFL7yEtNYFgo0nWiNklqMqBLDxmrrD27
# sgBpFUwbMZ52truQwaaSHD7hFb4Tb1B0JVaGoog3QfNOXaFeez/fAt5L+yo78cDm
# 7Q2tXvy2g0xDAL/TXn7bhtDzQunltBzdULrJEQO4zI0h8YgmF88a0zYZ9HRkDUn6
# dR9+G8TlZuUsWSOdvLdEvad9RqiHKeSrL6qgLBT5kqVt6AFsEtmFNz1s7xpsw/zP
# ZvIXtQTmb4h+GcE/b2sUFZUkRDCCBRwwggMEoAMCAQICEGvFUy533c2cT9eMSSjb
# 7YcwDQYJKoZIhvcNAQENBQAwGDEWMBQGA1UEAxMNQXV0b0hhcmRlbi1DQTAeFw0x
# OTEwMjkyMTU1MDlaFw0zOTEyMzEyMzU5NTlaMBgxFjAUBgNVBAMTDUF1dG9IYXJk
# ZW4tQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDZZvLb9iKlWoqy
# D/dEZyLDZUGDzAL1MEXAujcPtEJb+erVnM7zJfSBdPodr1BefpZ0hJCTBganixWi
# YEqPZTch3k3446qRHDFQcNZ15elUnzYoqw+3yU5Mmd65etz7DsG31gjw1tQLy7n2
# IQYooz5StZOESRZIhWW2ZKXucrNLmOEFRY/mU2ltBANDJ3F9mGe++UJ1+xyTtB3z
# HBxhk8Tj4QKiez6fiAa7O+ZWmgEnpCUk1bm+46rOWngKUJFFoCnpdX5itLQb9+XX
# hNT+QAV4vip7s1gmQ1PM5yAwJ49as/unNtSiobJRHc2JUUpauJD3BfeuBhAsUbYK
# tM9ac4Vf1rwSY1ozadxuXvI1H47gINrrRf8Xf4+xjVPL5ZQwFxY5eHM3NbGhmQ3F
# PGv7msHijI6keFn8lKfx/5geyRSZThwRk0bM1mgFP+BNFfmyAlzSOWroJFdvXItB
# 6LgRt1hXEIgOavtVNr2P7HFcjD5vGXnAntm/kg/4qT7RbKXDj0rUZuREIC+AlnVa
# UppvPiUTtDXK0p0LTTwsDwU93OzizsGCwZfFh3CRtcjibULy479ZKDJiZB0dHYzg
# 8fCIPX6gBSx9HOveBOlSW6Iw1Rqfy0UfS5yZ82JVgGKE90nD0PbnrIK+MfFUp6zO
# nDBtwEkA/dkVVygg3qf0atvSF7b46QIDAQABo2IwYDATBgNVHSUEDDAKBggrBgEF
# BQcDAzBJBgNVHQEEQjBAgBD6fk25FcvbuYoJNgqnF9jooRowGDEWMBQGA1UEAxMN
# QXV0b0hhcmRlbi1DQYIQa8VTLnfdzZxP14xJKNvthzANBgkqhkiG9w0BAQ0FAAOC
# AgEAwYg8KFYtmIVs5TFExOSR1FFJBpE2jFSn42ARYlB3kECGlLkqt3TET5X6Q0Us
# 7d01uZn8HD3cMGrRNMXhjd6988kIJ8xBv7zFa8cJIHxXpFWLxOCWuedTEpMAANn7
# kxxrEQfbRG065Gxq9+W12WMTqRh6WSInxRExQk+qzqYXg3cThFOmMi3iGIBnRgpi
# krSd10pL6gYe6EOOTNPoql/coyTRqFIPlzC55OCvvu68SJP0hrVAbiKbAd5LJiLF
# yJnpVMR8N8XupxpJJ3AJvcl+601NTNX6q8WqAYhr8fY5asQ1TCM8w4Gu7ylw7D/4
# lJm+H3nkyKMu/koKhlrEr0Yi7egOQniEOV2k64Vjfpmxqur7xU2bnLWOi83bn8IZ
# W2VxZn1Py57EaazNhM2H22vFWZpnzAQaZ2K8Oav93eX/TkpjZEUI7NB31Wm/W+OI
# VjVHdkCesr4zOYHQd+u3pFWoC6VXW/+JsMyjpbKQ1C0pU+6wHrjnNZ48pbvNKWwR
# QjYge9gJljW6hCuPBDZaFK++TYbkyie+JZY/jbeoPcw87F7hSAsiSC74BPI3vOxk
# F6fu9dmkhqiQS4hkxY7kt1HLSfKnZX+c5F8OpjAedvzN0GIOryPtgGEXNhEF0b5v
# GUpQymInafZmReNxHFxVZLZyvO8fkymFY530xqJny3wF6U4xggLNMIICyQIBATAs
# MBgxFjAUBgNVBAMTDUF1dG9IYXJkZW4tQ0ECEJT4siLIQeOYRTz8zShOH04wCQYF
# Kw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJ
# KoZIhvcNAQkEMRYEFFY4+ZyHqEtK3cpk+ek6uyjkxNrUMA0GCSqGSIb3DQEBAQUA
# BIICAG3c0K2oOXm7mk/QXmoPFpPX8J2caChqTCb6NFaLuBwWiGfK+CWlumQbmDW0
# cTMyY+HMC+KFNocm2FbUr+Kv30BC/OdhgnfXGU9HE8Va19TnmoCeoczKgRj1tVEQ
# SivQosjzCtzsyhHF6+1PFVVF5fr+ck8s/7co+u6emPFcAY44lPSmQOnKSyVfy/ff
# JrxvbVewzdyxGJERyJ6EEZ/x3huNLcu8I49ibTdo/GoqAFpVzPRs21Nja9zaH/Lu
# uA6WXnYemFNE5eMo/aoJqIJvaBpCIxtAwnRtRTbTU9hoT8EIsU/zn3mpI8nGPT3u
# fq233ChStsCwlXTyJvLXwRbqxsg1eFME7G/gX+jLaUE6cbk5qQVN5Hybq/eH0Vix
# LFMN1wYlLcmpzGO7JW1foKEI8/TJQ2BrfsbrCFitoSns5gkJY1huYvfoVymm3bfz
# mIgx4ngRJ404xcl/QV4LpQ+ZZxwelTvVd7Z39BUst6RjpqWSjZqbZ2IezeXo1bSr
# DJ7AEmFon2Z8gfKEzkWcGp9uDyyJalg274on4dvn9Ba8JYcPWoYeKkizOzg1mifK
# 0dUl0XLSbBOkB7Cj8HIhi1UKqJ6iJjCoyBX6VEXGbKmYJbP1G1/hPiXRBERc/i8Q
# SSytue4igjmq1ZRcBoijFrZmItmsFT7GsY4IFOvHBbfQwvRy
# SIG # End signature block
