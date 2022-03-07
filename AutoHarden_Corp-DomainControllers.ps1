# AutoHarden - A simple script that automates Windows Hardening
#
# Filename: AutoHarden_Corp-DomainControllers.ps1
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
$AutoHarden_Group='Corp-DomainControllers'
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
$IP_ADMIN='10.1.30.218-10.1.30.234'
$ETH_ADMIN='Ethernet 3'
$ETH_USER='Ethernet 2'
$DC1_IP='10.24.96.3'
$DNS_SERVER='8.8.8.8'
$GATEWAY='10.24.96.0'
$INSTALL_MODE=$false

function createTempFile( $data, [Parameter(Mandatory=$false)][string]$ext='' )
{
	$tmpFileName = -join ((65..90) + (97..122) | Get-Random -Count 25 | % {[char]$_});
	$tmpFileName = "${tmp}\${tmpFileName}${ext}"
	[System.IO.File]::WriteAllLines($tmpFileName, $data, (New-Object System.Text.UTF8Encoding $False));
	return $tmpFileName;
}

if( $INSTALL_MODE ){
	Add-WindowsFeature AD-Domain-Services
	Install-ADDSForest -DomainName unicorn.local
	New-NetFirewallRule -DisplayName "[AutoHarden] ADMIN-ACCESS for unicorn.local" -Name "[AutoHarden] ADMIN-ACCESS for unicorn.local" -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -InterfaceAlias $ETH_ADMIN

	#Install-ADDSForest -DomainName vdom.local -InstallDNS
	# Set static IP
	$adapter = Get-NetAdapter -Name 'Ethernet 2'
	If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
		$adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false
	}
	If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
		$adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false
	}
	# Configure the IP address and default gateway
	$adapter | New-NetIPAddress -AddressFamily IPv4 -IPAddress $DC1_IP -PrefixLength 20 -DefaultGateway $GATEWAY
	# Configure the DNS client server IP addresses
	#$adapter | Set-DnsClientServerAddress -ServerAddresses $DNS_SERVER
}





# Filter SMB communication to allow only SMB <=> SMB between DC
$domainDontrollerList = (Get-DnsClientGlobalSetting).SuffixSearchList | foreach {
	Resolve-DnsName -Type ALL -Name _ldap._tcp.dc._msdcs.$_
} | foreach {
	$_.IP4Address
} | sort -unique

$domainDontrollerList | foreach {
	New-NetFirewallRule -Group "DC-INTERCOMMUNICATION" -DisplayName "[AutoHarden] DC-INTERCOMMUNICATION" -Name "[AutoHarden] DC-INTERCOMMUNICATION in-udp" -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol UDP -RemoteIP $_
	New-NetFirewallRule -Group "DC-INTERCOMMUNICATION" -DisplayName "[AutoHarden] DC-INTERCOMMUNICATION" -Name "[AutoHarden] DC-INTERCOMMUNICATION in-tcp" -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol TCP -RemoteIP $_
	New-NetFirewallRule -Group "DC-INTERCOMMUNICATION" -DisplayName "[AutoHarden] DC-INTERCOMMUNICATION" -Name "[AutoHarden] DC-INTERCOMMUNICATION out-udp" -Enabled True -Profile Any -Direction Outbound -Action Allow -Protocol UDP -RemoteIP $_
	New-NetFirewallRule -Group "DC-INTERCOMMUNICATION" -DisplayName "[AutoHarden] DC-INTERCOMMUNICATION" -Name "[AutoHarden] DC-INTERCOMMUNICATION out-tcp" -Enabled True -Profile Any -Direction Outbound -Action Allow -Protocol TCP -RemoteIP $_
}

Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False -DefaultOutboundAction Allow -DefaultInboundAction Block -AllowInboundRules True -AllowLocalFirewallRules True -AllowLocalIPsecRules True -AllowUnicastResponseToMulticast True -LogAllowed True -LogBlocked True -LogIgnored True -LogFileName "%windir%\system32\logfiles\firewall\pfirewall.log" -LogMaxSizeKilobytes 32767
New-NetFirewallRule -DisplayName "[AutoHarden] ADMIN-ACCESS" -Name "[AutoHarden] ADMIN-ACCESS" -Enabled True -Profile Any -Direction Inbound -Action Allow -RemoteIP $IP_ADMIN
New-NetFirewallRule -DisplayName "[AutoHarden] USERS-ACCESS-TCP" -Name "[AutoHarden] USERS-ACCESS-TCP" -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol TCP -LocalPort 88,389,445,464,636,3269,3268 -InterfaceAlias $ETH_USER
New-NetFirewallRule -DisplayName "[AutoHarden] USERS-ACCESS-UDP" -Name "[AutoHarden] USERS-ACCESS-UDP" -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol UDP -LocalPort 88,389,123 -InterfaceAlias $ETH_USER
Get-NetFirewallRule | where { -not $_.Name.StartsWith("[AutoHarden]") -and -not $_.Name.StartsWith("[AutoHarden]") } | Remove-NetFirewallRule
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled True -NotifyOnListen False -DefaultOutboundAction Allow -DefaultInboundAction Block -AllowInboundRules True -AllowLocalFirewallRules True -AllowLocalIPsecRules True -AllowUnicastResponseToMulticast True -LogAllowed True -LogBlocked True -LogIgnored True -LogFileName "%windir%\system32\logfiles\firewall\pfirewall.log" -LogMaxSizeKilobytes 32767

# Avoid the usage of the HTTP2SMB convertor (WebClient)
# WebClient is not installed by default on DC
sc.exe config webclient start= disabled

# Avoir coercing
New-NetFirewallRule -DisplayName "[AutoHarden] Block Coercing like PrintNightMare,PetitPotam,..." -Name "[AutoHarden] Block Coercing like PrintNightMare,PetitPotam,..." -Enabled True -Profile Any -Direction Outbound -Action Block -Protocol TCP -RemotePort 445

# Add a rule to drop access to EFS for non DA
# From: https://twitter.com/tiraniddo/status/1422223511599284227
# From: https://gist.github.com/tyranid/5527f5559041023714d67414271ca742
$acl = @'
rpc
filter
add rule layer=um actiontype=permit
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;DA)
add filter
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add filter
add rule layer=um actiontype=permit
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;DA)
add filter
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add filter
quit
'@
netsh -f (createTempFile $acl)
netsh rpc filter show filter

# Block IPv6
New-NetFirewallRule -direction Outbound -Action Block -Protocol 41 -Group AutoHarden-IPv6 -Name "[AutoHarden] IPv6" -DisplayName "[AutoHarden] IPv6" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 43 -Group AutoHarden-IPv6 -Name "[AutoHarden] IPv6-Route" -DisplayName "[AutoHarden] IPv6-Route" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 44 -Group AutoHarden-IPv6 -Name "[AutoHarden] IPv6-Frag" -DisplayName "[AutoHarden] IPv6-Frag" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 59 -Group AutoHarden-IPv6 -Name "[AutoHarden] IPv6-NoNxt" -DisplayName "[AutoHarden] IPv6-NoNxt" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 60 -Group AutoHarden-IPv6 -Name "[AutoHarden] IPv6-Opts" -DisplayName "[AutoHarden] IPv6-Opts" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol 58 -Group AutoHarden-IPv6 -Name "[AutoHarden] ICMPv6" -DisplayName "[AutoHarden] ICMPv6" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "547" -Group AutoHarden-IPv6 -Name "[AutoHarden] DHCPv6" -DisplayName "[AutoHarden] DHCPv6" -ErrorAction Ignore

# Protection against CVE-2020-16898: “Bad Neighbor”
netsh int ipv6 show int | foreach { $p=$_.trim().split(' ')[0]; [int]::TryParse($p,[ref]$null) -and (netsh int ipv6 set int $p rabaseddnsconfig=disable) -and (write-host "int >$p<") }

# Disable LLMNR
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /t REG_DWORD /v EnableMulticast /d 0 /f
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "5355" -Group AutoHarden-LLMNR -Name "[AutoHarden] LLMNR-UDP" -DisplayName "[AutoHarden] LLMNR" -ErrorAction Ignore

# This sets up your RDP session to NOT store credentials in the memory of the target host.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 1 /f

# Block NetBios
New-NetFirewallRule -direction Outbound -Action Block -Protocol "UDP" -RemotePort "137" -Group AutoHarden-NetBios -Name "[AutoHarden] NetBios-UDP137" -DisplayName "[AutoHarden] NetBios" -ErrorAction Ignore
New-NetFirewallRule -direction Outbound -Action Block -Protocol "TCP" -RemotePort "139" -Group AutoHarden-NetBios -Name "[AutoHarden] NetBios-TCP139" -DisplayName "[AutoHarden] NetBios3" -ErrorAction Ignore
set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip* -Name NetbiosOptions -Value 2

# Fix-HiveNightmare
# https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
icacls $env:windir\system32\config\*.* /inheritance:e
####################################################################################################
logInfo "Asking questions for the configuration"
ask "Execute AutoHarden every day at 08h00 AM" "0.1-AutoUpdate.ask"
ask "Block Internet communication for evil tools ? This filtering prevents viruses from downloading the payload." "1.1-Firewall-Malware.ask"
ask "Block Internet communication for Word and Excel ? Excel and Word will still be able to access files on local network shares. This filtering prevents viruses from downloading the payload." "1.2-Firewall-Office.ask"
ask "Block Internet communication for 'Internet Explorer' ? 'Internet Explorer' will still be able to access web server on local network. This filtering prevents viruses from downloading the payload." "1.3-Firewall-IE.ask"
ask "Avoid sending notification to Users about the firewall" "1.5-Firewall-DisableNotification.ask"
ask "Disable Cortana in Windows search bar" "Crapware-Cortana.ask"
ask "Remove OneDrive" "Crapware-Onedrive.ask"
ask "Uninstall OneNote ?" "Crapware-RemoveUseLessSoftware__Uninstall-OneNote.ask"
ask "Uninstall Skype ?" "Crapware-RemoveUseLessSoftware__Uninstall-Skype.ask"
ask "Disable voice control" "Harden-VoiceControl.ask"
ask "Disable Remote Assistance on this computer" "Hardening-RemoteAssistance.ask"
ask "Optimiz the Windows GUI" "Optimiz-ClasicExplorerConfig.ask"
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
echo "# 2-Hardening-Powershell"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "2-Hardening-Powershell" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running 2-Hardening-Powershell"
# Disable Powershellv2
DISM /Online /Disable-Feature:MicrosoftWindowsPowerShellV2Root /NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
Write-Progress -Activity AutoHarden -Status "2-Hardening-Powershell" -Completed
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
echo "# Crapware-Onedrive"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-Onedrive" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-Onedrive"
if( ask "Remove OneDrive" "Crapware-Onedrive.ask" ){
$x86="$env:SYSTEMROOT\System32\OneDriveSetup.exe"
$x64="$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
$onedriverPath = $false
if( [System.IO.File]::Exists($x86) ){
	$onedriverPath = "$x86"
}elseif( [System.IO.File]::Exists($x64) ){
	$onedriverPath = "$x64"
}
if( $onedriverPath ){
	taskkill /f /im OneDrive.exe >$null 2>&1
	# Suppression du fichier
	takeown /F "$onedriverPath" /A
	icacls "$onedriverPath" /grant:r Utilisateurs:F
	icacls "$onedriverPath" /grant:r Administrateurs:F
	Remove-Item -Recurse -Force "$onedriverPath" -ErrorAction SilentlyContinue
	
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:USERPROFILE\OneDrive" | Out-Null
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:USERPROFILE\OneDrive" | Out-Null
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "C:\OneDriveTemp" | Out-Null
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:LOCALAPPDATA\Microsoft\OneDrive" | Out-Null
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:PROGRAMDATA\Microsoft OneDrive" | Out-Null
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:PROGRAMDATA\Microsoft OneDrive" | Out-Null
	echo "Removing OneDrive from the Explorer Side Panel."
	echo .
	reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>&1
	reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>&1
}
# Suppression du OneDrive de explorer
reg add 'HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f
reg add 'HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f

# Désactivation de OneDrive
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OneDrive' /v PreventNetworkTrafficPreUserSignIn /t REG_DWORD /d 1 /f
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive' /v DisableFileSync /t REG_DWORD /d 1 /f
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive' /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f
}
Write-Progress -Activity AutoHarden -Status "Crapware-Onedrive" -Completed
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
echo "# Crapware-RemoveUseLessSoftware__Uninstall-OneNote"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-RemoveUseLessSoftware__Uninstall-OneNote" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-RemoveUseLessSoftware__Uninstall-OneNote"
if( ask "Uninstall OneNote ?" "Crapware-RemoveUseLessSoftware__Uninstall-OneNote.ask" ){
Get-AppxPackage *onenote* | Remove-AppxPackage
}
Write-Progress -Activity AutoHarden -Status "Crapware-RemoveUseLessSoftware__Uninstall-OneNote" -Completed
echo "####################################################################################################"
echo "# Crapware-RemoveUseLessSoftware__Uninstall-Skype"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Crapware-RemoveUseLessSoftware__Uninstall-Skype" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Crapware-RemoveUseLessSoftware__Uninstall-Skype"
if( ask "Uninstall Skype ?" "Crapware-RemoveUseLessSoftware__Uninstall-Skype.ask" ){
Get-AppxPackage *skypeapp* | Remove-AppxPackage
}
Write-Progress -Activity AutoHarden -Status "Crapware-RemoveUseLessSoftware__Uninstall-Skype" -Completed
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
echo "# Optimiz-ClasicExplorerConfig"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Optimiz-ClasicExplorerConfig" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Optimiz-ClasicExplorerConfig"
if( ask "Optimiz the Windows GUI" "Optimiz-ClasicExplorerConfig.ask" ){
# These make "Quick Access" behave much closer to the old "Favorites"
# Disable Quick Access: Recent Files
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v ShowFrequent /t REG_DWORD /d 0 /f
# Disable Quick Access: Frequent Folders
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v ShowRecent /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarSmallIcons /t REG_DWORD /d 1 /f
# Disable Icon Grouping
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarGlomLevel /t REG_DWORD /d 1 /f
# Change Explorer home screen back to "This PC"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
}
Write-Progress -Activity AutoHarden -Status "Optimiz-ClasicExplorerConfig" -Completed
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
echo "# Reset-KrbTgt-Password-For-RWDCs-And-RODCs-1.0-functions"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Reset-KrbTgt-Password-For-RWDCs-And-RODCs-1.0-functions" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Reset-KrbTgt-Password-For-RWDCs-And-RODCs-1.0-functions"
### Abstract: This PoSH Script Resets The KrbTgt Password For RWDCs And RODCs In A Controlled Manner
###
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
### E-Mail Address For Feedback/Questions: scripts.gallery@iamtec.eu
###
### Paste The Following Quick Link Between The Double Quotes In Browser To Send Mail:
### --> "mailto:Jorge's Script Gallery <scripts.gallery@iamtec.eu>?subject=[Script Gallery Feedback:] 'REPLACE-THIS-PART-WITH-SOMETHING-MEANINGFULL'"
###
### For Questions/Feedback:
### --> Please Describe Your Scenario As Best As Possible With As Much Detail As Possible.
### --> If Applicable Describe What Does and Does Not Work.
### --> If Applicable Describe What Should Be/Work Different And Explain Why/How.
### --> Please Add Screendumps.
###

<#
.SYNOPSIS
	This PoSH Script Resets The KrbTgt Password For RWDCs And RODCs In A Controlled Manner

.VERSION
	v2.8, 2020-04-02 (UPDATE THE VERSION VARIABLE BELOW)
	
.AUTHOR
	Initial Script/Thoughts.......: Jared Poeppelman, Microsoft
	Script Re-Written/Enhanced....: Jorge de Almeida Pinto [MVP Enterprise Mobility And Security, EMS]
	Blog..........................: Blog: http://jorgequestforknowledge.wordpress.com/
	For Feedback/Questions........: scripts.gallery@iamtec.eu ("mailto:Jorge's Script Gallery <scripts.gallery@iamtec.eu>?subject=[Script Gallery Feedback:] 'REPLACE-THIS-PART-WITH-SOMETHING-MEANINGFULL'")

.DESCRIPTION
    This PoSH script provides the following functions:
	- Single Password Reset for the KrbTgt account in use by RWDCs in a specific AD domain, using either TEST or PROD KrbTgt accounts
	- Single Password Reset for the KrbTgt account in use by an individual RODC in a specific AD domain, using either TEST or PROD KrbTgt accounts
		* A single RODC in a specific AD domain
		* A specific list of RODCs in a specific AD domain
		* All RODCs in a specific AD domain
	- Resetting the password/keys of the KrbTgt Account can be done for multiple reasons such as for example:
		* From a security perspective as mentioned in https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/
		* From an AD recovery perspective as mentioned in https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password
	- For all scenarios, an informational mode, which is mode 1 with no changes
	- For all scenarios, a simulation mode, which is mode 2 where replication is tested through the replication of a temporary canary
		object that is created and deleted afterwards. No Password Resets involved here as the temporary canary object is a contact object
	- For all scenarios, a simulation mode, which is mode 3 where NO password reset of the chosen TEST KrbTgt account occurs. Basically this
		just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a real reset mode, which is mode 4 where the password reset of the chosen TEST KrbTgt account is actually executed
		and replication of it is monitored through the environment for its duration. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a simulation mode, which is mode 5 where NO password reset of the chosen PROD KrbTgt account occurs. Basically this
		just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a real reset mode, which is mode 6 where the password reset of the chosen PROD KrbTgt account is actually executed
		and replication of it is monitored through the environment for its duration
	- The creation of Test KrbTgt Accounts, which is mode 8
	- The deletion of Test KrbTgt Accounts, which is mode 9
	
	Behavior:
	- In this script a DC is reachable/available, if its name is resolvable and connectivity is possible for all of the following ports:
		TCP:135 (Endpoint Mapper), TCP:389 (LDAP) and TCP:9839 (AD Web Services)
	- In mode 1 you will always get a list of all RWDCs, and alls RODCs if applicable, in the targeted AD domain that are available/reachable
		or not
	- In mode 2 it will create the temporary canary object and, depending on the scope, it will check if it exists in the AD database of the
		remote DC(s) (RWDC/RODC)
	- In mode 3, depending on the scope, it uses TEST/BOGUS krbtgt account(s). It just checks and compares the state of the pwdLastSet attribute
		on the source RWDC with other scoped DCs. Nothing is changed/updated!
		* For RWDCs it uses the TEST/BOGUS krbtgt account "krbtgt_TEST" (All RWDCs) (= Created when running mode 8)
		* For RODCs it uses the TEST/BOGUS krbtgt account "krbtgt_<Numeric Value>_TEST" (RODC Specific) (= Created when running mode 8)
	- In mode 4, depending on the scope, it uses TEST/BOGUS krbtgt account(s) to reset the password on an originating RWDC. After that it
		checks if pwdLastSet attribute value of the targeted TEST/BOGUS krbtgt account(s) on the remote DC(s) (RWDC/RODC) matches the
		pwdLastSet attribute value of the same TEST/BOGUS krbtgt account on the originating RWDC
		* For RWDCs it uses the TEST/BOGUS krbtgt account "krbtgt_TEST" (All RWDCs) (= Created when running mode 8)
		* For RODCs it uses the TEST/BOGUS krbtgt account "krbtgt_<Numeric Value>_TEST" (RODC Specific) (= Created when running mode 8)
	- In mode 5, depending on the scope, it uses PROD/REAL krbtgt account(s). It just checks and compares the state of the pwdLastSet attribute
		on the source RWDC with other scoped DCs. Nothing is changed/updated!
	- In mode 6, depending on the scope, it uses PROD/REAL krbtgt account(s) to reset the password on an originating RWDC. After that it
		checks if pwdLastSet attribute value of the targeted PROD/REAL krbtgt account(s) on the remote DC(s) (RWDC/RODC) matches the pwdLastSet
		attribute value of the same PROD/REAL krbtgt account on the originating RWDC
		* For RWDCs it uses the PROD/REAL krbtgt account "krbtgt" (All RWDCs)
		* For RODCs it uses the PROD/REAL krbtgt account "krbtgt_<Numeric Value>" (RODC Specific)
	- In mode 8, for RWDCs it creates (in disabled state!) the TEST/BOGUS krbtgt account "krbtgt_TEST" and adds it to the AD group
		"Denied RODC Password Replication Group". If any RODC exists in the targeted AD domain, it reads the attribute "msDS-KrbTgtLink" of
		each RODC computer account to determine the RODC specific krbtgt account and creates (in disabled state!) the TEST/BOGUS krbtgt
		account "krbtgt_<Numeric Value>_TEST" and adds it to the AD group "Allowed RODC Password Replication Group"
	- In mode 9, for RWDCs it deletes the TEST/BOGUS krbtgt account "krbtgt_TEST" if it exists. If any RODC exists in the targeted AD domain,
		it reads the attribute "msDS-KrbTgtLink" of each RODC computer account to determine the RODC specific krbtgt account and deletes the
		TEST/BOGUS krbtgt account "krbtgt_<Numeric Value>_TEST" if it exists.
	- In mode 2, 3, 4, 5 or 6, if a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database
		to determine if the change made reached it or not.
	- In mode 2 when performing the "replicate single object" operation, it will always be for the full object, no matter if the remote DC
		is an RWDC or an RODC
	- In mode 3, 4, 5 or 6 when performing the "replicate single object" operation, it will always be for the full object, if the remote DC is an
		RWDC. If the remote DC is an RODC it will always be for the partial object and more specifically "secrets only"
	- When targeting the krbtgt account (TEST/BOGUS or PROD/REAL) in use by all the RWDCs, the originating RWDC is the RWDC with the PDC FSMO
		and all other available/reachable RWDCs will be checked against to see if the change has reached them. No RODCs are involved as those
		do not use the krbtg account in use by the RWDCs and also do not store/cache its password.
	- When targeting the krbtgt account (TEST/BOGUS or PROD/REAL) in use by an RODC, the originating RWDC is the direct replication RWDC if
		available/reachable and when not available the RWDC with the PDC FSMO is used as the originating RWDC. Only the RODC that uses the
		specific krbtgt account is checked against to see if the change has reached them, but only if the RODCs is available/reachable. If the
		RODC itself is not available, then the RWDC with the PDC FSMO is used as the originating RWDC and the change will eventually replicate
		to the RODC
	- If the operating system attribute of an RODC computer account does not have a value, it is determined to be unknown (not a real RODC),
		and therefore something else. It could for example be a Riverbed appliance in "RODC mode".
	- The only DC that knows what the real replication partner is of an RODC, is the RODC itself. Only the RODC manages a connection object
		that only exists in the AD database of the RODC and does not replicate out to other DCs as RODCs do not support outbound replication.
		Therefore, assuming the RODC is available, the CO is looked up in the RODC AD database and from that CO, the "source" server is
		determined. In case the RODC is not available or its "source" server is not available, the RWDC with the PDC FSMO is used to reset
		the password of the krbtgt account in use by that RODC. If the RODC is available a check will be done against its database, and if
		not available the check is skipped

.TODO
	- N.A.

.KNOWN ISSUES/BUGS
	- When targeting a remote AD forest for which no trust exist with the AD forest the running account belongs to, the public profile of WinRM may be
		used. In that case the PSSession for 'Get-GPOReport' may fail due to the default firewall exception only allowing access from remote computers
		on the same local subnet. In that case the default 'MaxTicketAge' (default 10 hours) and 'MaxClockSkew' (default 5 minutes) is used instead.
		You may see the following error:
		[<FQDN TARGET DC>] Connecting to remote server <FQDN TARGET DC> failed with the following error message : WinRM cannot complete the operation.
		Verify that the specified computer name is valid, that the computer is accessible over the network, and that a firewall exception for the WinRM
		service is enabled and allows access from this computer. By default, the WinRM firewall exception for public profiles limits access to remote
		computers within the same local subnet. For more information, see the about_Remote_Troubleshooting Help topic.
		+ CategoryInfo          : OpenError: (<FQDN TARGET DC>:String) [], PSRemotingTransportException
        + FullyQualifiedErrorId : WinRMOperationTimeout,PSSessionStateBroken
	- Although this script can be used in an environment with Windows Server 2000/2003 RWDCs, it is NOT supported to do this. Windows Server
		2000/2003 RWDCs cannot do KDC PAC validation using the previous (N-1) krbtgt password. Those RWDCs only attempt that with the current
		(N) password. That means that in the subset of KRB AP exchanges where KDC PAC validation is performed, authentication issues could be
		experienced because the target server gets a PAC validation error when asking the KDC (domain controller) to validate the KDC signature
		of the PAC that is inside the service ticket that was presented by the client to the server. This problem would potentially persist
		for the lifetime of the service ticket(s). It is also highly recommended NOT to use products that have reached their end support.
		Please upgrade as soon as possible.
	- This is not related to this script. When increasing the DFL from Windows Server 2003 to any higher level, the password of the KrbTgt
		Account will be reset automatically due to the introduction of AES encryption for Kerberos and the requirement to regenerate new keys
		for DES, RC4, AES128, AES256!

.RELEASE NOTES
	v2.8, 2020-04-02, Jorge de Almeida Pinto [MVP-EMS]:
		- Fixed an issue when the RODC itself is not reachable/available, whereas in that case, the source should be the RWDC with the PDC FSMO
		- Checks to make sure both the RWDC with the PDC FSMO role and the nearest RWDC are available. If either one is not available, the script will abort

	v2.7, 2020-04-02, Jorge de Almeida Pinto [MVP-EMS]:
		- Added DNS name resolution check to the portConnectionCheck function
		- To test membership of the administrators group in a remote AD forest the "title" attribute is now used instead of the "displayName" attribute to try to write to it
		- Removed usage of $remoteADforest variable and only use the $localADforest variable
		- Removed usage of $remoteCredsUsed variable and only use the $adminCrds variable (Was $adminCreds)
		- Added a warning if the special purpose krbtgt account 'Krbtgt_AzureAD' is discovered in the AD domain
		- If the number of RODCs in the AD domain is 0, then it will not present the options for RODCs
		- If the number of RODCs in the AD domain is 1 of more, amd you chose to manually specify the FQDN of RODCs to process, it will present a list of RODCs to choose from
		- Operational modes have been changed (WARNING: pay attention to what you choose!). The following modes are the new modes
			- 1 - Informational Mode (No Changes At All)
			- 2 - Simulation Mode | Temporary Canary Object Created To Test Replication Convergence!
			- 3 - Simulation Mode | Use KrbTgt TEST/BOGUS Accounts - No Password Reset/WhatIf Mode!
			- 4 - Real Reset Mode | Use KrbTgt TEST/BOGUS Accounts - Password Will Be Reset Once!
			- 5 - Simulation Mode | Use KrbTgt PROD/REAL Accounts - No Password Reset/WhatIf Mode!
			- 6 - Real Reset Mode | Use KrbTgt PROD/REAL Accounts - Password Will Be Reset Once!
		- When choosing RODC Krb Tgt Account scope the following will now occur:
			- If the RODC is not reachable, the real source RWDC of the RODC cannot be determined. In that case, the RWDC with the PDC FSMO role is used as the source for the change and replication
			- If the RODC is reachable, but the real source RWDC of the RODC is not reachable it cannot be used as the source for the change and replication. In that case, the RWDC with the PDC FSMO role is used as the source for the change and replication
		- Sections with '#XXX' have been removed
		- Calls using the CMDlet 'Get-ADReplicationAttributeMetadata' (W2K12 and higher) have been replaced with .NET calls to support older OS'es such as W2K8 and W2K8R2. A function has been created to retrieve metadata
		- Some parts were rewritten/optimized

	v2.6, 2020-02-25, Jorge de Almeida Pinto [MVP-EMS]:
		- Removed code that was commented out
		- Logging where the script is being executed from
		- Updated the function 'createTestKrbTgtADAccount' to also include the FQDN of the RODC for which the Test KrbTgt account is created for better recognition
		- In addition to the port 135 (RPC Endpoint Mapper) and 389 (LDAP), the script will also check for port 9389 (AD Web Service) which is used by the ADDS PoSH CMDlets
		- Updated script to included more 'try/catch' and more (error) logging, incl. line where it fails, when things go wrong to make troubleshooting easier
	
	v2.5, 2020-02-17, Jorge de Almeida Pinto [MVP-EMS]:
		- To improve performance, for some actions the nearest RWDC is discovered instead of using the RWDC with the PDC FSMO Role
		
	v2.4, 2020-02-10, Jorge de Almeida Pinto [MVP-EMS]:
		- Checked script with Visual Studio Code and fixed all "problems" identified by Visual Studio Code
			- Variable "$remoteCredsUsed" is ignored by me, as the problem is due to the part 'Creds' in the variable name 
			- Variable "$adminCreds" is ignored by me, as the problem is due to the part 'Creds' in the variable name
		- Bug Fix: Fixed language specific issue with the groups 'Allowed RODC Password Replication Group' and 'Denied RODC Password Replication Group'
		- Added support to execute this script against a remote AD forest, either with or without a trust

	v2.3, 2019-02-25, Jorge de Almeida Pinto [MVP-EMS]:
		- Bug Fix: Removed the language specific error checking. Has been replaced with another check. This solution also resolved another
			issue when checking if a (RW/RO)DC was available or not

	v2.2, 2019-02-12, Jorge de Almeida Pinto [MVP-EMS]:
		- Bug Fix: Instead of searching for "Domain Admins" or "Enterprise Admins" membership, it resolves the default RIDs of those groups,
			combined with the corresponding domain SID, to the actual name of those domain groups. This helps in supporting non-english names
			of those domain groups
		
	v2.1, 2019-02-11, Jorge de Almeida Pinto [MVP-EMS]:
		- New Feature: Read and display metadata of the KrbTgt accounts before and after to assure it was only updated once!
		- Bug Fix: Added a try catch when enumerating details about a specific AD domain that appears not to be available
			
	v2.0, 2018-12-30, Jorge de Almeida Pinto [MVP-EMS]:
		- Renamed script to Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1
		- Full rewrite and major release
		- Added possibility to also reset KrbTgt account in use by RODCs
		- Added possibility to try this procedure using a temp canary object (contact object)
		- Added possibility to try this procedure using a TEST krbtgt accounts and perform password reset on those TEST krbtgt accounts
		- Added possibility to create TEST krbtgt accounts if required
		- Added possibility to delete TEST krbtgt accounts if required
		- Check if an RODC account is indeed in use by a Windows RODC and not something simulating an RODC (e.g. Riverbed)
		- Removed dependency for REPADMIN.EXE
		- Removed dependency for RPCPING.EXE
		- Extensive logging to both screen and file
		- Added more checks, such as permissions check, etc.

    v1.7, Jared Poeppelman, Microsoft
		- Modified rpcping.exe call to use "-u 9 -a connect" parameters to accomodate tighter RPC security settings as specified in
			DISA STIG ID: 5.124 Rule ID: SV-32395r1_rule , Vuln ID: V-14254 (thanks Adam Haynes)

    v1.6, Jared Poeppelman, Microsoft
		- Removed 'finally' block of Get-GPOReport error handling (not a bug, just not needed)
                
    v1.5, Jared Poeppelman, Microsoft
		- Renamed script to New-CtmADKrbtgtKeys.ps1
		- Added logic for GroupPolicy Powershell module dependency
		- Fixed bug of attempting PDC to PDC replication
		- Replaced function for password generation
		- Renamed functions to use appropriate Powershell verbs 
		- Added error handling around Get-GpoReport for looking up MaxTicketAge and MaxClockSkew

    v1.4, Jared Poeppelman, Microsoft
 		- First version published on TechNet Script Gallery

.EXAMPLE
	Execute The Script
	
	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1

.NOTES
	- To execute this script, the account running the script MUST be a member of the "Domain Admins" or Administrators group in the
		targeted AD domain.
	- If the account used is from another AD domain in the same AD forest, then the account running the script MUST be a member of the
		"Enterprise Admins" group in the AD forest or Administrators group in the targeted AD domain. For all AD domains in the same
		AD forest, membership of the "Enterprise Admins" group is easier as by default it is a member of the Administrators group in
		every AD domain in the AD forest
	- If the account used is from another AD domain in another AD forest, then the account running the script MUST be a member of the
		"Administrators" group in the targeted AD domain. This also applies to any other target AD domain in that same AD forest
	- This is due to the reset of the password for the targeted KrbTgt account(s) and forcing (single object) replication between DCs
	- Testing "Domain Admins" membership is done through "IsInRole" method as the group is domain specific
	- Testing "Enterprise Admins" membership is done through "IsInRole" method as the group is forest specific
	- Testing "Administrators" membership cannot be done through "IsInRole" method as the group exist in every AD domain with the same
		SID. To still test for required permissions in that case, the value of the Description attribute of the KRBTGT account is copied
		into the Title attribute and cleared afterwards. If both those actions succeed it is proven the required permissions are
		in place!
#>

### FUNCTION: Logging Data To The Log File
Function Logging($dataToLog, $lineType) {
	$datetimeLogLine = "[" + $(Get-Date -format "yyyy-MM-dd HH:mm:ss") + "] : "
	Out-File -filepath "$logFilePath" -append -inputObject "$datetimeLogLine$dataToLog"
	If ($null -eq $lineType) {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Yellow
	}
	If ($lineType -eq "SUCCESS") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Green
	}
	If ($lineType -eq "ERROR") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
	}
	If ($lineType -eq "WARNING") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
	}
	If ($lineType -eq "MAINHEADER") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Magenta
	}
	If ($lineType -eq "HEADER") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor DarkCyan
	}
	If ($lineType -eq "REMARK") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Cyan
	}
	If ($lineType -eq "REMARK-IMPORTANT") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Green
	}
	If ($lineType -eq "REMARK-MORE-IMPORTANT") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Yellow
	}
	If ($lineType -eq "REMARK-MOST-IMPORTANT") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
	}
	If ($lineType -eq "ACTION") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor White
	}
	If ($lineType -eq "ACTION-NO-NEW-LINE") {
		Write-Host "$datetimeLogLine$dataToLog" -NoNewline -ForeGroundColor White
	}
}

### FUNCTION: Test The Port Connection
Function portConnectionCheck($fqdnServer, $port, $timeOut) {
	# Test To See If The HostName Is Resolvable At All
	Try {
		[System.Net.Dns]::gethostentry($fqdnServer) | Out-Null
	} Catch {
		Return "ERROR"
	}
	
	$tcpPortSocket = $null
	$portConnect = $null
	$tcpPortWait = $null
	$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
	$portConnect = $tcpPortSocket.BeginConnect($fqdnServer, $port, $null, $null)
	$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut, $false)
	If(!$tcpPortWait) {
		$tcpPortSocket.Close()
		Return "ERROR"
	} Else {
		$ErrorActionPreference = "SilentlyContinue"
		$tcpPortSocket.EndConnect($portConnect) | Out-Null
		If (!$?) {
			Return "ERROR"
		} Else {
			Return "SUCCESS"
		}
		$tcpPortSocket.Close()
		$ErrorActionPreference = "Continue"
	}
}

### FUNCTION: Load Required PowerShell Modules
Function loadPoSHModules($PoSHModule) {
	$retValue = $null
	If(@(Get-Module | Where-Object{$_.Name -eq $PoSHModule}).count -eq 0) {
		If(@(Get-Module -ListAvailable | Where-Object{$_.Name -eq $PoSHModule} ).count -ne 0) {
			Import-Module $PoSHModule
			Logging "PoSH Module '$PoSHModule' Has Been Loaded..." "SUCCESS"
			$retValue = "HasBeenLoaded"
		} Else {
			Logging "PoSH Module '$PoSHModule' Is Not Available To Load..." "ERROR"
			Logging "Aborting Script..." "ERROR"
			$retValue = "NotAvailable"
		}
	} Else {
		Logging "PoSH Module '$PoSHModule' Already Loaded..." "SUCCESS"
		$retValue = "AlreadyLoaded"
	}
	Return $retValue
}

### FUNCTION: Test Credentials For Specific Admin Role
Function testAdminRole($adminRole) {
	# Determine Current User
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	
	# Check The Current User Is In The Specified Admin Role
	(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole($adminRole)
}

### FUNCTION: Create Temporary Canary Object
Function createTempCanaryObject($targetedADdomainRWDCFQDN, $krbTgtSamAccountName, $execDateTimeCustom1, $localADforest, $adminCrds) {
	# Determine The DN Of The Default NC Of The Targeted Domain
	$targetedADdomainDefaultNC = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDCFQDN).defaultNamingContext
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetedADdomainRWDCFQDN' For 'rootDSE'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDCFQDN -Credential $adminCrds).defaultNamingContext
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetedADdomainRWDCFQDN' For 'rootDSE' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	
	# Determine The DN Of The Users Container Of The Targeted Domain
	$containerForTempCanaryObject = $null
	$containerForTempCanaryObject = "CN=Users," + $targetedADdomainDefaultNC
	
	# Generate The Name Of The Temporary Canary Object
	$targetObjectToCheckName = $null
	$targetObjectToCheckName = "_adReplTempObject_" + $krbTgtSamAccountName + "_" + $execDateTimeCustom1
	
	# Specify The Description Of The Temporary Canary Object
	$targetObjectToCheckDescription = "...!!!.TEMP OBJECT TO CHECK AD REPLICATION IMPACT.!!!..."
	
	# Generate The DN Of The Temporary Canary Object
	$targetObjectToCheckDN = $null
	$targetObjectToCheckDN = "CN=" + $targetObjectToCheckName + "," + $containerForTempCanaryObject
	Logging "  --> RWDC To Create Object On..............: '$targetedADdomainRWDCFQDN'"
	Logging "  --> Full Name Temp Canary Object..........: '$targetObjectToCheckName'"
	Logging "  --> Description...........................: '$targetObjectToCheckDescription'"
	Logging "  --> Container For Temp Canary Object......: '$containerForTempCanaryObject'"
	Logging ""
	
	# Try To Create The Canary Object In The AD Domain And If Not Successfull Throw Error
	Try {
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			New-ADObject -Type contact -Name $targetObjectToCheckName -Path $containerForTempCanaryObject -DisplayName $targetObjectToCheckName -Description $targetObjectToCheckDescription -Server $targetedADdomainRWDCFQDN
		}
		If ($localADforest -eq $false -And $adminCrds) {
			New-ADObject -Type contact -Name $targetObjectToCheckName -Path $containerForTempCanaryObject -DisplayName $targetObjectToCheckName -Description $targetObjectToCheckDescription -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
		}
	} Catch {
		Logging "  --> Temp Canary Object [$targetObjectToCheckDN] FAILED TO BE CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}
	
	# Check The Temporary Canary Object Exists And Was created In AD
	$targetObjectToCheck = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$targetObjectToCheck = Get-ADObject -LDAPFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))" -Server $targetedADdomainRWDCFQDN
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'name=$targetObjectToCheckName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$targetObjectToCheck = Get-ADObject -LDAPFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))" -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'name=$targetObjectToCheckName' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($targetObjectToCheck) {
		$targetObjectToCheckDN = $null
		$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName
		Logging "  --> Temp Canary Object [$targetObjectToCheckDN] CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
		Logging "" "REMARK"
	}
	Return $targetObjectToCheckDN
}

### FUNCTION: Confirm Generated Password Meets Complexity Requirements
# Source: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
Function confirmPasswordIsComplex($pwd) {
	Process {
		$criteriaMet = 0
		
		# Upper Case Characters (A through Z, with diacritic marks, Greek and Cyrillic characters)
		If ($pwd -cmatch '[A-Z]') {$criteriaMet++}
		
		# Lower Case Characters (a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters)
		If ($pwd -cmatch '[a-z]') {$criteriaMet++}
		
		# Numeric Characters (0 through 9)
		If ($pwd -match '\d') {$criteriaMet++}
		
		# Special Chracters (Non-alphanumeric characters, currency symbols such as the Euro or British Pound are not counted as special characters for this policy setting)
		If ($pwd -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') {$criteriaMet++}
		
		# Check If It Matches Default Windows Complexity Requirements
		If ($criteriaMet -lt 3) {Return $false}
		If ($pwd.Length -lt 8) {Return $false}
		Return $true
	}
}

### FUNCTION: Generate New Complex Password
Function generateNewComplexPassword([int]$passwordNrChars) {
	Process {
		$iterations = 0
        Do {
			If ($iterations -ge 20) {
				Logging "  --> Complex password generation failed after '$iterations' iterations..." "ERROR"
				Logging "" "ERROR"
				EXIT
			}
			$iterations++
			$pwdBytes = @()
			$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
			Do {
				[byte[]]$byte = [byte]1
				$rng.GetBytes($byte)
				If ($byte[0] -lt 33 -or $byte[0] -gt 126) {
					CONTINUE
				}
                $pwdBytes += $byte[0]
			}
			While ($pwdBytes.Count -lt $passwordNrChars)
				$pwd = ([char[]]$pwdBytes) -join ''
			} 
        Until (confirmPasswordIsComplex $pwd)
        Return $pwd
	}
}

### FUNCTION: Retrieve The Metadata Of An Object
Function retrieveObjectMetadata($targetedADdomainRWDCFQDN, $ObjectDN, $localADforest, $adminCrds) {
	# Get The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object BEFORE THE PASSWORD SET
	$objectMetadata = $null
	$targetedADdomainRWDCContext = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		$targetedADdomainRWDCContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer", $targetedADdomainRWDCFQDN)
	}
	If ($localADforest -eq $false -And $adminCrds) {
		$targetedADdomainRWDCContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer", $targetedADdomainRWDCFQDN, $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().Password))
	}
	$targetedADdomainRWDCObject = $null
	Try {
		$targetedADdomainRWDCObject = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($targetedADdomainRWDCContext)
		$objectMetadata = $targetedADdomainRWDCObject.GetReplicationMetadata($ObjectDN)
	} Catch {
		Logging "" "ERROR"
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Logging "Error Getting Metadata From '$targetedADdomainRWDCFQDN' For Object '$krbTgtObjectBeforeDN'..." "ERROR"
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Logging "Error Getting Metadata From '$targetedADdomainRWDCFQDN' For Object '$krbTgtObjectBeforeDN' Using '$($adminCrds.UserName)'..." "ERROR"
		}
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}

	If ($objectMetadata) {
		Return $($objectMetadata.Values)
	}
}

### FUNCTION: Reset Password Of AD Account
Function setPasswordOfADAccount($targetedADdomainRWDCFQDN, $krbTgtSamAccountName, $localADforest, $adminCrds) {
	# Retrieve The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBefore = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$krbTgtObjectBefore = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCFQDN
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$krbTgtObjectBefore = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	
	# Get The DN Of The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBeforeDN = $null
	$krbTgtObjectBeforeDN = $krbTgtObjectBefore.DistinguishedName
	
	# Get The Password Last Set Value From The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBeforePwdLastSet = $null
	$krbTgtObjectBeforePwdLastSet = Get-Date $([datetime]::fromfiletime($krbTgtObjectBefore.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
	
	# Get The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object BEFORE THE PASSWORD SET
	$objectMetadataBefore = $null
	$objectMetadataBefore = retrieveObjectMetadata $targetedADdomainRWDCFQDN $krbTgtObjectBeforeDN $localADforest $adminCrds
	$objectMetadataBeforeAttribPwdLastSet = $null
	$objectMetadataBeforeAttribPwdLastSet = $objectMetadataBefore | Where-Object{$_.Name -eq "pwdLastSet"}
	$objectMetadataBeforeAttribPwdLastSetOrgRWDCFQDN = $null
	$objectMetadataBeforeAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataBeforeAttribPwdLastSet.OriginatingServer) {$objectMetadataBeforeAttribPwdLastSet.OriginatingServer} Else {"RWDC Demoted"}
	$objectMetadataBeforeAttribPwdLastSetOrgTime = $null
	$objectMetadataBeforeAttribPwdLastSetOrgTime = Get-Date $($objectMetadataBeforeAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
	$objectMetadataBeforeAttribPwdLastSetVersion = $null
	$objectMetadataBeforeAttribPwdLastSetVersion = $objectMetadataBeforeAttribPwdLastSet.Version
	
	Logging "  --> RWDC To Reset Password On.............: '$targetedADdomainRWDCFQDN'"
	Logging "  --> sAMAccountName Of KrbTgt Account......: '$krbTgtSamAccountName'"
	Logging "  --> Distinguished Name Of KrbTgt Account..: '$krbTgtObjectBeforeDN'"
	
	# Specify The Number Of Characters The Generate Password Should Contain
	$passwordNrChars = 64
	Logging "  --> Number Of Chars For Pwd Generation....: '$passwordNrChars'"
	
	# Generate A New Password With The Specified Length (Text)
	$newKrbTgtPassword = $null
	$newKrbTgtPassword = (generateNewComplexPassword $passwordNrChars).ToString()
	
	# Convert The Text Based Version Of The New Password To A Secure String
	$newKrbTgtPasswordSecure = $null
	$newKrbTgtPasswordSecure = ConvertTo-SecureString $newKrbTgtPassword -AsPlainText -Force
	
	# Try To Set The New Password On The Targeted KrbTgt Account And If Not Successfull Throw Error
	Try {
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Set-ADAccountPassword -Identity $krbTgtObjectBeforeDN -Server $targetedADdomainRWDCFQDN -Reset -NewPassword $newKrbTgtPasswordSecure
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Set-ADAccountPassword -Identity $krbTgtObjectBeforeDN -Server $targetedADdomainRWDCFQDN -Reset -NewPassword $newKrbTgtPasswordSecure -Credential $adminCrds
		}
	} Catch {
		Logging ""
		Logging "  --> Setting the new password for [$krbTgtObjectBeforeDN] FAILED on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}

	# Retrieve The KrgTgt Object In The AD Domain AFTER THE PASSWORD SET
	$krbTgtObjectAfter = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$krbTgtObjectAfter = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCFQDN
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$krbTgtObjectAfter = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	
	# Get The DN Of The KrgTgt Object In The AD Domain AFTER THE PASSWORD SET
	$krbTgtObjectAfterDN = $null
	$krbTgtObjectAfterDN = $krbTgtObjectAfter.DistinguishedName
	
	# Get The Password Last Set Value From The KrgTgt Object In The AD Domain AFTER THE PASSWORD SET
	$krbTgtObjectAfterPwdLastSet = $null
	$krbTgtObjectAfterPwdLastSet = Get-Date $([datetime]::fromfiletime($krbTgtObjectAfter.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
	
	# Get The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object AFTER THE PASSWORD SET
	$objectMetadataAfter = $null
	$objectMetadataAfter = retrieveObjectMetadata $targetedADdomainRWDCFQDN $krbTgtObjectAfterDN $localADforest $adminCrds
	$objectMetadataAfterAttribPwdLastSet = $null
	$objectMetadataAfterAttribPwdLastSet = $objectMetadataAfter | Where-Object{$_.Name -eq "pwdLastSet"}
	$objectMetadataAfterAttribPwdLastSetOrgRWDCFQDN = $null
	$objectMetadataAfterAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataAfterAttribPwdLastSet.OriginatingServer) {$objectMetadataAfterAttribPwdLastSet.OriginatingServer} Else {"RWDC Demoted"}
	$objectMetadataAfterAttribPwdLastSetOrgTime = $null
	$objectMetadataAfterAttribPwdLastSetOrgTime = Get-Date $($objectMetadataAfterAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
	$objectMetadataAfterAttribPwdLastSetVersion = $null
	$objectMetadataAfterAttribPwdLastSetVersion = $objectMetadataAfterAttribPwdLastSet.Version
	
	Logging ""
	Logging "  --> Previous Password Set Date/Time.......: '$krbTgtObjectBeforePwdLastSet'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Password Set Date/Time............: '$krbTgtObjectAfterPwdLastSet'"
	}
	Logging ""
	Logging "  --> Previous Originating RWDC.............: '$objectMetadataBeforeAttribPwdLastSetOrgRWDCFQDN'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Originating RWDC..................: '$objectMetadataAfterAttribPwdLastSetOrgRWDCFQDN'"
	}
	Logging ""
	Logging "  --> Previous Originating Time.............: '$objectMetadataBeforeAttribPwdLastSetOrgTime'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Originating Time..................: '$objectMetadataAfterAttribPwdLastSetOrgTime'"
	}
	Logging ""
	Logging "  --> Previous Version Of Attribute Value...: '$objectMetadataBeforeAttribPwdLastSetVersion'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Version Of Attribute Value........: '$objectMetadataAfterAttribPwdLastSetVersion'"
	}

	# Check And Confirm If The Password Value Has Been Updated By Comparing The Password Last Set Before And After The Reset
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging ""
		Logging "  --> The new password for [$krbTgtObjectAfterDN] HAS BEEN SET on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
		Logging "" "REMARK"
	}
}

### FUNCTION: Replicate Single AD Object
# INFO: https://msdn.microsoft.com/en-us/library/cc223306.aspx
Function replicateSingleADObject($sourceDCNTDSSettingsObjectDN, $targetDCFQDN, $objectDN, $contentScope, $localADforest, $adminCrds) {
	# Define And Target The root DSE Context
	$rootDSE = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$rootDSE = [ADSI]"LDAP://$targetDCFQDN/rootDSE"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetDCFQDN' For 'rootDSE'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$rootDSE = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetDCFQDN/rootDSE"),$($adminCrds.UserName), $($adminCrds.GetNetworkCredential().password))
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetDCFQDN' For 'rootDSE' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	
	# Perform A Replicate Single Object For The Complete Object
	If ($contentScope -eq "Full") {
		Try {
			$rootDSE.Put("replicateSingleObject",$sourceDCNTDSSettingsObjectDN+":"+$objectDN)
		} Catch {
			Logging "" "ERROR"
			Logging "Replicate Single Object (Full) Failed From '$sourceDCNTDSSettingsObjectDN' To '$targetDCFQDN' For Object '$objectDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	
	# Perform A Replicate Single Object For Obnly The Secrets Of The Object
	If ($contentScope -eq "Secrets") {
		Try {
			$rootDSE.Put("replicateSingleObject",$sourceDCNTDSSettingsObjectDN+":"+$objectDN+":SECRETS_ONLY")
		} Catch {
			Logging "" "ERROR"
			Logging "Replicate Single Object (Secrets Only) Failed From '$sourceDCNTDSSettingsObjectDN' To '$targetDCFQDN' For Object '$objectDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}	
	
	# Commit The Change To The Operational Attribute
	Try {
		$rootDSE.SetInfo()
	} Catch {
		Logging "" "ERROR"
		Logging "Triggering Replicate Single Object On '$targetDCFQDN' From '$sourceDCNTDSSettingsObjectDN' Failed For Object '$objectDN' Using The '$contentScope' Scope..." "ERROR"
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}
}

### FUNCTION: Delete/Cleanup Temporary Canary Object
Function deleteTempCanaryObject($targetedADdomainRWDCFQDN, $targetObjectToCheckDN, $localADforest, $adminCrds) {
	# Try To Delete The Canary Object In The AD Domain And If Not Successfull Throw Error
	Try {
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Remove-ADObject -Identity $targetObjectToCheckDN -Server $targetedADdomainRWDCFQDN -Confirm:$false
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Remove-ADObject -Identity $targetObjectToCheckDN -Server $targetedADdomainRWDCFQDN -Credential $adminCrds -Confirm:$false
		}
	} Catch {
		Logging "  --> Temp Canary Object [$targetObjectToCheckDN] FAILED TO BE DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
		Logging "  --> Manually delete the Temp Canary Object [$targetObjectToCheckDN] on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}
	
	# Retrieve The Temporary Canary Object From The AD Domain And If It Does Not Exist It Was Deleted Successfully
	$targetObjectToCheck = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainRWDCFQDN
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$targetObjectToCheckDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If (!$targetObjectToCheck) {
		Logging "  --> Temp Canary Object [$targetObjectToCheckDN] DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
		Logging "" "REMARK"
	}
}

### FUNCTION: Check AD Replication Convergence
Function checkADReplicationConvergence($targetedADdomainFQDN, $targetedADdomainSourceRWDCFQDN, $targetObjectToCheckDN, $listOfDCsToCheckObjectOnStart, $listOfDCsToCheckObjectOnEnd, $modeOfOperationNr, $localADforest, $adminCrds) {
	# Determine The Starting Time
	$startDateTime = Get-Date
	
	# Counter
	$c = 0
	
	# Boolean To Use In The While Condition
	$continue = $true
	
	# The Delay In Seconds Before The Next Check Iteration
	$delay = 0.1
	
	While($continue) {
		$c++
		$oldpos = $host.UI.RawUI.CursorPosition
		Logging ""
		Logging "  =================================================================== CHECK $c ==================================================================="
		Logging ""
		
		# Wait For The Duration Of The Configured Delay Before Trying Again
		Start-Sleep $delay
		
		# Variable Specifying The Object Is In Sync
		$replicated = $true
		
		# For Each DC To Check On The Starting List With All DCs To Check Execute The Following...
		ForEach ($dcToCheck in $listOfDCsToCheckObjectOnStart) {
			# HostName Of The DC To Check
			$dcToCheckHostName = $null
			$dcToCheckHostName = $dcToCheck."Host Name"
			
			# Is The DC To Check Also The PDC?
			$dcToCheckIsPDC = $null
			$dcToCheckIsPDC = $dcToCheck.PDC

			# Type (RWDC Or RODC) Of The DC To Check
			$dcToCheckDSType = $null
			$dcToCheckDSType = $dcToCheck."DS Type"

			# SiteName Of The DC To Check
			$dcToCheckSiteName = $null
			$dcToCheckSiteName = $dcToCheck."Site Name"
			
			# IP Address Of The DC To Check
			$dcToCheckIPAddress = $null
			$dcToCheckIPAddress = $dcToCheck."IP Address"
			
			# Reachability Of The DC To Check
			$dcToCheckReachability = $null
			$dcToCheckReachability = $dcToCheck.Reachable
			
			# HostName Of The Source RWDC Of The DC To Check
			#$dcToCheckSourceRWDCFQDN = $null
			#$dcToCheckSourceRWDCFQDN = $dcToCheck."Source RWDC FQDN"
			
			# DSA DN Of The Source RWDC Of The DC To Check
			$dcToCheckSourceRWDCNTDSSettingsObjectDN = $null
			$dcToCheckSourceRWDCNTDSSettingsObjectDN = $dcToCheck."Source RWDC DSA"

			# If Mode 3, Simulate Password Reset Of KrbTgt TEST/BOGUS Accounts (No Password Reset/WhatIf Mode)
			# If Mode 4, Do A Real Password Reset Of KrbTgt TEST/BOGUS Accounts (Password Reset!)
			# If Mode 5, Simulate Password Reset Of KrbTgt PROD/REAL Accounts (No Password Reset/WhatIf Mode)
			# If Mode 6, Do A Real Password Reset Of KrbTgt PROD/REAL Accounts (Password Reset!)
			If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
				# Retrieve The Object From The Source Originating RWDC
				$objectOnSourceOrgRWDC = $null
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
					Try {
						$objectOnSourceOrgRWDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $targetedADdomainSourceRWDCFQDN
					} Catch {
						Logging "" "ERROR"
						Logging "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN'..." "ERROR"
						Logging "" "ERROR"
						Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
						Logging "" "ERROR"
						Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
						Logging "" "ERROR"
						Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
						Logging "" "ERROR"
					}
				}
				If ($localADforest -eq $false -And $adminCrds) {
					Try {
						$objectOnSourceOrgRWDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCrds
					} Catch {
						Logging "" "ERROR"
						Logging "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." "ERROR"
						Logging "" "ERROR"
						Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
						Logging "" "ERROR"
						Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
						Logging "" "ERROR"
						Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
						Logging "" "ERROR"
					}
				}
				
				# Retrieve The Password Last Set Of The Object On The Source Originating RWDC
				$objectOnSourceOrgRWDCPwdLastSet = $null
				$objectOnSourceOrgRWDCPwdLastSet = Get-Date $([datetime]::fromfiletime($objectOnSourceOrgRWDC.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
			}

			# When The DC To Check Is Also The Source (Originating) RWDC
			If ($dcToCheckHostName -eq $targetedADdomainSourceRWDCFQDN) {
				Logging "  - Contacting DC in AD domain ...[$($dcToCheckHostName.ToUpper())]...(SOURCE RWDC)"
				Logging "     * DC is Reachable..." "SUCCESS"
				
				# For Mode 2 Only
				If ($modeOfOperationNr -eq 2) {
					Logging "     * Object [$targetObjectToCheckDN] exists in the AD database" "SUCCESS"
				}
				
				# For Mode 3 Or 4 Or 5 Or 6 Only
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
					Logging "     * The (new) password for Object [$targetObjectToCheckDN] exists in the AD database" "SUCCESS"
				}
				Logging ""
				CONTINUE
			}
			
			Logging "  - Contacting DC in AD domain ...[$($dcToCheckHostName.ToUpper())]..."
			If ($dcToCheckReachability -eq $true) {
				# When The DC To Check Is Reachable
				Logging "     * DC is Reachable..." "SUCCESS"
				
				# When The DC To Check Is Not The Source (Originating) RWDC
				If ($dcToCheckHostName -ne $targetedADdomainSourceRWDCFQDN) {
					# As The DSA DN Use The DSA DN Of The Source (Originating) RWDC Of The DC Being Checked
					$sourceDCNTDSSettingsObjectDN = $dcToCheckSourceRWDCNTDSSettingsObjectDN
					
					# For Mode 2 Perform A Full Replicate Single Object
					If ($modeOfOperationNr -eq 2) {
						$contentScope = "Full"
					}
					
					# For Mode 3 Or 4 Or 5 Or 6 Only
					If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
						# If The DC Being Checked Is An RWDC Perform A Full Replicate Single Object
						If ($dcToCheckDSType -eq "Read/Write") {
							$contentScope = "Full"
						}
						
						# If The DC Being Checked Is An RODC Perform A Partial Replicate Single Object (Secrets Only)
						If ($dcToCheckDSType -eq "Read-Only") {
							$contentScope = "Secrets"
						}
					}
					
					# Execute The Replicate Single Object Function For The Targeted Object To Check
					replicateSingleADObject $sourceDCNTDSSettingsObjectDN $dcToCheckHostName $targetObjectToCheckDN $contentScope $localADforest $adminCrds
				}
				
				# For Mode 2 From The DC to Check Retrieve The AD Object Of The Temporary Canary Object That Was Created On The Source (Originating) RWDC
				If ($modeOfOperationNr -eq 2) {
					$targetObjectToCheck = $null
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
						Try {
							$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $dcToCheckHostName
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$dcToCheckHostName' For Object With 'distinguishedName=$targetObjectToCheckDN'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
					If ($localADforest -eq $false -And $adminCrds) {
						Try {
							$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $dcToCheckHostName -Credential $adminCrds
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$dcToCheckHostName' For User Object With 'distinguishedName=$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
				}
				
				# For Mode 3 Or 4 From The DC to Check Retrieve The AD Object Of The Targeted KrbTgt Account (And Its Password Last Set) That Had Its Password Reset On The Source (Originating) RWDC
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
					# Retrieve The Object From The Target DC
					$objectOnTargetDC = $null
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
						Try {
							$objectOnTargetDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $dcToCheckHostName
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$dcToCheckHostName' For Object '$targetObjectToCheckDN'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
					If ($localADforest -eq $false -And $adminCrds) {
						Try {
							$objectOnTargetDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $dcToCheckHostName -Credential $adminCrds
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$dcToCheckHostName' For Object '$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
					
					# Retrieve The Password Last Set Of The Object On The Target DC
					$objectOnTargetDCPwdLastSet = $null
					$objectOnTargetDCPwdLastSet = Get-Date $([datetime]::fromfiletime($objectOnTargetDC.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
				}
			} Else {
				# When The DC To Check Is Not Reachable
				Logging "     * DC is NOT reachable..." "ERROR"
			}
			
			If ($dcToCheckReachability -eq $true) {
				# When The DC To Check Is Reachable

				If ($targetObjectToCheck -Or $objectOnTargetDCPwdLastSet -eq $objectOnSourceOrgRWDCPwdLastSet) {
					# If The Target Object To Check Does Exist Or Its Password Last Set Does Match With The Password Last Set Of The Object On The Source (Originating) RWDC
					# For Mode 2 Only
					If ($modeOfOperationNr -eq 2) {
						Logging "     * Object [$targetObjectToCheckDN] now does exist in the AD database" "SUCCESS"
					}
					
					# For Mode 3 Or 4 Or 5 Or 6 Only
					If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
						Logging "     * The (new) password for Object [$targetObjectToCheckDN] now does exist in the AD database" "SUCCESS"
					}
					Logging "" "SUCCESS"
					
					# If The DC To Check Does Not Yet Exist On The Ending List With All DCs That Were Checked, Then Add It To The Ending List
					If (!($listOfDCsToCheckObjectOnEnd | Where-Object{$_."Host Name" -eq $dcToCheckHostName})) {
						# Define The Columns For This DC To Be Filled In
						$listOfDCsToCheckObjectOnEndObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN",Time
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj."Host Name" = $null
						$listOfDCsToCheckObjectOnEndObj."Host Name" = $dcToCheckHostName
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj.PDC = $null
						$listOfDCsToCheckObjectOnEndObj.PDC = $dcToCheckIsPDC
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj."Site Name" = $null
						$listOfDCsToCheckObjectOnEndObj."Site Name" = $dcToCheckSiteName
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj."DS Type" = $null
						$listOfDCsToCheckObjectOnEndObj."DS Type" = $dcToCheckDSType
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj."IP Address" = $null
						$listOfDCsToCheckObjectOnEndObj."IP Address" = $dcToCheckIPAddress
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj.Reachable = $null
						$listOfDCsToCheckObjectOnEndObj.Reachable = $dcToCheckReachability
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $null
						$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $targetedADdomainSourceRWDCFQDN
						
						# Set The Corresponding Value Of The DC In The Correct Column Of The Table
						$listOfDCsToCheckObjectOnEndObj.Time = ("{0:n2}" -f ((Get-Date) - $startDateTime).TotalSeconds)
						
						# Add The Row For The DC To The Table
						$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj
					}
				} Else {
					# If The Target Object To Check Does Not Exist Or Its Password Last Set Does Not Match (Yet) With The Password Last Set Of The Object On The Source (Originating) RWDC
					# For Mode 2 Only
					If ($modeOfOperationNr -eq 2) {
						Logging "     * Object [$targetObjectToCheckDN] does NOT exist yet in the AD database" "WARNING"
					}
					
					# For Mode 3 Or 4 Or 5 Or 6 Only
					If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
						Logging "     * The (new) password for Object [$targetObjectToCheckDN] does NOT exist yet in the AD database" "WARNING"
					}
					Logging "" "WARNING"
					
					# Variable Specifying The Object Is Not In Sync
					$replicated = $false
				}
			} Else {
				# When The DC To Check Is Not Reachable
				Logging "     * Unable to connect to DC and check for Object [$targetObjectToCheckDN]..." "ERROR"
				Logging "" "WARNING"
				
				# If The DC To Check Does Not Yet Exist On The Ending List With All DCs That Were Checked, Then Add It To The Ending List
				If (!($listOfDCsToCheckObjectOnEnd | Where-Object{$_."Host Name" -eq $dcToCheckHostName})) {
					# Define The Columns For This DC To Be Filled In
					$listOfDCsToCheckObjectOnEndObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN",Time
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj."Host Name" = $null
					$listOfDCsToCheckObjectOnEndObj."Host Name" = $dcToCheckHostName
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj.PDC = $null
					$listOfDCsToCheckObjectOnEndObj.PDC = $dcToCheckIsPDC
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj."Site Name" = $null
					$listOfDCsToCheckObjectOnEndObj."Site Name" = $dcToCheckSiteName
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj."DS Type" = $null
					$listOfDCsToCheckObjectOnEndObj."DS Type" = $dcToCheckDSType
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj."IP Address" = $null
					$listOfDCsToCheckObjectOnEndObj."IP Address" = $dcToCheckIPAddress
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj.Reachable = $null
					$listOfDCsToCheckObjectOnEndObj.Reachable = $dcToCheckReachability
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $null
					$listOfDCsToCheckObjectOnEndObj."Source RWDC FQDN" = $targetedADdomainSourceRWDCFQDN
					
					# Set The Corresponding Value Of The DC In The Correct Column Of The Table
					$listOfDCsToCheckObjectOnEndObj.Time = "<Fail>"
					
					# Add The Row For The DC To The Table
					$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj
				}
			}
		}

		# If The Object Is In Sync
		If ($replicated) {
			# Do Not Continue For The DC That Is Being Checked
			$continue = $false
		} Else {
			# Do Continue For The DC That Is Being Checked And Move The Cursor Back To The Initial Position
			$host.UI.RawUI.CursorPosition = $oldpos
		}
	}

	# Determine The Ending Time
	$endDateTime = Get-Date
	
	# Calculate The Duration
	$duration = "{0:n2}" -f ($endDateTime.Subtract($startDateTime).TotalSeconds)
	Logging ""
	Logging "  --> Start Time......: $(Get-Date $startDateTime -format 'yyyy-MM-dd HH:mm:ss')"
	Logging "  --> End Time........: $(Get-Date $endDateTime -format 'yyyy-MM-dd HH:mm:ss')"
	Logging "  --> Duration........: $duration Seconds"
	Logging ""

	# If Mode 2 Was Being Executed, Then Delete The Temp Canary Object On The Source (Originating) RWDC
	If ($modeOfOperationNr -eq 2) {
		# Retrieve The Temp Canary Object From The Source (Originating) RWDC
		$targetObjectToCheck = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainSourceRWDCFQDN
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCrds
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		
		# If The Temp Canary Object Exists On The Source (Originating) RWDC, Then Delete It
		If ($targetObjectToCheck) {
			# Execute The Deletion Of The Temp Canary Object On The Source (Originating) RWDC. There Is No Need To Force Deletion Of The Object On All The Other DCs As In Time It Will Be Deleted
			deleteTempCanaryObject $targetedADdomainSourceRWDCFQDN $targetObjectToCheckDN $localADforest $adminCrds
		}
	}

	# Sort The Ending List With All DCs That Were Checked
	$listOfDCsToCheckObjectOnEnd = $listOfDCsToCheckObjectOnEnd | Sort-Object -Property @{Expression = "Time"; Descending = $False} | Format-Table -Autosize
	Logging ""
	Logging "List Of DCs In AD Domain '$targetedADdomainFQDN' And Their Timing..."
	Logging ""
	Logging "$($listOfDCsToCheckObjectOnEnd | Out-String)"
	Logging ""
}

### FUNCTION: Create Test Krbtgt Accounts
Function createTestKrbTgtADAccount($targetedADdomainRWDCFQDN, $krbTgtSamAccountName, $krbTgtUse, $targetedADdomainDomainSID, $localADforest, $adminCrds) {
	# Determine The DN Of The Default NC Of The Targeted Domain
	$targetedADdomainDefaultNC = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDCFQDN).defaultNamingContext
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetedADdomainRWDCFQDN' For 'rootDSE'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDCFQDN -Credential $adminCrds).defaultNamingContext
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetedADdomainRWDCFQDN' For 'rootDSE' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	
	# Determine The DN Of The Users Container Of The Targeted Domain
	$containerForTestKrbTgtAccount = $null
	$containerForTestKrbTgtAccount = "CN=Users," + $targetedADdomainDefaultNC
	
	# Set The SamAccountName For The Test/Bogus KrbTgt Account
	$testKrbTgtObjectSamAccountName = $null
	$testKrbTgtObjectSamAccountName = $krbTgtSamAccountName
	
	# Set The Name For The Test/Bogus KrbTgt Account
	$testKrbTgtObjectName = $null
	$testKrbTgtObjectName = $testKrbTgtObjectSamAccountName
	
	# Set The Description For The Test/Bogus KrbTgt Account
	$testKrbTgtObjectDescription = $null
	
	# Set The Description For The Test/Bogus KrbTgt Account For RWDCs
	If ($krbTgtUse -eq "RWDC") {
		$testKrbTgtObjectDescription = "Test Copy Representing '$($krbTgtSamAccountName.SubString(0,$krbTgtSamAccountName.IndexOf('_TEST')))' - Key Distribution Center Service Account For RWDCs"
	}
	
	# Set The Description For The Test/Bogus KrbTgt Account For RODCs
	If ($krbTgtUse -eq "RODC") {
		$rodcComputerAccountDN = $null
		Try {
			$rodcComputerAccountDN = (Get-ADUser -Identity $($krbTgtSamAccountName.SubString(0,$krbTgtSamAccountName.IndexOf('_TEST'))) -Properties "msDS-KrbTgtLinkBl" -Server $targetedADdomainRWDCFQDN)."msDS-KrbTgtLinkBl"[0]
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$($krbTgtSamAccountName.SubString(0,$krbTgtSamAccountName.IndexOf('_TEST')))'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}		
		$rodcFQDN = $null
		If ($rodcComputerAccountDN) {
			Try {
				$rodcFQDN = (Get-ADComputer -Identity $rodcComputerAccountDN -Properties dNSHostName -Server $targetedADdomainRWDCFQDN).dNSHostName
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Computer Object '$rodcComputerAccountDN'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($rodcFQDN) {
			$testKrbTgtObjectDescription = "Test Copy Representing '$($krbTgtSamAccountName.SubString(0,$krbTgtSamAccountName.IndexOf('_TEST')))' - Key Distribution Center Service Account For RODC '$rodcFQDN'"
		} Else {
			$testKrbTgtObjectDescription = "Test Copy Representing '$($krbTgtSamAccountName.SubString(0,$krbTgtSamAccountName.IndexOf('_TEST')))' - Key Distribution Center Service Account For RODC 'UNABLE TO DETERMINE - WEIRD!'"
		}
	}	
	
	# Generate The DN Of The Test KrbTgt Object
	$testKrbTgtObjectDN = $null
	$testKrbTgtObjectDN = "CN=" + $testKrbTgtObjectName + "," + $containerForTestKrbTgtAccount
	Logging "  --> RWDC To Create Object On..............: '$targetedADdomainRWDCFQDN'"
	Logging "  --> Full Name Test KrbTgt Account.........: '$testKrbTgtObjectName'"
	Logging "  --> Description...........................: '$testKrbTgtObjectDescription'"
	Logging "  --> Container Test KrbTgt Account.........: '$containerForTestKrbTgtAccount'"
	If ($krbTgtUse -eq "RODC") {
		Logging "  --> For RODC With FQDN....................: '$rodcFQDN'"
	}
	
	# If The Test/Bogus KrbTgt Account Is Used By RWDCs
	If ($krbTgtUse -eq "RWDC") {
		$deniedRODCPwdReplGroupRID = "572"
		$deniedRODCPwdReplGroupObjectSID  = $targetedADdomainDomainSID + "-" + $deniedRODCPwdReplGroupRID
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				$deniedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $deniedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDCFQDN).Name
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$deniedRODCPwdReplGroupObjectSID'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				$deniedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $deniedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDCFQDN -Credential $adminCrds).Name
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$deniedRODCPwdReplGroupObjectSID' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		Logging "  --> Made Member Of RODC PRP Group.........: '$deniedRODCPwdReplGroupObjectName'"
	}
	
	# If The Test/Bogus KrbTgt Account Is Used By RODCs
	If ($krbTgtUse -eq "RODC") {
		$allowedRODCPwdReplGroupRID = "571"
		$allowedRODCPwdReplGroupObjectSID  = $targetedADdomainDomainSID + "-" + $allowedRODCPwdReplGroupRID
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				$allowedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $allowedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDCFQDN).Name
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$allowedRODCPwdReplGroupObjectSIDD'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				$allowedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $allowedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDCFQDN -Credential $adminCrds).Name
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$allowedRODCPwdReplGroupObjectSID' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}		
		Logging "  --> Made Member Of RODC PRP Group.........: '$allowedRODCPwdReplGroupObjectName'"
	}
	Logging ""
	
	# Check If The Test/Bogus KrbTgt Account Already Exists In AD
	$testKrbTgtObject = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Properties Description -Server $targetedADdomainRWDCFQDN
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Properties Description -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($testKrbTgtObject) {
		# Update The Description For The Test KrbTgt Account If There Is A Mismatch For Whatever Reason
		If ($testKrbTgtObject.Description -ne $testKrbTgtObjectDescription) {
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					Set-ADUser -Identity $testKrbTgtObjectSamAccountName -description $testKrbTgtObjectDescription -Server $targetedADdomainRWDCFQDN
				} Catch {
					Logging "" "ERROR"
					Logging "Error Updating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					Set-ADUser -Identity $testKrbTgtObjectSamAccountName -description $testKrbTgtObjectDescription -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
				} Catch {
					Logging "" "ERROR"
					Logging "Error Updating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
		}
		
		Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ALREADY EXISTS on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
		Logging "" "REMARK"
	} Else {
		# If The Test/Bogus KrbTgt Account Does Not Exist Yet In AD
		# Specify The Number Of Characters The Generate Password Should Contain
		$passwordNrChars = 64
		
		# Generate A New Password With The Specified Length (Text)
		$krbTgtPassword = $null
		$krbTgtPassword = (generateNewComplexPassword $passwordNrChars).ToString()
		
		# Convert The Text Based Version Of The New Password To A Secure String
		$krbTgtPasswordSecure = $null
		$krbTgtPasswordSecure = ConvertTo-SecureString $krbTgtPassword -AsPlainText -Force
		
		# Try To Create The Test/Bogus KrbTgt Account In The AD Domain And If Not Successfull Throw Error
		Try {
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					New-ADUser -SamAccountName $testKrbTgtObjectSamAccountName -Name $testKrbTgtObjectName -DisplayName $testKrbTgtObjectName -Path $containerForTestKrbTgtAccount -AccountPassword $krbTgtPasswordSecure -Enabled $False -description $testKrbTgtObjectDescription -Server $targetedADdomainRWDCFQDN
				} Catch {
					Logging "" "ERROR"
					Logging "Error Creating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					New-ADUser -SamAccountName $testKrbTgtObjectSamAccountName -Name $testKrbTgtObjectName -DisplayName $testKrbTgtObjectName -Path $containerForTestKrbTgtAccount -AccountPassword $krbTgtPasswordSecure -Enabled $False -description $testKrbTgtObjectDescription -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
				} Catch {
					Logging "" "ERROR"
					Logging "Error Creating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
		} Catch {
			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] FAILED TO BE CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
			Logging "" "ERROR"
		}
		
		# Check The The Test/Bogus KrbTgt Account Exists And Was created In AD
		$testKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				$testKrbTgtObject = Get-ADObject -LDAPFilter "(&(objectClass=user)(name=$testKrbTgtObjectName))" -Server $targetedADdomainRWDCFQDN
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'name=$testKrbTgtObjectName'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				$testKrbTgtObject = Get-ADObject -LDAPFilter "(&(objectClass=user)(name=$testKrbTgtObjectName))" -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'name=$testKrbTgtObjectName' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($testKrbTgtObject) {
			$testKrbTgtObjectDN = $null
			$testKrbTgtObjectDN = $testKrbTgtObject.DistinguishedName
			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
			Logging "" "REMARK"
		}
	}
	If ($testKrbTgtObject) {
		# If The Test/Bogus KrbTgt Account Already Exists In AD
		# If The Test/Bogus KrbTgt Account Is Used By RWDCs
		If ($krbTgtUse -eq "RWDC") {
			# Check If The Test/Bogus KrbTgt Account Is Already A Member Of The Specified AD Group
			$membershipDeniedPRPGroup = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					$membershipDeniedPRPGroup = Get-ADGroupMember -Identity $deniedRODCPwdReplGroupObjectName -Server $targetedADdomainRWDCFQDN | Where-Object{$_.distinguishedName -eq $testKrbTgtObjectDN}
				} Catch {
					Logging "" "ERROR"
					Logging "Error Retrieving Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$deniedRODCPwdReplGroupObjectName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					$membershipDeniedPRPGroup = Get-ADGroupMember -Identity $deniedRODCPwdReplGroupObjectName -Server $targetedADdomainRWDCFQDN -Credential $adminCrds | Where-Object{$_.distinguishedName -eq $testKrbTgtObjectDN}
				} Catch {
					Logging "" "ERROR"
					Logging "Error Retrieving Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$deniedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($membershipDeniedPRPGroup) {
				# If The Test/Bogus KrbTgt Account Is Already A Member Of The Specified AD Group
				Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ALREADY MEMBER OF [$deniedRODCPwdReplGroupObjectName]!..." "REMARK"
				Logging "" "REMARK"
			} Else {
				# If The Test/Bogus KrbTgt Account Is Not Yet A Member Of The Specified AD Group, Then Add It As A Member
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
					Try {
						Add-ADGroupMember -Identity $deniedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN
					} Catch {
						Logging "" "ERROR"
						Logging "Error Adding Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$deniedRODCPwdReplGroupObjectName'..." "ERROR"
						Logging "" "ERROR"
						Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
						Logging "" "ERROR"
						Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
						Logging "" "ERROR"
						Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
						Logging "" "ERROR"
					}
				}
				If ($localADforest -eq $false -And $adminCrds) {
					Try {
						Add-ADGroupMember -Identity $deniedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
					} Catch {
						Logging "" "ERROR"
						Logging "Error Retrieving Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$deniedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." "ERROR"
						Logging "" "ERROR"
						Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
						Logging "" "ERROR"
						Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
						Logging "" "ERROR"
						Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
						Logging "" "ERROR"
					}
				}
				Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ADDED AS MEMBER OF [$deniedRODCPwdReplGroupObjectName]!..." "REMARK"
				Logging "" "REMARK"
			}
		}
		
		# If The Test/Bogus KrbTgt Account Is Used By RODCs
		If ($krbTgtUse -eq "RODC") {
			# Check If The Test/Bogus KrbTgt Account Is Already A Member Of The Specified AD Group
			$membershipAllowedPRPGroup = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					$membershipAllowedPRPGroup = Get-ADGroupMember -Identity $allowedRODCPwdReplGroupObjectName -Server $targetedADdomainRWDCFQDN | Where-Object{$_.distinguishedName -eq $testKrbTgtObjectDN}
				} Catch {
					Logging "" "ERROR"
					Logging "Error Retrieving Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$allowedRODCPwdReplGroupObjectName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					$membershipAllowedPRPGroup = Get-ADGroupMember -Identity $allowedRODCPwdReplGroupObjectName -Server $targetedADdomainRWDCFQDN -Credential $adminCrds | Where-Object{$_.distinguishedName -eq $testKrbTgtObjectDN}
				} Catch {
					Logging "" "ERROR"
					Logging "Error Retrieving Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$allowedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($membershipAllowedPRPGroup) {
				# If The Test/Bogus KrbTgt Account Is Already A Member Of The Specified AD Group
				Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ALREADY MEMBER OF [$allowedRODCPwdReplGroupObjectName]!..." "REMARK"
				Logging "" "REMARK"
			} Else {
				# If The Test/Bogus KrbTgt Account Is Not Yet A Member Of The Specified AD Group, Then Add It As A Member
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
					Try {
						Add-ADGroupMember -Identity $allowedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN
					} Catch {
						Logging "" "ERROR"
						Logging "Error Adding Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$allowedRODCPwdReplGroupObjectName'..." "ERROR"
						Logging "" "ERROR"
						Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
						Logging "" "ERROR"
						Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
						Logging "" "ERROR"
						Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
						Logging "" "ERROR"
					}
				}
				If ($localADforest -eq $false -And $adminCrds) {
					Try {
						Add-ADGroupMember -Identity $allowedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
					} Catch {
						Logging "" "ERROR"
						Logging "Error Retrieving Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$allowedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." "ERROR"
						Logging "" "ERROR"
						Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
						Logging "" "ERROR"
						Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
						Logging "" "ERROR"
						Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
						Logging "" "ERROR"
					}
				}
				Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ADDED AS MEMBER OF [$allowedRODCPwdReplGroupObjectName]!..." "REMARK"
				Logging "" "REMARK"
			}
		}
	}
}

### FUNCTION: Delete Test Krbtgt Accounts
Function deleteTestKrbTgtADAccount($targetedADdomainRWDCFQDN, $krbTgtSamAccountName) {
	# Check If The Test/Bogus KrbTgt Account Exists In AD
	$testKrbTgtObject = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$testKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainRWDCFQDN
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}	
		
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$testKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($testKrbTgtObject) {
		# If It Does Exist In AD
		$testKrbTgtObjectDN = $null
		$testKrbTgtObjectDN = $testKrbTgtObject.DistinguishedName
		Logging "  --> RWDC To Delete Object On..............: '$targetedADdomainRWDCFQDN'"
		Logging "  --> Test KrbTgt Account DN................: '$testKrbTgtObjectDN'"
		Logging ""
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				Remove-ADUser -Identity $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN -Confirm:$false
			} Catch {
				Logging "" "ERROR"
				Logging "Error Deleting User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectDN'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				Remove-ADUser -Identity $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN -Credential $adminCrds -Confirm:$false
			} Catch {
				Logging "" "ERROR"
				Logging "Error Deleting User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectDN' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		$testKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Server $targetedADdomainRWDCFQDN
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If (!$testKrbTgtObject) {
			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
			Logging "" "REMARK"
		} Else {
			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] FAILED TO BE DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
			Logging "  --> Manually delete the Test KrbTgt Account [$testKrbTgtObjectDN] on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
			Logging "" "ERROR"
		}
	} Else {
		# If It Does Not Exist In AD
		Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] DOES NOT EXIST on RWDC [$targetedADdomainRWDCFQDN]!..." "WARNING"
		Logging "" "WARNING"
	}
}

### Version Of Script
$version = "v2.8, 2020-04-02"

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ RESET KRBTGT ACCOUNT PASSWORD FOR RWDCs/RODCs +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 400
$uiConfigBufferSize.Height = 9999
$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
$uiConfigScreenSize = $uiConfig.WindowSize
If ($uiConfigScreenSizeMaxWidth -lt 240) {
	$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
} Else {
	$uiConfigScreenSize.Width = 240
}
If ($uiConfigScreenSizeMaxHeight -lt 75) {
	$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
} Else {
	$uiConfigScreenSize.Height = 75
}
$uiConfig.BufferSize = $uiConfigBufferSize
$uiConfig.WindowSize = $uiConfigScreenSize

### Definition Of Some Constants
$execDateTime = Get-Date
$execDateTimeYEAR = $execDateTime.Year
$execDateTimeMONTH = $execDateTime.Month
$execDateTimeDAY = $execDateTime.Day
$execDateTimeHOUR = $execDateTime.Hour
$execDateTimeMINUTE = $execDateTime.Minute
$execDateTimeSECOND = $execDateTime.Second
$execDateTimeCustom = [STRING]$execDateTimeYEAR + "-" + $("{0:D2}" -f $execDateTimeMONTH) + "-" + $("{0:D2}" -f $execDateTimeDAY) + "_" + $("{0:D2}" -f $execDateTimeHOUR) + "." + $("{0:D2}" -f $execDateTimeMINUTE) + "." + $("{0:D2}" -f $execDateTimeSECOND)
$execDateTimeCustom1 = [STRING]$execDateTimeYEAR + $("{0:D2}" -f $execDateTimeMONTH) + $("{0:D2}" -f $execDateTimeDAY) + $("{0:D2}" -f $execDateTimeHOUR) + $("{0:D2}" -f $execDateTimeMINUTE) + $("{0:D2}" -f $execDateTimeSECOND)
$adRunningUserAccount = $ENV:USERDOMAIN + "\" + $ENV:USERNAME
$scriptFullPath = $MyInvocation.MyCommand.Definition
$currentScriptFolderPath = Split-Path $scriptFullPath
$localComputerName = $(Get-WmiObject -Class Win32_ComputerSystem).Name
$fqdnDomainName = $(Get-WmiObject -Class Win32_ComputerSystem).Domain
$fqdnLocalComputer = $localComputerName + "." + $fqdnDomainName
[string]$logFilePath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Reset-KrbTgt-Password-For-RWDCs-And-RODCs.log")

### Presentation Of Script Header
Logging ""
Logging "                                          **********************************************************" "MAINHEADER"
Logging "                                          *                                                        *" "MAINHEADER"
Logging "                                          *  --> Reset KrbTgt Account Password For RWDCs/RODCs <-- *" "MAINHEADER"
Logging "                                          *                                                        *" "MAINHEADER"
Logging "                                          *     Re-Written By: Jorge de Almeida Pinto [MVP-EMS]    *" "MAINHEADER"
Logging "                                          *                                                        *" "MAINHEADER"
Logging "                                          *            BLOG: Jorge's Quest For Knowledge           *" "MAINHEADER"
Logging "                                          *   (URL: http://jorgequestforknowledge.wordpress.com/)  *" "MAINHEADER"
Logging "                                          *                                                        *" "MAINHEADER"
Logging "                                          *                    $version                    *" "MAINHEADER"
Logging "                                          *                                                        *" "MAINHEADER"
Logging "                                          **********************************************************" "MAINHEADER"
Logging ""

### Logging Where The Script Is Being Executed From
Logging ""
Logging "Script Running On...: $fqdnLocalComputer"

### Providing Information About What The Script Is Capable Of And How The Script Works
Logging ""
Logging "Do you want to read information about the script, its functions, its behavior and the impact? [YES | NO]: " "ACTION-NO-NEW-LINE"
$yesOrNo = $null
$yesOrNo = Read-Host
If ($yesOrNo.ToUpper() -ne "NO") {
	$yesOrNo = "YES"
}
Logging ""
Logging "  --> Chosen: $yesOrNo" "REMARK"
Logging ""
If ($yesOrNo.ToUpper() -ne "NO") {
	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "INFORMATION ABOUT THE SCRIPT, ITS FUNCTIONS AND BEHAVIOR, AND IMPACT TO THE ENVIRONMENT - PLEASE READ CAREFULLY..." "HEADER"
	Logging ""
	Logging "-----" "REMARK"
	Logging "This PoSH script provides the following functions:" "REMARK"
	Logging "-----" "REMARK"
	Logging " - Single Password Reset for the KrbTgt account in use by RWDCs in a specific AD domain, using either TEST or PROD KrbTgt accounts" "REMARK"
	Logging " - Single Password Reset for the KrbTgt account in use by an individual RODC in a specific AD domain, using either TEST or PROD KrbTgt accounts" "REMARK"
	Logging "     * A single RODC in a specific AD domain" "REMARK"
	Logging "     * A specific list of in a specific AD domain" "REMARK"
	Logging "     * All RODCs in a specific AD domain" "REMARK"
	Logging " - Resetting the password/keys of the KrbTgt Account can be done for multiple reasons such as for example:" "REMARK"
	Logging "     * From a security perspective as mentioned in:" "REMARK"
	Logging "       https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/" "REMARK"
	Logging "     * From an AD recovery perspective as mentioned in:" "REMARK"
	Logging "       https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password" "REMARK"
	Logging " - For all scenarios, an informational mode, which is mode 1 with no changes" "REMARK"
	Logging " - For all scenarios, a simulation mode, which is mode 2 where replication is tested through the replication of a temporary canary" "REMARK"
	Logging "     object that is created and deleted afterwards" "REMARK"
	Logging " - For all scenarios, a simulation mode, which is mode 3 where the password reset of the chosen TEST KrbTgt account is actually executed" "REMARK"
	Logging "     and replication of it is monitored through the environment for its duration" "REMARK"
	Logging " - For all scenarios, a real reset mode, which is mode 4 where the password reset of the chosen PROD KrbTgt account is actually executed" "REMARK"
	Logging "     and replication of it is monitored through the environment for its duration" "REMARK"
	Logging " - The creation of Test KrbTgt Accounts" "REMARK"
	Logging " - The cleanup of previously created Test KrbTgt Accounts" "REMARK"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging "-----" "REMARK"
	Logging "This PoSH script has the following behavior:" "REMARK"
	Logging "-----" "REMARK"
	Logging ""
	Logging " - Mode 1 is INFORMATIONAL MODE..." "REMARK-IMPORTANT"
	Logging "     * Safe to run at any time as there are not changes in any way!" "REMARK-IMPORTANT"
	Logging "     * Analyzes the environment and check for issues that may impact mode 2, 3 or 4!" "REMARK-IMPORTANT"
	Logging "     * For the targeted AD domain, it always retrieves all RWDCs, and all RODCs if applicable." "REMARK-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 2 is SIMULATION MODE USING A TEMPORARY CANARY OBJECT..." "REMARK-MORE-IMPORTANT"
	Logging "     * Also executes everything from mode 1!" "REMARK-MORE-IMPORTANT"
	Logging "     * Creates the temporary canary object and, depending on the scope, it will check if it exists in the AD database of the remote DC(s)" "REMARK-MORE-IMPORTANT"
	Logging "       (RWDC/RODC)." "REMARK-MORE-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RWDCs, the creation of the object is against the RWDC with the PDC Emulator FSMO followed" "REMARK-MORE-IMPORTANT"
	Logging "       by the 'replicate single object' operation against every available/reachable RWDC. This is a way to estimate the total replication" "REMARK-MORE-IMPORTANT"
	Logging "       time for mode 4." "REMARK-MORE-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RODCs, the creation of the object is against the RWDC the RODC is replicating from if" "REMARK-MORE-IMPORTANT"
	Logging "       available. If not available the creation is against the RWDC with the PDC Emulator FSMO. Either way it is followed by the 'replicate" "REMARK-MORE-IMPORTANT"
	Logging "       single object' operation against the RODC. This is a way to estimate the total replication time for mode 4." "REMARK-MORE-IMPORTANT"
	Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MORE-IMPORTANT"
	Logging "       the change made reached it or not." "REMARK-MORE-IMPORTANT"
	Logging "     * When performing the 'replicate single object' operation, it will always be for the full object, no matter if the remote DC is an RWDC" "REMARK-MORE-IMPORTANT"
	Logging "       or an RODC" "REMARK-MORE-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 3 is SIMULATION MODE USING TEST/BOGUS KRBTGT ACCOUNTS..." "REMARK-MORE-IMPORTANT"
	Logging "     * Also executes everything from mode 1!" "REMARK-MORE-IMPORTANT"
	Logging "     * Instead of using PROD/REAL KrbTgt Account(s), it uses pre-created TEST/BOGUS KrbTgt Accounts(s) for the password reset whatif!" "REMARK-MORE-IMPORTANT"
	Logging "       * For RWDCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_TEST' (All RWDCs) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "       * For RODCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' (RODC Specific) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "     * IT DOES NOT reset the password of the TEST/BOGUS KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" "REMARK-MORE-IMPORTANT"
	Logging "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" "REMARK-MORE-IMPORTANT"
	Logging "       RWDC." "REMARK-MORE-IMPORTANT"
	Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MORE-IMPORTANT"
	Logging "       the change made reached it or not." "REMARK-MORE-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 4 is SIMULATION MODE USING TEST/BOGUS KRBTGT ACCOUNTS..." "REMARK-MORE-IMPORTANT"
	Logging "     * Also executes everything from mode 1!" "REMARK-MORE-IMPORTANT"
	Logging "     * Instead of using PROD/REAL KrbTgt Account(s), it uses pre-created TEST/BOGUS KrbTgt Accounts(s) for the password reset!" "REMARK-MORE-IMPORTANT"
	Logging "       * For RWDCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_TEST' (All RWDCs) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "       * For RODCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' (RODC Specific) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "     * Resets the password of the TEST/BOGUS KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" "REMARK-MORE-IMPORTANT"
	Logging "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" "REMARK-MORE-IMPORTANT"
	Logging "       RWDC." "REMARK-MORE-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RWDCs, the password reset is done for the TEST/BOGUS KrbTgt Accounts(s) against the RWDC with" "REMARK-MORE-IMPORTANT"
	Logging "       the PDC Emulator FSMO followed by the 'replicate single object' operation against every available/reachable RWDC. No RODCs are involved" "REMARK-MORE-IMPORTANT"
	Logging "       as those do not use the KrbTgt account in use by the RWDCs and also do not store/cache its password. This is a way to estimate the" "REMARK-MORE-IMPORTANT"
	Logging "       total replication time for mode 6." "REMARK-MORE-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RODCs, the password reset is done for the TEST/BOGUS KrbTgt Accounts(s) against the RWDC the" "REMARK-MORE-IMPORTANT"
	Logging "       RODC is replicating from if available/reachable. If not available the password reset is against the RWDC with the PDC Emulator FSMO." "REMARK-MORE-IMPORTANT"
	Logging "       Either way it is followed by the 'replicate single object' operation against the RODC that uses that KrbTgt account. Only the RODC" "REMARK-MORE-IMPORTANT"
	Logging "       that uses the specific KrbTgt account is checked against to see if the change has reached it, but only if the RODC is available/reachable." "REMARK-MORE-IMPORTANT"
	Logging "       This is a way to estimate the total replication time for mode 6." "REMARK-MORE-IMPORTANT"
	Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MORE-IMPORTANT"
	Logging "       the change made reached it or not." "REMARK-MORE-IMPORTANT"
	Logging "     * When performing the 'replicate single object' operation, it will always be for the full object if the target DC is an RWDC. If the" "REMARK-MORE-IMPORTANT"
	Logging "       target DC is an RODC, then it will be for the partial object (secrets only)." "REMARK-MORE-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 5 is SIMULATION MODE USING PROD/REAL KRBTGT ACCOUNTS..." "REMARK-MORE-IMPORTANT"
	Logging "     * Also executes everything from mode 1!" "REMARK-MORE-IMPORTANT"
	Logging "     * Now it does use the PROD/REAL KrbTgt Accounts(s) for the password reset whatif!" "REMARK-MORE-IMPORTANT"
	Logging "       * For RWDCs it uses the PROD/REAL KrbTgt account 'krbtgt_TEST' (All RWDCs) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "       * For RODCs it uses the PROD/REAL KrbTgt account 'krbtgt_<Numeric Value>_TEST' (RODC Specific) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "     * IT DOES NOT reset the password of the PROD/REAL KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" "REMARK-MORE-IMPORTANT"
	Logging "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" "REMARK-MORE-IMPORTANT"
	Logging "       RWDC." "REMARK-MORE-IMPORTANT"
	Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MORE-IMPORTANT"
	Logging "       the change made reached it or not." "REMARK-MORE-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 6 is REAL RESET MODE USING PROD/REAL KRBTGT ACCOUNTS..." "REMARK-MOST-IMPORTANT"
	Logging "     * Also executes everything from mode 1!" "REMARK-MOST-IMPORTANT"
	Logging "     * Now it does use the PROD/REAL KrbTgt Accounts(s) for the password reset!" "REMARK-MOST-IMPORTANT"
	Logging "       * For RWDCs it uses the PROD/REAL KrbTgt account 'krbtgt' (All RWDCs)" "REMARK-MOST-IMPORTANT"
	Logging "       * For RODCs it uses the PROD/REAL KrbTgt account 'krbtgt_<Numeric Value>' (RODC Specific)" "REMARK-MOST-IMPORTANT"
	Logging "     * Resets the password of the PROD/REAL KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" "REMARK-MOST-IMPORTANT"
	Logging "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" "REMARK-MOST-IMPORTANT"
	Logging "       RWDC." "REMARK-MOST-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RWDCs, the password reset is done for the PROD/REAL KrbTgt Accounts(s) against the RWDC with" "REMARK-MOST-IMPORTANT"
	Logging "       the PDC Emulator FSMO followed by the 'replicate single object' operation against every available/reachable RWDC. No RODCs are involved" "REMARK-MOST-IMPORTANT"
	Logging "       as those do not use the KrbTgt account in use by the RWDCs and also do not store/cache its password. Once the replication is" "REMARK-MOST-IMPORTANT"
	Logging "       complete, the total impact time will be displayed." "REMARK-MOST-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RODCs, the password reset is done for the PROD/REAL KrbTgt Accounts(s) against the RWDC the" "REMARK-MOST-IMPORTANT"
	Logging "       RODC is replicating from if available/reachable. If not available the password reset is against the RWDC with the PDC Emulator FSMO." "REMARK-MOST-IMPORTANT"
	Logging "       Either way it is followed by the 'replicate single object' operation against the RODC that uses that KrbTgt account. Only the RODC" "REMARK-MOST-IMPORTANT"
	Logging "       that uses the specific KrbTgt account is checked against to see if the change has reached it, but only if the RODC is available/reachable." "REMARK-MOST-IMPORTANT"
	Logging "       Once the replication is complete, the total impact time will be displayed." "REMARK-MOST-IMPORTANT"
	Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MOST-IMPORTANT"
	Logging "       the change made reached it or not." "REMARK-MOST-IMPORTANT"
	Logging "     * When performing the 'replicate single object' operation, it will always be for the full object if the target DC is an RWDC. If the" "REMARK-MOST-IMPORTANT"
	Logging "       target DC is an RODC, then it will be for the partial object (secrets only)." "REMARK-MOST-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 8 is CREATE TEST KRBTGT ACCOUNTS MODE..." "REMARK-IMPORTANT"
	Logging "     * Creates so called TEST/BOGUS KrbTgt Account(s) to simulate the password reset with." "REMARK-IMPORTANT"
	Logging "     * Has no impact on the PROD/REAL KrbTgt Account(s)." "REMARK-IMPORTANT"
	Logging "     * For RWDCs it creates (in disabled state!) the TEST/BOGUS KrbTgt account 'krbtgt_TEST' and adds it to the AD group 'Denied RODC" "REMARK-IMPORTANT"
	Logging "       Password Replication Group'." "REMARK-IMPORTANT"
	Logging "     * For RODCs, if any in the AD domain, it creates (in disabled state!) the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' and" "REMARK-IMPORTANT"
	Logging "       adds it to the AD group 'Allowed RODC Password Replication Group'. To determine the specific KrbTgt account in use by an RODC, the" "REMARK-IMPORTANT"
	Logging "       script reads the attribute 'msDS-KrbTgtLink' on the RODC computer account." "REMARK-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 9 is CLEANUP TEST KRBTGT ACCOUNTS MODE..." "REMARK-IMPORTANT"
	Logging "     * Cleanup (delete) the so called TEST/BOGUS KrbTgt Account(s) that were used to simulate the password reset with." "REMARK-IMPORTANT"
	Logging "     * For RWDCs it deletes the TEST/BOGUS KrbTgt account 'krbtgt_TEST' if it exists." "REMARK-IMPORTANT"
	Logging "     * For RODCs, if any in the AD domain, it deletes the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' if it exists. To determine" "REMARK-IMPORTANT"
	Logging "       the specific KrbTgt account in use by an RODC, the script reads the attribute 'msDS-KrbTgtLink' on the RODC computer account." "REMARK-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - ADDITIONAL INFO - BEHAVIOR..." "REMARK-IMPORTANT"
	Logging "     * If the operating system attribute of an RODC computer account does not have a value, it is determined to be unknown (not a real RODC)," "REMARK-IMPORTANT"
	Logging "       and therefore something else. It could for example be a Riverbed appliance in 'RODC mode'." "REMARK-IMPORTANT"
	Logging "     * The only DC that knows what the real replication partner is of an RODC, is the RODC itself. Only the RODC manages a connection object" "REMARK-IMPORTANT"
	Logging "       (CO) that only exists in the AD database of the RODC and does not replicate out to other DCs as RODCs do not support outbound replication." "REMARK-IMPORTANT"
	Logging "       Therefore, assuming the RODC is available, the CO is looked up in the RODC AD database and from that CO, the 'source' server is" "REMARK-IMPORTANT"
	Logging "       determined. In case the RODC is not available or its 'source' server is not available, the RWDC with the PDC FSMO is used to reset" "REMARK-IMPORTANT"
	Logging "       the password of the krbtgt account in use by that RODC. If the RODC is available a check will be done against its database, and if" "REMARK-IMPORTANT"
	Logging "       not available the check is skipped." "REMARK-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - ADDITIONAL INFO - OBSERVED IMPACT..." "REMARK-IMPORTANT"
	Logging "     * Within an AD domain, all RWDCs use the account 'krbtgt' to encrypt/sign Kerberos tickets trusted by all RWDCs" "REMARK-IMPORTANT"
	Logging "     * Within an AD domain, every RODC uses its own 'krbtgt_<Numeric Value>' account to encrypt/sign Kerberos tickets trusted by only that RODC" "REMARK-IMPORTANT"
	Logging "       and that account is specified in the attribute 'msDS-KrbTgtLink' on the RODC computer account." "REMARK-IMPORTANT"
	Logging "     * RODCs are cryptographically isolated from other RODCs and the RWDCs, whether these are in the same AD site or not. Any Kerberos TGT/Service" "REMARK-IMPORTANT"
	Logging "       tickets issued by an RODC are only valid against that RODC and any resource that has a secure channel with that RODC. That's why when an" "REMARK-IMPORTANT"
	Logging "       RODC is compromised the scope of impact is only for that RODC and any resource using it, and not the complete AD domain." "REMARK-IMPORTANT"
	Logging "     * Kerberos PAC validation failures: Until the new KrbTgt account password is replicated to all DCs in the domain using that KrbTgt account," "REMARK-IMPORTANT"
	Logging "       applications which attempt KDC PAC validation may experience KDC PAC validation failures. This is possible  when a client in one AD site" "REMARK-IMPORTANT"
	Logging "       is accessing an application leveraging the Kerberos Authentication protocol that is in a different AD site. If that application is not a" "REMARK-IMPORTANT"
	Logging "       trusted part of the operating system, it may attempt to validate the PAC of the client's Kerberos Service Ticket against the KDC (DC) in" "REMARK-IMPORTANT"
	Logging "       its AD site. If the DC in its site does not yet have the new KrbTgt account password, this KDC PAC validation will fail. This will likely" "REMARK-IMPORTANT"
	Logging "       manifest itself to the client as authentication errors for that application. Once all DCs using a specific KrbTgt account have the new" "REMARK-IMPORTANT"
	Logging "       password some affected clients may recover gracefully and resume functioning normally. If not, rebooting the affected client(s) will" "REMARK-IMPORTANT"
	Logging "       resolve the issue. This issue may not occur if the replication of the new KrbTgt account password is timely and successful and no" "REMARK-IMPORTANT"
	Logging "       applications attempt KDC PAC validation against an out of sync DC during that time." "REMARK-IMPORTANT"
	Logging "     * Kerberos TGS request failures: Until the new KrbTgt account password is replicated to all DCs in the domain that use that KrbTgt account," "REMARK-IMPORTANT"
	Logging "       a client may experience Kerberos authentication failures. This is when a client in one AD site has obtained a Kerberos Ticket Granting" "REMARK-IMPORTANT"
	Logging "       Ticket (TGT) from an RWDC that has the new KrbTgt account password, but then subsequently attempts to obtain a Kerberos Service Ticket" "REMARK-IMPORTANT"
	Logging "       via a TGS request against an RWDC in a different AD site. If that RWDC does not also have the new KrbTgt account password, it will not" "REMARK-IMPORTANT"
	Logging "       be able to decrypt the client''s TGT, which will result in a TGS request failure.  This will manifest itself to the client as authenticate" "REMARK-IMPORTANT"
	Logging "       errors. However, it should be noted that this impact is very unlikely, because it is very unlikely that a client will attempt to obtain a" "REMARK-IMPORTANT"
	Logging "       service ticket from a different RWDC than the one from which their TGT was obtained, especially during the relatively short impact" "REMARK-IMPORTANT"
	Logging "       duration of Mode 4." "REMARK-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging "    >>> It is highly recommended to use the following order of execution: <<<" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 1 - Informational Mode (No Changes At All)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 8 - Create TEST KrbTgt Accounts" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 2 - Simulation Mode (Temporary Canary Object Created, No Password Reset!)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 3 - Simulation Mode - Use KrbTgt TEST/BOGUS Accounts (No Password Reset, Check Only!)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 4 - Real Reset Mode - Use KrbTgt TEST/BOGUS Accounts (Password Will Be Reset Once!)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 5 - Simulation Mode - Use KrbTgt PROD/REAL Accounts (No Password Reset, Check Only!)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 6 - Real Reset Mode - Use KrbTgt PROD/REAL Accounts (Password Will Be Reset Once!)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 9 - Cleanup TEST KrbTgt Accounts (Could be skipped to reuse accounts the next time!)" "REMARK-MORE-IMPORTANT"
	Logging ""
}

### Loading Required PowerShell Modules
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "LOADING REQUIRED POWERSHELL MODULES..." "HEADER"
Logging ""

# Try To Load The Required PowerShell Module. Abort Script If Not Available
"ActiveDirectory","GroupPolicy" | ForEach-Object{
	$poshModule = $null
	$poshModule = loadPoSHModules $_
	If ($poshModule -eq "NotAvailable") {
		Logging ""
		EXIT
	}
	Logging ""
}

### Display And Selecting The Mode Of Operation
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "SELECT THE MODE OF OPERATION..." "HEADER"
Logging ""
Logging "Which mode of operation do you want to execute?"
Logging ""
Logging " - 1 - Informational Mode (No Changes At All)"
Logging ""
Logging " - 2 - Simulation Mode | Temporary Canary Object Created To Test Replication Convergence!"
Logging ""
Logging " - 3 - Simulation Mode | Use KrbTgt TEST/BOGUS Accounts - No Password Reset/WhatIf Mode!"
Logging ""
Logging " - 4 - Real Reset Mode | Use KrbTgt TEST/BOGUS Accounts - Password Will Be Reset Once!"
Logging ""
Logging " - 5 - Simulation Mode | Use KrbTgt PROD/REAL Accounts - No Password Reset/WhatIf Mode!"
Logging ""
Logging " - 6 - Real Reset Mode | Use KrbTgt PROD/REAL Accounts - Password Will Be Reset Once!"
Logging ""
Logging ""
Logging " - 8 - Create TEST KrbTgt Accounts"
Logging " - 9 - Cleanup TEST KrbTgt Accounts"
Logging ""
Logging ""
Logging " - 0 - Exit Script"
Logging ""
Logging "Please specify the mode of operation: " "ACTION-NO-NEW-LINE"
$modeOfOperationNr = Read-Host
Logging ""

# If Anything Else Than The Allowed/Available Non-Zero Modes, Abort The Script
If (($modeOfOperationNr -ne 1 -And $modeOfOperationNr -ne 2 -And $modeOfOperationNr -ne 3 -And $modeOfOperationNr -ne 4 -And $modeOfOperationNr -ne 5 -And $modeOfOperationNr -ne 6 -And $modeOfOperationNr -ne 8 -And $modeOfOperationNr -ne 9) -Or $modeOfOperationNr -notmatch "^[\d\.]+$") {
	Logging "  --> Chosen mode: Mode 0 - Exit Script..." "REMARK"
	Logging ""
	
	EXIT
}

# If Mode 1
If ($modeOfOperationNr -eq 1) {
	Logging "  --> Chosen Mode: Mode 1 - Informational Mode (No Changes At All)..." "REMARK"
	Logging ""
}

# If Mode 2
If ($modeOfOperationNr -eq 2) {
	Logging "  --> Chosen Mode: Mode 2 - Simulation Mode | Temporary Canary Object Created To Test Replication Convergence..." "REMARK"
	Logging ""
}

# If Mode 3
If ($modeOfOperationNr -eq 3) {
	Logging "  --> Chosen Mode: Mode 3 - Simulation Mode | Use KrbTgt TEST/BOGUS Accounts - No Password Reset/WhatIf Mode!..." "REMARK"
	Logging ""
}

# If Mode 4
If ($modeOfOperationNr -eq 4) {
	Logging "  --> Chosen Mode: Mode 4 - Real Reset Mode | Use KrbTgt TEST/BOGUS Accounts - Password Will Be Reset Once!..." "REMARK"
	Logging ""
}

# If Mode 5
If ($modeOfOperationNr -eq 5) {
	Logging "  --> Chosen Mode: Mode 5 - Simulation Mode | Use KrbTgt PROD/REAL Accounts - No Password Reset/WhatIf Mode!..." "REMARK"
	Logging ""
}

# If Mode 6
If ($modeOfOperationNr -eq 6) {
	Logging "  --> Chosen Mode: Mode 6 - Real Reset Mode | Use KrbTgt PROD/REAL Accounts - Password Will Be Reset Once!..." "REMARK"
	Logging ""
}

# If Mode 8
If ($modeOfOperationNr -eq 8) {
	Logging "  --> Chosen Mode: Mode 8 - Create TEST KrbTgt Accounts..." "REMARK"
	Logging ""
}

# If Mode 9
If ($modeOfOperationNr -eq 9) {
	Logging "  --> Chosen Mode: Mode 9 - Cleanup TEST KrbTgt Accounts..." "REMARK"
	Logging ""
}

### All Modes - Selecting The Target AD Forest
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "SPECIFY THE TARGET AD FOREST..." "HEADER"
Logging ""

# Retrieve The AD Domain And AD Forest Of The Computer Where The Script Is Executed
$currentADDomainOfLocalComputer = $null
$currentADDomainOfLocalComputer = $(Get-WmiObject -Class Win32_ComputerSystem).Domain
$currentADForestOfLocalComputer = $null
$currentADForestOfLocalComputer = (Get-ADDomain $currentADDomainOfLocalComputer).Forest

# Ask Which AD Forest To Target
Logging "For the AD forest to be targeted, please provide the FQDN or press [ENTER] for the current AD forest: " "ACTION-NO-NEW-LINE"
$targetedADforestFQDN = $null
$targetedADforestFQDN = Read-Host

# If No FQDN Of An AD Domain Is Specified, Then Use The AD Domain Of The Local Computer
If ($targetedADforestFQDN -eq "" -Or $null -eq $targetedADforestFQDN) {
	$targetedADforestFQDN = $currentADForestOfLocalComputer
}
Logging ""
Logging "  --> Selected AD Forest: '$targetedADforestFQDN'..." "REMARK"

# Validate The Specified AD Forest And Check A (Forest) Trust Is In Place, If Applicable
$adForestValidity = $false

# Test To See If The Forest FQDN Is Resolvable At All
Try {
	[System.Net.Dns]::gethostentry($targetedADforestFQDN) | Out-Null
	$adForestValidity = $true
} Catch {
	$adForestValidity = $false
}
If ($targetedADforestFQDN -eq $currentADForestOfLocalComputer) {
	$localADforest = $true
	$adForestLocation = "Local"
} Else {
	$localADforest = $false
	$adForestLocation = "Remote"
}
Logging ""
Logging "Checking Resolvability of the specified $adForestLocation AD forest '$targetedADforestFQDN' through DNS..."
If ($adForestValidity -eq $true) {
	# If The AD Forest Is Resolvable And Therefore Exists, Continue
	Logging "" "SUCCESS"
	Logging "The specified $adForestLocation AD forest '$targetedADforestFQDN' is resolvable through DNS!" "SUCCESS"
	Logging "" "SUCCESS"
	Logging "Continuing Script..." "SUCCESS"
	Logging "" "SUCCESS"
} Else {
	# If The AD Forest Is Not Resolvable And Therefore Does Not Exists, Abort
	Logging "" "ERROR"
	Logging "The specified $adForestLocation AD forest '$targetedADforestFQDN' IS NOT resolvable through DNS!" "ERROR"
	Logging "" "ERROR"
	Logging "Please re-run the script and provide the FQDN of an AD forest that is resolvable through DNS..." "ERROR"
	Logging "" "ERROR"
	Logging "Aborting Script..." "ERROR"
	Logging "" "ERROR"

	EXIT
}

# Validate The Specified AD Forest Is Accessible. If it is the local AD forest then it is accessible. If it is a remote AD forest and a (forest) trust is in place, then it is accessible. If it is a remote AD forest and a (forest) trust is NOT in place, then it is NOT accessible.
$adForestAccessibility = $false
# Test To See If The AD Forest Is Accessible
Try {
	# Retrieve The Nearest RWDC In The Forest Root AD Domain
	$nearestRWDCInForestRootADDomain = $null
	$nearestRWDCInForestRootADDomain = (Get-ADDomainController -DomainName $targetedADforestFQDN -Discover).HostName[0]
	
	# Retrieve Information About The AD Forest
	$thisADForest = $null
	$thisADForest = Get-ADForest -Identity $targetedADforestFQDN -Server $nearestRWDCInForestRootADDomain
	$adForestAccessibility = $true
} Catch {
	$adForestAccessibility = $false
}
Logging ""
Logging "Checking Accessibility of the specified AD forest '$targetedADforestFQDN' By Trying To Retrieve AD Forest Data..."
If ($adForestAccessibility -eq $true) {
	# If The AD Forest Is Accessible, Continue
	Logging "" "SUCCESS"
	Logging "The specified AD forest '$targetedADforestFQDN' is accessible!" "SUCCESS"
	Logging "" "SUCCESS"
	Logging "Continuing Script..." "SUCCESS"
	Logging "" "SUCCESS"
} Else {
	# If The AD Forest Is NOT Accessible, Ask For Credentials
	Logging "" "WARNING"
	Logging "The specified AD forest '$targetedADforestFQDN' IS NOT accessible!" "WARNING"
	Logging "" "WARNING"
	Logging "Custom credentials are needed..." "WARNING"
	Logging "" "ERROR"
	Logging "Continuing Script And Asking For Credentials..." "WARNING"
	Logging "" "WARNING"
	Logging ""
	
	# Ask For The Remote Credentials
	Logging "Please provide an account (<DOMAIN FQDN>\<ACCOUNT>) that is a member of the 'Administrators' group in every AD domain of the specified AD forest: " "ACTION-NO-NEW-LINE"
	$adminUserAccountRemoteForest = $null
	$adminUserAccountRemoteForest = Read-Host
	
	# Ask For The Admin User Account
	If ($adminUserAccountRemoteForest -eq "" -Or $null -eq $adminUserAccountRemoteForest) {
		Logging ""
		Logging "Please provide an account (<DOMAIN FQDN>\<ACCOUNT>) that is a member of the 'Administrators' group in every AD domain of the specified AD forest: " "ACTION-NO-NEW-LINE"
		$adminUserAccountRemoteForest = $null
		$adminUserAccountRemoteForest = Read-Host
	}
	
	# Ask For The Corresponding Password
	Logging "Please provide the corresponding password of that admin account: " "ACTION-NO-NEW-LINE"
	$adminUserPasswordRemoteForest = $null
	[System.Security.SecureString]$adminUserPasswordRemoteForest = Read-Host -AsSecureString
	If ($adminUserPasswordRemoteForest -eq "" -Or $null -eq $adminUserPasswordRemoteForest) {
		Logging ""
		Logging "Please provide the corresponding password of that admin account: " "ACTION-NO-NEW-LINE"
		$adminUserPasswordRemoteForest = $null
		[System.Security.SecureString]$adminUserPasswordRemoteForest = Read-Host -AsSecureString
	}
	[string]$adminUserPasswordRemoteForest = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminUserPasswordRemoteForest))
	$secureAdminUserPasswordRemoteForest = ConvertTo-SecureString $adminUserPasswordRemoteForest -AsPlainText -Force
	$adminCrds = $null
	$adminCrds = New-Object System.Management.Automation.PSCredential $adminUserAccountRemoteForest, $secureAdminUserPasswordRemoteForest
	
	# Test To See If The AD Forest Is Accessible
	Try {
		# Retrieve Information About The AD Forest
		$thisADForest = $null
		$thisADForest = Get-ADForest -Identity $targetedADforestFQDN -Server $nearestRWDCInForestRootADDomain -Credential $adminCrds
		$adForestAccessibility = $true
	} Catch {
		$adForestAccessibility = $false
	}
	Logging ""
	Logging "Checking Accessibility of the specified AD forest '$targetedADforestFQDN' By Trying To Retrieve AD Forest Data..."
	If ($adForestAccessibility -eq $true) {
		# If The AD Forest Is Accessible, Continue
		Logging "" "SUCCESS"
		Logging "The specified AD forest '$targetedADforestFQDN' is accessible!" "SUCCESS"
		Logging "" "SUCCESS"
		Logging "Continuing Script..." "SUCCESS"
		Logging "" "SUCCESS"
	} Else {
		# If The AD Forest Is NOT Accessible, Ask For Credentials
		Logging "" "ERROR"
		Logging "The specified AD forest '$targetedADforestFQDN' IS NOT accessible!" "ERROR"
		Logging "" "ERROR"
		Logging "Please re-run the script and provide the correct credentials to connect to the remote AD forest..." "ERROR"
		Logging "" "ERROR"
		Logging "Aborting Script..." "ERROR"
		Logging "" "ERROR"
	
		EXIT
	}
}

### All Modes - Selecting The Target AD Domain
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "SELECT THE TARGET AD DOMAIN..." "HEADER"
Logging ""

# Retrieve Root AD Domain Of The AD Forest
$rootADDomainInADForest = $null
$rootADDomainInADForest = $thisADForest.RootDomain

# Retrieve All The AD Domains In The AD Forest
$listOfADDomainsInADForest = $null
$listOfADDomainsInADForest = $thisADForest.Domains

# Retrieve The DN Of The Partitions Container In The AD Forest
$partitionsContainerDN = $null
$partitionsContainerDN = $thisADForest.PartitionsContainer

# Retrieve The Mode/Functional Level Of The AD Forest
$adForestMode = $null
$adForestMode = $thisADForest.ForestMode

# Define An Empty List/Table That Will Contain All AD Domains In The AD Forest And Related Information
$tableOfADDomainsInADForest = @()
Logging "Forest Mode/Level...: $adForestMode"

# Set The Counter To Zero
$nrOfDomainsInForest = 0

# Execute For All AD Domains In The AD Forest
$listOfADDomainsInADForest | ForEach-Object{
	# Increase The Counter
	$nrOfDomainsInForest += 1
	
	# Get The FQDN Of The AD Domain
	$domainFQDN = $null
	$domainFQDN = $_
	
	# Retrieve The Nearest RWDC In The AD Domain
	$nearestRWDCInADDomain = $null
	$nearestRWDCInADDomain = (Get-ADDomainController -DomainName $domainFQDN -Discover).HostName[0]
	
	# Retrieve The Object Of The AD Domain From AD
	$domainObj = $null
	Try {
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			$domainObj = Get-ADDomain $domainFQDN -Server $nearestRWDCInADDomain
		}
		If ($localADforest -eq $false -And $adminCrds) {
			$domainObj = Get-ADDomain $domainFQDN -Server $nearestRWDCInADDomain -Credential $adminCrds
		}
	} Catch {
		$domainObj = $null
	}
	
	# Define The Columns For This AD Domain To Be Filled In
	$tableOfADDomainsInADForestObj = "" | Select-Object Name,DomainSID,IsRootDomain,DomainMode,IsCurrentDomain,IsAvailable,PDCFsmoOwner,NearestRWDC
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.Name = $null
	$tableOfADDomainsInADForestObj.Name = $domainFQDN
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.DomainSID = $null
	$tableOfADDomainsInADForestObj.DomainSID = $domainObj.DomainSID.Value
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.IsRootDomain = $null
	If ($rootADDomainInADForest -eq $domainFQDN) {
		$tableOfADDomainsInADForestObj.IsRootDomain = "TRUE"
	} Else {
		$tableOfADDomainsInADForestObj.IsRootDomain = "FALSE"
	}
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.DomainMode = $null
	If ($domainObj) {
		$tableOfADDomainsInADForestObj.DomainMode = $domainObj.DomainMode
	} Else {
		$tableOfADDomainsInADForestObj.DomainMode = "AD Domain Is Not Available"
	}
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.IsCurrentDomain = $null
	If ($domainFQDN -eq $currentADDomainOfLocalComputer) {
		$tableOfADDomainsInADForestObj.IsCurrentDomain = "TRUE"
	} Else {
		$tableOfADDomainsInADForestObj.IsCurrentDomain = "FALSE"
	}
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.IsAvailable = $null
	If ($domainObj) {
		$tableOfADDomainsInADForestObj.IsAvailable = "TRUE"
	} Else {
		$tableOfADDomainsInADForestObj.IsAvailable = "FALSE"
	}
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.PDCFsmoOwner = $null
	If ($domainObj) {
		$tableOfADDomainsInADForestObj.PDCFsmoOwner = $domainObj.PDCEmulator
	} Else {
		$tableOfADDomainsInADForestObj.PDCFsmoOwner = "AD Domain Is Not Available"
	}
	
	# Set The Corresponding Value Of The AD Domain In The Correct Column Of The Table
	$tableOfADDomainsInADForestObj.NearestRWDC = $null
	If ($domainObj) {
		$tableOfADDomainsInADForestObj.NearestRWDC = $nearestRWDCInADDomain
	} Else {
		$tableOfADDomainsInADForestObj.NearestRWDC = "AD Domain Is Not Available"
	}
	
	# Add The Row For The AD Domain To The Table
	$tableOfADDomainsInADForest += $tableOfADDomainsInADForestObj
}

# Display The List And Amount Of AD Domains
Logging ""
Logging "List Of AD Domains In AD Forest '$rootADDomainInADForest'..."
Logging ""
Logging "$($tableOfADDomainsInADForest | Format-Table | Out-String)"
Logging "  --> Found [$nrOfDomainsInForest] AD Domain(s) in the AD forest '$rootADDomainInADForest'..." "REMARK"
Logging ""

# Ask Which AD Domain To Target From The Previously Presented List
Logging "For the AD domain to be targeted, please provide the FQDN or press [ENTER] for the current AD domain: " "ACTION-NO-NEW-LINE"
$targetedADdomainFQDN = $null
$targetedADdomainFQDN = Read-Host

# If No FQDN Of An AD Domain Is Specified, Then Use The AD Domain Of The Local Computer
If ($targetedADdomainFQDN -eq "" -Or $null -eq $targetedADdomainFQDN) {
	$targetedADdomainFQDN = $currentADDomainOfLocalComputer
}
Logging ""
Logging "  --> Selected AD Domain: '$targetedADdomainFQDN'..." "REMARK"

# Validate The Chosen AD Domain Against The List Of Available AD Domains To See If It Does Exist In The AD Forest
$adDomainValidity = $false
$listOfADDomainsInADForest | ForEach-Object{
	$domainFQDN = $null
	$domainFQDN = $_
	If ($domainFQDN -eq $targetedADdomainFQDN) {
		$adDomainValidity = $true
	}
}
Logging ""
Logging "Checking existence of the specified AD domain '$targetedADdomainFQDN' in the AD forest '$rootADDomainInADForest'..."
If ($adDomainValidity -eq $true) {
	# If The AD Domain Is Valid And Therefore Exists, Continue
	Logging "" "SUCCESS"
	Logging "The specified AD domain '$targetedADdomainFQDN' exists in the AD forest '$rootADDomainInADForest'!" "SUCCESS"
	Logging "" "SUCCESS"
	Logging "Continuing Script..." "SUCCESS"
	Logging "" "SUCCESS"
} Else {
	# If The AD Domain Is Not Valid And Therefore Does Not Exist, Abort
	Logging "" "ERROR"
	Logging "The specified AD domain '$targetedADdomainFQDN' DOES NOT exist in the AD forest '$rootADDomainInADForest'!" "ERROR"
	Logging "" "ERROR"
	Logging "Please re-run the script and provide the FQDN of an AD domain that does exist in the AD forest '$rootADDomainInADForest'..." "ERROR"
	Logging "" "ERROR"
	Logging "Aborting Script..." "ERROR"
	Logging "" "ERROR"

	EXIT
}

### All Modes - Testing If Required Permissions Are Available (Domain/Enterprise Admin Credentials)
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "TESTING IF REQUIRED PERMISSIONS ARE AVAILABLE (DOMAIN/ENTERPRISE ADMINS OR ADMINISTRATORS CREDENTIALS)..." "HEADER"
Logging ""

# If The AD Forest Is Local, Then We Can Test For Role Membership Of Either Domain Admins Or Enterprise Admins.
If ($localADforest -eq $true) {
	# Validate The User Account Running This Script Is A Member Of The Domain Admins Group Of The Targeted AD Domain
	$targetedDomainObjectSID = ($tableOfADDomainsInADForest | Where-Object{$_.Name -eq $targetedADdomainFQDN}).DomainSID
	$domainAdminRID = "512"
	$domainAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($targetedDomainObjectSID + "-" + $domainAdminRID)).Translate([System.Security.Principal.NTAccount]).Value
	$userIsDomainAdmin = $null
	$userIsDomainAdmin = testAdminRole $domainAdminRole
	If (!$userIsDomainAdmin) {
		# The User Account Running This Script Has Been Validated Not Being A Member Of The Domain Admins Group Of The Targeted AD Domain
		# Validate The User Account Running This Script Is A Member Of The Enterprise Admins Group Of The AD Forest
		$forestRootDomainObjectSID = ($tableOfADDomainsInADForest | Where-Object{$_.IsRootDomain -eq "TRUE"}).DomainSID
		$enterpriseAdminRID = "519"
		$enterpriseAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($forestRootDomainObjectSID + "-" + $enterpriseAdminRID)).Translate([System.Security.Principal.NTAccount]).Value
		$userIsEnterpriseAdmin = $null
		$userIsEnterpriseAdmin = testAdminRole $enterpriseAdminRole
		If (!$userIsEnterpriseAdmin) {
			# The User Account Running This Script Has Been Validated Not Being A Member Of The Enterprise Admins Group Of The AD Forest
			Logging "The user account '$adRunningUserAccount' IS NOT running with Domain/Enterprise Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "ERROR"
			Logging "The user account '$adRunningUserAccount' IS NOT a member of '$domainAdminRole' and NOT a member of '$enterpriseAdminRole'!..." "ERROR"
			Logging "" "ERROR"
			Logging "For this script to run successfully, Domain/Enterprise Administrator equivalent permissions are required..." "ERROR"
			Logging "" "ERROR"
			Logging "Aborting Script..." "ERROR"
			Logging "" "ERROR"
			
			EXIT
		} Else {
			# The User Account Running This Script Has Been Validated To Be A Member Of The Enterprise Admins Group Of The AD Forest
			Logging "The user account '$adRunningUserAccount' is running with Enterprise Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
			Logging "The user account '$adRunningUserAccount' is a member of '$enterpriseAdminRole'!..." "SUCCESS"
			Logging "" "SUCCESS"
			Logging "Continuing Script..." "SUCCESS"
			Logging "" "SUCCESS"
		}
	} Else {
		# The User Account Running This Script Has Been Validated To Be A Member Of The Domain Admins Group Of The Targeted AD Domain
		Logging "The user account '$adRunningUserAccount' is running with Domain Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
		Logging "The user account '$adRunningUserAccount' is a member of '$domainAdminRole'!..." "SUCCESS"
		Logging "" "SUCCESS"
		Logging "Continuing Script..." "SUCCESS"
		Logging "" "SUCCESS"
	}
}

# If The AD Forest Is Remote Then We Cannot Test For Role Membership Of The Administrators Group. We Will Test Permissions By Copying The Value Of The Description Field Into The Display Name Field And Clearing It Again
If ($localADforest -eq $false -And !$adminCrds) {
	Try {
		Set-ADUser -Identity KRBTGT -Title $((Get-ADUser -Identity KRBTGT -Properties Description -Server $targetedADdomainFQDN).Description) -Server $targetedADdomainFQDN
		Set-ADUser -Identity KRBTGT -Clear Title -Server $targetedADdomainFQDN
		Logging "The user account '$adRunningUserAccount' is running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
		Logging "" "SUCCESS"
		Logging "Continuing Script..." "SUCCESS"
		Logging "" "SUCCESS"
	} Catch {
		Logging "The user account '$adRunningUserAccount' IS NOT running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "ERROR"
		Logging "" "ERROR"
		Logging "For this script to run successfully, Administrators equivalent permissions are required in the AD Domain '$targetedADdomainFQDN'..." "ERROR"
		Logging "" "ERROR"
		Logging "Aborting Script..." "ERROR"
		Logging "" "ERROR"
		
		EXIT
	}
}
If ($localADforest -eq $false -And $adminCrds) {
	Try {
		Set-ADUser -Identity KRBTGT -Title $((Get-ADUser -Identity KRBTGT -Properties Description -Server $targetedADdomainFQDN -Credential $adminCrds).Description) -Server $targetedADdomainFQDN -Credential $adminCrds
		Set-ADUser -Identity KRBTGT -Clear Title -Server $targetedADdomainFQDN -Credential $adminCrds
		Logging "The user account '$adminUserAccountRemoteForest' is running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
		Logging "" "SUCCESS"
		Logging "Continuing Script..." "SUCCESS"
		Logging "" "SUCCESS"
	} Catch {
		Logging "The user account '$adminUserAccountRemoteForest' IS NOT running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "ERROR"
		Logging "" "ERROR"
		Logging "For this script to run successfully, Administrators equivalent permissions are required in the AD Domain '$targetedADdomainFQDN'..." "ERROR"
		Logging "" "ERROR"
		Logging "Aborting Script..." "ERROR"
		Logging "" "ERROR"
		
		EXIT
	}
}

### All Modes - Gathering AD Domain Information
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "GATHERING TARGETED AD DOMAIN INFORMATION..." "HEADER"
Logging ""

# Target AD Domain Data
$targetedADdomainData = $null
$targetedADdomainData = $tableOfADDomainsInADForest | Where-Object{$_.Name -eq $targetedADdomainFQDN}

# Retrieve The HostName Of Nearest RWDC In The AD Domain
$targetedADdomainNearestRWDCFQDN = $null
$targetedADdomainNearestRWDCFQDN = $targetedADdomainData.NearestRWDC

# Retrieve Information For The AD Domain That Was Chosen
$thisADDomain = $null
Try {
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		$thisADDomain = Get-ADDomain $targetedADdomainFQDN -Server $targetedADdomainNearestRWDCFQDN
	}
	If ($localADforest -eq $false -And $adminCrds) {
		$thisADDomain = Get-ADDomain $targetedADdomainFQDN -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
	}
} Catch {
	$thisADDomain = $null
}
If ($thisADDomain) {
	# Retrieve The Domain SID
	$targetedADdomainDomainSID = $null
	$targetedADdomainDomainSID = $thisADDomain.DomainSID.Value

	# Retrieve The HostName Of RWDC In The AD Domain That Hosts The PDC FSMO Role
	$targetedADdomainRWDCFQDNWithPDCFSMOFQDN = $null
	$targetedADdomainRWDCFQDNWithPDCFSMOFQDN = $thisADDomain.PDCEmulator

	# Retrieve The DSA DN Of RWDC In The AD Domain That Hosts The PDC FSMO Role
	$targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = (Get-ADDomainController $targetedADdomainRWDCFQDNWithPDCFSMOFQDN -Server $targetedADdomainNearestRWDCFQDN).NTDSSettingsObjectDN
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$targetedADdomainRWDCFQDNWithPDCFSMOFQDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = (Get-ADDomainController $targetedADdomainRWDCFQDNWithPDCFSMOFQDN -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds).NTDSSettingsObjectDN
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$targetedADdomainRWDCFQDNWithPDCFSMOFQDN' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	
	# Retrieve Domain Functional Level/Mode Of The AD Domain
	$targetedADdomainDomainFunctionalMode = $null
	$targetedADdomainDomainFunctionalMode = $thisADDomain.DomainMode
	$targetedADdomainDomainFunctionalModeLevel = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$targetedADdomainDomainFunctionalModeLevel = (Get-ADObject -LDAPFilter "(&(objectClass=crossRef)(nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))))" -SearchBase $partitionsContainerDN -Properties "msDS-Behavior-Version" -Server $targetedADdomainNearestRWDCFQDN)."msDS-Behavior-Version"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Cross Reference Object With 'nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$targetedADdomainDomainFunctionalModeLevel = (Get-ADObject -LDAPFilter "(&(objectClass=crossRef)(nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))))" -SearchBase $partitionsContainerDN -Properties "msDS-Behavior-Version" -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds)."msDS-Behavior-Version"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Cross Reference Object With 'nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	
	# Determine The Max Tgt Lifetime In Hours And The Max Clock Skew In Minutes
	Try {
		$gpoObjXML = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			[xml]$gpoObjXML = Get-GPOReport -Domain $targetedADdomainFQDN -Guid '{31B2F340-016D-11D2-945F-00C04FB984F9}' -ReportType Xml -Server $targetedADdomainNearestRWDCFQDN
		}
		If ($localADforest -eq $false -And $adminCrds) {
			#$targetedServerSession = New-PSSession -ComputerName $targetedADdomainRWDCFQDNWithPDCFSMOFQDN -Credential $adminCrds -ErrorAction SilentlyContinue
			$targetedServerSession = New-PSSession -ComputerName $targetedADdomainNearestRWDCFQDN -Credential $adminCrds -ErrorAction SilentlyContinue
			[xml]$gpoObjXML = Invoke-Command -Session $targetedServerSession -ArgumentList $targetedADdomainFQDN,$targetedADdomainNearestRWDCFQDN -ScriptBlock {
				Param (
					$targetedADdomainFQDN,
					$targetedADdomainNearestRWDCFQDN
				)
				[xml]$gpoObjXML = Get-GPOReport -Domain $targetedADdomainFQDN -Guid '{31B2F340-016D-11D2-945F-00C04FB984F9}' -ReportType Xml -Server $targetedADdomainNearestRWDCFQDN
				Return $gpoObjXML
			}
			Remove-PSSession $targetedServerSession
		}
		$targetedADdomainMaxTgtLifetimeHrs = $null
		$targetedADdomainMaxTgtLifetimeHrs = (($gpoObjXML.gpo.Computer.ExtensionData | Where-Object{$_.name -eq 'Security'}).Extension.ChildNodes | Where-Object{$_.Name -eq 'MaxTicketAge'}).SettingNumber
		$targetedADdomainMaxClockSkewMins = $null
		$targetedADdomainMaxClockSkewMins = (($gpoObjXML.gpo.Computer.ExtensionData | Where-Object{$_.name -eq 'Security'}).Extension.ChildNodes | Where-Object{$_.Name -eq 'MaxClockSkew'}).SettingNumber
		$sourceInfoFrom = "Default Domain GPO"
	} Catch {
		Logging "Could not lookup 'MaxTicketAge' (default 10 hours) and 'MaxClockSkew' (default 5 minutes) from the 'Default Domain Policy' GPO, so default values will be assumed." "WARNING"
		Logging ""
		$targetedADdomainMaxTgtLifetimeHrs = 10
		$targetedADdomainMaxClockSkewMins = 5
		$sourceInfoFrom = "Assumed"
	}
} Else {
	$targetedADdomainRWDCFQDNWithPDCFSMOFQDN = "Unavailable"
	$targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = "Unavailable"
	$targetedADdomainDomainFunctionalMode = "Unavailable"
	$targetedADdomainDomainFunctionalModeLevel = "Unavailable"
	$targetedADdomainMaxTgtLifetimeHrs = "Unavailable"
	$targetedADdomainMaxClockSkewMins = "Unavailable"
	$sourceInfoFrom = "Unavailable"
}

# Present The Information
Logging "Domain FQDN...........................: '$targetedADdomainFQDN'"
Logging "Domain Functional Mode................: '$targetedADdomainDomainFunctionalMode'"
Logging "Domain Functional Mode Level..........: '$targetedADdomainDomainFunctionalModeLevel'"
Logging "FQDN RWDC With PDC FSMO...............: '$targetedADdomainRWDCFQDNWithPDCFSMOFQDN'"
Logging "DSA RWDC With PDC FSMO................: '$targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN'"
Logging "Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
Logging "Max Clock Skew (Minutes)..............: '$targetedADdomainMaxClockSkewMins'"
Logging "TGT Lifetime/Clock Skew Sourced From..: '$sourceInfoFrom'"
Logging ""
Logging "Checking Domain Functional Mode of targeted AD domain '$targetedADdomainFQDN' is high enough..."

# Check If The Domain Functional Level/Mode Of The AD Domain Is High Enough To Continue
If ($targetedADdomainDomainFunctionalModeLevel -ne "Unavailable" -And $targetedADdomainDomainFunctionalModeLevel -ge 3) {
	# If The Domain Functional Level/Mode Of The AD Domain Is Equal Or Higher Than Windows Server 2008 (3), Then Continue
	Logging "" "SUCCESS"
	Logging "The specified AD domain '$targetedADdomainFQDN' has a Domain Functional Mode of 'Windows2008Domain (3)' or higher!..." "SUCCESS"
	Logging "" "SUCCESS"
	Logging "Continuing Script..." "SUCCESS"
	Logging "" "SUCCESS"
} Else {
	# If The Domain Functional Level/Mode Of The AD Domain Is Lower Than Windows Server 2008 (3) Or It Cannot Be Determined, Then Abort
	Logging "" "ERROR"
	Logging "It CANNOT be determined the specified AD domain '$targetedADdomainFQDN' has a Domain Functional Mode of 'Windows2008Domain (3)' or higher!..." "ERROR"
	Logging "" "ERROR"
	Logging "AD domains with Windows Server 2000/2003 DCs CANNOT do KDC PAC validation using the previous (N-1) KrbTgt Account Password" "ERROR"
	Logging "like Windows Server 2008 and higher DCs are able to. Windows Server 2000/2003 DCs will only attempt it with the current (N)" "ERROR"
	Logging "KrbTgt Account Password. That means that in the subset of KRB AP exchanges where KDC PAC validation is performed," "ERROR"
	Logging "authentication issues could be experience because the target server gets a PAC validation error when asking the KDC (DC)" "ERROR"
	Logging "to validate the KDC signature of the PAC that is inside the service ticket that was presented by the client to the server." "ERROR"
	Logging "This problem would potentially persist for the lifetime of the service ticket(s). And by the way... for Windows Server" "ERROR"
	Logging "2000/2003 support already ended years ago. Time to upgrade to higher version dude!" "ERROR"
	Logging "Be aware though, when increasing the DFL from Windows Server 2003 to any higher level, the password of the KrbTgt Account" "ERROR"
	Logging "will be reset automatically due to the introduction of AES encryption for Kerberos and the requirement to regenerate new" "ERROR"
	Logging "keys for DES, RC4, AES128, AES256!" "ERROR"
	Logging "" "ERROR"
	Logging "Aborting Script..." "ERROR"
	Logging "" "ERROR"

	EXIT
}

### All Modes - Gathering Domain Controller Information And Testing Connectivity
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "GATHERING DOMAIN CONTROLLER INFORMATION AND TESTING CONNECTIVITY..." "HEADER"
Logging ""

# Define An Empty List/Table That Will Contain All DCs In The AD Domain And Related Information
$tableOfDCsInADDomain = @()

# Retrieve All The RWDCs In The AD Domain
$listOfRWDCsInADDomain = $null
$listOfRWDCsInADDomain = $thisADDomain.ReplicaDirectoryServers

# Set The Counters To Zero
$nrOfRWDCs = 0
$nrOfReachableRWDCs = 0
$nrOfUnReachableRWDCs = 0

# Execute For All RWDCs In The AD Domain If Any
If ($listOfRWDCsInADDomain) {
	$listOfRWDCsInADDomain | ForEach-Object{
		# Get The FQDN Of The RWDC
		$rwdcFQDN = $null
		$rwdcFQDN = $_
		
		# Retrieve The Object Of The RWDC From AD
		$rwdcObj = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				$rwdcObj = Get-ADDomainController $rwdcFQDN -Server $targetedADdomainNearestRWDCFQDN
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$rwdcFQDN'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				$rwdcObj = Get-ADDomainController $rwdcFQDN -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$rwdcFQDN' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		
		# Define The Columns For The RWDCs In The AD Domain To Be Filled In
		$tableOfDCsInADDomainObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","Krb Tgt","Pwd Last Set","Org RWDC","Org Time","Ver","IP Address","OS Version",Reachable,"Source RWDC FQDN","Source RWDC DSA"
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."Host Name" = $null
		$tableOfDCsInADDomainObj."Host Name" = $rwdcFQDN
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj.PDC = $null
		If ($rwdcObj.OperationMasterRoles -contains "PDCEmulator") {
			$tableOfDCsInADDomainObj.PDC = $True
		} Else {
			$tableOfDCsInADDomainObj.PDC = $False
		}
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."Site Name" = $null
		$tableOfDCsInADDomainObj."Site Name" = $rwdcObj.Site
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."DS Type" = $null
		$tableOfDCsInADDomainObj."DS Type" = "Read/Write"
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$rwdcKrbTgtSamAccountName = $null
		If ($modeOfOperationNr -eq 1 -Or $modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
			# Use The PROD/REAL KrbTgt Account Of The RWDC
			$rwdcKrbTgtSamAccountName = "krbtgt"
		}
		If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
			# Use The TEST/BOGUS KrbTgt Account Of The RWDC
			$rwdcKrbTgtSamAccountName = "krbtgt_TEST"
		}
		$tableOfDCsInADDomainObj."Krb Tgt" = $rwdcKrbTgtSamAccountName
		
		# Retrieve The Object Of The KrbTgt Account
		$rwdcKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				$rwdcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rwdcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$rwdcKrbTgtSamAccountName'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				$rwdcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rwdcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$rwdcKrbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		$tableOfDCsInADDomainObj."Pwd Last Set" = $null
		$tableOfDCsInADDomainObj."Org RWDC" = $null
		$tableOfDCsInADDomainObj."Org Time" = $null
		$tableOfDCsInADDomainObj."Ver" = $null
		If ($rwdcKrbTgtObject) {
			# If The Object Of The KrbTgt Account Exists
			# Retrieve The DN OF The Object
			$rwdcKrbTgtObjectDN = $null
			$rwdcKrbTgtObjectDN = $rwdcKrbTgtObject.DistinguishedName
			
			# Retrieve The Password Last Set Value Of The KrbTgt Account
			$rwdcKrbTgtPwdLastSet = $null
			$rwdcKrbTgtPwdLastSet = Get-Date $([datetime]::fromfiletime($rwdcKrbTgtObject.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Pwd Last Set" = $rwdcKrbTgtPwdLastSet
			
			# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
			$objectMetadata = $null
			$objectMetadata = retrieveObjectMetadata $targetedADdomainNearestRWDCFQDN $rwdcKrbTgtObjectDN $localADforest $adminCrds
			$objectMetadataAttribPwdLastSet = $null
			$objectMetadataAttribPwdLastSet = $objectMetadata | Where-Object{$_.Name -eq "pwdLastSet"}
			$objectMetadataAttribPwdLastSetOrgRWDCFQDN = $null
			$objectMetadataAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataAttribPwdLastSet.OriginatingServer) {$objectMetadataAttribPwdLastSet.OriginatingServer} Else {"RWDC Demoted"}
			$objectMetadataAttribPwdLastSetOrgTime = $null
			$objectMetadataAttribPwdLastSetOrgTime = Get-Date $($objectMetadataAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
			$objectMetadataAttribPwdLastSetVersion = $null
			$objectMetadataAttribPwdLastSetVersion = $objectMetadataAttribPwdLastSet.Version
			
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Org RWDC" = $objectMetadataAttribPwdLastSetOrgRWDCFQDN
			$tableOfDCsInADDomainObj."Org Time" = $objectMetadataAttribPwdLastSetOrgTime
			$tableOfDCsInADDomainObj."Ver" = $objectMetadataAttribPwdLastSetVersion
		} Else {
			# If The Object Of The KrbTgt Account Does Not Exist
			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Pwd Last Set" = "No Such Object"
			$tableOfDCsInADDomainObj."Org RWDC" = "No Such Object"
			$tableOfDCsInADDomainObj."Org Time" = "No Such Object"
			$tableOfDCsInADDomainObj."Ver" = "No Such Object"
		}
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."IP Address" = $null
		$tableOfDCsInADDomainObj."IP Address" = $rwdcObj.IPv4Address
		
		# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."OS Version" = $null
		$tableOfDCsInADDomainObj."OS Version" = $rwdcObj.OperatingSystem
		
		# Define The Ports To Check Against
		$ports = 135,389,9389	# RPC Endpoint Mapper, LDAP, AD Web Service
		
		# Define The Connection Check To Be True Initially
		$connectionCheckOK = $true
		
		# For Every Defined Port Check The Connection And Report
		$ports | ForEach-Object{
			# Set The Port To Check Against
			$port = $null
			$port = $_
			
			# Test The Connection To The Server Using The Port
			$connectionResult = $null
			$connectionResult = portConnectionCheck $rwdcFQDN $port 500
			If ($connectionResult -eq "ERROR") {
				$connectionCheckOK = $false
			}
		}
		If ($connectionCheckOK -eq $true) {
			# If The Connection Check Is OK
			# Connect To The RootDSE Of The RWDC
			$rwdcRootDSEObj = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					$rwdcRootDSEObj = [ADSI]"LDAP://$rwdcFQDN/rootDSE"
				} Catch {
					Logging "" "ERROR"
					Logging "Error Connecting To '$rwdcFQDN' For 'rootDSE'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					$rwdcRootDSEObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rwdcFQDN/rootDSE"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
				} Catch {
					Logging "" "ERROR"
					Logging "Error Connecting To '$rwdcFQDN' For 'rootDSE' Using '$adminUserAccountRemoteForest'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($rwdcRootDSEObj.Path -eq $null) {
				# If It Throws An Error Then The RWDC Is Not Available/Reachable And Increase The Counter Of Unreachable RWDCs
				$tableOfDCsInADDomainObj.Reachable = $False
				$nrOfUnReachableRWDCs += 1
				
			} Else {
				# If It Does Not Throw An Error Then The RWDC Is Available/Reachable And Increase The Counter Of Reachable RWDCs
				$tableOfDCsInADDomainObj.Reachable = $True
				$nrOfReachableRWDCs += 1
			}
		} Else {
			# If The Connection Check Is Not OK Then The RWDC Is Not Available/Reachable And Increase The Counter Of Unreachable RWDCs
			$tableOfDCsInADDomainObj.Reachable = $False
			$nrOfUnReachableRWDCs += 1
		}
		If ($rwdcObj.OperationMasterRoles -contains "PDCEmulator") {
			# If The RWDC Is The RWDC With The PDC FSMO, Then Do Not Specify A Source RWDC As The RWDC With The PDC FSMO Is The Source Originating RWDC
			$tableOfDCsInADDomainObj."Source RWDC FQDN" = "N.A."
			$tableOfDCsInADDomainObj."Source RWDC DSA" = "N.A."
		} Else {
			# If The RWDC Is Not The RWDC With The PDC FSMO, Then Specify A Source RWDC Being The RWDC With The PDC FSMO As The Source Originating RWDC
			$tableOfDCsInADDomainObj."Source RWDC FQDN" = $targetedADdomainRWDCFQDNWithPDCFSMOFQDN
			$tableOfDCsInADDomainObj."Source RWDC DSA" = $targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN
		}
		
		# Increase The Counter For The Number Of RWDCs
		$nrOfRWDCs += 1
		
		# Add The Row For The RWDC To The Table
		$tableOfDCsInADDomain += $tableOfDCsInADDomainObj
	}
}
	
# Retrieve All The RODCs In The AD Domain
$listOfRODCsInADDomain = $null
$listOfRODCsInADDomain = $thisADDomain.ReadOnlyReplicaDirectoryServers

# Set The Counters To Zero
$nrOfRODCs = 0
$nrOfReachableRODCs = 0
$nrOfUnReachableRODCs = 0
$nrOfUnDetermined = 0

# Execute For All RODCs In The AD Domain
If ($listOfRODCsInADDomain) {
	$listOfRODCsInADDomain | ForEach-Object{
		# Get The FQDN Of The RODC
		$rodcFQDN = $null
		$rodcFQDN = $_
		
		# Get The FQDN Of The RODC
		$rodcObj = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				$rodcObj = Get-ADDomainController $rodcFQDN -Server $targetedADdomainNearestRWDCFQDN
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$rodcFQDN'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				$rodcObj = Get-ADDomainController $rodcFQDN -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$rodcFQDN' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		
		# Define The Columns For The RODCs In The AD Domain To Be Filled In
		$tableOfDCsInADDomainObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","Krb Tgt","Pwd Last Set","Org RWDC","Org Time","Ver","IP Address","OS Version",Reachable,"Source RWDC FQDN","Source RWDC DSA"
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."Host Name" = $null
		$tableOfDCsInADDomainObj."Host Name" = $rodcFQDN
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj.PDC = $null
		$tableOfDCsInADDomainObj.PDC = $False
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."Site Name" = $null
		If ($rodcObj.OperatingSystem) {
			$tableOfDCsInADDomainObj."Site Name" = $rodcObj.Site
		} Else {
			$tableOfDCsInADDomainObj."Site Name" = "Unknown"
		}
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."DS Type" = $null
		$tableOfDCsInADDomainObj."DS Type" = "Read-Only"
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$rodcKrbTgtSamAccountName = $null
		If ($modeOfOperationNr -eq 1 -Or $modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
			# Use The PROD/REAL KrbTgt Account Of The RODC
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					$rodcKrbTgtSamAccountName = ((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDCFQDN)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDCFQDN).Name
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' To Determine The KrbTgt Account In Use By '$($rodcObj.HostName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					$rodcKrbTgtSamAccountName = ((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds).Name
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' To Determine The KrbTgt Account In Use By '$($rodcObj.HostName)' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}			
		}
		If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
			# Use The TEST/BOGUS KrbTgt Account Of The RODC
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					$rodcKrbTgtSamAccountName = $(((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDCFQDN)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDCFQDN).Name) + "_TEST"
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' To Determine The TEST KrbTgt Account In Use By '$($rodcObj.HostName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					$rodcKrbTgtSamAccountName = $(((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds).Name) + "_TEST"
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' To Determine The TEST KrbTgt Account In Use By '$($rodcObj.HostName)' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
		}
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."Krb Tgt" = $null
		$tableOfDCsInADDomainObj."Krb Tgt" = $rodcKrbTgtSamAccountName
		
		# Retrieve The Object Of The KrbTgt Account
		$rodcKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				$rodcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rodcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$rodcKrbTgtSamAccountName'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				$rodcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rodcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$rodcKrbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		$tableOfDCsInADDomainObj."Pwd Last Set" = $null
		$tableOfDCsInADDomainObj."Org RWDC" = $null
		$tableOfDCsInADDomainObj."Org Time" = $null
		$tableOfDCsInADDomainObj."Ver" = $null
		If ($rodcKrbTgtObject) {
			# If The Object Of The KrbTgt Account Exists
			# Retrieve The DN OF The Object
			$rodcKrbTgtObjectDN = $null
			$rodcKrbTgtObjectDN = $rodcKrbTgtObject.DistinguishedName		
			
			# Retrieve The Password Last Set Value Of The KrbTgt Account
			$rodcKrbTgtPwdLastSet = $null
			$rodcKrbTgtPwdLastSet = Get-Date $([datetime]::fromfiletime($rodcKrbTgtObject.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
			
			# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Pwd Last Set" = $rodcKrbTgtPwdLastSet
			
			# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
			$objectMetadata = $null
			$objectMetadata = retrieveObjectMetadata $targetedADdomainNearestRWDCFQDN $rodcKrbTgtObjectDN $localADforest $adminCrds
			$objectMetadataAttribPwdLastSet = $null
			$objectMetadataAttribPwdLastSet = $objectMetadata | Where-Object{$_.Name -eq "pwdLastSet"}
			$objectMetadataAttribPwdLastSetOrgRWDCFQDN = $null
			$objectMetadataAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataAttribPwdLastSet.OriginatingServer) {$objectMetadataAttribPwdLastSet.OriginatingServer} Else {"RWDC Demoted"}
			$objectMetadataAttribPwdLastSetOrgTime = $null
			$objectMetadataAttribPwdLastSetOrgTime = Get-Date $($objectMetadataAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
			$objectMetadataAttribPwdLastSetVersion = $null
			$objectMetadataAttribPwdLastSetVersion = $objectMetadataAttribPwdLastSet.Version
			
			# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Org RWDC" = $objectMetadataAttribPwdLastSetOrgRWDCFQDN
			$tableOfDCsInADDomainObj."Org Time" = $objectMetadataAttribPwdLastSetOrgTime
			$tableOfDCsInADDomainObj."Ver" = $objectMetadataAttribPwdLastSetVersion
		} Else {
			# If The Object Of The KrbTgt Account Does Not Exist
			# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Pwd Last Set" = "No Such Object"
			$tableOfDCsInADDomainObj."Org RWDC" = "No Such Object"
			$tableOfDCsInADDomainObj."Org Time" = "No Such Object"
			$tableOfDCsInADDomainObj."Ver" = "No Such Object"
		}
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."IP Address" = $null
		If ($rodcObj.OperatingSystem) {
			$tableOfDCsInADDomainObj."IP Address" = $rodcObj.IPv4Address
		} Else {
			$tableOfDCsInADDomainObj."IP Address" = "Unknown"
		}
		
		# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
		$tableOfDCsInADDomainObj."OS Version" = $null
		If ($rodcObj.OperatingSystem) {
			$tableOfDCsInADDomainObj."OS Version" = $rodcObj.OperatingSystem
		} Else {
			$tableOfDCsInADDomainObj."OS Version" = "Unknown"
		}
		
		# Define The Ports To Check Against
		$ports = 135,389,9389	# RPC Endpoint Mapper, LDAP, AD Web Service
		
		# Define The Connection Check To Be True Initially
		$connectionCheckOK = $true
		
		# For Every Defined Port Check The Connection And Report
		$failedPorts = @()
		$ports | ForEach-Object{
			# Set The Port To Check Against
			$port = $null
			$port = $_
			
			# Test The Connection To The Server Using The Port
			$connectionResult = $null
			$connectionResult = portConnectionCheck $rodcFQDN $port 500
			If ($connectionResult -eq "ERROR") {
				$failedPorts += $port
				$connectionCheckOK = $false
			}
		}
		If ($connectionCheckOK -eq $true) {		
			# If The Connection Check Is OK
			# Connect To The RootDSE Of The RODC
			$rodcRootDSEObj = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					$rodcRootDSEObj = [ADSI]"LDAP://$rodcFQDN/rootDSE"
				} Catch {
					Logging "" "ERROR"
					Logging "Error Connecting To '$rodcFQDN' For 'rootDSE'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					$rodcRootDSEObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rodcFQDN/rootDSE"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
				} Catch {
					Logging "" "ERROR"
					Logging "Error Connecting To '$rodcFQDN' For 'rootDSE' Using '$adminUserAccountRemoteForest'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($rodcRootDSEObj.Path -eq $null) {
				# If It Throws An Error Then The RODC Is Not Available/Reachable And Increase The Counter Of Unreachable RODCs
				$tableOfDCsInADDomainObj.Reachable = $False
				$nrOfUnReachableRODCs += 1
			} Else {
				# If It Does Not Throw An Error Then The RWDC Is Available/Reachable And Increase The Counter Of Reachable RODCs
				$tableOfDCsInADDomainObj.Reachable = $True
				$nrOfReachableRODCs += 1
			}
		} Else {
			# If The Connection Check Is Not OK Then The RWDC Is Not Available/Reachable And Increase The Counter Of Unreachable RODCs
			$tableOfDCsInADDomainObj.Reachable = $False
			$nrOfUnReachableRODCs += 1
		}
		If ($rodcObj.OperatingSystem) {
			# If The RODC Has An Operating System Specified, Then It Is Most Likely A Windows RODC
			If ($tableOfDCsInADDomainObj.Reachable -eq $True) {
				# If The RODC Is Available/Reachable
				# Get The DSA DN Of The RODC
				$rodcNTDSSettingsObjectDN = $null
				$rodcNTDSSettingsObjectDN = $rodcObj.NTDSSettingsObjectDN
				
				# Define An LDAP Query With A Search Base And A Filter To Determine The DSA DN Of The Source RWDC Of The RODC
				$dsDirSearcher = $null
				$dsDirSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
				$dsDirSearcher.SearchRoot = $null
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
					$dsDirSearcher.SearchRoot = "LDAP://$rodcFQDN/$rodcNTDSSettingsObjectDN"
				}
				If ($localADforest -eq $false -And $adminCrds) {
					$dsDirSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rodcFQDN/$rodcNTDSSettingsObjectDN"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
				}
				$dsDirSearcher.Filter = $null
				$dsDirSearcher.Filter = "(&(objectClass=nTDSConnection)(ms-DS-ReplicatesNCReason=*))"
				$sourceRWDCsNTDSSettingsObjectDN = $null
				Try {
					$sourceRWDCsNTDSSettingsObjectDN = $dsDirSearcher.FindAll().Properties.fromserver
				} Catch {
					Logging "" "ERROR"
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
						Logging "Error Querying AD Against '$rodcFQDN' For Object '$rodcNTDSSettingsObjectDN'..." "ERROR"
					}
					If ($localADforest -eq $false -And $adminCrds) {
						Logging "Error Querying AD Against '$rodcFQDN' For Object '$rodcNTDSSettingsObjectDN' Using '$($adminCrds.UserName)'..." "ERROR"
					}
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
				
				# For Every DSA DN Of The Source RWDC Retrieved
				$sourceRWDCsNTDSSettingsObjectDN | ForEach-Object{
					$sourceRWDCNTDSSettingsObjectDN = $null
					$sourceRWDCNTDSSettingsObjectDN = $_
					
					# Strip "CN=NTDS Settings," To End Up With The Server Object DN
					$sourceRWDCServerObjectDN = $null
					$sourceRWDCServerObjectDN = $sourceRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)
					
					# Connect To The Server Object DN
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
						Try {
							$sourceRWDCServerObjectObj = ([ADSI]"LDAP://$targetedADdomainNearestRWDCFQDN/$sourceRWDCServerObjectDN")
						} Catch {
							Logging "" "ERROR"
							Logging "Error Connecting To '$targetedADdomainNearestRWDCFQDN' For Object '$sourceRWDCServerObjectDN'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
					If ($localADforest -eq $false -And $adminCrds) {
						Try {
							$sourceRWDCServerObjectObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetedADdomainNearestRWDCFQDN/$sourceRWDCServerObjectDN"),$adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
						} Catch {
							Logging "" "ERROR"
							Logging "Error Connecting To '$targetedADdomainNearestRWDCFQDN' For Object '$sourceRWDCServerObjectDN' Using '$adminUserAccountRemoteForest'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
					
					# If The Domain Of The Source RWDC Matches The Domain Of The RODC, Then That's The One We Need
					If (($sourceRWDCServerObjectObj.dnshostname).SubString($sourceRWDCServerObjectObj.name.Length + 1) -eq $rodcObj.Domain) {
						# The HostName Of Source RWDC Used By The RODC - Set The Corresponding Value Of The RODC In The Correct Column Of The Table
						$tableOfDCsInADDomainObj."Source RWDC FQDN" = $sourceRWDCServerObjectObj.dnshostname[0]
						
						# The DSA DN Of Source RWDC Used By The RODC - Set The Corresponding Value Of The RODC In The Correct Column Of The Table
						$tableOfDCsInADDomainObj."Source RWDC DSA" = $sourceRWDCsNTDSSettingsObjectDN[0]
					}
				}
			} Else {
				# If The RODC Is Available/Reachable
				# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
				$tableOfDCsInADDomainObj."Source RWDC FQDN" = "RODC Unreachable"
				$tableOfDCsInADDomainObj."Source RWDC DSA" = "RODC Unreachable"
			}
		} Else {
			# If The RODC Does Not Have An Operating System Specified, Then It Is Most Likely Not A Windows RODC
			# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj."Source RWDC FQDN" = "Unknown"
			$tableOfDCsInADDomainObj."Source RWDC DSA" = "Unknown"
		}
		If ($rodcObj.OperatingSystem) {
			# If The RODC Has An Operating System Specified, Then It Is Most Likely A Windows RODC, Therefore Increase The Counter For Real RODCs
			$nrOfRODCs += 1
		} Else {
			# If The RODC Does Not Have An Operating System Specified, Then It Is Most Likely Not A Windows RODC, Therefore Increase The Counter For Unknown RODCs
			$nrOfUnDetermined += 1
		}
		# Add The Row For The RODC To The Table
		$tableOfDCsInADDomain += $tableOfDCsInADDomainObj
	}
}

# Sort The Table With DCs In The AD Domain In The Order "DS Type" (Read/Write At The Top), Then If It Is The PDC Or Not (PDC At The Top), Then If It Is Reachable Or Not (Reachable At the Top)
$tableOfDCsInADDomain = $tableOfDCsInADDomain | Sort-Object -Property @{Expression = "DS Type"; Descending = $False}, @{Expression = "PDC"; Descending = $True}, @{Expression = "Reachable"; Descending = $True}

# Determine The Number Of DCs Based Upon The Number Of RWDCs And The Number Of RODCs
$nrOfDCs = $nrOfRWDCs + $nrOfRODCs

# Display The Information
Logging "" "REMARK"
Logging "List Of Domain Controllers In AD Domain '$targetedADdomainFQDN'..."
Logging "" "REMARK"
Logging "$($tableOfDCsInADDomain | Format-Table * -Autosize | Out-String)"
Logging "" "REMARK"
Logging "REMARKS:" "REMARK"
Logging " - 'N.A.' in the columns 'Source RWDC FQDN' and 'Source RWDC DSA' means the RWDC is considered as the master for this script." "REMARK"
Logging " - 'RODC Unreachable' in the columns 'Source RWDC FQDN' and 'Source RWDC DSA' means the RODC cannot be reached to determine its replicating source" "REMARK"
Logging "     RWDC/DSA. The unavailability can be due to firewalls/networking or the RODC actually being down." "REMARK"
Logging " - 'Unknown' in various columns means that an RODC was found that may not be a true Windows Server RODC. It may be an appliance acting as an RODC." "REMARK"
Logging " - 'RWDC Demoted' in the column 'Org RWDC' means the RWDC existed once, but it does not exist anymore as it has been decommissioned in the past." "REMARK"
Logging "     This is normal." "REMARK"
Logging " - 'No Such Object' in the columns 'Pwd Last Set', 'Org RWDC', 'Org Time' or 'Ver' means the targeted object was not found in the AD domain." "REMARK"
Logging "     Although this is possible for any targeted object, this is most likely the case when targeting the KrbTgt TEST/BOGUS accounts and if those" "REMARK"
Logging "     do not exist yet. This may also occur for an appliance acting as an RODC as in that case no KrbTgt TEST/BOGUS account is created." "REMARK"
$krbTgtAADname = "krbtgt_AzureAD"
$krbTgtAAD = Get-ADUser -Filter 'name -eq $krbTgtAADname' -SearchBase $("DC=" + $targetedADdomainFQDN.Replace(".",",DC=")) -Server $targetedADdomainNearestRWDCFQDN
If ($krbTgtAAD) {
	Logging "" "REMARK"
	Logging "WARNING:" "WARNING"
	Logging " - In this AD domain '$targetedADdomainFQDN' the special purpose krbtgt account '$krbTgtAADname' for Azure AD was found!" "WARNING"
	Logging " - DO NOT reset the password of this krbtgt account in any way except using the official method to reset the password and rotate the keys" "WARNING"
	Logging "     (See: - https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-passwordless-security-key-on-premises)" "WARNING"
	Logging " - To reset the password and rotate the keys of the krbtgt account '$krbTgtAADname' perform the following steps:" "WARNING"
	Logging "    * Go to an Azure AD Connect server (v1.4.32.0 or later)" "WARNING"
	Logging "    * Open a PowerShell Command Prompt window" "WARNING"
	Logging "    * In that window execute the following commands:" "WARNING"
	Logging "" "WARNING"
	Logging "       # Import The PowerShell Module For Azure AD Kerberos Server" "WARNING"
	Logging "       Import-Module `"C:\Program Files\Microsoft Azure Active Directory Connect\AzureADKerberos\AzureAdKerberos.psd1`"" "WARNING"
	Logging "" "WARNING"
	Logging "       # AD Domain/Enterprise Admin Credentials" "WARNING"
	Logging "       `$adDomainAdminAccount = Read-Host `"AD Admin Account`"" "WARNING"
	Logging "       `$adDomainAdminPassword = Read-Host `"AD Admin Account Password`" -AsSecureString" "WARNING"
	Logging "       `$secureAdDomainAdminPassword = ConvertTo-SecureString `$adDomainAdminPassword -AsPlainText -Force" "WARNING"
	Logging "       `$adDomainAdminCreds = New-Object System.Management.Automation.PSCredential `$adDomainAdminAccount, `$secureAdDomainAdminPassword" "WARNING"
	Logging "" "WARNING"
	Logging "       # Azure AD Global Admin Credentials" "WARNING"
	Logging "       `$aadDomainAdminAccount = Read-Host `"Azure AD Admin Account`"" "WARNING"
	Logging "       `$aadDomainAdminPassword = Read-Host `"Azure AD Admin Account Password`" -AsSecureString" "WARNING"
	Logging "       [string]`$aadDomainAdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$aadDomainAdminPassword))" "WARNING"
	Logging "       `$secureAadDomainAdminPassword = ConvertTo-SecureString `$aadDomainAdminPassword -AsPlainText -Force" "WARNING"
	Logging "       `$aadDomainAdminCreds = New-Object System.Management.Automation.PSCredential `$aadDomainAdminAccount, `$secureAadDomainAdminPassword" "WARNING"
	Logging "" "WARNING"
	Logging "       # Check the CURRENT status of the Azure AD Kerberos Server object in Active Directory" "WARNING"
	Logging "       Get-AzureADKerberosServer -Domain $targetedADdomainFQDN -DomainCredential `$adDomainAdminCreds -CloudCredential `$aadDomainAdminCreds" "WARNING"
	Logging "" "WARNING"
	Logging "       # Reset the password and rotate the keys" "WARNING"
	Logging "       Set-AzureADKerberosServer -Domain $targetedADdomainFQDN -DomainCredential `$adDomainAdminCreds -CloudCredential `$aadDomainAdminCreds -RotateServerKey" "WARNING"
	Logging "" "WARNING"
	Logging "       # Check the NEW status of the Azure AD Kerberos Server object in Active Directory" "WARNING"
	Logging "       Get-AzureADKerberosServer -Domain $targetedADdomainFQDN -DomainCredential `$adDomainAdminCreds -CloudCredential `$aadDomainAdminCreds" "WARNING"
	Logging "" "WARNING"
	Logging "    REMARK: Make sure the 'KeyVersion' value matches the 'CloudKeyVersion' value and the 'KeyUpdatedOn' value matches the 'CloudKeyUpdatedOn' value!" "WARNING"
}
Logging "" "REMARK"
Logging "" "REMARK"
Logging "" "REMARK"
Logging "  --> Found [$nrOfDCs] Real DC(s) In AD Domain..." "REMARK"
Logging "" "REMARK"
Logging "  --> Found [$nrOfRWDCs] RWDC(s) In AD Domain..." "REMARK"
Logging "  --> Found [$nrOfReachableRWDCs] Reachable RWDC(s) In AD Domain..." "REMARK"
Logging "  --> Found [$nrOfUnReachableRWDCs] UnReachable RWDC(s) In AD Domain..." "REMARK"
Logging "" "REMARK"
Logging "  --> Found [$nrOfRODCs] RODC(s) In AD Domain..." "REMARK"
Logging "  --> Found [$nrOfReachableRODCs] Reachable RODC(s) In AD Domain..." "REMARK"
Logging "  --> Found [$nrOfUnReachableRODCs] UnReachable RODC(s) In AD Domain..." "REMARK"
Logging "  --> Found [$nrOfUnDetermined] Undetermined RODC(s) In AD Domain..." "REMARK"
Logging "" "REMARK"

### Mode 2 And 3 And 4 and 5 And 6 And 8 And 9 Only - Making Sure The RWDC With The PDC FSMO And The Nearest RWDC Are Reachable/Available
If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
	If (($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $true}).Reachable -eq $false) {
		Logging "" "ERROR"
		Logging "  --> The RWDC With The PDC FSMO Role '$targetedADdomainRWDCFQDNWithPDCFSMOFQDN' IS NOT Reachable For The Ports '$($ports -join ', ')'..." "ERROR"
		Logging "" "ERROR"

		$abortDueToUnreachable = $true
	}
	
	If (($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainNearestRWDCFQDN}).Reachable -eq $false) {
		Logging "" "ERROR"
		Logging "  --> The Nearest RWDC '$targetedADdomainNearestRWDCFQDN' IS NOT Reachable For The Ports '$($ports -join ', ')'..." "ERROR"
		Logging "" "ERROR"
	
		$abortDueToUnreachable = $true
	}

	If ($abortDueToUnreachable -eq $true) {
		Logging "" "ERROR"
		Logging "  --> Due To Unavailability Issues Of The RWDC With The PDC FSMO Role And/Or The Nearest RWDC, The Script Cannot Continue ..." "ERROR"
		Logging "  --> Both The RWDC With The PDC FSMO Role And The The Nearest RWDC MUST Be Available/Reachable..." "ERROR"
		Logging "" "ERROR"
		Logging "Aborting Script..." "ERROR"
		Logging "" "ERROR"

		EXIT
	}
}

### Mode 2 And 3 And 4 and 5 And 6 Only - Selecting The KrbTgt Account To Target And Scope If Applicable (Only Applicable To RODCs)
If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "SELECT THE SCOPE OF THE KRBTGT ACCOUNT(S) TO TARGET..." "HEADER"
	Logging ""
	Logging "Which KrbTgt account do you want to target?"
	Logging ""
	Logging " - 1 - Scope of KrbTgt in use by all RWDCs in the AD Domain"
	Logging ""
	If ($nrOfRODCs -gt 0) {
		Logging " - 2 - Scope of KrbTgt in use by specific RODC - Single/Multiple RODC(s) in the AD Domain"
		Logging ""
		Logging " - 3 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain"
		Logging ""
	}
	Logging ""
	Logging " - 0 - Exit Script"
	Logging ""
	Logging "Please specify the scope of KrbTgt Account to target: " "ACTION-NO-NEW-LINE"
	$targetKrbTgtAccountNr = Read-Host
	Logging ""
	
	# If Anything Else Than The Allowed/Available Non-Zero KrbTgt Accounts, Abort The Script
	If (($targetKrbTgtAccountNr -ne 1 -And $targetKrbTgtAccountNr -ne 2 -And $targetKrbTgtAccountNr -ne 3) -Or $targetKrbTgtAccountNr -notmatch "^[\d\.]+$") {
		Logging "  --> Chosen Scope KrbTgt Account Target: 0 - Exit Script..." "REMARK"
		Logging ""
		
		EXIT
	}
	
	# If KrbTgt Account Scope 1
	If ($targetKrbTgtAccountNr -eq 1) {
		$targetKrbTgtAccountDescription = "1 - Scope of KrbTgt in use by all RWDCs in the AD Domain..."
	}
	
	# If KrbTgt Account Scope 2
	If ($targetKrbTgtAccountNr -eq 2) {
		$targetKrbTgtAccountDescription = "2 - Scope of KrbTgt in use by specific RODC - Single/Multiple RODC(s) in the AD Domain..."
	}
	
	# If KrbTgt Account Scope 3
	If ($targetKrbTgtAccountNr -eq 3) {
		$targetKrbTgtAccountDescription = "3 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain..."
	}
	Logging "  --> Chosen Scope KrbTgt Account Target: $targetKrbTgtAccountDescription" "REMARK"
	Logging ""
	
	# Use The RWDC With The PDC FSMO Role To Represent All RWDCs In The AD Domain
	If ($targetKrbTgtAccountNr -eq 1) {
		$targetDCFQDNList = $tableOfDCsInADDomain | Where-Object{$_.PDC -eq $true}
	}

	# Present List Of RODCs When Option 2 Or 3 Is Chosen To Make It Easier To Chose From
	# Specify A Comma Separated List Of FQDNs Of RODCs To Target (Single/Multiple)
	If ($targetKrbTgtAccountNr -eq 2) {
		Logging "" "REMARK"
		Logging "List Of Read-Only Domain Controllers In AD Domain '$targetedADdomainFQDN'..."
		Logging "" "REMARK"
		Logging "$($tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only"} | Format-Table "Host Name","DS Type","Krb Tgt","Pwd Last Set","Reachable" -Autosize | Out-String)"
		Logging "" "REMARK"

		Logging "Specify a single, or comma-separated list of FQDNs of RODCs for which the KrbTgt Account Password must be reset: " "ACTION-NO-NEW-LINE"
		$targetDCFQDNList = Read-Host
		$targetDCFQDNList = $targetDCFQDNList.Split(",")
		Logging ""
		Logging "  --> Specified RODCs:" "REMARK"
		$targetDCFQDNList | ForEach-Object{
			Logging "       * $($_)" "REMARK"
		}
		Logging ""
	}
}

### Mode 2/3/5 - Simulation Mode AND Mode 4/6 - Real Reset Mode
If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
	# Mode 2 - Simulation Mode - TEMPORARY CANARY OBJECT
	If ($modeOfOperationNr -eq 2) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "SIMULATION MODE (MODE $modeOfOperationNr) - CREATING/REPLICATING TEMPORARY CANARY OBJECT TO TEST REPLICATION CONVERGENCE" "HEADER"
		Logging "SCOPE: $targetKrbTgtAccountDescription" "HEADER"
		Logging ""
	}

	# Mode 3 - Simulation Mode - SCOPED TEST/BOGUS KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 3) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "SIMULATION MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED TEST/BOGUS KRBTGT ACCOUNT(S) (WHAT IF MODE)" "HEADER"
		Logging "SCOPE: $targetKrbTgtAccountDescription" "HEADER"
		Logging ""
	}

	# Mode 4 - Real Reset Mode - SCOPED TEST/BOGUS KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 4) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "REAL RESET MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED TEST/BOGUS KRBTGT ACCOUNT(S)" "HEADER"
		Logging "SCOPE: $targetKrbTgtAccountDescription" "HEADER"
		Logging ""
	}

	# Mode 5 - Simulation Mode - SCOPED PROD/REAL KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 5) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "SIMULATION MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED PROD/REAL KRBTGT ACCOUNT(S) (WHAT IF MODE)" "HEADER"
		Logging "SCOPE: $targetKrbTgtAccountDescription" "HEADER"
		Logging ""
	}

	# Mode 6 - Real Reset Mode - SCOPED PROD/REAL KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 6) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "REAL RESET MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED PROD/REAL KRBTGT ACCOUNT(S)" "HEADER"
		Logging "SCOPE: $targetKrbTgtAccountDescription" "HEADER"
		Logging ""
	}
	
	# Asking Confirmation To Continue Or Not
	Logging "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
	$continueOrStop = $null
	$continueOrStop = Read-Host
	
	# Any Confirmation Not Equal To CONTINUE Will Be Equal To STOP
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		$continueOrStop = "STOP"
	}
	Logging ""
	Logging "  --> Chosen: $continueOrStop" "REMARK"
	Logging ""
	
	# Any Confirmation Not Equal To CONTINUE Will Abort The Script
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {

		EXIT
	}	
	
	# For The KrbTgt Account Scope Of All RWDCs
	If ($targetKrbTgtAccountNr -eq 1) {
		# Collection Of DCs To Process
		$collectionOfDCsToProcess = $targetDCFQDNList
	}
	
	# For The KrbTgt Account Scope Of Specified, But Individual RODCs
	If ($targetKrbTgtAccountNr -eq 2) {
		# Collection Of Reachable RODCs
		$collectionOfRODCsToProcessReachable = $null
		$collectionOfRODCsToProcessReachable = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $true -And $_."Source RWDC FQDN" -ne "Unknown" -And $_."Source RWDC FQDN" -ne "RODC Unreachable" -And $targetDCFQDNList -contains $_."Host Name"}

		# Collection Of UnReachable RODCs
		$collectionOfRODCsToProcessUnReachable = $null
		$collectionOfRODCsToProcessUnReachable = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "RODC Unreachable" -And $targetDCFQDNList -contains $_."Host Name"}

		# Collection Of Unknown RODCs
		$collectionOfRODCsToProcessUnknown = $null
		$collectionOfRODCsToProcessUnknown = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "Unknown" -And $targetDCFQDNList -contains $_."Host Name"}

		# Collection Of DCs To Process
		$collectionOfDCsToProcess = @()
		$collectionOfDCsToProcess += $collectionOfRODCsToProcessReachable
		$collectionOfDCsToProcess += $collectionOfRODCsToProcessUnReachable

		# Collection Of DCs NOT To Process
		$collectionOfDCsNotToProcess = @()
		$collectionOfDCsNotToProcess += $collectionOfRODCsToProcessUnknown
	}
	
	# For The KrbTgt Account Scope Of Each Individual RODCs
	If ($targetKrbTgtAccountNr -eq 3) {
		# Collection Of Reachable RODCs
		$collectionOfRODCsToProcessReachable = $null
		$collectionOfRODCsToProcessReachable = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $true -And $_."Source RWDC FQDN" -ne "Unknown" -And $_."Source RWDC FQDN" -ne "RODC Unreachable"}

		# Collection Of UnReachable RODCs
		$collectionOfRODCsToProcessUnReachable = $null
		$collectionOfRODCsToProcessUnReachable = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "RODC Unreachable"}

		# Collection Of Unknown RODCs
		$collectionOfRODCsToProcessUnknown = $null
		$collectionOfRODCsToProcessUnknown = $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "Unknown"}

		# Collection Of DCs To Process
		$collectionOfDCsToProcess = @()
		$collectionOfDCsToProcess += $collectionOfRODCsToProcessReachable
		$collectionOfDCsToProcess += $collectionOfRODCsToProcessUnReachable

		# Collection Of DCs NOT To Process
		$collectionOfDCsNotToProcess = @()
		$collectionOfDCsNotToProcess += $collectionOfRODCsToProcessUnknown
	}
	
	# If Any DC Exists In The List, Process it
	If ($collectionOfDCsToProcess) {
		$collectionOfDCsToProcess | ForEach-Object{
			# The DC Object In The List To Process
			$dcToProcess = $null
			$dcToProcess = $_

			# Retrieve The sAMAccountName Of The KrbTgt Account In Use By The DC(s)
			$krbTgtSamAccountName = $null
			$krbTgtSamAccountName = $dcToProcess."Krb Tgt"

			# Retrieve The KrbTgt Account Object DN
			$krbTgtObjectDN = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					$krbTgtObjectDN = (Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainNearestRWDCFQDN).DistinguishedName
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					$krbTgtObjectDN = (Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds).DistinguishedName
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}

			# Present The Information Of The KrbTgt Account Scope Being Processed
			Logging "+++++" "REMARK"
			Logging "+++ Processing KrbTgt Account....: '$krbTgtSamAccountName' | '$krbTgtObjectDN' +++" "REMARK"
			If ($targetKrbTgtAccountNr -eq 1) {
				Logging "+++ Used By RWDC.................: 'All RWDCs' +++" "REMARK"
			}
			If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3) {
				Logging "+++ Used By RODC.................: '$($dcToProcess."Host Name")' (Site: $($dcToProcess."Site Name")) +++" "REMARK"
			}
			Logging "+++++" "REMARK"
			Logging "" "REMARK"
			
			# Determine The HostName Of The Source RWDC
			If ($targetKrbTgtAccountNr -eq 1) {
				$targetedADdomainSourceRWDCFQDN = $null
				$targetedADdomainSourceRWDCFQDN = $dcToProcess."Host Name"
			}
			If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3) {
				$targetedADdomainDCToProcessReachability = $null
				$targetedADdomainDCToProcessReachability = $dcToProcess.Reachable

				$targetedADdomainSourceRWDCFQDN = $null
				$targetedADdomainSourceRWDCFQDN = $dcToProcess."Source RWDC FQDN"

				If ($targetedADdomainDCToProcessReachability -eq $false -Or $targetedADdomainSourceRWDCFQDN -eq "RODC Unreachable" -Or $targetedADdomainSourceRWDCFQDN -eq "Unknown") {
					$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"
					$dcToProcess."Source RWDC DSA" = (Get-ADDomainController $targetedADdomainSourceRWDCFQDN -Server $targetedADdomainSourceRWDCFQDN).NTDSSettingsObjectDN
				} Else {
					$targetedADdomainSourceRWDCReachability = $null
					$targetedADdomainSourceRWDCReachability = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN}).Reachable
					If ($targetedADdomainSourceRWDCReachability -eq $false) {
						$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"
						$dcToProcess."Source RWDC DSA" = (Get-ADDomainController $targetedADdomainSourceRWDCFQDN -Server $targetedADdomainSourceRWDCFQDN).NTDSSettingsObjectDN
					}
				}
			}
			
			# Retrieve Details Of The Source RWDC
			$targetedADdomainSourceRWDCIsPDC = $null
			$targetedADdomainSourceRWDCIsPDC = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN}).PDC
			$targetedADdomainSourceRWDCDSType = $null
			$targetedADdomainSourceRWDCDSType = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN})."DS Type"
			$targetedADdomainSourceRWDCSiteName = $null
			$targetedADdomainSourceRWDCSiteName = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN})."Site Name"
			$targetedADdomainSourceRWDCIPAddress = $null
			$targetedADdomainSourceRWDCIPAddress = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN})."IP Address"
			$targetedADdomainSourceRWDCReachability = $null
			$targetedADdomainSourceRWDCReachability = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN}).Reachable
			
			# Only Continue If The Source RWDC Is Available/Reachable To Process The Change
			If ($targetedADdomainSourceRWDCReachability -eq $true) {
				# If Mode 2, Execute The Creation Of the Temporary Canary Object, And Abort The Script If That Fails
				If ($modeOfOperationNr -eq 2) {
					$targetObjectToCheckDN = $null
					$targetObjectToCheckDN = createTempCanaryObject $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $execDateTimeCustom1 $localADforest $adminCrds
					If (!$targetObjectToCheckDN) {

						EXIT
					}
				}
				
				# If Mode 3, Simulate Password Reset Of KrbTgt TEST/BOGUS Accounts (No Password Reset/WhatIf Mode)
				# If Mode 4, Do A Real Password Reset Of KrbTgt TEST/BOGUS Accounts (Password Reset!)
				# If Mode 5, Simulate Password Reset Of KrbTgt PROD/REAL Accounts (No Password Reset/WhatIf Mode)
				# If Mode 6, Do A Real Password Reset Of KrbTgt PROD/REAL Accounts (Password Reset!)
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
					# Retrieve The KrbTgt Account Object
					$targetObjectToCheck = $null
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
						Try {
							$targetObjectToCheck = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
					If ($localADforest -eq $false -And $adminCrds) {
						Try {
							$targetObjectToCheck = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}

					# If The KrbTgt Account Object Was Found
					If ($targetObjectToCheck) {
						# If The KrbTgt Account Object Exists (You're In Deep Sh!t If The Account Does Not Exist! :-))
						# Retrieve The DN Of The KrbTgt Account Object
						$targetObjectToCheckDN = $null
						$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName			

						# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
						$objectMetadata = $null
						$objectMetadata = retrieveObjectMetadata $targetedADdomainNearestRWDCFQDN $targetObjectToCheckDN $localADforest $adminCrds
						$objectMetadataAttribPwdLastSet = $null
						$objectMetadataAttribPwdLastSet = $objectMetadata | Where-Object{$_.Name -eq "pwdLastSet"}
						$objectMetadataAttribPwdLastSetOrgRWDCFQDN = $null
						$objectMetadataAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataAttribPwdLastSet.OriginatingServer) {$objectMetadataAttribPwdLastSet.OriginatingServer} Else {"RWDC Demoted"}
						$objectMetadataAttribPwdLastSetOrgTime = $null
						$objectMetadataAttribPwdLastSetOrgTime = Get-Date $($objectMetadataAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
						$objectMetadataAttribPwdLastSetVersion = $null
						$objectMetadataAttribPwdLastSetVersion = $objectMetadataAttribPwdLastSet.Version

						# Retrieve The Password Last Set Of The KrbTgt Account Object
						$targetObjectToCheckPwdLastSet = $null
						$targetObjectToCheckPwdLastSet = Get-Date $([datetime]::fromfiletime($targetObjectToCheck.pwdLastSet))

						# If Mode 3, Do A WHAT IF Password Reset Of KrbTgt TEST/BOGUS Accounts (No Password Reset!)
						# If Mode 5, Do A WHAT IF Password Reset Of KrbTgt PROD/REAL Accounts (No Password Reset!)
						If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 5) {
							Logging "  --> According To RWDC.....................: '$targetedADdomainNearestRWDCFQDN'"
							Logging "  --> Previous Password Set Date/Time.......: '$(Get-Date $targetObjectToCheckPwdLastSet -f 'yyyy-MM-dd HH:mm:ss')'"
							Logging "  --> Originating RWDC Previous Change......: '$objectMetadataAttribPwdLastSetOrgRWDCFQDN'"
							Logging "  --> Originating Time Previous Change......: '$objectMetadataAttribPwdLastSetOrgTime'"
							Logging "  --> Current Version Of Attribute Value....: '$objectMetadataAttribPwdLastSetVersion'"
							Logging ""
							Logging "REMARK: What If Mode! NO PASSWORD RESET HAS OCCURED!" "REMARK"
							Logging ""
						}

						# If Mode 4, Do A Real Password Reset Of KrbTgt TEST/BOGUS Accounts (Password Reset!)
						# If Mode 6, Do A Real Password Reset Of KrbTgt PROD/REAL Accounts (Password Reset!)
						If ($modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 6) {
							# Calculate The Expiration Date/Time Of N-1 Kerberos Tickets
							$expirationTimeForNMinusOneKerbTickets = $null
							$expirationTimeForNMinusOneKerbTickets = (($targetObjectToCheckPwdLastSet.AddHours($targetedADdomainMaxTgtLifetimeHrs)).AddMinutes($targetedADdomainMaxClockSkewMins)).AddMinutes($targetedADdomainMaxClockSkewMins)

							# Check If It Advisable To Reset The Password Or Not.
							# If YES, Just Continue
							# If NO, Ask For Acknowledgement
							$okToReset = $null
							If ($expirationTimeForNMinusOneKerbTickets -lt [DateTime]::Now) {
								# Allow The Password Reset To Occur Without Questions If The Expiration Date/Time Of N-1 Kerberos Tickets Is Earlier Than The Current Time
								$okToReset = $True
							} Else {
								# Allow The Password Reset To Occur After Confirnation Only If The Expiration Date/Time Of N-1 Kerberos Tickets Is Equal Or Later Than The Current Time
								Logging "  --> According To RWDC.....................: '$targetedADdomainNearestRWDCFQDN'"
								Logging "  --> Previous Password Set Date/Time.......: '$(Get-Date $targetObjectToCheckPwdLastSet -f 'yyyy-MM-dd HH:mm:ss')'"
								Logging "  --> Date/Time N-1 Kerberos Tickets........: '$(Get-Date $expirationTimeForNMinusOneKerbTickets -f 'yyyy-MM-dd HH:mm:ss')'"
								Logging "  --> Date/Time Now.........................: '$(Get-Date $([DateTime]::Now) -f 'yyyy-MM-dd HH:mm:ss')'"
								Logging "  --> Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
								Logging "  --> Max Clock Skew (Minutes)..............: '$targetedADdomainMaxClockSkewMins'"
								Logging "  --> Originating RWDC Previous Change......: '$objectMetadataAttribPwdLastSetOrgRWDCFQDN'"
								Logging "  --> Originating Time Previous Change......: '$objectMetadataAttribPwdLastSetOrgTime'"
								Logging "  --> Current Version Of Attribute Value....: '$objectMetadataAttribPwdLastSetVersion'"
								Logging ""
								If ($targetKrbTgtAccountNr -eq 1) {
									Logging "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR DOMAIN WIDE IMPACT'" "WARNING"
									Logging "" "WARNING"
									Logging "What do you want to do? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
								}
								If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3) {
									Logging "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR IMPACT FOR RESOURCES SERVICED BY $($dcToProcess."Host Name")' (Site: $($dcToProcess."Site Name"))" "WARNING"
									Logging "" "WARNING"
									Logging "What do you want to do? [CONTINUE | SKIP | STOP]: " "ACTION-NO-NEW-LINE"
								}
								
								$continueOrStop = $null
								$continueOrStop = Read-Host

								If ($targetKrbTgtAccountNr -eq 1) {
									# Any Confirmation Not Equal To CONTINUE Will Be Equal To STOP
									If ($continueOrStop.ToUpper() -ne "CONTINUE") {
										$continueOrStop = "STOP"
									}
								}
								If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3) {
									# Any Confirmation Not Equal To CONTINUE And Not Equal To SKIP And Not Equal To STOP Will Be Equal To STOP
									If ($continueOrStop.ToUpper() -ne "CONTINUE" -And $continueOrStop.ToUpper() -ne "SKIP" -And $continueOrStop.ToUpper() -ne "STOP") {
										$continueOrStop = "STOP"
									}
								}
								
								Logging ""
								If ($continueOrStop.ToUpper() -eq "CONTINUE") {
									# If The Confirmation Equals CONTINUE Allow The Password Reset To Continue
									$okToReset = $True
								} Else {
									# If The Confirmation Does Not Equal CONTINUE Do Not Allow The Password Reset To Continue. Abort
									$okToReset = $False
								}
								Logging "  --> Chosen: $continueOrStop" "REMARK"
								Logging ""
							}
							If ($okToReset -eq $true) {
								# If OK To Reset Then Execute The Password Reset Of The KrbTgt Account
								setPasswordOfADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $adminCrds
							} Else {
								# If Not OK To Reset Then Abort
								
								EXIT
							}
						}
						# If Mode 3, Do A WHAT IF Password Reset Of KrbTgt TEST/BOGUS Accounts (No Password Reset!)
						# If Mode 5, Do A WHAT IF Password Reset Of KrbTgt PROD/REAL Accounts (No Password Reset!)
						If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 5) {
							
						}
					} Else {
						# If The KrbTgt Account Object Does Not Exist (You're In Deep Sh!t If The Account Does Not Exist! :-))
						Logging "  --> KrbTgt Account With sAMAccountName '$krbTgtSamAccountName' Does NOT Exist! Skipping..." "ERROR"
						Logging "" "ERROR"
					}
				}
			} Else {
				# If The Source RWDC Is NOT Reachable
				Logging ""
				Logging "The RWDC '$targetedADdomainSourceRWDCFQDN' To Make The Change On Is Not Reachable/Available..." "ERROR"
				Logging ""
			}

			# If The DN Of The Target Object To Check (Temp Canary Object Or KrbTgt Account, Depends On The Mode Chosen) Was Determined/Found
			If ($targetObjectToCheckDN) {
				# Retrieve/Define The Start List With RWDCs To Check
				If ($targetKrbTgtAccountNr -eq 1) {
					$listOfDCsToCheckObjectOnStart = $null
					$listOfDCsToCheckObjectOnStart = ($tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read/Write"})
				}
				If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3) {
					$listOfDCsToCheckObjectOnStart = @()
					$listOfDCsToCheckObjectOnStart += $tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN}
					$listOfDCsToCheckObjectOnStart += $dcToProcess
				}
				
				# Define The End List With RWDCs That Have Been Checked. Now Only Contains The Source RWDC. While Looping Through The Start List And Determing The Object Has Replicated, DCs Are Added To The End List
				$listOfDCsToCheckObjectOnEnd = @()
				
				# Define The Columns For The RWDCs In The AD Domain To Be Filled In
				$listOfDCsToCheckObjectOnEndSourceRWDCObj = "" | Select-Object "Host Name",PDC,"Site Name","DS Type","IP Address",Reachable,"Source RWDC FQDN",Time
				
				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."Host Name" = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."Host Name" = $targetedADdomainSourceRWDCFQDN
				
				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj.PDC = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj.PDC = $targetedADdomainSourceRWDCIsPDC
				
				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."DS Type" = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."DS Type" = $targetedADdomainSourceRWDCDSType

				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."Site Name" = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."Site Name" = $targetedADdomainSourceRWDCSiteName
				
				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."IP Address" = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."IP Address" = $targetedADdomainSourceRWDCIPAddress
				
				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj.Reachable = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj.Reachable = $targetedADdomainSourceRWDCReachability
				
				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."Source RWDC FQDN" = "N.A."
				
				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj.Time = 0.00
				
				# Add The Row For The RWDC To The Table
				$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndSourceRWDCObj

				# Execute The Check AD Replication Convergence Function For The Targeted Object To Check
				checkADReplicationConvergence $targetedADdomainFQDN $targetedADdomainSourceRWDCFQDN $targetObjectToCheckDN $listOfDCsToCheckObjectOnStart $listOfDCsToCheckObjectOnEnd $modeOfOperationNr $localADforest $adminCrds
			}
		}

		# If Any DC Object Exists In The Unknown DC List
		If ($collectionOfDCsNotToProcess) {
			Logging "+++++" "REMARK"
			Logging "+++ The Following Look Like DCs, But May Not Be Real DCs..." "REMARK"
			Logging "+++++" "REMARK"
			Logging "" "REMARK"

			# For Every Unknown DC
			$collectionOfDCsNotToProcess | ForEach-Object{
				$dcToProcess = $null
				$dcToProcess = $_
				Logging "$($dcToProcess | Format-Table * | Out-String)"
				Logging ""
			}
			Logging ""
		}
	}
}

### Mode 8 - Create TEST KrbTgt Accounts
If ($modeOfOperationNr -eq 8) {
	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "CREATE TEST KRBTGT ACCOUNTS (MODE 8)..." "HEADER"
	Logging ""

	# Asking Confirmation To Continue Or Not
	Logging "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
	$continueOrStop = $null
	$continueOrStop = Read-Host
	
	# Any Confirmation Not Equal To CONTINUE Will Be Equal To STOP
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		$continueOrStop = "STOP"
	}
	Logging ""
	Logging "  --> Chosen: $continueOrStop" "REMARK"
	Logging ""
	
	# Any Confirmation Not Equal To CONTINUE Will Abort The Script
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		EXIT
	}	
	
	# Retrieve The FQDN Of The RWDC With The PDC FSMO To Create The TEST/BOGUS KrbTgt Account Objects
	$targetedADdomainSourceRWDCFQDN = $null
	$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"
	
	# Determine The KrbTgt Account In Use By The RWDC with The PDC FSMO (Representative For All RWDCs In The AD Domain)
	$krbTgtSamAccountName = $null
	$krbTgtSamAccountName = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Krb Tgt"
	Logging "+++++" "REMARK"
	Logging "+++ Create Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
	Logging "+++ Used By RWDC.................: 'All RWDCs' +++" "REMARK"
	Logging "+++++" "REMARK"
	Logging "" "REMARK"
	
	# Execute The Creation Test KrbTgt Accounts Function To Create The TEST/BOGUS KrbTgt Account For RWDCs
	createTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName "RWDC" $targetedADdomainDomainSID $localADforest $adminCrds

	# For All RODCs In The AD Domain That Do Not Have An Unknown RWDC Specfied
	$tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -ne "Unknown"} | ForEach-Object{
		# Retrieve The RODC Object In The List
		$rodcToProcess = $null
		$rodcToProcess = $_
		
		# Retrieve The sAMAccountName Of The KrbTgt Account In Use By The RODC
		$krbTgtSamAccountName = $null
		$krbTgtSamAccountName = $rodcToProcess."Krb Tgt"
		
		# Retrieve The HostName Of The RODC
		$rodcFQDNTarget = $null
		$rodcFQDNTarget = $rodcToProcess."Host Name"
		
		# Retrieve The SiteName Of The RODC
		$rodcSiteTarget = $null
		$rodcSiteTarget = $rodcToProcess."Site Name"
		Logging "+++++" "REMARK"
		Logging "+++ Create Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
		Logging "+++ Used By RODC.................: '$rodcFQDNTarget' (Site: $rodcSiteTarget) +++" "REMARK"
		Logging "+++++" "REMARK"
		Logging "" "REMARK"
		
		# Execute The Create Test KrbTgt Accounts Function To Create The TEST/BOGUS KrbTgt Account For Each RODC		
		createTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName "RODC" $targetedADdomainDomainSID $localADforest $adminCrds
	}
}

### Mode 9 - Cleanup TEST KrbTgt Accounts
If ($modeOfOperationNr -eq 9) {
	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "CLEANUP TEST KRBTGT ACCOUNTS (MODE 9)..." "HEADER"
	Logging ""

	# Asking Confirmation To Continue Or Not
	Logging "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
	$continueOrStop = $null
	$continueOrStop = Read-Host
	
	# Any Confirmation Not Equal To CONTINUE Will Be Equal To STOP
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		$continueOrStop = "STOP"
	}
	Logging ""
	Logging "  --> Chosen: $continueOrStop" "REMARK"
	Logging ""
	
	# Any Confirmation Not Equal To CONTINUE Will Abort The Script
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		EXIT
	}	
	
	# Retrieve The FQDN Of The RWDC With The PDC FSMO To Delete The TEST/BOGUS KrbTgt Account Objects
	$targetedADdomainSourceRWDCFQDN = $null
	$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"
	
	# Determine The KrbTgt Account In Use By The RWDC with The PDC FSMO (Representative For All RWDCs In The AD Domain)
	$krbTgtSamAccountName = $null
	$krbTgtSamAccountName = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Krb Tgt"
	Logging "+++++" "REMARK"
	Logging "+++ Delete Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
	Logging "+++ Used By RWDC.................: 'All RWDCs' +++" "REMARK"
	Logging "+++++" "REMARK"
	Logging "" "REMARK"
	
	# Execute The Delete Test KrbTgt Accounts Function To Delete The TEST/BOGUS KrbTgt Account For RWDCs. There Is No Need To Force Deletion Of The Object On All The Other DCs As In Time It Will Be Deleted
	deleteTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $adminCrds
	
	# For All RODCs In The AD Domain That Do Not Have An Unknown RWDC Specfied
	$tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -ne "Unknown"} | ForEach-Object{
		# Retrieve The RODC Object In The List
		$rodcToProcess = $null
		$rodcToProcess = $_
		
		# Retrieve The sAMAccountName Of The KrbTgt Account In Use By The RODC
		$krbTgtSamAccountName = $null
		$krbTgtSamAccountName = $rodcToProcess."Krb Tgt"
		
		# Retrieve The HostName Of The RODC
		$rodcFQDNTarget = $null
		$rodcFQDNTarget = $rodcToProcess."Host Name"
		
		# Retrieve The SiteName Of The RODC
		$rodcSiteTarget = $null
		$rodcSiteTarget = $rodcToProcess."Site Name"
		Logging "+++++" "REMARK"
		Logging "+++ Delete Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
		Logging "+++ Used By RODC.................: '$rodcFQDNTarget' (Site: $rodcSiteTarget) +++" "REMARK"
		Logging "+++++" "REMARK"
		Logging "" "REMARK"
		
		# Execute The Delete Test KrbTgt Accounts Function To Delete The TEST/BOGUS KrbTgt Account For Each RODC. There Is No Need To Force Deletion Of The Object On All The Other DCs As In Time It Will Be Deleted
		deleteTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $adminCrds
	}
}

# Display The Full Path To The Log File
Logging ""
Logging "Log File Path...: $logFilePath" "REMARK"
Logging ""
Write-Progress -Activity AutoHarden -Status "Reset-KrbTgt-Password-For-RWDCs-And-RODCs-1.0-functions" -Completed
echo "####################################################################################################"
echo "# Reset-KrbTgt-Password-For-RWDCs-And-RODCs-2.0-calls"
echo "####################################################################################################"
Write-Progress -Activity AutoHarden -Status "Reset-KrbTgt-Password-For-RWDCs-And-RODCs-2.0-calls" -PercentComplete 0
Write-Host -BackgroundColor Blue -ForegroundColor White "Running Reset-KrbTgt-Password-For-RWDCs-And-RODCs-2.0-calls"
#https://www.it-connect.fr/active-directory-comment-reinitialiser-le-mot-de-passe-krbtgt/
Write-Progress -Activity AutoHarden -Status "Reset-KrbTgt-Password-For-RWDCs-And-RODCs-2.0-calls" -Completed
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
