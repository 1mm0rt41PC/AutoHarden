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