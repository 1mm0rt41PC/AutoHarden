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
		New-NetFirewallRule -Enabled True -Profile Any @param -ErrorAction Continue > $null
	}else{
		logSuccess ("FW rule is in place: {0}" -f ($param | ConvertTo-Json))
	}
}

###############################################################################
# Remove invalid or old rule
# This version doesn't remove hidden rules. Hidden rules can only be removed via registry...
#Get-NetFirewallRule | where {
#	-not ($_.DisplayName -like "*[AutoHarden]*" -or $_.DisplayName -like "*AutoHarden*$AutoHarden_version*")
#} | Remove-NetFirewallRule -ErrorAction Continue > $null
#Get-NetFirewallRule -all -policystore configurableservicestore | where {
#	-not ($_.DisplayName -like "*[AutoHarden]*" -or $_.DisplayName -like "*AutoHarden*$AutoHarden_version*")
#} | Remove-NetFirewallRule -ErrorAction Continue > $null


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
