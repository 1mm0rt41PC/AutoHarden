# Enable rules
logInfo 'Enable rules'
Get-NetFirewallRule -DisplayName '*AutoHarden*' | Enable-NetFirewallRule

# Remove all rules that are not tagged
logInfo 'Remove all rules that are not tagged'
FWRemoveBadRules

# Enable all rules
Enable-NetFirewallRule -Name '*'

try{
	mkdir -Force $env:windir\system32\logfiles\firewall > $null
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
