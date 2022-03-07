# Enable rules
logInfo 'Enable rules'
Get-NetFirewallRule -DisplayName '*AutoHarden*' | Enable-NetFirewallRule

# Remove all rules that are not tagged
logInfo 'Remove all rules that are not tagged'
FWRemoveBadRules


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

