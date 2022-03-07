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