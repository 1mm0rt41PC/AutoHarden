fwRule @{
	Name='SNMP'
	Group='SNMP'
	Direction='Outbound'
	Action='Block'
	Protocol='udp'
	RemotePort=161
}