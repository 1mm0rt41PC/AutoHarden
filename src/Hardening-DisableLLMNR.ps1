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