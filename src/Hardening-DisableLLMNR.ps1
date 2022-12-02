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

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v " EnableMDNS" /t REG_DWORD /d "0" /f
fwRule @{
	Name='MDNS'
	Protocol='udp'
	RemotePort=5353
	Group='Multicast'
	Direction='Outbound'
	Action='Block'
}