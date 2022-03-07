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
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NodeType /t REG_DWORD /d 2 /f