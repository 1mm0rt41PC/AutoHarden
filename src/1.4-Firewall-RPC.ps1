reg add "HKLM\SOFTWARE\Microsoft\Rpc\Internet" /v Ports /t REG_MULTI_SZ /f /d "60000-65000"
reg add "HKLM\SOFTWARE\Microsoft\Rpc\Internet" /v PortsInternetAvailable /t REG_SZ /f /d N
reg add "HKLM\SOFTWARE\Microsoft\Rpc\Internet" /v UseInternetPorts /t REG_SZ /f /d N
netsh int ipv4 set dynamicport tcp start=60000 num=5000 | Out-Null
netsh int ipv4 set dynamicport udp start=60000 num=5000 | Out-Null
netsh int ipv6 set dynamicport tcp start=60000 num=5000 | Out-Null
netsh int ipv6 set dynamicport udp start=60000 num=5000 | Out-Null

function testNetshRPCPort ($ipversion, $proto)
{
	$ret=netsh int $ipversion show dynamicport $proto | Out-String
	if( $ret.Contains('60000') -and $ret.Contains('5000') ){
		logSuccess "$ipversion on $proto use the correct RPC range"
	}else{
		logError "$ipversion on $proto DO NOT USE the correct RPC range"
	}
}

testNetshRPCPort 'ipv4' 'udp'
testNetshRPCPort 'ipv4' 'tcp'
testNetshRPCPort 'ipv6' 'udp'
testNetshRPCPort 'ipv6' 'tcp'