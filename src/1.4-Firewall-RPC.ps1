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



###################################################################################################
# RPC: Allow only authenticated RPC Clients to connect to RPC Servers
# reg add "HKLM\Software\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_SZ /f /d 1
# WARNING, a Windows update, will break all laptops.
# CONFLIC with DMA, will crash computer into bootloop
# In case of laptop locked down by dma, the computer will show an error "unable to read memory at 0x...." and the laptop will not be able to reboot.
# Fix:
#		> get a shell in rescue mode and type:
#		SET letter=C:
#		reg.exe load HKLM\hklm_system %letter%\Windows\System32\Config\system
#		reg.exe load HKLM\hklm_soft %letter%\Windows\System32\Config\software
#		reg.exe delete "HKLM\hklm_soft\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /f
#		reg.exe add HKLM\hklm_soft\Policies\Microsoft\FVE /v DisableExternalDMAUnderLock /d 0 /t REG_DWORD /f
#		reg.exe unload HKLM\hklm_system
#		reg.exe unload HKLM\hklm_soft
#		del /q %letter%\Windows\AutoHarden\*.ps1

