reg.exe add HKLM\SOFTWARE\Microsoft\Rpc\Internet /v Ports /t REG_MULTI_SZ /f /d 60000-65000
reg.exe add HKLM\SOFTWARE\Microsoft\Rpc\Internet /v PortsInternetAvailable /t REG_SZ /f /d N
reg.exe add HKLM\SOFTWARE\Microsoft\Rpc\Internet /v UseInternetPorts /t REG_SZ /f /d N
netsh int ipv4 set dynamicport tcp start=60000 num=5000
netsh int ipv4 set dynamicport udp start=60000 num=5000
netsh int ipv6 set dynamicport tcp start=60000 num=5000
netsh int ipv6 set dynamicport udp start=60000 num=5000

netsh int ipv4 show dynamicport tcp
netsh int ipv4 show dynamicport udp
netsh int ipv6 show dynamicport tcp
netsh int ipv6 show dynamicport udp