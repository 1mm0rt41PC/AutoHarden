# Network access: Do not allow storage of passwords and credentials for network authentication
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableDomainCreds /t REG_DWORD /d 1 /f
# The memory will be cleared in 30 seconds after the user has logged off.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v TokenLeakDetectDelaySecs /t REG_DWORD /d 30 /f
# 'Allow all' = '0'
# 'Deny all domain accounts' = '1'
# 'Deny all accounts' = '2'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictReceivingNTLMTraffic /t REG_DWORD /d 2 /f
# 0) All all
# 1) Audit
# 2) Disable NetNTLM auth
# /!\ On domain controller use (2) to force kerberos only and avoid coercing.
# 		It's possible to all ip for Kerberos auth. clients allow IPv4 and IPv6 address hostnames in Service Principal Names (SPNs)
#		https://learn.microsoft.com/en-us/windows-server/security/kerberos/configuring-kerberos-over-ip
#		reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v TryIPSPN /t REG_DWORD /d 1 /f
#		Setspn -s <service>/ip.address> <domain-user-account>
#		Setspn -s host/192.168.1.1 server01
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 1 /f


# 0x00000010  = Require message integrity
# 0x00000020  = Require message confidentiality
# 0x00080000  = Require NTLMv2 session security
# 0x20000000  = Require 128-bit encryption
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 0x20080000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 0x20080000 /f


# Send LM & NTLM responses = 0
# Send LM & NTLM – use NTLMv2 session security if negotiated = 1
# Send NTLM response only = 2
# Send NTLMv2 response only = 3
# Send NTLMv2 response only. Refuse LM = 4
# Send NTLMv2 response only. Refuse LM & NTLM = 5
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f