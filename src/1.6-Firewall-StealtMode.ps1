# Force Windows Firewall to block packets instead of just dropping them.
# 0x00000000 (default – StealthMode enabled)
# 0x00000001 (StealthMode disabled)
$value=0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"   /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"   /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"                                /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"                               /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"                                /d $value /v DisableStealthMode /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"                              /d $value /v DisableStealthMode /t REG_DWORD /f
