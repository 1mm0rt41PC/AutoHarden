# Force Windows Firewall to block packets instead of just dropping them.
# 0x00000000 (default – StealthMode enabled)
# 0x00000001 (StealthMode disabled)
$value=0x00000000
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
New-ItemProperty -ErrorAction Ignore -Force -PropertyType DWORD -Name DisableStealthMode -Value $value -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile'
