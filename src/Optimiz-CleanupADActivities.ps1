Remove-Item -Force -Recurse C:\Users\*\AppData\Local\Microsoft\Windows\SchCache\*.sch
Get-Item registry::HKEY_USERS\*\SOFTWARE\Microsoft\ADs\Providers\LDAP | Remove-Item -Force -Recurse
Get-Item "registry::HKEY_USERS\*\SOFTWARE\Microsoft\Office\*\*\File MRU" | %{ $mypath=$_.PSPath; $_.Property | ?{ $_ -ne "FOLDERID_Desktop" -and $_ -ne "FOLDERID_Documents" } | %{ Remove-ItemProperty -Path $mypath -Name $_} }
Get-Item "registry::HKEY_USERS\*\SOFTWARE\Microsoft\Office\*\*\Place MRU" | %{ $mypath=$_.PSPath; $_.Property | ?{ $_ -ne "FOLDERID_Desktop" -and $_ -ne "FOLDERID_Documents" } | %{ Remove-ItemProperty -Path $mypath -Name $_} }
Remove-Item -Force -Recurse "registry::HKEY_USERS\*\SOFTWARE\Microsoft\Office\*\*\User MRU"
Remove-Item -Force -Recurse "registry::HKEY_USERS\*\SOFTWARE\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords"
Remove-Item -Force -Recurse "registry::HKEY_USERS\*\SOFTWARE\Microsoft\Office\*\Word\Reading Locations"
Remove-Item -Force -Recurse "registry::HKEY_USERS\*\SOFTWARE\Microsoft\Terminal Server Client\Default"
Remove-Item -Force -Recurse "registry::HKEY_USERS\*\SOFTWARE\Microsoft\Terminal Server Client\Servers"
Remove-Item -Force -Recurse "registry::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List"
Remove-Item -Force -Recurse "registry::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
Remove-Item -Force -Recurse "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\Intranet"
Remove-Item -Force -Recurse "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\IntranetForests"
Remove-Item -Force -Recurse "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\*"