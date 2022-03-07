###############################################################################
# FUNCTIONS - Const var
$askMigration = ConvertFrom-StringData -StringData @'
0.1-AutoUpdate.ask = 0-AutoUpdate.ask
1.2-Firewall-Office.ask = block-communication-for-excel,word.ask
1.3-Firewall-IE.ask = block-communication-for-InternetExplorer.ask
1.1-Firewall-Malware.ask = block-communication-for-powershell,eviltools.ask
Hardening-DisableMimikatz__CredentialsGuard.ask = CredentialsGuard.ask
1.4-Firewall-BlockOutgoingSNMP.ask = Hardening-BlockOutgoingSNMP.ask
Hardening-DisableMimikatz__Mimikatz-DomainCredAdv.ask = Mimikatz-DomainCred.ask
Crapware-RemoveUseLessSoftware__Uninstall-OneNote.ask = Uninstall-OneNote.ask
Crapware-RemoveUseLessSoftware__Uninstall-Skype.ask = Uninstall-Skype.ask
'@

$isLaptop = (Get-WmiObject -Class win32_systemenclosure | Where-Object { $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 -or $_.chassistypes -eq 14}).Count -gt 0 -And (Get-WmiObject -Class win32_battery).Name -ne ''

$getRole = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
$getRole = @{
	"WinNT"     = "WorkStation";
	"LanmanNT"  = "Domain Controller";
	"ServerNT"  = "Server";
}[$getRole.ProductType];

$isDomainLinked = ( "\\$($env:COMPUTERNAME)" -eq $env:LOGONSERVER -And  $getRole -eq "Domain Controller" ) -Or "\\$($env:COMPUTERNAME)" -ne $env:LOGONSERVER
