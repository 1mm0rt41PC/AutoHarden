if( (Get-Item "C:\Program Files*\VMware\*\vmnat.exe") -eq $null ){
	# Credentials Guard
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags /t REG_DWORD /d 1 /f
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlagsDefault /t REG_DWORD /d 1 /f
	# Credentials Guard bloque VMWare...
	# En cas de blocage, il faut désactive CG via DG_Readiness.ps1 -Disable
	# cf https://stackoverflow.com/questions/39858200/vmware-workstation-and-device-credential-guard-are-not-compatible
	# cf https://www.microsoft.com/en-us/download/details.aspx?id=53337
}