reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /t REG_DWORD /v NoAutoRebootWithLoggedOnUsers /d 1 /f
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /Disable
if( !(Test-Path -PathType Container "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot") ){
	schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Reboot" /Disable
	ren "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot" "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot.bak"
	md "$env:WINDIR\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot"
}
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /t REG_DWORD /v ActiveHoursStart /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /t REG_DWORD /v ActiveHoursEnd /d 23 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /t REG_DWORD /v IsActiveHoursEnabled /d 1 /f
