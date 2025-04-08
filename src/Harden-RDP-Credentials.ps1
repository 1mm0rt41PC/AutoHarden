Get-Item "HKCU:\Software\Microsoft\Terminal Server Client\Servers\*" -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse  -ErrorAction SilentlyContinue


# From: https://blog.bitsadmin.com/spying-on-users-using-rdp-shadowing?s=09
	# From: https://swarm.ptsecurity.com/remote-desktop-services-shadowing/
# 0 – No remote control allowed;
# 1 – Full Control with user’s permission;
# 2 – Full Control without user’s permission;
# 3 – View Session with user’s permission;
# 4 – View Session without user’s permission.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 0 /f
