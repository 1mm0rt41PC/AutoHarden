# Enable UAC
# This key is called EnableLUA because User Access Control was previously called Limited User Account (LUA).
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableLUA /d 1 /f