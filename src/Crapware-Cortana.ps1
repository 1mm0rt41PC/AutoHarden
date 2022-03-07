reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowCortana /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowCortana /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowSearchToUseLocation /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v AllowCortanaAboveLock /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v DisableWebSearch /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /t REG_DWORD /v ConnectedSearchUseWeb /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /t REG_DWORD /v BingSearchEnabled /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v PublishUserActivities /d 0 /f
# From: Fireice
# https://www.winhelponline.com/blog/disable-web-results-windows-10-start-menu/
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /t REG_DWORD /v DisableSearchBoxSuggestions /d 1 /f
Get-appxpackage -allusers *Microsoft.549981C3F5F10* | Remove-AppxPackage