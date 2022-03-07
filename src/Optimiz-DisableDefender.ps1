reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v Start /t REG_DWORD /d 4 /f
# https://twitter.com/jonasLyk/status/1293815234805760000?s=20


#Remove-Item "C:\ProgramData\Microsoft\Windows Defender" -stream "omgwtfbbq" -Force -ErrorAction SilentlyContinue 
#fsutil reparsepoint delete "C:\ProgramData\Microsoft\Windows Defender"
## Can crash WINDOWS. This part will be removed in december 2020 !!!!
#cmd /c 'mklink "C:\ProgramData\Microsoft\Windows Defender:omgwtfbbq" "\??\NUL"'
