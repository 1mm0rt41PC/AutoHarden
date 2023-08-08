# By https://github.com/starbuck3000
# UAC - Ensure 'User Account Control: Consent prompt behavior' is set to '2' (2 = Prompt for username and password AND require secure desktop)
# More information: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f