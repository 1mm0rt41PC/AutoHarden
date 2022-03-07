reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v DontDisplayNetworkSelectionUI /d 1 /f

# WiFi Sense: Shared HotSpot Auto-Connect: Disable
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /t REG_DWORD /v value /d 0 /f
