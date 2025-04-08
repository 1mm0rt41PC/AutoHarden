# To fix the unpredictable freez of Office apps (Outlook/Teams/OneDrive): http://aldrid.ge/W10MU-AAD-Auth
# https://techpress.net/how-to-unjoin-a-hybrid-azure-ad-join-device/
# Deny Teams&co to autojoin device to AzureAD
# If the computer in autoenrolled:
# 1) Check:
# dsregcmd.exe /debug /status
# 2) Unenroll:
# dsregcmd.exe /debug /leave (run it in SYSTEM via a scheduledtask)
#
# WARNING! do not disable DisableAADWAM or EnableADAL, it will kill the MFA on Azure, all account with WFA will not work anymore
#
# In AAD/Microsoft-Entra go to Identity > Devices > All devices > Device settings
#	- "Users may join devices to Microsoft Entra ID": SELECTED (only dedicated user)
#	- "Additional local administrators on Microsoft Entra joined devices": NONE
#	- "Require multifactor authentication (MFA) to join devices": YES
<#
# Check logs:
Get-WinEvent -LogName "Microsoft-Windows-AAD/Operational" | Where-Object { ($_.LevelDisplayName -eq "Error" -or $_.LevelDisplayName -eq "Warning") -and $_.TimeCreated -gt [DateTime]::Now.AddMinutes(-10)  }

# Run this script in the session context of the user
if( (Get-AppxPackage Microsoft.AAD.BrokerPlugin) -eq $null ){
	Write-Host "Broker service missing - reinstalling" -ForegroundColor Yellow
	Add-AppxPackage -Register "C:\Windows\SystemApps\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\Appxmanifest.xml" -DisableDevelopmentMode -ForceApplicationShutdown
}else{
	Write-Host "Broker service found - exiting now" -ForegroundColor Green
}

# Remove all cache about AAD (This part require admin priv)
Get-ItemProperty -Path "C:\Users\*\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin*" | %{ rmdir /q /s "$($_.FullName)" } | Out-Null 
#>

# Avoid Office apps (Outlook/Teams/OneDrive/...) to autojoin device to AAD
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin /v BlockAADWorkplaceJoin /d 1 /t REG_DWORD /F
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin /v autoWorkplaceJoin /d 0 /t REG_DWORD /F