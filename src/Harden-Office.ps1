try{
Get-Item -errorAction SilentlyContinue -Force "HKCU:\SOFTWARE\Microsoft\Office\*\*\" | foreach {
	$name=$_.PSPath
	Write-Host "Create $name\Security"
	New-Item -Force -Path $name -Name Security | Out-Null
}
}catch{}
try{
Get-Item -errorAction SilentlyContinue -Force "HKCU:\SOFTWARE\Microsoft\Office\*\" | foreach {
	$name=$_.PSPath
	Write-Host "Create $name\Security"
	New-Item -Force -Path $name -Name Security | Out-Null
}
}catch{}

# OfficeOLE hardens Office Packager Objects.
# 0 - No prompt from Office when user clicks, object executes.
# 1 - Prompt from Office when user clicks, object executes.
# 2 - No prompt, Object does not execute.
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name PackagerPrompt -Value 2 -errorAction SilentlyContinue

# OfficeMacros contains Macro registry keys.
# 1 - Enable all.
# 2 - Disable with notification.
# 3 - Digitally signed only.
# 4 - Disable all.
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name VBAWarnings -Value 3 -errorAction SilentlyContinue

# OfficeActiveX contains ActiveX registry keys.
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\Security" -Name DisableAllActiveX -Value 1 -errorAction SilentlyContinue
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name DisableAllActiveX -Value 1 -errorAction SilentlyContinue

# AllowDDE: part of Update ADV170021
# disables DDE for Word (default setting after installation of update)
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name AllowDDE -Value 0 -errorAction SilentlyContinue
