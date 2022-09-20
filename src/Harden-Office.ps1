try{
Get-Item -errorAction SilentlyContinue -Force "HKCU:\SOFTWARE\Microsoft\Office\*\*\" | foreach {
	$name=$_.PSPath
	Write-Host "Create $name\Security"
	New-Item -Force -Path $name -Name Security > $null
}
}catch{}
try{
Get-Item -errorAction SilentlyContinue -Force "HKCU:\SOFTWARE\Microsoft\Office\*\" | foreach {
	$name=$_.PSPath
	Write-Host "Create $name\Security"
	New-Item -Force -Path $name -Name Security > $null
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

# If you enable this policy setting, macros are blocked from running, even if "Enable all macros" is selected in the Macro Settings section of the Trust Center. Also, instead of having the choice to "Enable Content," users will receive a notification that macros are blocked from running. If the Office file is saved to a trusted location or was previously trusted by the user, macros will be allowed to run.
#Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Security" -Name BlockContentExecutionFromInternet -Value 1 -errorAction SilentlyContinue

Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Options" -Name DontUpdateLinks -Value 1 -errorAction SilentlyContinue
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Office\*\*\Options\WordMail" -Name DontUpdateLinks -Value 1 -errorAction SilentlyContinue