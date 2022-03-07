if( -not (ask "Disable WindowsDefender" "Optimiz-DisableDefender.ask") -and (ask "Harden Windows Defender" "Harden-WindowsDefender.ask") ){
	# From https://gist.github.com/decay88/5bd6b2c9ebf681324847e541ba1fb191
	# From https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
	################################################################################################################
	# Windows Defender Device Guard - Exploit Guard Policies (Windows 10 Only)
	# Enable ASR rules in Win10 ExploitGuard (>= 1709) to mitigate Office malspam
	# Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
	# Note these only work when Defender is your primary AV
	# Sources:
	# https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office
	# https://www.darkoperator.com/blog/2017/11/8/windows-defender-exploit-guard-asr-obfuscated-script-rule
	# https://www.darkoperator.com/blog/2017/11/6/windows-defender-exploit-guard-asr-vbscriptjs-rule
	# https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction
	# https://demo.wd.microsoft.com/Page/ASR2
	# https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSettings/1.2/Content/WindowsDefender_InternalEvaluationSettings.ps1
	# ---------------------
	#%programfiles%\"Windows Defender"\MpCmdRun.exe -RestoreDefaults
	#
	# Block Office applications from creating child processes
	Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block Office applications from injecting code into other processes
	Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block Win32 API calls from Office macro
	Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block Office applications from creating executable content
	Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block execution of potentially obfuscated scripts
	Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block executable content from email client and webmail
	Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block JavaScript or VBScript from launching downloaded executable content
	Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
	#
	# Block executable files from running unless they meet a prevalence, age, or trusted list criteria
	Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
	#
	# Use advanced protection against ransomware
	Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
	
	if( (Get-Item "C:\Program Files*\VMware\*\vmnat.exe") -eq $null ){
		# Block credential stealing from the Windows local security authority subsystem (lsass.exe)
		Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
	}else{
		Remove-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2
	}
	#
	# Block untrusted and unsigned processes that run from USB
	#A TEST#########Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
	#
	# Enable Controlled Folder
	#Set-MpPreference -EnableControlledFolderAccess Enabled
	#
	# Enable Cloud functionality of Windows Defender
	#A TEST#########Set-MpPreference -MAPSReporting Advanced
	#A TEST#########Set-MpPreference -SubmitSamplesConsent Always
	#
	# Enable Network protection
	# Enabled - Users will not be able to access malicious IP addresses and domains
	# Disable (Default) - The Network protection feature will not work. Users will not be blocked from accessing malicious domains
	# AuditMode - If a user visits a malicious IP address or domain, an event will be recorded in the Windows event log but the user will not be blocked from visiting the address.
	Set-MpPreference -EnableNetworkProtection Enabled 
	#
	################################################################################################################
	# Enable exploit protection (EMET on Windows 10)
	# Sources:
	# https://www.wilderssecurity.com/threads/process-mitigation-management-tool.393096/
	# https://blogs.windows.com/windowsexperience/2018/03/20/announcing-windows-server-vnext-ltsc-build-17623/
	# ---------------------
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Disable-NetFirewallRule
	Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/ProcessMitigation.xml -OutFile $env:temp\ProcessMitigation.xml
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Enable-NetFirewallRule
	Set-ProcessMitigation -PolicyFilePath $env:temp\ProcessMitigation.xml
	rm $env:temp\ProcessMitigation.xml
}else{
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 2>$null
	Remove-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 2>$null
	Set-MpPreference -EnableNetworkProtection Disabled 2>$null
}