# Install cert to avoid git takeover
$AutoHardenCert = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"
[IO.File]::WriteAllBytes($AutoHardenCert, [Convert]::FromBase64String("&{AutoHardenCert}"))
Import-Certificate -Filepath $AutoHardenCert -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
$AutoHardenCertCA = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"
[IO.File]::WriteAllBytes($AutoHardenCertCA, [Convert]::FromBase64String("&{AutoHardenCertCA}"))
Import-Certificate -Filepath $AutoHardenCertCA -CertStoreLocation Cert:\LocalMachine\AuthRoot | Out-Null
	
$Trigger = New-ScheduledTaskTrigger -At 08:00am -Daily
#$Action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec AllSigned -nop -File C:\Windows\AutoHarden\AutoHarden.ps1 > C:\Windows\AutoHarden\ScheduledTask.log"
$Action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec ByPass -nop -File ${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1"
$Setting = New-ScheduledTaskSettingsSet -RestartOnIdle -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)
Register-ScheduledTask -TaskName "AutoHarden_${AutoHarden_Group}" -Trigger $Trigger -User "NT AUTHORITY\SYSTEM" -Action $Action -RunLevel Highest -Settings $Setting -Force | Out-Null
if( ask "Auto update AutoHarden every day at 08h00 AM" "0-AutoUpdateFromWeb.ask" ){
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Disable-NetFirewallRule
	$tmpPS1 = -join ((65..90) + (97..122) | Get-Random -Count 25 | % {[char]$_})
	$tmpPS1 = "${AutoHarden_Folder}\${tmpPS1}.ps1"
	Invoke-WebRequest -Uri $AutoHarden_WebDomain -OutFile $tmpPS1 | Out-Null
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Enable-NetFirewallRule
	if( (Get-AuthenticodeSignature $tmpPS1).Status -eq [System.Management.Automation.SignatureStatus]::Valid ){
		logSuccess 'The downloaded PS1 has a valid signature !'
		move -force $tmpPS1 ${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1 | Out-Null
	}else{
		logError 'The downloaded PS1 has an invalid signature !'
	}
}