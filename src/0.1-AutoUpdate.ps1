$ps1TestSign = "${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1"
if( -not [System.IO.File]::Exists($ps1TestSign) ){
	$ps1TestSign = "${AutoHarden_Folder}\AutoHarden.ps1"
}
if( -not [System.IO.File]::Exists($ps1TestSign) ){
	$ps1TestSign = $null
}
for( $i=3; $i -gt 0; $i-- )
{
	# Install cert to avoid git takeover
	$AutoHardenCert = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"
	while( -not [System.IO.File]::Exists($AutoHardenCert) )
	{
		[IO.File]::WriteAllBytes($AutoHardenCert, [Convert]::FromBase64String("&{AutoHardenCert}"))
		Import-Certificate -Filepath $AutoHardenCert -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
	}

	$AutoHardenCertCA = "${env:temp}\"+[System.IO.Path]::GetRandomFileName()+".cer"
	while( -not [System.IO.File]::Exists($AutoHardenCertCA) )
	{
		[IO.File]::WriteAllBytes($AutoHardenCertCA, [Convert]::FromBase64String("&{AutoHardenCertCA}"))
		Import-Certificate -Filepath $AutoHardenCertCA -CertStoreLocation Cert:\LocalMachine\AuthRoot | Out-Null
	}
	try{
		Remove-Item -ErrorAction SilentlyContinue -Force $AutoHardenCert $AutoHardenCertCA
	}catch{}

	if( $ps1TestSign -ne $null -and (Get-AuthenticodeSignature $ps1TestSign).Status -eq [System.Management.Automation.SignatureStatus]::Valid ){
		$i=0;
	}
}

$Trigger = New-ScheduledTaskTrigger -At 08:00am -Daily
#$Action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec AllSigned -nop -File C:\Windows\AutoHarden\AutoHarden.ps1 > C:\Windows\AutoHarden\ScheduledTask.log"
$Action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-exec ByPass -nop -File ${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1"
$Setting = New-ScheduledTaskSettingsSet -RestartOnIdle -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)
Register-ScheduledTask -TaskName "AutoHarden_${AutoHarden_Group}" -Trigger $Trigger -User "NT AUTHORITY\SYSTEM" -Action $Action -RunLevel Highest -Settings $Setting -Force | Out-Null
if( ask "Auto update AutoHarden every day at 08h00 AM" "0-AutoUpdateFromWeb.ask" ){
	$tmpPS1 = -join ((65..90) + (97..122) | Get-Random -Count 25 | % {[char]$_})
	$tmpPS1 = "${AutoHarden_Folder}\${tmpPS1}.ps1"
	mywget -Uri $AutoHarden_WebDomain -OutFile $tmpPS1 | Out-Null
	if( (Get-AuthenticodeSignature $tmpPS1).Status -eq [System.Management.Automation.SignatureStatus]::Valid ){
		logSuccess 'The downloaded PS1 has a valid signature !'
		Move-Item -force $tmpPS1 ${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1 | Out-Null
	}else{
		logError 'The downloaded PS1 has an invalid signature !'
	}
}
if( [System.IO.File]::Exists("${AutoHarden_Folder}\AutoHarden_${AutoHarden_Group}.ps1") -And (Get-ScheduledTask -TaskName "AutoHarden_${AutoHarden_Group}" -ErrorAction SilentlyContinue) -ne $null ){
	Unregister-ScheduledTask -TaskName "AutoHarden" -Confirm:$False -ErrorAction SilentlyContinue
}