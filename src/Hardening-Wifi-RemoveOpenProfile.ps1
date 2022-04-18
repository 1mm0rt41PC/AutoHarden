netsh wlan export profile folder=C:\Windows\Temp | Out-Null
Get-Item C:\Windows\temp\Wi-Fi-*.xml | foreach {
	$xml=[xml] (Get-Content $_.FullName)
	Write-Host "[*] Lecture du profile wifi $($_.Name)"
	if( $xml.WLANProfile.MSM.security.authEncryption.authentication.ToLower() -eq "open" ){
		$p=$xml.WLANProfile.SSIDConfig.SSID.name.Replace('"','')
		logSuccess "[*] Suppression du profile wifi $p"
		netsh wlan delete profile name="$p" interface=*
	}
}
Remove-Item C:\Windows\temp\Wi-Fi-*.xml | Out-Null