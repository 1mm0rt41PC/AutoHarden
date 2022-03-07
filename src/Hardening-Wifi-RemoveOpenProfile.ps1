netsh wlan export profile folder=C:\Windows\Temp
get-item C:\Windows\temp\Wi-Fi-*.xml | foreach {
	$xml=[xml] (cat $_.FullName)
	Write-Host "[*] Lecture du profile wifi $($_.Name)"
	if( $xml.WLANProfile.MSM.security.authEncryption.authentication.ToLower() -eq "open" ){
		$p=$xml.WLANProfile.SSIDConfig.SSID.name.Replace('"','')
		Write-Host "[*] Suppression du profile wifi $p"		
		netsh wlan delete profile name="$p" interface=*
	}
}
rm C:\Windows\temp\Wi-Fi-*.xml | Out-Null