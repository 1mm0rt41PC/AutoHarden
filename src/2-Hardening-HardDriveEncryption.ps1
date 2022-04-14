# AES 256-bit
reg add 'HKLM\SOFTWARE\Policies\Microsoft\FVE' /v EncryptionMethod  /t REG_DWORD /d 4 /f
try{
	(Get-BitLockerVolume -MountPoint 'C:').KeyProtector | foreach {
		logSuccess ('C: is protected with: {0}' -f $_.KeyProtectorType)
	}

	if( (Get-BitLockerVolume -MountPoint 'C:').KeyProtector.Count -eq 0 ){
		logError 'C: is not encrypted !'
	}
}catch{
	logError 'C: is not encrypted !'
}
# Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -TpmProtector -RecoveryKeyProtector -RecoveryKeyPath "C:\"