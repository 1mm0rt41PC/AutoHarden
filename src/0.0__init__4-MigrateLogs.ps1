Get-ChildItem -File $AutoHarden_Folder\*.log | foreach {
	$name = $_.Name
	$_ | Compress-Archive -CompressionLevel "Optimal" -DestinationPath ${AutoHarden_Logs}\${name}.zip -ErrorAction SilentlyContinue
}