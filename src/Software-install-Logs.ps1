##############################################################################
# Enable sysmon
if( -not (Get-Command sysmon -errorAction SilentlyContinue) ){
	chocoInstall sysmon
	$sysmonconfig = curl.exe $AutoHarden_SysmonUrl
	if( -not [String]::IsNullOrWhiteSpace($sysmonconfig) ){
		$sysmonconfig | Out-File -Encoding ASCII C:\Windows\sysmon.xml
		sysmon.exe -accepteula -i C:\Windows\sysmon.xml
		sysmon.exe -accepteula -c C:\Windows\sysmon.xml
	}
}


##############################################################################
# Log all autoruns to detect malware
# From: https://github.com/palantir/windows-event-forwarding/
if( Get-Command autorunsc -errorAction SilentlyContinue ){
	$autorunsc7z = ("${AutoHarden_Logs}\autorunsc_"+(Get-Date -Format "yyyy-MM-dd"))
	start-job -Name LogActivity_autoruns -scriptblock {
		autorunsc -nobanner /accepteula -a "*" -c -h -s -v -vt "*" | Out-File -Encoding UTF8 "${autorunsc7z}.csv"
		Compress-Archive -Path "${autorunsc7z}.csv" -CompressionLevel "Optimal" -DestinationPath "${autorunsc7z}.csv.zip"
		if( [System.IO.File]::Exists("${autorunsc7z}.csv.zip") ){
			rm -Force "${autorunsc7z}.csv"
		}
	}
}