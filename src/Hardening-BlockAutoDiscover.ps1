# Avoid credentials leak https://www.guardicore.com/labs/autodiscovering-the-great-leak/
$autodicover=Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern "127.0.0.1 autodicover"
if( [string]::IsNullOrEmpty($autodicover) ){
	$tlds = mywget -Uri 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
	$domains = $tlds.Content.ToLower().Replace("`r","").Replace("\r","").Split("`n") | where { -not [string]::IsNullOrEmpty($_) -and -not $_.StartsWith('#') } | foreach {
		echo "127.0.0.1 autodicover.$_"
	}
	$domains = $domains -join "`r`n"
	[System.IO.File]::AppendAllText("C:\Windows\System32\drivers\etc\hosts", "`r`n# [AutoHarden] Block Autodiscover`r`n$domains", (New-Object System.Text.UTF8Encoding $False));
	RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8
	ipconfig /flushdns
}