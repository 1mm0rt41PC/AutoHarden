# Avoid credentials leak https://www.guardicore.com/labs/autodiscovering-the-great-leak/
$autodicover=Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern "0.0.0.0 autodicover"
if( [string]::IsNullOrEmpty($autodicover) ){
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Disable-NetFirewallRule
	$tlds = Invoke-WebRequest -Uri 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
	Get-NetFirewallRule -Name '*AutoHarden*Powershell*' | Enable-NetFirewallRule

	$domains = $tlds.Content.ToLower().Replace("`r","").Replace("\r","").Split("`n") | where { -not [string]::IsNullOrEmpty($_) -and -not $_.StartsWith('#') } | foreach {
		echo "127.0.0.1 autodicover.$_"
	}
	$domains = $domains -join "`r`n"
	[System.IO.File]::AppendAllText("C:\Windows\System32\drivers\etc\hosts", "`r`n# [AutoHarden] Block Autodiscover`r`n$domains", (New-Object System.Text.UTF8Encoding $False));
	RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8
	ipconfig /flushdns
}