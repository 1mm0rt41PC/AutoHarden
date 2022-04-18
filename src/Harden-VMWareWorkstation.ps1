# Disable VM Sharing (free the port 443/TCP)
@("VMwareHostd") | foreach {
	$srv = Get-Service -ErrorAction SilentlyContinue $_
	if( $srv -eq $null -or $srv.Count -eq 0 ){
		logInfo "Service >$_< is not INSTALLED"
	}elseif( (Get-Service -ErrorAction SilentlyContinue $_).StartType -eq "Disabled" ){
		logInfo "Service >$_< is already disabled"
	}else{
		Stop-Service -ErrorAction SilentlyContinue -Force -Name $_
		Set-Service -ErrorAction SilentlyContinue -Name $_ -Status Stopped -StartupType Disabled
		logSuccess "Service >$_< has been disabled"
	}
}