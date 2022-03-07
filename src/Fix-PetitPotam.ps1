###############################################################################
# Fix for DC
if( $getRole -eq 'Domain Controller' ){
	# Avoid the usage of the HTTP2SMB convertor (WebClient)
	# WebClient is not installed by default on DC
	sc.exe config webclient start= disabled 2>$null >$null
	
	
	# Filter SMB communication to allow only SMB <=> SMB between DC
	$domainDontrollerList = (Get-DnsClientGlobalSetting).SuffixSearchList | foreach {
		Resolve-DnsName -Type ALL -Name _ldap._tcp.dc._msdcs.$_
	} | foreach {
		$_.IP4Address
	} | sort -unique
	
	fwRule @{
		Name='DC2DC'
		Group='PetitPotam'
		Direction='*'
		Action='Allow'
		RemoteAddress=$domainDontrollerList
	}
	fwRule @{
		Name='DC2DC'
		Group='PetitPotam'
		Direction='Outbound'
		Action='Block'
		Protocol='tcp'
		RemotePort=445
	}
}

# Add a rule to drop access to EFS for non DA
# From: https://twitter.com/tiraniddo/status/1422223511599284227
# From: https://gist.github.com/tyranid/5527f5559041023714d67414271ca742
addRpcAcl -name 'EFS' -uuid @('c681d488-d850-11d0-8c52-00c04fd90f7e', 'df1941c5-fe89-4e79-bf10-463657acf44d')