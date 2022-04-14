if( $getRole -ne 'Domain Controller' ){
	# This rule avoid users use SMB on internet
	# This rule is incompactible with PetiPotam fix which allows SMB outbound to only other DC
	FWRule @{
		Name='SMB'
		Group='Harding'
		Direction='Outbound'
		Action='Block'
		RemotePort=445
		Protocol='tcp'
		RemoteAddress=$IPForInternet
	}
}