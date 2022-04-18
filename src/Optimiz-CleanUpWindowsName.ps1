$finalUser='Administrateur'
try{
	if( -Not (New-Object System.Security.Principal.NTAccount($finalUser)).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
		$finalUser='Invité'
	}
}catch{
	$finalUser='Administrator'
	if( -Not (New-Object System.Security.Principal.NTAccount($finalUser)).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
		$finalUser='Guest'
	}
}


function killfakename( $file ){
	echo "$file ========="
	#takeown.exe /f $file
	icacls.exe "$file" /setowner $env:username | Out-Null
	remove-item -Force $file | Out-Null
	echo '' | Out-File $file
	icacls.exe "$file" /setowner $finalUser | Out-Null
	attrib +s +h $file | Out-Null
	#(Get-Acl $file).Owner
	#(Get-Acl $file).Access
}

killfakename 'C:\Users\desktop.ini'
killfakename 'C:\Program Files\desktop.ini'
killfakename 'C:\Program Files (x86)\desktop.ini'
