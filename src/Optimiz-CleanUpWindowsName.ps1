function killfakename( $file )
{
	echo "$file ========="
	$null | out-file "$file.acl"
	icacls "$file" /save "$file.acl"
	icacls.exe "$file" /setowner $env:username
	remove-item -Force $file
	echo '' | Out-File $file
	icacls "$file.acl" /save "$file"
	attrib +s +h $file
	remove-item -Force "$file.acl"
	(Get-Acl $file).Owner
	#(Get-Acl $file).Access
}
killfakename 'C:\Users\desktop.ini'
killfakename 'C:\Program Files\desktop.ini'
killfakename 'C:\Program Files (x86)\desktop.ini'
