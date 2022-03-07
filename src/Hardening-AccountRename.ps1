try{
if( (New-Object System.Security.Principal.NTAccount('Administrateur')).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
	Rename-LocalUser -Name Administrateur -NewName Adm | Out-Null
	Rename-LocalUser -Name Invité -NewName Administrateur | Out-Null
	Rename-LocalUser -Name Adm -NewName Invité | Out-Null
}
}catch{}
try{
if( (New-Object System.Security.Principal.NTAccount('Administrator')).Translate([System.Security.Principal.SecurityIdentifier]).value.EndsWith('-500') ){
	Rename-LocalUser -Name Administrator -NewName Adm | Out-Null
	Rename-LocalUser -Name Guest -NewName Administrator | Out-Null
	Rename-LocalUser -Name Adm -NewName Guest | Out-Null
}
}catch{}
