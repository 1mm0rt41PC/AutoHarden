$adm = Get-LocalUser | Where { $_.SID.Value.EndsWith('-500') }
if( $adm.Name -eq 'Administrateur' ){
	logSuccess 'Renaming Administrateur to Invité'
	$adm | Rename-LocalUser -NewName Adm | Out-Null
	Get-LocalUser | Where { $_.SID.Value.EndsWith('-501') } | Rename-LocalUser -NewName Administrateur | Out-Null
	$adm | Rename-LocalUser -NewName Invité | Out-Null
}elseif( $adm.Name -eq 'Administrator' ){
	logSuccess 'Renaming Administrator to Guest'
	$adm | Rename-LocalUser -NewName Adm | Out-Null
	Get-LocalUser | Where { $_.SID.Value.EndsWith('-501') } | Rename-LocalUser -NewName Administrator | Out-Null
	$adm | Rename-LocalUser -NewName Guest | Out-Null
}else{
	logInfo 'Account already inverted'
}