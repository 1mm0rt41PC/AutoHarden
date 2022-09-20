$adm = Get-LocalUser | Where { $_.SID.Value.EndsWith('-500') }
if( $adm.Name -eq 'Administrateur' ){
	logSuccess 'Renaming Administrateur to Invité'
	$adm | Rename-LocalUser -NewName Adm > $null
	Get-LocalUser | Where { $_.SID.Value.EndsWith('-501') } | Rename-LocalUser -NewName Administrateur > $null
	$adm | Rename-LocalUser -NewName Invité > $null
}elseif( $adm.Name -eq 'Administrator' ){
	logSuccess 'Renaming Administrator to Guest'
	$adm | Rename-LocalUser -NewName Adm > $null
	Get-LocalUser | Where { $_.SID.Value.EndsWith('-501') } | Rename-LocalUser -NewName Administrator > $null
	$adm | Rename-LocalUser -NewName Guest > $null
}else{
	logInfo 'Account already inverted'
}