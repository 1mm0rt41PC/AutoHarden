###############################################################################
# FUNCTIONS - Global
function ask( $query, $config )
{
	if( [System.IO.File]::Exists("${AutoHarden_AsksFolder}\${config}") ){
		Write-Host "# [${AutoHarden_AsksFolder}\${config}] Exist => Using the new file location"
		return _ask $query $config $AutoHarden_AsksFolder
	}
	if( [System.IO.File]::Exists("${AutoHarden_Folder}\${config}") ){
		Write-Host "# [${AutoHarden_Folder}\${config}] The new 'ask' location doesn't exist but the old one exist => Using the old file location"
		$ret = _ask $query $config $AutoHarden_Folder
		[System.IO.File]::WriteAllLines("${AutoHarden_AsksFolder}\${config}", "$ret", (New-Object System.Text.UTF8Encoding $False));
		Remove-Item -Force "${AutoHarden_Folder}\${config}" -ErrorAction Ignore;
		return $ret;
	}
	if( $askMigration.Contains($config) ){
		if( [System.IO.File]::Exists("${AutoHarden_Folder}\$($askMigration[$config])") ){
			Write-Host "# [${AutoHarden_AsksFolder}\${config}] Not found but the old configuration exist ${AutoHarden_Folder}\$($askMigration[$config])"
			$ret=cat "${AutoHarden_Folder}\$($askMigration[$config])" -ErrorAction Ignore;
			if( $config -eq 'Hardening-DisableMimikatz__Mimikatz-DomainCredAdv.ask' ){
				if( $ret -eq 'Yes' ){
					$ret = 'No'
				}else{
					$ret = 'Yes'
				}
			}
			[System.IO.File]::WriteAllLines("${AutoHarden_AsksFolder}\${config}","$ret", (New-Object System.Text.UTF8Encoding $False));
			Remove-Item -Force $AutoHarden_Folder\$askMigration[$config] -ErrorAction Ignore;
			return $ret -eq 'Yes';
		}
	}	
	Write-Host "# [${AutoHarden_AsksFolder}\${config}] This parameter is new and doesn't exist at all"
	return _ask $query $config $AutoHarden_AsksFolder
}


function _ask( $query, $config, $folder )
{
	$ret=cat "${folder}\${config}" -ErrorAction Ignore;
	logInfo "[${folder}\${config}] Checking..."
	try{
		if( [string]::IsNullOrEmpty($ret) ){
			logInfo "[${folder}\${config}] Undefined... Asking"
			if( $AutoHarden_Asks ){
				$ret = 'No'
				if( -not [Environment]::UserInteractive ){
					throw 'UserNotInteractive'
				}
				Write-Host ""
				do{
					$ret = (Read-Host "${query}? (Y/n)").substring(0,1).toupper()
				}while( $ret -ne 'Y' -and $ret -ne 'N' -and $ret -ne '' );
				if( $ret -eq 'Y' ){
					$ret = 'Yes'
				}else{
					$ret = 'No'
				}				
				logInfo "[${folder}\${config}] Admin said >$ret<"
			}else{
				logInfo "[${folder}\${config}] AutoManagement ... NOASKING => YES"
				$ret = 'Yes'
			}
			[System.IO.File]::WriteAllLines("${AutoHarden_AsksFolder}\${config}","$ret", (New-Object System.Text.UTF8Encoding $False));
		}
		logSuccess "[${folder}\${config}] is >$ret<"
		return $ret -eq 'Yes' -Or $ret -eq 'True';
	}catch{
		logError "[${folder}\${config}][WARN] An update of AutoHarden require an action from the administrator."
		if( $global:AutoHarden_boradcastMsg -And $AutoHarden_Asks ) {
			$global:AutoHarden_boradcastMsg=$false
			msg * "An update of AutoHarden require an action from the administrator. Please run ${AutoHarden_Folder}\AutoHarden.ps1"
		}
		return $false;
	}
}


function createTempFile( $data, [Parameter(Mandatory=$false)][string]$ext='' )
{
	$tmpFileName = -join ((65..90) + (97..122) | Get-Random -Count 25 | % {[char]$_});
	$tmpFileName = "${AutoHarden_Folder}\${tmpFileName}${ext}"
	[System.IO.File]::WriteAllLines($tmpFileName, $data, (New-Object System.Text.UTF8Encoding $False));
	return $tmpFileName;
}