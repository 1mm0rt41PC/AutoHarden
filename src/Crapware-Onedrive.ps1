$x86="$env:SYSTEMROOT\System32\OneDriveSetup.exe"
$x64="$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
$onedriverPath = $false
if( [System.IO.File]::Exists($x86) ){
	$onedriverPath = "$x86"
}elseif( [System.IO.File]::Exists($x64) ){
	$onedriverPath = "$x64"
}
if( $onedriverPath ){
	taskkill /f /im OneDrive.exe >$null 2>&1
	# Suppression du fichier
	takeown /F "$onedriverPath" /A
	icacls "$onedriverPath" /grant:r Utilisateurs:F
	icacls "$onedriverPath" /grant:r Administrateurs:F
	Remove-Item -Recurse -Force "$onedriverPath" -ErrorAction SilentlyContinue
	
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:USERPROFILE\OneDrive" | Out-Null
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:USERPROFILE\OneDrive" | Out-Null
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "C:\OneDriveTemp" | Out-Null
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:LOCALAPPDATA\Microsoft\OneDrive" | Out-Null
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:PROGRAMDATA\Microsoft OneDrive" | Out-Null
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:PROGRAMDATA\Microsoft OneDrive" | Out-Null
	echo "Removing OneDrive from the Explorer Side Panel."
	echo .
	reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>&1
	reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>&1
}
# Suppression du OneDrive de explorer
reg add 'HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f
reg add 'HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f

# Désactivation de OneDrive
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OneDrive' /v PreventNetworkTrafficPreUserSignIn /t REG_DWORD /d 1 /f
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive' /v DisableFileSync /t REG_DWORD /d 1 /f
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive' /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f

[System.Environment]::SetEnvironmentVariable('OneDrive','NUL',[System.EnvironmentVariableTarget]::User)
[System.Environment]::SetEnvironmentVariable('OneDrive','NUL',[System.EnvironmentVariableTarget]::Machine)