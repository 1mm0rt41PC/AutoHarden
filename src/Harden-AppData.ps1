$grpLocalAdmins = ([System.Security.Principal.SecurityIdentifier] 'S-1-5-32-544').Translate([System.Security.Principal.NTAccount])
$localApp = @('Dism++','FlowLauncher','JDownloader 2.0','Microsoft\Teams','Microsoft\WindowsApps','Microsoft\OneDrive','Obsidian','WhatsApp')
$ignoreFolders = @('Public','All Users','Default','Default User')
Get-ChildItem -Path "C:\Users" -Directory | where { -not $ignoreFolders.Contains($_.Name) } | foreach {
	$username = $_.Name
	$currentUser = ([System.Security.Principal.NTAccount] $username).Translate([System.Security.Principal.SecurityIdentifier]).ToString()
	$localApp | foreach {
		$FolderPath = "C:\Users\$username\AppData\Local\$_"
		Write-Host "Target $FolderPath"

		# Remove inheritance but preserve existing entries
		$acl = Get-Acl $FolderPath -ErrorAction SilentlyContinue
		if( $acl ){
			$acl.SetAccessRuleProtection($true,$true)
			Set-Acl $FolderPath -AclObject $acl

			$acl = Get-Acl $FolderPath
			$loUser = $acl.GetAccessRules($true,$true,[System.Security.Principal.NTAccount]) | Where-Object {$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).ToString() -eq $currentUser}
			$acl.Access | %{
				if( $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).ToString() -eq $currentUser ){
					Write-Host "Remove ACL"
					$acl.RemoveAccessRule($_)
				}
			}

			$acl.SetOwner($grpLocalAdmins)
			$rule = New-Object System.Security.AccessControl.FileSystemAccessRule([System.Security.Principal.NTAccount] $username,'ReadAndExecute',"ContainerInherit, ObjectInherit", "None",'Allow')
			$acl.AddAccessRule($rule)
			Set-Acl $FolderPath $acl | Out-Null
		}
	}
	reg.exe ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "C:\Users\$username\AppData\Local\signal-desktop-updater\installer.exe" /d "~ RUNASADMIN" /f
	reg.exe ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "C:\Users\$username\AppData\Local\Microsoft\Teams\current\Squirrel.exe" /d "~ RUNASADMIN" /f
	reg.exe ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "C:\Users\$username\AppData\Local\Microsoft\Teams\Update.exe" /d "~ RUNASADMIN" /f
	reg.exe ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "C:\Users\$username\AppData\Local\FlowLauncher\Update.exe" /d "~ RUNASADMIN" /f
	reg.exe ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "C:\Users\$username\AppData\Local\WhatsApp\Update.exe" /d "~ RUNASADMIN" /f
}