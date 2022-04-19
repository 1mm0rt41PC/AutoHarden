# AutoHarden - A simple script that automates Windows Hardening
#
# Filename: build.ps1
# Author: 1mm0rt41PC - immortal-pc.info - https://github.com/1mm0rt41PC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
param([switch]$RefreshRules = $false, [switch]$RemoveSymLink = $false)
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
$MyDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
$date = Get-Date -Format 'yyyy-MM-dd-HH-mm-ss'

mkdir -Force "${PSScriptRoot}\tmp\" > $null
mkdir -Force "${PSScriptRoot}\cert\" > $null
if( -not [System.IO.File]::Exists("${PSScriptRoot}\cert\AutoHarden-CA.pvk") -or -not [System.IO.File]::Exists("${PSScriptRoot}\cert\AutoHarden-CA.cer") ){
	makecert -n "CN=AutoHarden-CA" -a sha512 -len 4096 -eku 1.3.6.1.5.5.7.3.3 -r -ss Root -sr localmachine -sy 1mm0rt41PC -sv ${PSScriptRoot}\cert\AutoHarden-CA.pvk ${PSScriptRoot}\cert\AutoHarden-CA.cer
}
if( -not [System.IO.File]::Exists("${PSScriptRoot}\cert\AutoHarden.pfx") -or -not [System.IO.File]::Exists("${PSScriptRoot}\cert\AutoHarden.cer") ){
	makecert -n "CN=AutoHarden" -a sha512 -len 4096 -eku 1.3.6.1.5.5.7.3.3 -pe -ss MY -iv ${PSScriptRoot}\cert\AutoHarden-CA.pvk -ic ${PSScriptRoot}\cert\AutoHarden-CA.cer -sy 1mm0rt41PC
	$password = (Get-Credential -UserName AutoHarden -Message "Password for certificate").Password
	$cert = ls Cert:\CurrentUser\My\ | where { $_.Subject.ToString() -eq "CN=AutoHarden" }
	Export-PfxCertificate -Cert $cert -FilePath ${PSScriptRoot}\cert\AutoHarden.pfx -Password $password -Force > $null
	Export-Certificate -Cert $cert -FilePath ${PSScriptRoot}\cert\AutoHarden.cer -Force > $null
}
$cert = ls Cert:\CurrentUser\My\ | where { $_.Subject.ToString() -eq "CN=AutoHarden" }
$AutoHardenCertCA = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$PSScriptRoot\cert\AutoHarden-CA.cer"))
$AutoHardenCert = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$PSScriptRoot\cert\AutoHarden.cer"))
$utf8 = New-Object System.Text.UTF8Encoding $False


if( $RefreshRules ){
	# Clean all symlink
	sudo powershell -exec bypass -Nop -Command "& $MyDir\WebDomain\DispatchRules.ps1"
}


Get-ChildItem -Directory ${PSScriptRoot}\WebDomain\* | foreach {
	$AutoHarden_Group = $_.Name
	$WebDomainPath=$_.FullName
	$outps1 = "AutoHarden_${AutoHarden_Group}.ps1"
	echo '####################################################################################################'
	echo $AutoHarden_Group
	echo '####################################################################################################'
	
	$insertAllAsks = $true
	$data = (Get-ChildItem $WebDomainPath\*.ps1 | foreach {
		Write-Host $_.FullName
		if( -not $_.FullName.Contains('__init__')  -And -not $_.FullName.Contains('__END__') ){
			if( $insertAllAsks ){
				# Get a list of all ASK
				echo '####################################################################################################'
				echo 'logInfo "Asking questions for the configuration"'
				Get-ChildItem $WebDomainPath\*.ps1 | foreach {
					if( [System.IO.File]::Exists($_.FullName.Replace('.ps1','.ask')) ){
						Get-ChildItem $_.FullName.Replace('.ps1','.ask')
					}elseif( -Not [string]::IsNullOrEmpty($_.Target) -And [System.IO.File]::Exists($_.Target.Replace('.ps1','.ask')) ){
						Get-ChildItem $_.Target.Replace('.ps1','.ask')
					}
				} | foreach {
					echo ('ask "'+(cat $_.FullName.Replace('.ps1','.ask')).Replace('"',"'")+'" "'+($_.Name.Replace('.ps1','.ask'))+'"')
				}
				echo 'logSuccess "All asks have been processed"'
				echo '####################################################################################################'
				$insertAllAsks = $false
			}
			
			
			echo 'echo "####################################################################################################"'
			echo ('echo "# '+$_.Name.Replace('.ps1','')+'"')
			echo 'echo "####################################################################################################"'
			echo ('Write-Progress -Activity AutoHarden -Status "'+$_.Name.Replace('.ps1','')+'" -PercentComplete 0')
			echo ('Write-Host -BackgroundColor Blue -ForegroundColor White "Running '+$_.Name.Replace('.ps1','')+'"')
		}
		$isAsk=$false
		if( [System.IO.File]::Exists($_.FullName.Replace('.ps1','.ask')) ){
			echo ('if( ask "'+(cat $_.FullName.Replace('.ps1','.ask')).Replace('"',"'")+'" "'+($_.Name.Replace('.ps1','.ask'))+'" ){')
			$isAsk=$true
		}elseif( -Not [string]::IsNullOrEmpty($_.Target) -And [System.IO.File]::Exists($_.Target.Replace('.ps1','.ask')) ){
			echo ('if( ask "'+(cat $_.Target.Replace('.ps1','.ask')).Replace('"',"'")+'" "'+(Get-ChildItem $_.Target).Name.Replace('.ps1','.ask')+'" ){')
			$isAsk=$true
		}
		cat $_.FullName
		if( $isAsk ){
			echo '}'
		}
		if( $isAsk ){
			if( [System.IO.File]::Exists($_.FullName.Replace('.ps1','.rollback')) ){
				echo 'else{'
				cat $_.FullName.Replace('.ps1','.rollback')
				echo '}'
			}elseif( -Not [string]::IsNullOrEmpty($_.Target) -And [System.IO.File]::Exists($_.Target.Replace('.ps1','.rollback')) ){
				echo 'else{'
				cat $_.Target.Replace('.ps1','.rollback')
				echo '}'
			}
		}
		if( -not $_.FullName.Contains('__init__') -And -not $_.FullName.Contains('__END__') ){
			echo ('Write-Progress -Activity AutoHarden -Status "'+$_.Name.Replace('.ps1','')+'" -Completed')
		}
	}).Replace('&{AutoHarden_ScriptName}',$outps1).Replace('&{AutoHardenCert}',$AutoHardenCert).Replace('&{AutoHardenCertCA}', $AutoHardenCertCA).Replace('&{date}',$date).Replace('&{AutoHarden_Group}',$AutoHarden_Group)
	
	[System.IO.File]::WriteAllLines("$MyDir\tmp\$outps1", $data, $utf8);

	if( Set-AuthenticodeSignature -filepath "$MyDir\tmp\$outps1" -cert $cert -IncludeChain All ){
		Write-Host 'Signature OK'
		mv -Force "$MyDir\tmp\$outps1" "$MyDir\$outps1"
	}
}

if( $RemoveSymLink ){
	Get-ChildItem -Recurse -Force $MyDir\WebDomain\*\*.ps1 |where { $_.LinkType } | Remove-Item
	$host.SetShouldExit(0)
	exit 0
}