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

$global:buff = ''
function toBuff( $data )
{
	$global:buff += $data + "`r`n"
}

Get-ChildItem -Directory ${PSScriptRoot}\WebDomain\* | foreach {
	$AutoHarden_Group = $_.Name
	$WebDomainPath=$_.FullName
	$global:buff = ''
	$outps1 = "AutoHarden_${AutoHarden_Group}.ps1"
	Write-Host '####################################################################################################'
	Write-Host $AutoHarden_Group
	Write-Host '####################################################################################################'

	Write-Host '[i] Reading init files'
	Get-ChildItem $WebDomainPath\*__init__*.ps1 | foreach {
		toBuff (cat $_.FullName | out-string)
	}

	Write-Host '[i] Reading asks files'
	toBuff '####################################################################################################'
	toBuff 'logInfo "Asking questions for the configuration"'
	Get-ChildItem ${PSScriptRoot}\src\*.ask | foreach {
		toBuff ('ask "'+(cat $_.FullName | out-string).Trim().Replace('"',"'")+'" "'+$_.Name+'" | Out-Null')
	}
	toBuff '$global:asks_cache | Format-Table -Autosize'
	toBuff 'logSuccess "All asks have been processed"'
	toBuff '####################################################################################################'
	
	Write-Host "[i] Reading all other $WebDomainPath\*.ps1 files"
	Get-ChildItem $WebDomainPath\*.ps1 | where { -not $_.FullName.Contains('__init__') } | foreach {
		Write-Host ('	[i] Reading '+$_.Name)
		toBuff 'echo "####################################################################################################"'
		toBuff ('echo "# '+$_.Name.Replace('.ps1','')+'"')
		toBuff 'echo "####################################################################################################"'
		toBuff ('Write-Progress -Activity AutoHarden -Status "'+$_.Name.Replace('.ps1','')+'" -PercentComplete 0')
		toBuff ('Write-Host -BackgroundColor Blue -ForegroundColor White "Running '+$_.Name.Replace('.ps1','')+'"')
		
		$f = "{0}\src\{1}" -f $PSScriptRoot,$_.Name.Replace('.ps1','.ask')
		if( [System.IO.File]::Exists($f) ){
			toBuff ('$q=ask "'+(cat $f | out-string).Trim().Replace('"',"'")+'" "'+($_.Name.Replace('.ps1','.ask'))+'"')
			toBuff 'if( $q -eq $true ){'
			toBuff (cat $_.FullName | out-string)
			
			$f = "{0}\src\{1}" -f $PSScriptRoot,$_.Name.Replace('.ps1','.rollback')
			if( [System.IO.File]::Exists($f) ){
				toBuff '}elseif($q -eq $false){'
				toBuff (cat $f | out-string)
			}
			toBuff '}'
		}else{
			toBuff (cat $_.FullName | out-string)
		}
		toBuff ('Write-Progress -Activity AutoHarden -Status "'+$_.Name.Replace('.ps1','')+'" -Completed')
	}
	$data = $global:buff.Replace('&{AutoHarden_ScriptName}',$outps1).Replace('&{AutoHardenCert}',$AutoHardenCert).Replace('&{AutoHardenCertCA}', $AutoHardenCertCA).Replace('&{date}',$date).Replace('&{AutoHarden_Group}',$AutoHarden_Group)

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