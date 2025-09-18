$global:hkcu = (Get-ChildItem REGISTRY::HKEY_USERS -ErrorAction SilentlyContinue | Select Name).Name
function reg_fast_hkcu()
{
	$action = $args[0].ToLower()
	$hk     = $args[1].Replace('HKCU:\','').Replace('HKCU','').Replace('HKEY_CURRENT_USER','')

	$type  = 'REG_DWORD'
	$key   = ''
	$value = ''

	for( $i=2; $i -lt $args.Count; $i+=2 )
	{
		if( $args[$i] -eq '/t' ){
			$type=$args[$i+1]
		}elseif( $args[$i] -eq '/v' ){
			$key=$args[$i+1]
		}elseif( $args[$i] -eq '/d' ){
			$value=$args[$i+1]
		}elseif( $args[$i] -eq '/f' ){
			$i-=1
			# Pass
		}
	}
	$value = "$value".PadLeft(8,'0')
	return $global:hkcu | foreach {
		$name = $_.Trim('\')
		$name = ('{0}\{1}' -f $name,$hk).Replace('\\','\')
		return "[$name]`r`n`"$key`"=dword:$value"
	}
}

$regFile = "$($env:tmp)\$([guid]::NewGuid().ToString()).reg"
Write-Host "[.] Using temp file reg $regFile"
echo "Windows Registry Editor Version 5.00`r`n" | Out-File -Encoding ASCII $regFile
$apps = @('Publisher','Word','Excel','PowerPoint','Outlook','Access','Lync','OneNote')
@('8.0','12.0','13.0','14.0','15.0','16.0','17.0','18.0') | %{
	$ver = $_
	$apps | %{
		Write-Host "[.] ========================================= $($app.PadLeft(15)):$($ver.PadRight(4)) ========================================="
		$app = $_
		@('Policies\','') | %{
			$pol = $_
			# OfficeMacros contains Macro registry keys.
			# 1 - Enable all.
			# 2 - Disable with notification.
			# 3 - Digitally signed only.
			# 4 - Disable all.
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\$app\Security"      /v VBAWarnings            /t REG_DWORD /d 3 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\General"     /v VBAWarnings            /t REG_DWORD /d 3 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\Security"    /v VBAWarnings            /t REG_DWORD /d 3 /f

			# If you enable this policy setting, macros are blocked from running, even if "Enable all macros" is selected in the Macro Settings section of the Trust Center.
			# Also, instead of having the choice to "Enable Content," users will receive a notification that macros are blocked from running.
			# If the Office file is saved to a trusted location or was previously trusted by the user, macros will be allowed to run.
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\$app\Security"      /v BlockContentExecutionFromInternet            /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\General"     /v BlockContentExecutionFromInternet            /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\Security"    /v BlockContentExecutionFromInternet            /t REG_DWORD /d 1 /f

			# OfficeOLE hardens Office Packager Objects.
			# 0 - No prompt from Office when user clicks, object executes.
			# 1 - Prompt from Office when user clicks, object executes.
			# 2 - No prompt, Object does not execute.
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\$app\Security"      /v PackagerPrompt            /t REG_DWORD /d 2 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\General"     /v PackagerPrompt            /t REG_DWORD /d 2 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\Security"    /v PackagerPrompt            /t REG_DWORD /d 2 /f

			# OfficeActiveX contains ActiveX registry keys.
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\$app\Security"      /v DisableAllActiveX         /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\General"     /v DisableAllActiveX         /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\Security"    /v DisableAllActiveX         /t REG_DWORD /d 1 /f

			# AllowDDE: part of Update ADV170021
			# disables DDE for Word (default setting after installation of update)
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\$app\Security"      /v AllowDDE                  /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\General"     /v AllowDDE                  /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\Security"    /v AllowDDE                  /t REG_DWORD /d 0 /f

			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\$app\Security"      /v MarkInternalAsUnsafe   /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\General"     /v MarkInternalAsUnsafe   /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKCU\Software\${pol}Microsoft\Office\$ver\Common\Security"    /v MarkInternalAsUnsafe   /t REG_DWORD /d 0 /f

			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common\feedback"             /v Enabled           /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common\feedback\feedback"    /v IncludeScreenshot /t REG_DWORD /d 0 /f

			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common\General"           /v SkipOpenAndSaveAsPlace /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common\General"           /v FirstRun               /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common\General"           /v FileFormatBallotBoxTelemetrySent                    /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common\General"           /v FileFormatBallotBoxTelemetryEventSent               /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common\General"           /v FileFormatBallotBoxTelemetryConfirmationEventSent   /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common\General"           /v FileFormatBallotBoxShowAttempts                     /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common\General"           /v ShownFileFmtPrompt                                  /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Registration"             /v AcceptAllEulas                                      /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\Common\Privacy\SettingsStore\Anonymous" /v FRESettingsMigrated                        /t REG_DWORD /d 1 /f

			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\$app\Options"             /v DontUpdateLinks /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\$app\Options\WordMail"    /v DontUpdateLinks /t REG_DWORD /d 1 /f
			
			# HKCU\SOFTWARE\Microsoft\Office\16.0\Common\General
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common\General"  /v disableCloudCreate /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common\General"  /v AutoSaveByDefaultUserChoice /t REG_DWORD /d 2 /f
			reg_fast_hkcu add "HKLM\SOFTWARE\${pol}Microsoft\Office\$ver\Common\General"  /v disableCloudCreate /t REG_DWORD /d 1 /f
			reg_fast_hkcu add "HKLM\SOFTWARE\${pol}Microsoft\Office\$ver\Common\General"  /v AutoSaveByDefaultUserChoice /t REG_DWORD /d 2 /f
			# Do not default save document to OneDrive/Sharepoint/...
			# HKCU\SOFTWARE\Microsoft\Office\16.0\Word
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Word"  /v AutoSaveByDefaultUserChoice /t REG_DWORD /d 2 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Excel"  /v AutoSaveByDefaultUserChoice /t REG_DWORD /d 2 /f
			reg_fast_hkcu add "HKLM\SOFTWARE\${pol}Microsoft\Office\$ver\Word"  /v AutoSaveByDefaultUserChoice /t REG_DWORD /d 2 /f
			reg_fast_hkcu add "HKLM\SOFTWARE\${pol}Microsoft\Office\$ver\Excel"  /v AutoSaveByDefaultUserChoice /t REG_DWORD /d 2 /f
			
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common"  /v SendCustomerData /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common"  /v SendCustomerDataOptIn /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKCU\SOFTWARE\${pol}Microsoft\Office\$ver\Common"  /v SendCustomerDataOptInReason /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKLM\SOFTWARE\${pol}Microsoft\Office\$ver\Common"  /v SendCustomerData /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKLM\SOFTWARE\${pol}Microsoft\Office\$ver\Common"  /v SendCustomerDataOptIn /t REG_DWORD /d 0 /f
			reg_fast_hkcu add "HKLM\SOFTWARE\${pol}Microsoft\Office\$ver\Common"  /v SendCustomerDataOptInReason /t REG_DWORD /d 0 /f
		}
	}
} | Out-File -Encoding ASCII -Append $regFile
reg.exe import $regFile
rm -force $regFile