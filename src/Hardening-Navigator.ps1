@(
	'PasswordManagerEnabled',
	'AutofillAddressEnabled',
	'AutofillCreditCardEnabled',
	'ImportAutofillFormData'
) | foreach {
	reg add HKLM\Software\Policies\Google\Chrome /v $_ /d 0 /f
	reg add HKLM\Software\Policies\BraveSoftware\Brave /v $_ /d 0 /f
	reg add HKLM\Software\Policies\Chromium /v $_ /d 0 /f
	reg add HKLM\Software\Policies\Microsoft\Edge /v $_ /d 0 /f
}
# Enable support for chromecast
reg add HKLM\Software\Policies\Google\Chrome /v EnableMediaRouter /d 1 /f
reg add HKLM\Software\Policies\BraveSoftware\Brave /v EnableMediaRouter /d 1 /f
reg add HKLM\Software\Policies\Chromium /v EnableMediaRouter /d 1 /f

# Disable Edge Welcome screen
reg.exe add HKLM\Software\Policies\Microsoft\Edge /v HideFirstRunExperience /d 1 /t REG_DWORD /F
reg.exe add HKLM\Software\Policies\Microsoft\Edge /v AutoImportAtFirstRun /d 0 /t REG_DWORD /F
reg.exe add HKLM\Software\Policies\Microsoft\Edge /v SyncDisabled /d 1 /t REG_DWORD /F
reg.exe add HKLM\Software\Policies\Microsoft\Edge /v BrowserSignin /d 0 /t REG_DWORD /F