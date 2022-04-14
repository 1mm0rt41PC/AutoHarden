@(
	'PasswordManagerEnabled',
	'AutofillAddressEnabled',
	'AutofillCreditCardEnabled',
	'ImportAutofillFormData'
) | foreach {
	reg add HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome /v $_ /d 0 /f
	reg add HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave /v $_ /d 0 /f
	reg add HKEY_LOCAL_MACHINE\Software\Policies\Chromium /v $_ /d 0 /f
}
# Enable support for chromecast
reg add HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome /v EnableMediaRouter /d 1 /f
reg add HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave /v EnableMediaRouter /d 1 /f
reg add HKEY_LOCAL_MACHINE\Software\Policies\Chromium /v EnableMediaRouter /d 1 /f