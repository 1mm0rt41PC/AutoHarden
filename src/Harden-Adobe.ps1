# AdobePDFJS hardens Acrobat JavaScript.
# bEnableJS possible values:
# 0 - Disable AcroJS
# 1 - Enable AcroJS
Set-ItemProperty HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\JSPrefs -Name bEnableJS -Value 0 -Type DWord -errorAction SilentlyContinue

# Disables Acrobat Reader embedded objects
# AdobePDFObjects hardens Adobe Reader Embedded Objects.
# bAllowOpenFile set to 0 and
# bSecureOpenFile set to 1 to disable
# the opening of non-PDF documents
Set-ItemProperty HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\Originals -Name bAllowOpenFile -Value 0 -Type DWord -errorAction SilentlyContinue
Set-ItemProperty HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\Originals -Name bSecureOpenFile -Value 1 -Type DWord -errorAction SilentlyContinue

# AdobePDFProtectedMode switches on the Protected Mode setting under
# "Security (Enhanced)" (enabled by default in current versions).
# (HKEY_LOCAL_USER\Software\Adobe\Acrobat Reader<version>\Privileged -> DWord „bProtectedMode“)
# 0 - Disable Protected Mode
# 1 - Enable Protected Mode
Set-ItemProperty HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\Privileged -Name bProtectedMode -Value 1 -Type DWord -errorAction SilentlyContinue

# AdobePDFProtectedView switches on Protected View for all files from
# untrusted sources.
# (HKEY_CURRENT_USER\SOFTWARE\Adobe\Acrobat Reader\<version>\TrustManager -> iProtectedView)
# 0 - Disable Protected View
# 1 - Enable Protected View
Set-ItemProperty HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\TrustManager -Name iProtectedView -Value 1 -Type DWord -errorAction SilentlyContinue

# AdobePDFEnhancedSecurity switches on Enhanced Security setting under
# "Security (Enhanced)".
# (enabled by default in current versions)
# (HKEY_CURRENT_USER\SOFTWARE\Adobe\Acrobat Reader\DC\TrustManager -> bEnhancedSecurityInBrowser = 1 & bEnhancedSecurityStandalone = 1)
Set-ItemProperty HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\TrustManager -Name bEnhancedSecurityInBrowser -Value 1 -Type DWord -errorAction SilentlyContinue
Set-ItemProperty HKCU:\SOFTWARE\Adobe\Acrobat Reader\*\TrustManager -Name bEnhancedSecurityStandalone -Value 1 -Type DWord -errorAction SilentlyContinue
