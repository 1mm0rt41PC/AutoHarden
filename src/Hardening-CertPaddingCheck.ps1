# To inject shellcode inside signed binaries : https://github.com/med0x2e/SigFlip
# MS13-098 - Vulnerability in Windows Could Allow Remote Code Execution - https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2013/ms13-098?redirectedfrom=MSDN
#
# IMPACT: Impact of enabling the functionality changes included in the MS13-098 update. Non-conforming binaries will appear unsigned and, therefore, be rendered untrusted.
#
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\Wintrust\Config" /t REG_DWORD /v EnableCertPaddingCheck /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /t REG_DWORD /v EnableCertPaddingCheck /d 1 /f