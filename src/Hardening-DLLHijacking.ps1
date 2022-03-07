# Prevent (remote) DLL Hijacking
# Sources:
# https://www.greyhathacker.net/?p=235
# https://www.verifyit.nl/wp/?p=175464
# https://support.microsoft.com/en-us/help/2264107/a-new-cwdillegalindllsearch-registry-entry-is-available-to-control-the
# The value data can be 0x1, 0x2 or 0xFFFFFFFF. If the value name CWDIllegalInDllSearch does not exist or the value data is 0 then the machine will still be vulnerable to attack.
# Please be aware that the value 0xFFFFFFFF could break certain applications (also blocks dll loading from USB).
# Blocks a DLL Load from the current working directory if the current working directory is set to a WebDAV folder  (set it to 0x1)
# Blocks a DLL Load from the current working directory if the current working directory is set to a remote folder (such as a WebDAV or UNC location) (set it to 0x2)
# ---------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v CWDIllegalInDllSearch /t REG_DWORD /d 0x2 /f