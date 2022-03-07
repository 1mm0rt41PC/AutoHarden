reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Rdr\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Rdr\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f