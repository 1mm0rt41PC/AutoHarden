# Disable new DMA devices when this computer is locked
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /v DisableExternalDMAUnderLock /t REG_DWORD /d 1 /f
# WARNING, a Windows update, will break all laptops.
# CONFLIC with DMA, will crash computer into bootloop
# In case of laptop locked down by dma, the computer will show an error "unable to read memory at 0x...." and the laptop will not be able to reboot.
# Fix:
#		> get a shell in rescue mode and type:
#		SET letter=C:
#		reg.exe load HKLM\hklm_system %letter%\Windows\System32\Config\system
#		reg.exe load HKLM\hklm_soft %letter%\Windows\System32\Config\software
#		reg.exe delete "HKLM\hklm_soft\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /f
#		reg.exe add HKLM\hklm_soft\Policies\Microsoft\FVE /v DisableExternalDMAUnderLock /d 0 /t REG_DWORD /f
#		reg.exe unload HKLM\hklm_system
#		reg.exe unload HKLM\hklm_soft
#		del /q %letter%\Windows\AutoHarden\*.ps1
