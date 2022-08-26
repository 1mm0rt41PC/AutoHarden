# Disable new DMA devices when this computer is locked
# WARNING, an Windows update, will break any laptop.
# In case of laptop locked down by dma, the computer will show an error "unable to read memory at 0x...." and the laptop will not be able to reboot.
# Fix: Disable DMS by disabling secureboot or VT then remove this key and disable dma
# reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /v DisableExternalDMAUnderLock /t REG_DWORD /d 1 /f
