# https://www.malekal.com/comment-reduire-la-taille-du-dossier-windows-de-windows-10/

# Réduire la taille du dossier WinSxS
Dism.exe /online /Cleanup-Image /StartComponentCleanup

# Réparation des DLL et drivers
DISM /Online /Cleanup-image /Restorehealth
sfc /SCANNOW
