# https://www.malekal.com/comment-reduire-la-taille-du-dossier-windows-de-windows-10/

# En appliquant ces deux commandes, vous ne pourrez plus désinstaller les mises à jour Windows.
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
Dism.exe /online /Cleanup-Image /SPSuperseded