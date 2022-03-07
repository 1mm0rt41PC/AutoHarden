# Log powershell activity
# https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5ba3dc87e79c703f9bfff29a/1537465479833/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2018+v2.2.pdf
# https://www.malwarearchaeology.com/cheat-sheets
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableInvocationHeader /t REG_DWORD /d 1 /f
reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v OutputDirectory /t REG_SZ /d "${AutoHarden_Logs}\Powershell.log" /f
reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
# This is VERY noisy, do not set in most environments, or seriously test first (4105 & 4106)
#reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockInvocationLogging
#WevtUtil gl "Windows PowerShell"
#WevtUtil gl "Microsoft-Windows-PowerShell/Operational"

# Log DHCP
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcp-Client/Operational" /v Enabled /t REG_DWORD /d 1 /f

# Log DHCPv6
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcpv6-Client/Operational" /v Enabled /t REG_DWORD /d 1 /f

# Log DNS
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" /v Enabled /t REG_DWORD /d 1 /f

if( -not [System.IO.File]::Exists("${AutoHarden_Logs}\AuditPol_BEFORE.log.zip") ){
	Auditpol /get /category:* | Out-File -Encoding UT8 $AutoHarden_Logs\AuditPol_BEFORE.log
	Compress-Archive -Path "${AutoHarden_Logs}\AuditPol_BEFORE.log" -CompressionLevel "Optimal" -DestinationPath "${AutoHarden_Logs}\AuditPol_BEFORE.log.zip"
}


# From
#	https://github.com/rkovar/PowerShell/blob/master/audit.bat
#	https://forensixchange.com/posts/19_05_07_dns_investigation/
#	https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d

# SET THE LOG SIZE - What local size they will be
# ---------------------
#
# 540100100 will give you 7 days of local Event Logs with everything logging (Security and Sysmon)
# 1023934464 will give you 14 days of local Event Logs with everything logging (Security and Sysmon)
# Other logs do not create as much quantity, so lower numbers are fine
#
wevtutil sl Security /ms:540100100
wevtutil sl Application /ms:256000100
wevtutil sl Setup /ms:256000100
wevtutil sl System /ms:256000100
wevtutil sl "Windows Powershell" /ms:256000100
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:540100100


# PS C:\> auditpol /list /subcategory:* /r
#
# Catégorie/Sous-catégorie,GUID
# Système,{69979848-797A-11D9-BED3-505054503030}
#   Modification de l’état de la sécurité,{0CCE9210-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9210-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Extension système de sécurité,{0CCE9211-69AE-11D9-BED3-505054503030}
#   Intégrité du système,{0CCE9212-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9212-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Pilote IPSEC,{0CCE9213-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9213-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
#   Autres événements système,{0CCE9214-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9214-69AE-11D9-BED3-505054503030}" /success:disable /failure:enable
# Ouverture/Fermeture de session,{69979849-797A-11D9-BED3-505054503030}
#   Ouvrir la session,{0CCE9215-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Fermer la session,{0CCE9216-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Verrouillage du compte,{0CCE9217-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9217-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Mode principal IPsec,{0CCE9218-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9218-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
#   Mode rapide IPsec,{0CCE9219-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9219-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
#   Mode étendu IPsec,{0CCE921A-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921A-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
#   Ouverture de session spéciale,{0CCE921B-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Autres événements d’ouverture/fermeture de session,{0CCE921C-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Serveur NPS,{0CCE9243-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9243-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Revendications utilisateur/de périphérique,{0CCE9247-69AE-11D9-BED3-505054503030}
#   Appartenance à un groupe,{0CCE9249-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9249-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# Accès aux objets,{6997984A-797A-11D9-BED3-505054503030}
#   Système de fichiers,{0CCE921D-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Registre,{0CCE921E-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921E-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Objet de noyau,{0CCE921F-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE921F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   SAM,{0CCE9220-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9220-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Services de certification,{0CCE9221-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9221-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Généré par application,{0CCE9222-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9222-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Manipulation de handle,{0CCE9223-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Partage de fichiers,{0CCE9224-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9224-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Rejet de paquet par la plateforme de filtrage,{0CCE9225-69AE-11D9-BED3-505054503030} == "Filtering Platform Packet Drop"
auditpol /set /subcategory:"{0CCE9225-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Connexion de la plateforme de filtrage,{0CCE9226-69AE-11D9-BED3-505054503030} == "Filtering Platform Connection"
#   Autres événements d’accès à l’objet,{0CCE9227-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Partage de fichiers détaillé,{0CCE9244-69AE-11D9-BED3-505054503030}
#   Stockage amovible,{0CCE9245-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9245-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Stratégie centralisée intermédiaire,{0CCE9246-69AE-11D9-BED3-505054503030}
# Utilisation de privilège,{6997984B-797A-11D9-BED3-505054503030}
#   Utilisation de privilèges sensibles,{0CCE9228-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9228-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Utilisation de privilèges non sensibles,{0CCE9229-69AE-11D9-BED3-505054503030}
#   Autres événements d’utilisation de privilèges,{0CCE922A-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922A-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
# Suivi détaillé,{6997984C-797A-11D9-BED3-505054503030}
#   Création du processus,{0CCE922B-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
# Log process activity
reg.exe add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
#   Fin du processus,{0CCE922C-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922C-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Activité DPAPI,{0CCE922D-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922D-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Événements RPC,{0CCE922E-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922E-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Événements Plug-and-Play,{0CCE9248-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9248-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Événements de jeton ajustés à droite,{0CCE924A-69AE-11D9-BED3-505054503030}
# Changement de stratégie,{6997984D-797A-11D9-BED3-505054503030}
#   Modification de la stratégie d’audit,{0CCE922F-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE922F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Modification de la stratégie d’authentification,{0CCE9230-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9230-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Modification de la stratégie d’autorisation,{0CCE9231-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9231-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Modification de la stratégie de niveau règle MPSSVC,{0CCE9232-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9232-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
#   Modification de la stratégie de plateforme de filtrage,{0CCE9233-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9233-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable
#   Autres événements de modification de stratégie,{0CCE9234-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9234-69AE-11D9-BED3-505054503030}" /success:disable /failure:enable
# Gestion des comptes,{6997984E-797A-11D9-BED3-505054503030}
#   Gestion des comptes d’utilisateur,{0CCE9235-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Gestion des comptes d’ordinateur,{0CCE9236-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9236-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Gestion des groupes de sécurité,{0CCE9237-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Gestion des groupes de distribution,{0CCE9238-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9238-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Gestion des groupes d’applications,{0CCE9239-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9239-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Autres événements de gestion des comptes,{0CCE923A-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE923A-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# Accès DS,{6997984F-797A-11D9-BED3-505054503030}
#   Accès au service d’annuaire,{0CCE923B-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE923B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Modification du service d’annuaire,{0CCE923C-69AE-11D9-BED3-505054503030}
#   Réplication du service d’annuaire,{0CCE923D-69AE-11D9-BED3-505054503030}
#   Réplication du service d’annuaire détaillé,{0CCE923E-69AE-11D9-BED3-505054503030}
# Connexion de compte,{69979850-797A-11D9-BED3-505054503030}
#   Validation des informations d’identification,{0CCE923F-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Opérations de ticket du service Kerberos,{0CCE9240-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9240-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Autres événements d’ouverture de session,{0CCE9241-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9241-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
#   Service d’authentification Kerberos,{0CCE9242-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9242-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable