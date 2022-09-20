if( ![bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") ){  Write-Host -BackgroundColor Red -ForegroundColor White "Administrator privileges required ! This terminal has not admin priv. This script ends now !"; pause;exit;}
mkdir $AutoHarden_Folder -Force -ErrorAction Continue > $null
mkdir $AutoHarden_Logs -Force -ErrorAction Continue > $null
mkdir $AutoHarden_AsksFolder -Force -ErrorAction Continue > $null
Move-Item -ErrorAction SilentlyContinue -Force ${AutoHarden_Folder}\*.log ${AutoHarden_Logs}
Move-Item -ErrorAction SilentlyContinue -Force ${AutoHarden_Folder}\*.7z ${AutoHarden_Logs}
$AutoHardenTransScriptLog = "${AutoHarden_Logs}\Activities_${AutoHarden_Group}_"+(Get-Date -Format "yyyy-MM-dd")+".log"
Start-Transcript -Force -IncludeInvocationHeader -Append ($AutoHardenTransScriptLog)
#$DebugPreference = "Continue"
#$VerbosePreference = "Continue"
$InformationPreference = "Continue"