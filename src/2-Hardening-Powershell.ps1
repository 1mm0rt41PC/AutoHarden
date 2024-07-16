# Disable Powershellv2
DISM /Online /Disable-Feature:MicrosoftWindowsPowerShellV2 /NoRestart
DISM /Online /Disable-Feature:MicrosoftWindowsPowerShellV2Root /NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart > $null
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart > $null