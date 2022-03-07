# Disable Powershellv2
DISM /Online /Disable-Feature:MicrosoftWindowsPowerShellV2Root /NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart