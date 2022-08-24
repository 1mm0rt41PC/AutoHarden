###############################################################################
# Cleaning the script...
###############################################################################
logInfo 'Waiting for the job autoruns...'
Wait-Job -Name LogActivity_autoruns -ErrorAction SilentlyContinue
Stop-Transcript
Compress-Archive -Path $AutoHardenTransScriptLog -CompressionLevel "Optimal" -DestinationPath "${AutoHardenTransScriptLog}.zip" -ErrorAction SilentlyContinue -Force
if( [System.IO.File]::Exists("${AutoHardenTransScriptLog}.zip") ){
	Remove-Item -Force $AutoHardenTransScriptLog
}