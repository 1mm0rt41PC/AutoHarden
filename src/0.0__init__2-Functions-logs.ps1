###############################################################################
# FUNCTIONS - Logs
function logInfo( $msg )
{
	Write-Host -NoNewline -Background 'Blue' '[i]'
	Write-Host " $msg"
}
function logSuccess( $msg )
{
	Write-Host -NoNewline -Background 'Green' '[v]'
	Write-Host " $msg"
}
function logError( $msg )
{
	Write-Host -NoNewline -Background 'Red' '[X]'
	Write-Host " $msg"
}