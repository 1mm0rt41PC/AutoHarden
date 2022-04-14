fwRule @{
	Name='[Deny Internet] InternetExplorer'
	Group='InternetExplorer'
	Direction='Outbound'
	Action='Block'
	blockExe=@(
		"C:\Program Files*\Internet Explorer\iexplore.exe"
	)
	RemoteAddress=$IPForInternet
}