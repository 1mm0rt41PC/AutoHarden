@(
	@{Name='Word'; blockExe=@(
		"C:\Program Files*\Microsoft Office*\root\*\winword.exe",
		"C:\Program Files*\Microsoft Office*\*\root\*\winword.exe",
		"C:\Program Files*\Microsoft Office*\*\winword.exe"
	)},
	@{Name='Excel'; blockExe=@(
		"C:\Program Files*\Microsoft Office*\root\*\EXCEL.EXE",
		"C:\Program Files*\Microsoft Office*\*\root\*\EXCEL.EXE",
		"C:\Program Files*\Microsoft Office*\*\EXCEL.EXE",
		"C:\Program Files*\Microsoft Office*\*\excelcnv.exe",
		"C:\Program Files*\Microsoft Office*\*\*\excelcnv.exe"
	)},
	@{Name='PowerPoint'; blockExe=@(
		"C:\Program Files*\Microsoft Office*\root\*\Powerpnt.exe",
		"C:\Program Files*\Microsoft Office*\*\root\*\Powerpnt.exe",
		"C:\Program Files*\Microsoft Office*\*\Powerpnt.exe"
	)},
	@{Name='OneNote'; blockExe=@(
		"C:\Program Files*\Microsoft Office*\root\*\ONENOTE.exe",
		"C:\Program Files*\Microsoft Office*\*\root\*\ONENOTE.exe",
		"C:\Program Files*\Microsoft Office*\*\ONENOTE.exe"
	)},
	@{Name='Teams'; blockExe=@(
		"C:\Users\*\AppData\Local\Microsoft\Teams\*\Squirrel.exe",
		"C:\Users\*\AppData\Local\Microsoft\Teams\update.exe"
	)}
) | foreach {
	FWRule @{
		Name=('[Deny Internet] {0}' -f $_.Name)
		Group='Office'
		Direction='Outbound'
		Action='Block'
		blockExe=$_.blockExe
		RemoteAddress=$IPForInternet
	}
}
# Avoid credentials leak https://www.guardicore.com/labs/autodiscovering-the-great-leak/
FWRule @{
	Name='Avoid credentials leak in Outlook'
	Group='Office'
	Direction='Outbound'
	Action='Block'
	blockExe=@(
		"C:\Program Files*\Microsoft Office*\root\*\OUTLOOK.exe",
		"C:\Program Files*\Microsoft Office*\*\root\*\OUTLOOK.exe",
		"C:\Program Files*\Microsoft Office*\*\OUTLOOK.exe"
	)
	Protocol='tcp'
	RemotePort=80
}
