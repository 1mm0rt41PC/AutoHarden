chocoInstall notepadplusplus.install
$npp_path=(Get-Item "C:\Program Files*\Notepad++\notepad++.exe").FullName.Replace('.exe','.vbs')
@'
'// DISCLAIMER
'// THIS COMES WITH NO WARRANTY, IMPLIED OR OTHERWISE. USE AT YOUR OWN RISK
'// IF YOU ARE NOT COMFORTABLE EDITING THE REGISTRY THEN DO NOT USE THIS SCRIPT
'//
'// NOTES:
'// This affects all users.
'// This will prevent ANY executable named notepad.exe from running located anywhere on this computer!!
'//
'// Save this text to your notepad++ folder as a text file named npp.vbs (some AV don't like vbs, get a different AV :-P )
'//
'// USAGE
'// 1)
'// Navigate to registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
'//
' // 2)
'// Add new subkey called notepad.exe
'// This step is what tells windows to use the notepad++ exe, to undo simply delete this key
'//
'// 3)
'// Create new Sting Value called Debugger
'//
'// 4)
'// Modify value and enter wscript.exe "path to npp.vbs" e.g. wscript.exe "C:\Program Files\Notepad++\npp.vbs"

Option Explicit
Dim sCmd, x
sCmd = """" & LeftB(WScript.ScriptFullName, LenB(WScript.ScriptFullName) - LenB(WScript.ScriptName)) & "notepad++.exe" & """ """
For x = 1 To WScript.Arguments.Count - 1
   sCmd = sCmd & WScript.Arguments(x) & " "
Next
sCmd = sCmd & """"
CreateObject("WScript.Shell").Exec(sCmd)
WScript.Quit
'@ | out-file -encoding ASCII $npp_path

if( [System.IO.File]::Exists($npp_path) ){
	# Create sub folder
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d x /f
	# Create key
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Name Debugger -Value ('wscript.exe "'+$npp_path+'"') -PropertyType String -Force | Out-Null
}