# assoc .txt
# .hta
cmd /c ftype  htafile="C:\Windows\notepad.exe" "%1"
# .js
cmd /c ftype  JSFile="C:\Windows\notepad.exe" "%1"
# .jse
cmd /c ftype  JSEFile="C:\Windows\notepad.exe" "%1"
# .vbe
cmd /c ftype VBEFile="C:\Windows\notepad.exe" "%1"
# .vbs
cmd /c ftype VBSFile="C:\Windows\notepad.exe" "%1"
# .wsf
cmd /c ftype WSFFile="C:\Windows\notepad.exe" "%1"
# .wsh
cmd /c ftype WSHFile="C:\Windows\notepad.exe" "%1"
# .reg
cmd /c ftype regfile="C:\Windows\notepad.exe" "%1"
# .inf
cmd /c ftype inffile="C:\Windows\notepad.exe" "%1"
# .scf 
cmd /c ftype SHCmdFile="C:\Windows\notepad.exe" "%1"
# .wsc
cmd /c ftype scriptletfile="C:\Windows\notepad.exe" "%1"
# .scr
cmd /c ftype scrfile="C:\Windows\notepad.exe" "%1"
# .pif
cmd /c ftype piffile="C:\Windows\notepad.exe" "%1"
# .mht
cmd /c ftype mhtmlfile="C:\Windows\notepad.exe" "%1"
# .ps1
cmd /c ftype Microsoft.PowerShellScript.1="C:\Windows\notepad.exe" "%1"
cmd /c ftype Microsoft.PowerShellXMLData.1="C:\Windows\notepad.exe" "%1"
cmd /c ftype Microsoft.PowerShellConsole.1="C:\Windows\notepad.exe" "%1"
# .xml
cmd /c ftype "XML Script Engine"="C:\Windows\notepad.exe" "%1"
cmd /c ftype sctfile="%systemroot%\system32\notepad.exe" "%1"
cmd /c ftype urlfile="%systemroot%\system32\notepad.exe" "%1"
# https://www.trustwave.com/Resources/SpiderLabs-Blog/Firework--Leveraging-Microsoft-Workspaces-in-a-Penetration-Test/
cmd /c ftype wcxfile="%systemroot%\system32\notepad.exe" "%1"
# https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
#ftype mscfile="%systemroot%\system32\notepad.exe" "%1"

# https://rinseandrepeatanalysis.blogspot.com/2018/09/dde-downloaders-excel-abuse-and.html
cmd /c ftype slkfile="%systemroot%\system32\notepad.exe" "%1"
cmd /c ftype iqyfile="%systemroot%\system32\notepad.exe" "%1"
cmd /c ftype prnfile="%systemroot%\system32\notepad.exe" "%1"
cmd /c ftype diffile="%systemroot%\system32\notepad.exe" "%1"

# CVE-2020-0765 impacting Remote Desktop Connection Manager (RDCMan) configuration files - MS won't fix
cmd /c ftype rdgfile="%systemroot%\system32\notepad.exe" "%1"


reg delete "HKCU:\Software\Classes\ms-appinstaller" /v "URL Protocol"