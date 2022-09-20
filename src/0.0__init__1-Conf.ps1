$AutoHarden_Folder='C:\Windows\AutoHarden'
$AutoHarden_Logs="${AutoHarden_Folder}\logs"
$AutoHarden_AsksFolder="${AutoHarden_Folder}\asks"
$AutoHarden_Group='&{AutoHarden_Group}'
$AutoHarden_Asks=($AutoHarden_Group -eq 'RELEASE')
$AutoHarden_WebDomain="https://raw.githubusercontent.com/1mm0rt41PC/AutoHarden/master/AutoHarden_${AutoHarden_Group}.ps1"
#$AutoHarden_SysmonUrl="https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
$AutoHarden_SysmonUrl="https://raw.githubusercontent.com/1mm0rt41PC/AutoHarden/master/sysmonconfig.xml"

Get-Variable
gci env:* | sort-object name