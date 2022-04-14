# From: https://twitter.com/JohnLaTwC/status/802218490404798464?s=19
# Empeche la création de service via les RPC/SMB distant. => psexec upload ok mais exec fail
$tmp=(sc.exe sdshow scmanager).split("`r`n")[1].split(":")[1]
if( -not $tmp.Contains("(D;;GA;;;NU)") -and -not $tmp.Contains("(D;;KA;;;NU)") ){
	sc.exe sdset scmanager "D:(D;;GA;;;NU)$tmp"
	logSuccess "Patched"
}else{
	logInfo "Already patched"
}

# https://twitter.com/olamotte33/status/1429386553562963970?s=09
# https://twitter.com/olamotte33/status/1429484420000534530?s=20
addRpcAcl -name 'SCManager' -uuid '367abb81-9844-35f1-ad32-98f038001003'
# https://twitter.com/tiraniddo/status/1429525321414369281?s=20
addRpcAcl -name 'WMI' -uuid '8bc3f05e-d86b-11d0-a075-00c04fb68820'