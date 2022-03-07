### Snort & Suricata signatures for:
### https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6
##
##alert udp fe80::/12 [546,547] -> fe80::/12 [546,547] (msg:"FOX-SRT - Policy - DHCPv6 advertise"; content:"|02|"; offset:48; depth:1; reference:url,blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/; threshold:type limit, track by_src, count 1, seconds 3600; classtype:policy-violation; sid:21002327; rev:2;)
##alert udp ::/0 53 -> any any (msg:"FOX-SRT - Suspicious - WPAD DNS reponse over IPv6"; byte_test:1,&,0x7F,2; byte_test:2,>,0,6; content:"|00 04|wpad"; nocase; fast_pattern; threshold: type limit, track by_src, count 1, seconds 1800; reference:url,blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/; classtype:attempted-admin; priority:1; sid:21002330; rev:1;)

FWRule @{
	Name='NMAP'
	Group='Pentest'
	Direction='*'
	Action='Allow'
	blockExe="C:\Program Files*\Nmap\nmap.exe"
}
FWRule @{
	Name='VMWare'
	Group='Pentest'
	Direction='*'
	Action='Allow'
	blockExe="C:\Program Files*\VMware\*\vmnat.exe"
}
# Note about 135/TCP => https://superuser.com/questions/669199/how-to-stop-listening-at-port-135/1012382#1012382
# Port 135/TCP can be killed in 100% of server and workstation if CreateObject("Excel.Application", RemoteMachine) is not used