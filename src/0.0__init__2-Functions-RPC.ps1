###############################################################################
# FUNCTIONS - RPC
$RpcRules = (netsh rpc filter show filter).Replace(' ','')
function addRpcAcl( $name='', $uuid=@(), $acl='' )
{
	if( $uuid.Count -gt 0 -Or $uuid -ne '' ){
		$acl = $uuid | foreach {
			return RpcRuleCreator $_ $name
		}
	}
	if( $acl -eq '' ){
		return $null;
	}
	$acl = @"
rpc
filter
$acl
quit
"@
	$file=createTempFile $acl
	netsh -f $file
	$global:RpcRules = (netsh rpc filter show filter)
	echo $global:RpcRules
	$global:RpcRules = ($global:RpcRules).Replace(' ','')
	rm $file
}


# Add a rule to drop access to EFS for non DA
# From: https://twitter.com/tiraniddo/status/1422223511599284227
# From: https://gist.github.com/tyranid/5527f5559041023714d67414271ca742
function RpcRuleCreator( $uuid, $name )
{
	$1st_uuid=$uuid.Split('-')[0]
	if( $RpcRules -Like "*$uuid*" -Or $RpcRules -Like "*$1st_uuid*" ){
		logInfo "RpcRules is already applied for $name => $uuid"
		return '';
	}
	$ret = '';
	if( $isDomainLinked ){
		logSuccess "RpcRules applied for $name with DOMAIN support => $uuid"
		$ret = @"
add rule layer=um actiontype=permit
add condition field=if_uuid matchtype=equal data=$uuid
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;DA)
add filter

"@
	}else{
		logSuccess "RpcRules applied for $name withOUT DOMAIN support => $uuid"
	}
	return $ret+@"
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=$uuid
add filter

"@
}