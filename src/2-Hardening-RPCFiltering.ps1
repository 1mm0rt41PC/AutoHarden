# Script from https://raw.githubusercontent.com/craigkirby/scripts/main/RPC_Filters.bat
# List of UUIDs
# https://vulners.com/openvas/OPENVAS:1361412562310108044
# https://github.com/p33kab00/dcerpc-pipe-scan/blob/master/dcerpc-pipe-scan.py

# Services
$rules = RpcRuleCreator '367abb81-9844-35f1-ad32-98f038001003' 'Services'
# Also Services as listed on Internet but might be a typo
$rules += RpcRuleCreator '367aeb81-9844-35f1-ad32-98f038001003' 'Service bis'
# Task Scheduler
$rules += RpcRuleCreator '378e52b0-c0a9-11cf-822d-00aa0051e40f' 'Task Scheduler 1'
$rules += RpcRuleCreator '0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53' 'Task Scheduler 2'
$rules += RpcRuleCreator '86d35949-83c9-4044-b424-db363231fd0c' 'Task Scheduler 3'
# AT Scheduler
$rules += RpcRuleCreator '1ff70682-0a51-30e8-076d-740be8cee98b' 'AT Scheduler'
# Security Configuration Editor Engine
$rules += RpcRuleCreator '93149ca2-973b-11d1-8c39-00c04fb984f9' 'Security Configuration Editor Engine'
# Remote Registry
$rules += RpcRuleCreator '338cd001-2244-31f1-aaaa-900038001003' 'Remote Registry'

# See PetitPotam fix
## Encrypting File System Remote (EFSRPC) Protocol
#$rules += RpcRuleCreator 'c681d488-d850-11d0-8c52-00c04fd90f7e' 'EFS'
#$rules += RpcRuleCreator 'df1941c5-fe89-4e79-bf10-463657acf44d' 'EFS'

# Print Spooler
$rules += RpcRuleCreator '12345678-1234-abcd-ef00-0123456789ab' 'Print Spooler'

addRpcAcl -acl $rules