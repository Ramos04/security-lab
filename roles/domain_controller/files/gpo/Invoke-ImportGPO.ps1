$script_path = Split-Path $script:MyInvocation.MyCommand.Path
$domain_path = (Get-ADDomain).DistinguishedName

Foreach ($folder in (Get-ChildItem -Directory $script_path) ) {
	$gpo_name = ([XML](get-content ($folder.FullName + "\gpreport.xml"))).GPO.Name
	$gpo_id = ([XML](get-content ($folder.FullName + "\gpreport.xml"))).GPO.Identifier.Identifier.'#text'
	
	Import-GPO -BackupGpoName $gpo_name -TargetName $gpo_name -path $script_path -CreateIfNeeded
	
	IF ($gpo_name | Select-String -Pattern 'Default' -NotMatch){
		Write-Host $gpo_name
		New-GPLink -Name $gpo_name -Target $domain_path 
	}
}

