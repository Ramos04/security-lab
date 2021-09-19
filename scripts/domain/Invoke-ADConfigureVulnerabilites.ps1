# AD Attack Methods
# 	https://adsecurity.org/?page_id=4031

# More scripts here need to go through 
# 	https://github.com/cfalta/adsec
 
# More lab write ups here, probs some sec
# shit in here
# 	https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/Building_A_Lab.md#pentest
 
# More example groups here 
# 	https://github.com/KevOtt/AD-Lab-Generator
 
 Function Disable-WindowsDefender{
<#
  .SYNOPSIS
  Adds new group policy to disable windows defender.
  
  .DESCRIPTION
  Adds new group policy to disable windows defender.
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/browninfosecguy/ADLab/blob/master/ADPentestLab.ps1
#> 
    [cmdletbinding()]
    param()

    if((Get-OSType) -ne 2)
    {
        Write-Host "Domain Controller not detected. Exiting!!" -BackgroundColor Yellow -ForegroundColor Black
        exit
                
    }
    
    try {
        $someerror = $true
        New-GPO -Name "Disable Windows Defender" -Comment "This policy disables windows defender" -ErrorAction Stop
    }
    catch {
        $someerror = $false
        Write-Warning "Unable to create the Policy."
        
    }
    
    if($someerror)
    {
        Set-GPRegistryValue -Name "Disable Windows Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Type DWord -Value 1
        Set-GPRegistryValue -Name "Disable Windows Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 1                
        New-GPLink -Name "Disable Windows Defender" -Target ((Get-ADDomain).DistinguishedName)
    }

}

Function New-ADLabSMBShare{
<#
  .SYNOPSIS
  Adds new share called hackme on the Domain controller and Share on workstation.
  
  .DESCRIPTION
  Adds new share called hackme on the Domain controller and Share on workstation.
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/browninfosecguy/ADLab/blob/master/ADPentestLab.ps1
#> 
    [cmdletbinding()]
    param()
    
    if((Get-OSType) -eq 2)
    {
        try {
            $someerror = $true
            New-Item "C:\hackMe" -Type Directory -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to create hackme folder"
            
        }
        if($someerror)
        {
            try {
                New-SmbShare -Name "hackMe" -Path "C:\hackMe" -ErrorAction Stop
            }
            catch {
                Write-Warning "Unable to create Share"
            }
        }            
    }
    elseif ((Get-OSType) -eq 1) {
        try {
            $someerror = $true
            New-Item "C:\Share" -Type Directory -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to create hackme folder"
            $someerror = $false
            
        }
        if($someerror)
        {
            try {
                New-SmbShare -Name "Share" -Path "C:\Share" -ErrorAction Stop
            }
            catch {
                Write-Warning "Unable to create Share"
            }
        }    
    }
    else {
        Write-Warning "Invalid install. Exiting!!"
        exit        
    }            
}

Function VulnAD-Kerberoasting {
<#
  .SYNOPSIS
  Creates service accounts with bad passwords for kerberoasting
  
  .DESCRIPTION
  Creates service accounts with bad passwords for kerberoasting
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/WazeHell/vulnerable-AD/blob/master/vulnad.ps1
#>
    $selected_service = (VulnAD-GetRandom -InputList $Global:ServicesAccountsAndSPNs)
    $svc = $selected_service.split(',')[0];
    $spn = $selected_service.split(',')[1];
    $password = VulnAD-GetRandom -InputList $Global:BadPasswords;
    Write-Info "Kerberoasting $svc $spn"
    Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:Domain" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -RestrictToSingleComputer -PassThru } Catch {}
    foreach ($sv in $Global:ServicesAccountsAndSPNs) {
        if ($selected_service -ne $sv) {
            $svc = $sv.split(',')[0];
            $spn = $sv.split(',')[1];
            Write-Info "Creating $svc services account"
            $password = ([System.Web.Security.Membership]::GeneratePassword(12,2))
            Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:Domain" -RestrictToSingleComputer -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru } Catch {}

        }
    }
}

Function Enable-Kerberoasting{
<#
  .SYNOPSIS
  Creates service accounts with bad passwords for kerberoasting
  
  .DESCRIPTION
  Creates service accounts with bad passwords for kerberoasting
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/snoopysecurity/Setup-AD-Security-Lab/blob/master/ADSecurityLab.ps1
#>	
	Write-Output "[+] Creating Kerberoasting setup"
	net localgroup administrators ADINSECURELAB\Robert.Pratt /add
	setspn -s http/adinsecurelab.local:80 Robert.Pratt
}

Function WinRM-Misconfiguration{
<#
  .SYNOPSIS
  Probably shouldn't fuck with this cause might fuck up ansible
  WinRM configuation
  
  .DESCRIPTION
  Probably shouldn't fuck with this cause might fuck up ansible
  WinRM configuation
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/snoopysecurity/Setup-AD-Security-Lab/blob/master/ADSecurityLab.ps1
#>
	Write-Output "[+] Enabling WinRM, if not already enabled and misconfiguring settings"
	winrm quickconfig -transport:http -quiet -force
	winrm set winrm/config/service '@{AllowUnencrypted="true"}'
	winrm set winrm/config/service/auth '@{Basic="true"}'
	winrm set winrm/config/service/auth '@{CredSSP="true"}'
}

Function Misconfigure-UACRemoteSettings{
<#
  .SYNOPSIS
  If LocalAccountTokenFilterPolicy is set to 1, If the account is an administrator
  the session with run with a full administrator token by default and UAC will be disabled
  
  More Information
	https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction#uac-remote-settings
  
  .DESCRIPTION
  If LocalAccountTokenFilterPolicy is set to 1, If the account is an administrator
  the session with run with a full administrator token by default and UAC will be disabled
  
  More Information
	https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction#uac-remote-settings
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/snoopysecurity/Setup-AD-Security-Lab/blob/master/ADSecurityLab.ps1
#>
	Write-Output "[+] Setting LocalAccountTokenFilterPolicy to 1"
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\microsoft\Windows\CurrentVersion\Policies\System\' -Name 'LocalAccountTokenFilterPolicy' -Value 1
}

Function Misconfigure-ACLSettings{
<#
  .SYNOPSIS
  If LocalAccountTokenFilterPolicy is set to 1, If the account is an administrator
  the session with run with a full administrator token by default and UAC will be disabled
  
  More Information
	https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction#uac-remote-settings
  
  .DESCRIPTION
  If LocalAccountTokenFilterPolicy is set to 1, If the account is an administrator
  the session with run with a full administrator token by default and UAC will be disabled
  
  More Information
	https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction#uac-remote-settings
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/snoopysecurity/Setup-AD-Security-Lab/blob/master/ADSecurityLab.ps1
#>	
	Write-Output "[+] Creating ACL Vulnerabilities"
	(Get-ADGroup -Identity Managers).ObjectGuid
	√
	$computer_schemaIDGUID = [guid] (Get-ADObject -SearchBase ($rootdse.schemaNamingContext) -LDAPFilter "(LDAPDisplayName=computer)" -Properties schemaIDGUID).schemaIDGUID
	$ou = Get-ADOrganizationalUnit -Identity ("OU=Managers,$($rootdse.defaultNamingContext)")
	$acl = Get-ACL "AD:\$ou"
	$domname = ([ADSI]"").Name   
	$who = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList "$domname", "Katie.Haggerty"
	$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
		$who,"WriteOwner","Allow"
	$acl.AddAccessRule($ace)
	Set-ACL "AD:\$ou" -AclObject $acl

	$Sid = (Get-ADObject -Identity "CN=Robert Pratt,OU=Dev,DC=adinsecurelab,DC=local").ObjectGUID
	$NewAccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid, "WriteDacl", "Allow", "Domain Admins")
	$Acl.AddAccessRule($NewAccessRule)
	Set-ACL "AD:\$ou" -AclObject $acl


	# Test with : Get-ObjectAcl -SamAccountName "Managers" -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "WriteOwner"}
	# Get-ACL "AD:\OU=Managers,DC=adinsecurelab,DC=local").Access |
	# Where-Object {$_.IdentityReference -eq "adinsecurelab\Katie.Haggerty"}  
}

Function Set-PasswordInSysvol {
<#
  .SYNOPSIS
  Creates passwords in SYSVOL
  
  .DESCRIPTION
  Creates passwords in SYSVOL
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/snoopysecurity/Setup-AD-Security-Lab/blob/master/ADSecurityLab.ps1
#>
	Write-Output "[+] Creating Passwords in SYSVOL"

	new-gpo -name MarketingGPO | new-gplink -target "OU=HR,DC=adinsecurelab,DC=local" | set-gppermissions -permissionlevel gpoedit -targetname "HR" -targettype group

	Write-Output "net user /add Olivia.Weidman St4SDFxSS11434DF" > "C:\Windows\SYSVOL\sysvol\adinsecurelab.local\scripts\create_backupuser.ps1"

	gpupdate
}

Function Set-PasswordInSysvol {
<#
  .SYNOPSIS
  Creates passwords in SYSVOL
  
  .DESCRIPTION
  Creates passwords in SYSVOL
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/snoopysecurity/Setup-AD-Security-Lab/blob/master/ADSecurityLab.ps1
#>
	echo "[+] Enabling AlwaysInstallElevated registry key"

	$objUser = New-Object System.Security.Principal.NTAccount("adinsecurelab.local", "Joe.Standing") 
	$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
	$userSID = $strSID.Value
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer 
	Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -Value 0x00000001 -Force
	New-Item -Path HKU:\$userSID\SOFTWARE\Policies\Microsoft\Windows\Installer 
	Set-ItemProperty -Path HKU:\$userSID\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -Value 0x00000001 -Force
}




Function VulnAD-ASREPRoasting {
<#
  .SYNOPSIS
  Turns off the Kerberos Pre-Authnetication so the account is
  vulnerable to AS-REP Roasting
  
  .DESCRIPTION
  Turns off the Kerberos Pre-Authnetication so the account is
  vulnerable to AS-REP Roasting
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/WazeHell/vulnerable-AD/blob/master/vulnad.ps1
#>
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $randomuser = (VulnAD-GetRandom -InputList $Global:CreatedUsers)
        $password = VulnAD-GetRandom -InputList $Global:BadPasswords;
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADAccountControl -Identity $randomuser -DoesNotRequirePreAuth 1
        Write-Info "AS-REPRoasting $randomuser"
    }
}

Function VulnAD-DnsAdmins {
<#
  .SYNOPSIS
  Adds users to DnsAdmins group
  
  More information here
	https://adsecurity.org/?p=4064
  
  .DESCRIPTION
  Adds users to DnsAdmins group
 
  More information here
	https://adsecurity.org/?p=4064
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/WazeHell/vulnerable-AD/blob/master/vulnad.ps1
#>
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $randomuser = (VulnAD-GetRandom -InputList $Global:CreatedUsers)
        Add-ADGroupMember -Identity "DnsAdmins" -Members $randomuser
        Write-Info "DnsAdmins : $randomuser"
    }
    $randomg = (VulnAD-GetRandom -InputList $Global:MidGroups)
    Add-ADGroupMember -Identity "DnsAdmins" -Members $randomg
    Write-Info "DnsAdmins Nested Group : $randomg"
}

function VulnAD-DCSync {
<#
  .SYNOPSIS
  Gives a random user DCSync privileges
  
  .DESCRIPTION
  Gives a random user DCSync privileges
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/WazeHell/vulnerable-AD/blob/master/vulnad.ps1
#>
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $ADObject = [ADSI]("LDAP://" + (Get-ADDomain $Global:Domain).DistinguishedName)
        $randomuser = (VulnAD-GetRandom -InputList $Global:CreatedUsers)
        $sid = (Get-ADUser -Identity $randomuser).sid

        $objectGuidGetChanges = New-Object Guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)

        $objectGuidGetChanges = New-Object Guid 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)

        $objectGuidGetChanges = New-Object Guid 89e95b76-444d-4c62-991a-0facbeda640c
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)
        $ADObject.psbase.CommitChanges()

        Set-ADUser $randomuser -Description "Replication Account"
        Write-Info "Giving DCSync to : $randomuser"
    }
}
function VulnAD-DisableSMBSigning {
<#
  .SYNOPSIS
  Disables SMB Signing
  
  .DESCRIPTION
  Disables SMB Signing
  
  .Notes
  This function was either copied or a modified version of a 
  function from:
	https://github.com/WazeHell/vulnerable-AD/blob/master/vulnad.ps1
#>
    Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
}
