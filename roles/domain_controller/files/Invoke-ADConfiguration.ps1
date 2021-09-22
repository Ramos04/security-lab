<#
  .NOTES
	=======================================================
	Filename:     	Populate-AD.ps1
	Version: 		1.6
	Created on:   	September 16th, 2021
	Created by:   	https://github.com/Ramos04
	=======================================================
	This script is used to create an insecure lab for 
	testing purposes. 
	
	By default the script will disable the password 
	complexity policy and pick a password from the 
	rockyou.txt file. 
   
	The script also creates users with the following flags
	set to true:
		-PasswordNeverExpires = True
		-ChangePasswordAtLogon = False
		-AllowReversiblePasswordEncryption = True
	
	The script also creates two users, malicious.user, 
	which is a regular user that is placed in all department 
	groups, and malicious.da, which is a domain admin,
	
	The users are created to make your activity easier to 
	spot in Splunk. 
	=======================================================
	Using the secure flag leaves the default password
	policy in place and generates a randomly generated 14 
	character password with letters (upper and lower), 
	numbers, and special characters. 
	
	The secure flag also uses the following flags when 
	generating users and computers 
		-PasswordNeverExpires = False
		-ChangePasswordAtLogon = True
		-AllowReversiblePasswordEncryption = False
   
	The secure flag also disables the creation of the 
	aforementioned malicous user and domain admin. 
	
	=======================================================
	I would not use this for anything besides lab purposes
	=======================================================
	
  .SYNOPSIS
  Populates Active Directory with OU's, Users and Groups

  .DESCRIPTION
  Generates random users from 3 name files and adds them 
  to Active Directory. 
   
  Uses the $Deparments array that is defined below to 
  create the OU's and and add the users. The $Deparments
  array also specIfies the number of users to create 
  for each one. 

  .PARAMETER Verbose
  Effectively runs the script in debug mode
  
  .PARAMETER Reset
  Removes all of the user previously created by the script
  and removes the top level Organizational Unit recursively
  effectively removing all of the changes
  
  .PARAMETER Secure
  Randomly generates user passwords and does not disable
  the domain password complexity policy
  
  .PARAMETER Status
  Writes a status bar output to the console during population

  .EXAMPLE
  PS> Populate-AD.ps1 -Status -Verbose

  .EXAMPLE
  PS> Populate-AD.ps1 -Status -Secure
  
  .EXAMPLE
  PS> Populate-AD.ps1 -Reset
#>
[CmdletBinding()]
param(
  [switch]$Status, 
  [switch]$Reset, 
  [switch]$Secure
)

# Set the flags
If ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent){ $flag_verbose = $true }
If ($PSCmdlet.MyInvocation.BoundParameters["Reset"].IsPresent){ $flag_reset = $true }
If ($PSCmdlet.MyInvocation.BoundParameters["Status"].IsPresent){ $flag_status = $true }
If ($PSCmdlet.MyInvocation.BoundParameters["Secure"].IsPresent){ $flag_secure = $true }

# Get the current directory
$scriptpath = Split-Path $script:MyInvocation.MyCommand.Path

# Set the DebugPreference to continue instead of prompting on errors
If ([bool]$PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true ) {
	If ( $debug = ( ([bool]$Script:PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent ) ) ) {
		$DebugPreference = 'Continue'
	}
}

# Dont download the name files If the -Remove parameter is set, as it would be unnecessary
If ( ! $flag_reset ){
	# Set TLS version for Invoke-WebRequest
	If ($flag_verbose -eq $true){
		Write-Host "Downloading the name files"
	}
	[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"; 

	# URL's for the name files
	$surname_url ="https://gist.githubusercontent.com/craigh411/19a4479b289ae6c3f6edb95152214efc/raw/d25a1afd3de42f10abdea7740ed098d41de3c330/List%2520of%2520the%25201,000%2520Most%2520Common%2520Last%2520Names%2520(USA)"
	$man_url = "https://www.cs.cmu.edu/afs/cs/project/ai-repository/ai/areas/nlp/corpora/names/male.txt"
	$woman_url = "https://www.cs.cmu.edu/afs/cs/project/ai-repository/ai/areas/nlp/corpora/names/female.txt"
	$password_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-40.txt"

	# Pull the name files, pretty them up and dump them to arrays
	Write-Host "Downloading the name lists"
	$man_array = ((Invoke-WebRequest -URI $man_url).Content.Split("`n") | Where { ($_ -ne '') -and ($_ -notmatch "^#") })
	$woman_array = ((Invoke-WebRequest -URI $woman_url).Content.Split("`n") | Where { ($_ -ne '') -and ($_ -notmatch "^#") })
	$surname_array = (((Invoke-WebRequest -URI $surname_url).Content -replace ",","").Split("`n") | Where-Object { $_.Length -gt 5 })
	$password_array = ((Invoke-WebRequest -URI $password_url).Content.Split("`n") | Where { ($_ -ne '') })
}

# Get the domain the host is in
$domain_name = [System.Net.Dns]::GetHostByName($env:computerName).Hostname.split(".",2)[-1]
$domain_path = (Get-ADDomain).DistinguishedName
$domain_bios_name = (Get-ADDomain).NetBIOSName
$top_level_ou_name = (Get-Culture).TextInfo.ToTitleCase((Get-ADDomain).NetBIOSName.ToLower())

# List of divisions, titles, and number of Employees in each
# Will iterate over this
$Divisions = @(
	[PSCustomObject]@{
		Name = "Finance"
		TLA = "FIN"
		Department =  @(
			[PSCustomObject]@{Name ="Accounting"; TLA = "ACC"; EmployeeCount = 18},
			[PSCustomObject]@{Name ="Accounts Payable"; TLA = "ACP"; EmployeeCount = 15},
			[PSCustomObject]@{Name ="Accounts Receivable"; TLA = "ACR"; EmployeeCount = 14}, 
			[PSCustomObject]@{Name ="Budget"; TLA = "BGT"; EmployeeCount = 16},
			[PSCustomObject]@{Name ="Corporate Tax"; TLA = "CPT"; EmployeeCount = 12}
		)
	},
	[PSCustomObject]@{
		Name = "Marketing"
		TLA = "MKT"
		Department =  @(
			[PSCustomObject]@{Name ="Corporate Communications"; TLA = "CPC"; EmployeeCount = 10}, 
			[PSCustomObject]@{Name ="Digital Communications"; TLA = "DGC"; EmployeeCount = 18},
			[PSCustomObject]@{Name ="Event Coordinator"; TLA = "EVC"; EmployeeCount = 14}, 
			[PSCustomObject]@{Name ="Market Research"; TLA = "MKR"; EmployeeCount = 13}
		)
	},
	[PSCustomObject]@{
		Name = "Human Resources"
		TLA = "HMR"
		Department =  @(
			[PSCustomObject]@{Name ="Internal Relations"; TLA = "INR"; EmployeeCount = 14}, 
			[PSCustomObject]@{Name ="Payroll"; TLA = "PYR"; EmployeeCount = 13},
			[PSCustomObject]@{Name ="Public Relations"; TLA = "PBR"; EmployeeCount = 12}, 
			[PSCustomObject]@{Name ="Recruiting"; TLA = "REC"; EmployeeCount = 7},
			[PSCustomObject]@{Name ="Training"; TLA = "TRA"; EmployeeCount = 8}
		)
	},
	[PSCustomObject]@{
		Name = "Information Technology"
		TLA = "ITS"
		Department =  @(
			[PSCustomObject]@{Name ="Database Administration"; TLA = "DBA"; EmployeeCount = 15}, 
			[PSCustomObject]@{Name ="Development"; TLA = "DEV"; EmployeeCount = 14},
			[PSCustomObject]@{Name ="Help Desk"; TLA = "HED"; EmployeeCount = 12}, 
			[PSCustomObject]@{Name ="Network Administration"; TLA = "NEA"; EmployeeCount = 19},
			[PSCustomObject]@{Name ="Security"; TLA = "SEC"; EmployeeCount = 18}, 
			[PSCustomObject]@{Name ="Server Administration"; TLA = "SEA"; EmployeeCount = 16}
		)
	}
)

Function Remove-PasswordComplexityPolicy{
	# Dump the policy 
	Write-Host "Dumping the security configuration to C:\secpol.cfg" -F Yellow
	secedit /export /cfg c:\secpol.cfg | Out-Null

	If ( ! (Get-Content C:\secpol.cfg | Select-String -Pattern 'PasswordComplexity = 0','MinimumPasswordLength = 2').Match.Success ){
		If ($flag_verbose -eq $true){
			Write-Host "Changing security policy password complexity and password length requirements" -F Yellow
		}
	(Get-Content C:\secpol.cfg) -replace "PasswordComplexity = 1","PasswordComplexity = 0" -replace "MinimumPasswordLength = 7","MinimumPasswordLength = 2" | Set-Content C:\secpol.cfg } Out-Null
		
		If ($flag_verbose -eq $true){
			Write-Host "Updating security policy with the new configuration" -F Yellow
		}
		secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY | Out-Null
	
	If ($flag_verbose -eq $true){
		Write-Host "Removing dumped security policy configuration file at C:\secpol.cfg" -F Yellow
	}
	rm -force c:\secpol.cfg -confirm:$false | Out-Null
}

Function Generate-SamAccountName {
	Param
    (
         [Parameter(Mandatory=$true)]
         [string[]] $sam_account_list
    ) 
	# Generate Random 5 digit ID number
	$id = (Get-Random -Minimum 10000 -Maximum 99999).ToString()

	# Check If the ID number is taken already
	While ( $sam_account_list.contains($id) ){
		$id = (Get-Random -Minimum 10000 -Maximum 99999).ToString()
	}
	
	return $id
}

Function Generate-ComputerAccountName {
	Param
    (
         [Parameter(Mandatory=$true)]
         [string[]] $computer_account_list
    )
	
	#$computer_sam = (-Join ("WIN-", (-Join ((48..57) + (65..90) | Get-Random -Count 7 | % {[char]$_})), "$"))
	$computer_sam = (-Join ("WIN-", (-Join ((48..57) + (65..90) | Get-Random -Count 7 | % {[char]$_}))))
	
	
	# Check If the ID number is taken already
	While ( $computer_account_list.contains($computer_sam) ){
		#$computer_sam = (-Join ("WIN-", (-Join ((48..57) + (65..90) | Get-Random -Count 7 | % {[char]$_})), "$"))
		$computer_sam = (-Join ("WIN-", (-Join ((48..57) + (65..90) | Get-Random -Count 7 | % {[char]$_}))))
	}
	
	return $computer_sam
}

Function Generate-User {
	Param
    (
        [Parameter(Mandatory=$true)]
        [string[]] $sam_account_list,
		[Parameter(Mandatory=$true)]
        [string] $Division, 
		[Parameter(Mandatory=$true)]
        [string] $Department
    )
	
	# Random whether is a man or woman
	$genderpreference = 0,1 | Get-Random

	# Grab random name from the list
	If ($genderpreference -eq 0){
		$givenname = $woman_array | Get-Random
	}
	Else{
		$givenname = $man_array | Get-Random
		
	}
	
	# Grab random last name
	$surname = $surname_array | Get-Random
		
	$SamAccountName = Generate-SamAccountName $sam_account_list
	
	# check if the secure flag is set
	If ($flag_secure -eq $true){
		$password = (-join ( (33, 42) + (35..38) + (48..57) + ( 65..90) + (97..122) | Get-Random -Count 14 | % {[char]$_}))
	}
	else{
		$password = ($password_array | Get-Random)
	}
	
	# Generate User Object 
	$user_object = [PSCustomObject]@{
		Name = $givenname + " " + $surname
		GivenName = $givenname
		Surname = $surname
		DisplayName = $givenname + " " + $surname
		Description = "ScriptGenerated"
		EmployeeID = $SamAccountName
		Division = $Division
		Department = $Department
		SamAccountName = $SamAccountName
		UserPrincipalName = $givenname.ToLower() + "." + $surname.ToLower() + "@" + $domain_name.ToLower()
		Password = (ConvertTo-SecureString $password -AsPlainText -force)
		Enabled = $True
		PasswordNeverExpires = $true
		AllowReversiblePasswordEncryption = $true
		ChangePasswordAtLogon = $false
	}

	If ($flag_secure -eq $true){
		$user_object.PasswordNeverExpires = $false
		$user_object.AllowReversiblePasswordEncryption =$false
		$user_object.ChangePasswordAtLogon = $true
	}
	
	$user_object | Format-List
	
	
	
	return $user_object
}

Function Generate-Computer {
	Param
    (
        [Parameter(Mandatory=$true)]
        [string[]] $computer_account_list
    )
	
	# Generate computer name
	$computer_name = Generate-ComputerAccountName $computer_account_list
	
		# check if the secure flag is set
	If ($flag_secure -eq $true){
		$password = (-join ( (33, 42) + (35..38) + (48..57) + ( 65..90) + (97..122) | Get-Random -Count 14 | % {[char]$_}))
	}
	else{
		$password = ($password_array | Get-Random)
	}

	# Generate Computer Object 
	$computer_object = [PSCustomObject]@{
		Name = $computer_name
		DisplayName = $computer_name
		Description = "ScriptGenerated"
		DNSHostname = $computer_name
		SamAccountName = $computer_name
		Password = (ConvertTo-SecureString $password -AsPlainText -force)
		Enabled = $True	
		PasswordNeverExpires = $true
		AllowReversiblePasswordEncryption = $true
		ChangePasswordAtLogon = $false
	}
	
	If ($flag_secure -eq $true){
		$computer_object.PasswordNeverExpires = $false
		$computer_object.AllowReversiblePasswordEncryption =$false
		$computer_object.ChangePasswordAtLogon = $true
	}
	
	return $computer_object
}

Function Populate-AD {
	# Keeps track of all SamAccountNames, so no colisions occur
	$SamAccountList = @(Get-ADUser -Filter * -SearchBase (Get-ADDomain).DistinguishedName | Select sAMAccountName)
	$computerAccountList = @(Get-ADComputer -Filter * -SearchBase (Get-ADDomain).DistinguishedName | Select sAMAccountName)

	$status_div_count = 0
	$status_user_count = 0
	
	Try{
		# Create the top level Organizational Unit
		# =====================================================
		New-ADOrganizationalUnit -Name $top_level_ou_name `
			-DisplayName $top_level_ou_name `
			-Description "ScriptGenerated" `
			-ProtectedFromAccidentalDeletion $false `
			-Path $domain_path
	}
	Catch{	
		Write-Host ("ERROR [" + $_.InvocationInfo.ScriptLineNumber + "]: " + $_.Exception.Message) -F Red
		Write-Host ("Object: " + $_.TargetObject) -F Red
		
		If ($flag_verbose -eq $true){
			Write-Host $_.InvocationInfo.PositionMessage -F Yellow
		}
	}
	
	Foreach ($division in $Divisions){
		$division_path = "OU=" + $top_level_ou_name + "," + $domain_path
		$status_div_count += 1

		# Write status If switch was passed
		If($flag_status){Write-Progress -Activity "Divisions" -Status $division.Name -PercentComplete ($status_div_count /$Divisions.Count*100) -Id 0}
		
		# Make sure the OU's are created first
		Try{
			# Create Division Organizational Unit
			# =====================================================
			#Write-Host ("Creating OU | " + "OU=" + $division.Name + "," + $division_path)
			Write-Host ("{0, -20} : {1}" -f "Creating OU", ("OU=" + $division.Name + "," + $division_path)) -F Yellow
			New-ADOrganizationalUnit -Name $division.Name `
				-DisplayName $division.Name `
				-Description "ScriptGenerated" `
				-ProtectedFromAccidentalDeletion $false `
				-Path $division_path
			
			# Create Division Groups Organizational Unit
			# =====================================================
			#Write-Host ("Creating Group | " + "OU=Groups,OU=" + $division.Name + "," + $division_path)
			Write-Host ("{0, -20} : {1}" -f "Creating OU", ("OU=Groups,OU=" + $division.Name + "," + $division_path)) -F Yellow
			New-ADOrganizationalUnit -Name "Groups" `
				-DisplayName "Groups" `
				-Description "ScriptGenerated" `
				-ProtectedFromAccidentalDeletion $false `
				-Path ("OU=" + $division.Name + "," + $division_path)
				
			# Create the Division Users Local Group 
			# =====================================================
			#Write-Host ("Creating Group | " + $domain_bios_name + "-" + $division.TLA + "-All-Users-LG")
			Write-Host ("{0, -20} : {1}" -f "Creating Group", ($domain_bios_name + "-" + $division.TLA + "-All-Users-LG")) -F Yellow
			New-ADGroup -Name ($domain_bios_name + "-" + $division.TLA + "-All-Users-LG") `
				-DisplayName ($domain_bios_name + "-" + $division.TLA + "-All-Users-LG") `
				-Description "ScriptGenerated" `
				-SamAccountName ($domain_bios_name + "-" + $division.TLA + "-All-Users-LG") `
				-Path ("OU=Groups,OU=" + $division.Name + "," + $division_path) `
				-GroupScope DomainLocal
			
			# Create Divisions Computers Local Group 
			# =====================================================
			#Write-Host ("Creating Group | " + $domain_bios_name + "-" + $division.TLA + "-All-Computers-LG")
			Write-Host ("{0, -20} : {1}" -f "Creating Group", ($domain_bios_name + "-" + $division.TLA + "-All-Computers-LG")) -F Yellow
			New-ADGroup -Name ($domain_bios_name + "-" + $division.TLA + "-All-Computers-LG") `
				-DisplayName ($domain_bios_name + "-" + $division.TLA + "-All-Computers-LG") `
				-Description "ScriptGenerated" `
				-SamAccountName ($domain_bios_name + "-" + $division.TLA + "-All-Computers-LG") `
				-Path ("OU=Groups,OU=" + $division.Name + "," + $division_path) `
				-GroupScope DomainLocal
		}
		Catch{
			Write-Host ("ERROR [" + $_.InvocationInfo.ScriptLineNumber + "]: " + $_.Exception.Message) -F Red
			Write-Host ("Object: " + $_.TargetObject) -F Red
			
			If ($flag_verbose -eq $true){
				Write-Host $_.InvocationInfo.PositionMessage -F Yellow
			}
		}
		
		$status_dept_count = 0
		Foreach ($department in $division.Department){
			$department_path = ("OU=" + $division.Name + "," + $division_path)
			$status_dept_count +=1
			
			If($flag_status){Write-Progress -Activity "Titles" -Status $department.Name -PercentComplete ($status_dept_count /$division.Department.Count*100) -Id 1 -ParentId 0}
			
			Try{
				# Create Department Organizational Unit
				# =====================================================
				#Write-Host ("Creating OU | " + "OU=" + $department.Name + "," + $department_path)
				Write-Host ("{0, -20} : {1}" -f "Creating OU", ("OU=" + $department.Name + "," + $department_path)) -F Yellow
				New-ADOrganizationalUnit -Name $department.Name `
					-DisplayName $department.Name `
					-Description "ScriptGenerated" `
					-ProtectedFromAccidentalDeletion $false `
					-Path $department_path
				
				# Create Department Computers Organizational Unit
				# =====================================================
				#Write-Host ("Creating OU | " + "OU=Computers,OU=" + $department.Name + "," + $department_path)
				Write-Host ("{0, -20} : {1}" -f "Creating OU", ("OU=Computers,OU=" + $department.Name + "," + $department_path)) -F Yellow
				New-ADOrganizationalUnit -Name "Computers" `
					-DisplayName "Computers" `
					-Description "ScriptGenerated" `
					-ProtectedFromAccidentalDeletion $false `
					-Path ("OU=" + $department.Name + "," + $department_path)
				
				# Create Department Groups Organizational Unit
				# =====================================================
				#Write-Host ("Creating OU | " + "OU=Groups,OU=" + $department.Name + "," + $department_path)
				Write-Host ("{0, -20} : {1}" -f "Creating OU", ("OU=Groups,OU=" + $department.Name + "," + $department_path)) -F Yellow
				New-ADOrganizationalUnit -Name "Groups" `
					-DisplayName "Groups" `
					-Description "ScriptGenerated" `
					-ProtectedFromAccidentalDeletion $false `
					-Path ("OU=" + $department.Name + "," + $department_path)
					
				# Create the Department Users Organizational Unit
				# =====================================================
				#Write-Host ("Creating OU | " + "OU=Users,OU=" + $department.Name + "," + $department_path)
				Write-Host ("{0, -20} : {1}" -f "Creating OU", ("OU=Users,OU=" + $department.Name + "," + $department_path)) -F Yellow
				New-ADOrganizationalUnit -Name "Users" `
					-DisplayName "Users" `
					-Description "ScriptGenerated" `
					-ProtectedFromAccidentalDeletion $false `
					-Path ("OU=" + $department.Name + "," + $department_path)
					
					
					
				# Create Department Users Global Group
				# =====================================================	
				#Write-Host ("Creating Group | " + $domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-GG")
				Write-Host ("{0, -20} : {1}" -f "Creating Group", ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-GG")) -F Yellow
				New-ADGroup -Name ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-GG") `
					-DisplayName ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-GG") `
					-Description "ScriptGenerated" `
					-SamAccountName ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-GG") `
					-Path ("OU=Groups,OU=" + $department.Name + "," + $department_path) `
					-GroupScope Global
				
				# Add Department Users GG to Division Users GG
				# =====================================================	
				#Write-Host ("Adding " + $domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-GG" + "to the group " + $domain_bios_name + "-" + $division.TLA + "-All-Users-LG")
				Write-Host ("Adding {0} to the group {1}" -f ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-GG"), ($domain_bios_name + "-" + $division.TLA + "-All-Users-LG")) -F Yellow
				Add-ADGroupMember -Identity ($domain_bios_name + "-" + $division.TLA + "-All-Users-LG") `
					-Members ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-GG")
				
				
	
				# Create Department Computers Global Group
				# =====================================================	
				#Write-Host ("Creating Group | " + $domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Computers-GG")
				Write-Host ("{0, -20} : {1}" -f "Creating Group", ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Computers-GG")) -F Yellow
				New-ADGroup -Name ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Computers-GG") `
					-DisplayName ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Computers-GG") `
					-Description "ScriptGenerated" `
					-SamAccountName ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Computers-GG") `
					-Path ("OU=Groups,OU=" + $department.Name + "," + $department_path) `
					-GroupScope Global
				
				# Add Department Computers GG to Division Computers GG
				# =====================================================	
				#Write-Host ("Adding " + $domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Computers-GG" + "to the group " + $domain_bios_name + "-" + $division.TLA + "-All-Computers-LG")
				Write-Host ("Adding {0} to the group {1}" -f ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Computers-GG"), ($domain_bios_name + "-" + $division.TLA + "-All-Computers-LG")) -F Yellow
				Add-ADGroupMember -Identity ($domain_bios_name + "-" + $division.TLA + "-All-Computers-LG") `
					-Members ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Computers-GG")
				
				# # Create the Department users Domain Local Group
				# # =====================================================	
				# Write-Host ("Creating Group | " + $domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-LG")
				# New-ADGroup -Name ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-LG") `
					# -DisplayName ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-LG") `
					# -Description "ScriptGenerated" `
					# -Path ("OU=Groups,OU=" + $department.Name + "," + $department_path) `
					# -GroupScope DomainLocal
					
				# # Create the Department computers Domain Local Group
				# # =====================================================
				# Write-Host ("Creating Group | " + $domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Computers-LG")				
				# New-ADGroup -Name ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Computers-LG") `
					# -DisplayName ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Computers-LG") `
					# -Description "ScriptGenerated" `
					# -Path ("OU=Groups,OU=" + $department.Name + "," + $department_path) `
					# -GroupScope DomainLocal
			}
			Catch{
				Write-Host ("ERROR [" + $_.InvocationInfo.ScriptLineNumber + "]: " + $_.Exception.Message) -F Red
				Write-Host ("Object: " + $_.TargetObject) -F Red
				
				If ($flag_verbose -eq $true){
					Write-Host $_.InvocationInfo.PositionMessage -F Yellow
				}
			}
			
			#Write-Host ("Creating users in the OU | " + "OU=" + $department.Name + ",OU=" + $division.Name + "," + $domain_path)
			Write-Host ("{0, -20} : {1}" -f "Creating users in OU", ("OU=Users,OU=" + $department.Name + "," + $department_path)) -F Yellow
			For($i=1; $i -le $department.EmployeeCount; $i++){
				$status_user_count += 1
				
				# Generate user and add to AD
				Try{
					# Generate User properties
					$user_object = Generate-User $SamAccountList $division.Name $department.Name
					
					# Create Active Directory User
					# =====================================================	
					New-ADUser -Name $user_object.Name `
						-DisplayName $user_object.DisplayName`
						-GivenName $user_object.GivenName `
						-Surname $user_object.Surname `
						-Description $user_object.Description `
						-Division $user_object.Division `
						-Department $user_object.Department `
						-EmployeeID $user_object.EmployeeID `
						-SamAccountName $user_object.SamAccountName `
						-UserPrincipalName $user_object.UserPrincipalName `
						-Path ("OU=Users,OU=" + $department.Name + "," + $department_path) `
						-AccountPassword $user_object.Password `
						-ChangePasswordAtLogon $user_object.ChangePasswordAtLogon `
						-Enabled $user_object.Enabled `
						-AllowReversiblePasswordEncryption $user_object.AllowReversiblePasswordEncryption `
						-PasswordNeverExpires $user_object.PasswordNeverExpires
						
					# Add the user to the SamAccountList
					$SamAccountList += $user_object.SamAccountName
					
					# Add User to Department Global Group
					# =====================================================	
					Add-ADGroupMember -Identity ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-GG") `
						-Members $user_object.SamAccountName
						
					# Create corresponding computer account
					# =====================================================	
					$computer_object = Generate-Computer $computerAccountList

					New-ADComputer -Name $computer_object.Name`
						-DisplayName $computer_object.DisplayName`
						-Description $computer_object.Description `
						-DNSHostName $computer_object.DNSHostName`
						-SamAccountName $computer_object.SamAccountName `
						-Path ("OU=Computers,OU=" + $department.Name + "," + $department_path) `
						-AccountPassword $computer_object.Password `
						-Enabled $computer_object.Enabled `
						-ChangePasswordAtLogon $user_object.ChangePasswordAtLogon `
						-AllowReversiblePasswordEncryption $user_object.AllowReversiblePasswordEncryption `
						-PasswordNeverExpires $user_object.PasswordNeverExpires
						
					# Add the computer name to the computer computerAccountList
					$computerAccountList += $computer_object.SamAccountName
				}
				Catch{
					Write-Host ("ERROR [" + $_.InvocationInfo.ScriptLineNumber + "]: " + $_.Exception.Message) -F Red
					Write-Host ("Object: " + $_.TargetObject) -F Red
					
					If ($flag_verbose -eq $true){
						Write-Host $_.InvocationInfo.PositionMessage -F Yellow
					}
				}
								
				
				If($flag_status){Write-Progress -Activity "Users" -Status $user_object.Name -PercentComplete ($i /$department.EmployeeCount*100) -Id 2 -ParentId 1}
			}
		}
	}
}

Function Reset-AD {
	Try{
		Write-Host "Removing all previously created users" 
		Get-ADUser -Filter 'Description -like "ScriptGenerated"'| Remove-ADUser -Confirm:$false		
		
		Write-Host ("Recursively removing OU | OU=" + $top_level_ou_name + "," + $domain_path)
		Set-ADObject -Identity ("OU=" + $top_level_ou_name + "," + $domain_path) -ProtectedFromAccidentalDeletion $false
		Remove-ADOrganizationalUnit -Identity ("OU=" + $top_level_ou_name + "," + $domain_path) -Confirm:$false -Recursive
	}
	Catch{
		Write-Host ("ERROR [" + $_.InvocationInfo.ScriptLineNumber + "]: " + $_.Exception.Message) -F Red
		Write-Host ("Object: " + $_.TargetObject) -F Red
		
		If ($flag_verbose -eq $true){
			Write-Host $_.InvocationInfo.PositionMessage -F Yellow
		}
	}
}

Function Add-MaliciousUsers {
	Write-Host "Creating malicious users to be used for testing" -F Yellow
	Try{	
		Write-Host "Creating Malicious Domain Admin malicious.da" 
		# Generate malicious Domain Admin
		# =====================================================
		New-ADUser -Name malicious.da `
			-DisplayName "malicious.da" `
			-GivenName "Malicious" `
			-Surname "Domain Admin"  `
			-Description "ScriptGenerated" `
			-SamAccountName "malicious.da" `
			-UserPrincipalName ("malicious.da@" + $domain_name.ToLower()) `
			-AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -force) `
			-ChangePasswordAtLogon $false `
			-Enabled $true `
			-AllowReversiblePasswordEncryption $true `
			-PasswordNeverExpires $true
		
		Add-ADGroupMember -Identity "Administrators" `
			-Members "malicious.da"
	}
	Catch{
		Write-Host ("ERROR [" + $_.InvocationInfo.ScriptLineNumber + "]: " + $_.Exception.Message) -F Red
		Write-Host ("Object: " + $_.TargetObject) -F Red
			
		If ($flag_verbose -eq $true){
			Write-Host $_.InvocationInfo.PositionMessage -F Yellow
		}
	}
	
	Try{		
		Write-Host "Creating Malicious User malicious.user"
		# Generate malicious user
		# =====================================================
		New-ADUser -Name malicious.user `
			-DisplayName "malicious.user" `
			-GivenName "Malicious" `
			-Surname "User"  `
			-Description "ScriptGenerated" `
			-SamAccountName "malicious.user" `
			-UserPrincipalName ("malicious.user@" + $domain_name.ToLower()) `
			-AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -force) `
			-ChangePasswordAtLogon $false `
			-Enabled $true `
			-AllowReversiblePasswordEncryption $true `
			-PasswordNeverExpires $true
	}
	Catch{
		Write-Host ("ERROR [" + $_.InvocationInfo.ScriptLineNumber + "]: " + $_.Exception.Message) -F Red
		Write-Host ("Object: " + $_.TargetObject) -F Red
		
		If ($flag_verbose -eq $true){
			Write-Host $_.InvocationInfo.PositionMessage -F Yellow
		}
	}
		
	# Add the malicious user to all groups cause why not
	# =====================================================	
	Foreach ($division in $Divisions){
		Foreach ($department in $division.Department){
			
			Try{		
				Add-ADGroupMember -Identity ($domain_bios_name + "-" +$division.TLA + "-" + $department.Name.Replace(" ","") + "-Users-GG") `
					-Members "malicious.user"
			}
			Catch{
				Write-Host ("ERROR [" + $_.InvocationInfo.ScriptLineNumber + "]: " + $_.Exception.Message) -F Red
				Write-Host ("Object: " + $_.TargetObject) -F Red
				
				If ($flag_verbose -eq $true){
					Write-Host $_.InvocationInfo.PositionMessage -F Yellow
				}
			}
		}
	}
}

If ( $flag_reset -ne $true ){
	
	Populate-AD
	
	if ( $flag_secure -ne $true ){
		Remove-PasswordComplexityPolicy
		Add-MaliciousUsers
	}
	
}
Else{
	Reset-AD
}
