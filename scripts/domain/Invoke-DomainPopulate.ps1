<#
  .NOTES
	=======================================================
	Filename:     	Populate-AD.ps1
	Version: 		1.0
	Created on:   	September 16th, 2021
	Created by:   	https://github.com/Ramos04
	=======================================================
	This script is used to create an insecure lab for 
	testing purposes. 
	
	By default the script will pick a password from the 
	rockyou.txt file. 
   
	The script also creates users with the following flags
	set to true:
		-AllowReversiblePasswordEncryption
		-PasswordNeverExpires
   
	I would not use this for anything besides lab purposes
	=======================================================
	
  .SYNOPSIS
  Populates Active Directory with OU's, Users and Groups

  .DESCRIPTION
  Generates random users from 3 name files and adds them 
  to Active Directory. 
   
  Uses the $Deparments array that is defined below to 
  create the OU's and and add the users. The $Deparments
  array also specIFies the number of users to create 
  for each one. 

  .PARAMETER Debug
  Temp
  
  .PARAMETER Remove
  Temp
  
  .PARAMETER Status
  Temp
  

  .INPUTS
  None. You cannot pipe objects to Update-Month.ps1.

  .OUTPUTS
  None. Update-Month.ps1 does not generate any output.

  .EXAMPLE
  PS> Populate-AD.ps1 -Status

  .EXAMPLE
  PS> Populate-AD.ps1 -Debug -Status
  
  .EXAMPLE
  PS> Populate-AD.ps1 -Remove
#>
[CmdletBinding()]
param(
  [switch]$Status, 
  [switch]$Remove, 
  [switch]$Insecure
)

# Get the current directory
$scriptpath = Split-Path $script:MyInvocation.MyCommand.Path

# Set the DebugPreference to continue instead of prompting on errors
IF ([bool]$PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true ) {
	IF ( $debug = ( ([bool]$Script:PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent ) ) ) {
		$DebugPreference = 'Continue'
	}
}

# Dont download the name files IF the -Remove parameter is set, as it would be unnecessary
IF ( ! $Remove.IsPresent){
	# Set TLS version for Invoke-WebRequest
	[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"; 

	# URL's for the name files
	$surname_url ="https://gist.githubusercontent.com/craigh411/19a4479b289ae6c3f6edb95152214efc/raw/d25a1afd3de42f10abdea7740ed098d41de3c330/List%2520of%2520the%25201,000%2520Most%2520Common%2520Last%2520Names%2520(USA)"
	$man_url = "https://www.cs.cmu.edu/afs/cs/project/ai-repository/ai/areas/nlp/corpora/names/male.txt"
	$woman_url = "https://www.cs.cmu.edu/afs/cs/project/ai-repository/ai/areas/nlp/corpora/names/female.txt"
	$password_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-40.txt"

	# Pull the name files, pretty them up and dump them to arrays
	$man_array = ((Invoke-WebRequest -URI $man_url).Content.Split("`n") | Where { ($_ -ne '') -and ($_ -notmatch "^#") })
	$woman_array = ((Invoke-WebRequest -URI $woman_url).Content.Split("`n") | Where { ($_ -ne '') -and ($_ -notmatch "^#") })
	$surname_array = (((Invoke-WebRequest -URI $surname_url).Content -replace ",","").Split("`n") | Where-Object { $_.Length -gt 5 })
	$password_array = ((Invoke-WebRequest -URI $password_url).Content.Split("`n") | Where { ($_ -ne '') })
}

# Get the domain the host is in
$domain_name = [System.Net.Dns]::GetHostByName($env:computerName).Hostname.split(".",2)[-1]
$domain_path = (Get-ADDomain).DistinguishedName

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
	secedit /export /cfg c:\secpol.cfg

	If ( ! (Get-Content C:\secpol.cfg | Select-String -Pattern 'PasswordComplexity = 0','MinimumPasswordLength = 2').Match.Success ){
		(Get-Content C:\secpol.cfg) -replace "PasswordComplexity = 1","PasswordComplexity = 0" -replace "MinimumPasswordLength = 7","MinimumPasswordLength = 2" | Set-Content C:\secpol.cfg
		secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
	}
	
	rm -force c:\secpol.cfg -confirm:$false
}
Function Generate-SamAccountName {
	Param
    (
         [Parameter(Mandatory=$true)]
         [string[]] $sam_account_list
    )
	
	# Generate Random 5 digit ID number
	$id = (Get-Random -Minimum 10000 -Maximum 99999).ToString()

	# Check IF the ID number is taken already
	While ( $sam_account_list.contains($id) ){
		$id = (Get-Random -Minimum 10000 -Maximum 99999).ToString()
	}
	
	return $id
}

Function Generate-User {
	Param
    (
        [Parameter(Mandatory=$true)]
        [string] $SamAccountName,
		[Parameter(Mandatory=$true)]
        [string] $Division, 
		[Parameter(Mandatory=$true)]
        [string] $Department
    )
	
	# Random whether is a man or woman
	$genderpreference = 0,1 | Get-Random

	# Grab random name from the list
	IF ($genderpreference -eq 0){
		$givenname = $woman_array | Get-Random
	}
	Else{
		$givenname = $man_array | Get-Random
		
	}
	
	# Grab random last name
	$surname = $surname_array | Get-Random
		
	# Generate User Object 
	$user_object = [PSCustomObject]@{
		Name = $givenname + " " + $surname
		GivenName = $givenname
		Surname = $surname
		DisplayName = $givenname + " " + $surname
		Description = "Generated Lab Account"
		EmployeeID = $SamAccountName
		Division = $Division
		Department = $Department
		Title = "GeneratedUser"
		SamAccountName = $SamAccountName
		UserPrincipalName = $givenname.ToLower() + "." + $surname.ToLower() + "@" + $domain_name.ToLower()
		Password = (ConvertTo-SecureString ($password_array | Get-Random) -AsPlainText -force)
		Enabled = $True
	}

	return $user_object
}

Function Populate-AD {
	# Keeps track of all SamAccountNames, so no colisions occur
	$SamAccountList = @(Get-ADUser -Filter * -SearchBase (Get-ADDomain).DistinguishedName | Select sAMAccountName)

	$status_div_count = 0
	$status_user_count = 0
	Foreach ($division in $Divisions){
		$status_div_count += 1

		# Write status IF switch was passed
		If($Status.IsPresent){Write-Progress -Activity "Divisions" -Status $division.Name -PercentComplete ($status_div_count /$Divisions.Count*100) -Id 0}
		
		# Make sure the OU's are created first
		Try{
			# Create the Divisions OU's
			New-ADOrganizationalUnit -Name $division.Name -DisplayName $division.Name -ProtectedFromAccidentalDeletion $false -Path $domain_path
			New-ADOrganizationalUnit -Name "Groups" -DisplayName "Groups" -ProtectedFromAccidentalDeletion $false -Path ("OU=" + $division.Name + "," + $domain_path)
		}
		Catch{
			Write-Host ($_.InvocationInfo.ScriptName + "] " + $_.Exception.Message + " OU=" + $division.Name + "," + $domain_path) -F Yellow

			IF ([bool]$PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true ) {
				IF ( $debug = ( ([bool]$Script:PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent ) ) ) {
					Write-Host ("`t" + "[LINE: " + $_.InvocationInfo.ScriptLineNumber + "] " + $_.InvocationInfo.Line.Trim()) -F Red
				}
			}
		}
		
		$status_dept_count = 0
		Foreach ($department in $division.Department){
			$status_dept_count +=1
			
			If($Status.IsPresent){Write-Progress -Activity "Titles" -Status $department.Name -PercentComplete ($status_dept_count /$division.Department.Count*100) -Id 1 -ParentId 0}
			
			Try{
				# Create the Title OU
				New-ADOrganizationalUnit -Name $department.Name -DisplayName $department.Name -ProtectedFromAccidentalDeletion $false -Path ("OU=" + $division.Name + "," + $domain_path)
				
				# Create the Useres and Computers OU's
				New-ADOrganizationalUnit -Name "Computers" -DisplayName "Computers" -ProtectedFromAccidentalDeletion $false -Path ("OU=" + $department.Name + ",OU=" + $division.Name + "," + $domain_path)
				New-ADOrganizationalUnit -Name "Groups" -DisplayName "Groups" -ProtectedFromAccidentalDeletion $false -Path ("OU=" + $department.Name + ",OU=" + $division.Name + "," + $domain_path)
				New-ADOrganizationalUnit -Name "Users" -DisplayName "Users" -ProtectedFromAccidentalDeletion $false -Path ("OU=" + $department.Name + ",OU=" + $division.Name + "," + $domain_path)
			}
			Catch{
				Write-Debug ("[LINE: " + $_.Exception.InvocationInfo.ScriptLineNumber + "]" + $_.Exception.Message + " OU=" + $division.Name +"," + $domain_path) 
				
				Write-Host ($_.InvocationInfo.ScriptName + "] " + $_.Exception.Message + " OU=" + $department.Name + ",OU=" + $division.Name + "," + $domain_path) -F Yellow
				
				IF ([bool]$PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true ) {
					IF ( $debug = ( ([bool]$Script:PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent ) ) ) {
						Write-Host ("`t" + "[LINE: " + $_.InvocationInfo.ScriptLineNumber + "] " + $_.InvocationInfo.Line.Trim()) -F Red
					}
				}
			}
			
			For($i=1; $i -le $department.EmployeeCount; $i++){
				$status_user_count += 1
				
				# Generate user and add to AD
				Try{
					# Generate User properties
					$user_object = Generate-User (Generate-SamAccountName $SamAccountList) $division.Name $department.Name
					
					# Create the new user in Active Directory from properties in $user_object
					New-ADUser -Name $user_object.Name `
					-DisplayName $user_object.DisplayName`
					-GivenName $user_object.GivenName `
					-Surname $user_object.Surname `
					-Description $user_object.Description `
					-Division $user_object.Division `
					-Department $user_object.Department `
					-Title $user_object.Title `
					-EmployeeID $user_object.EmployeeID `
					-SamAccountName $user_object.SamAccountName `
					-UserPrincipalName $user_object.UserPrincipalName `
					-Path ("OU=Users,OU=" + $department.Name + ",OU=" + $division.Name + "," + $domain_path) `
					-AccountPassword $user_object.Password `
					-Enabled $user_object.Enabled `
					-AllowReversiblePasswordEncryption $true `
					-PasswordNeverExpires $true `
				}
				Catch{
					Write-Host ($_.InvocationInfo.ScriptName + "] " + $_.Exception.Message + "CN=" + $user_object.Name + ",OU=" + $department.Name + ",OU=" + $division.Name + "," + $domain_path) -F Yellow
				
					IF ([bool]$PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true ) {
						IF ( $debug = ( ([bool]$Script:PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent ) ) ) {
							Write-Host ("`t" + "[LINE: " + $_.InvocationInfo.ScriptLineNumber + "] " + $_.InvocationInfo.Line.Trim()) -F Red
						}
					}
				}
								
				If($Status.IsPresent){Write-Progress -Activity "Users" -Status $user_object.Name -PercentComplete ($i /$department.EmployeeCount*100) -Id 2 -ParentId 1}
			}
		}
	}
}

Function Remove-OUs {
	Foreach ($division in $Divisions){
		Try{
			# Remove all generated users
			Get-ADUser -Filter 'Title -like "GeneratedUser"'| Remove-ADUser -Confirm:$false
			
			# Get-ADOrganizationalUnit -Identity $ou_identity | `
			Set-ADObject -Identity ("OU=" + $division.Name + "," + $domain_path) -ProtectedFromAccidentalDeletion:$false
			Remove-ADOrganizationalUnit -Identity ("OU=" + $division.Name + "," + $domain_path) -Confirm:$false -Recursive
		}
		Catch{
			Write-Debug ($_.Exception.Message + " OU=" + $division.Name +"," + $domain_path)
		}
	}
}

Function Write-Groups{
	Foreach ($division in $Divisions){
		Write-Host $division.Name.Replace(" ","_")
		
		Foreach ($department in $division.Department){
			Write-Host $department.Name.Replace(" ","_")
			
		}
	}
}

# Group Formatting
# =======================================================
# Group Type Prefix: 
# 	L - Domain Local 
#	G - Global 
# 	U - Universal
# 
# Permission: 
# 	R - Read Only
# 	RW - Read and Write
# 
# <Division/Department>-<Resource/Use>-<Group Type Prefix>-<Permissions>



# New-ADGroup -Server $setdc `
# -Description $Description `
# -Name $GroupNameFull `
# -Path $ouLocation `
# -GroupCategory Security `
# -GroupScope Global `
# -ManagedBy $ownerinfo.distinguishedname

# Check IF we are populating AD or removing the changes
IF ( ! $Remove.IsPresent){
	#Remove-PasswordComplexityPolicy
	#Populate-AD
	
	Write-Groups
}
Else{
	Remove-OUs
}
