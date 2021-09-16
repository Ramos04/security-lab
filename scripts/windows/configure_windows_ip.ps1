Param (
    [Parameter(Mandatory=$true)]
    [string]$Hostname, 
    [Parameter(Mandatory=$true)]
    [string]$IPAddress,
    [Parameter(Mandatory=$true)]
    [string]$Gateway,
    [string]$ComputerName = $env:COMPUTERNAME,
    [string]$Username="Ansible",
    [string]$Password="Password1!"
)

# convert to secure string
$SecureStrPassword = ConvertTo-SecureString $Password -AsPlainText -Force

Write-Host "Creating Ansible account"
try{
    New-LocalUser -Name $Username -Password $SecureStrPassword
}
catch{
    Write-Host "User Ansible already exists"
}

Write-Host "Adding Ansible user to Administrators"
try{
    Add-LocalGroupMember -Group "Administrators" -Member $Username
}
catch{
    Write-Host "User Ansible is already an Administrator"
}

Write-Host Changing host name
Rename-Computer $Hostname

#$ipv6_confirmation = Read-Host "Is this a Domain Controller? (y/n)"
#if ($ipv6_confirmation -eq 'n'){
#	Write-Host Disabling IPv6 to solve domain resolution issues
#	Disable-NetAdapterBinding -Name * -ComponentID ms_tcpip6
#}

Write-Host Setting the DNS servers 
Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ServerAddresses ("8.8.8.8","8.8.4.4")

Write-Host Setting the IP Address
New-NetIPAddress -IPAddress $IPAddress -DefaultGateway $Gateway -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex

Write-Host Rebooting host
Restart-Computer -ComputerName $ComputerName
