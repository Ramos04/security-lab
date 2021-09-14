Param (
	[Parameter(Mandatory=$true)]
    [string]$Hostname, 
    [Parameter(Mandatory=$true)]
    [string]$IPAddress,
    [Parameter(Mandatory=$true)]
    [string]$Gateway,
	[string]$ComputerName = $env:COMPUTERNAME
)

Write-Host Changing host name
Rename-Computer $Hostname

Write-Host Setting the IP Address
New-NetIPAddress -IPAddress $IPAddress -DefaultGateway $Gateway -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex

$ipv6_confirmation = Read-Host "Is this a Domain Controller? (y/n)"
if ($ipv6_confirmation -eq 'n'){
	Write-Host Disabling IPv6 to solve domain resolution issues
	Disable-NetAdapterBinding -Name * -ComponentID ms_tcpip6
}

Write-Host Setting the DNS servers 
Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ServerAddresses ("8.8.8.8","8.8.4.4")

ipconfig 

$reboot_confirmation = Read-Host "Does everyting above look correct? (y/n)"

if ($reboot_confirmation -eq 'y'){
	Write-Host Rebooting host
	Restart-Computer -ComputerName $ComputerName
}
else{
	Write-Host Aborting reboot
	Exit
}
