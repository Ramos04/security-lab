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

Write-Host Setting the DNS servers 
Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ServerAddresses ("8.8.8.8","8.8.4.4")

ipconfig 

$confirmation = Read-Host "Does everyting above look correct? (y/n)"

if ($confirmation -eq 'y'){
	Write-Host Rebooting host
	Restart-Computer -ComputerName $ComputerName
}
else{
	Write-Host Aborting reboot
	Exit
}
