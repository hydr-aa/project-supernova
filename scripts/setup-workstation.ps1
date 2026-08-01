# Supernova Lab Setup — Workstation Config
# Run on WS01/WS02 as Administrator after DC is live

$domainDNS = "supernova.vulnlab"
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
$ip = if ($env:COMPUTERNAME -like "*WS01*") { "192.168.70.100" } else { "192.168.70.101" }
Write-Host "Configuring workstation — IP: $ip" -ForegroundColor Cyan
New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress $ip -PrefixLength 24 -DefaultGateway 192.168.70.1
Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses "192.168.70.10"
$cred = Get-Credential -UserName "SUPERNOVA\Administrator" -Message "Enter domain admin password"
Add-Computer -DomainName $domainDNS -Credential $cred -Restart -Force
Write-Host "Joining $domainDNS — machine will reboot" -ForegroundColor Yellow
