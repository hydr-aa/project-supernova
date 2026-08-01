# Supernova Lab Setup Script
# Run on the DC01 VM as Administrator
# Creates the domain, users, groups, and seeds deliberate misconfigurations

Write-Host "[1/7] Installing AD DS role..." -ForegroundColor Cyan
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment

Write-Host "[2/7] Promoting to Domain Controller..." -ForegroundColor Cyan
$safePass = ConvertTo-SecureString "Supernova2026!" -AsPlainText -Force
Install-ADDSForest -DomainName "supernova.vulnlab" -DomainNetbiosName "SUPERNOVA" -ForestMode "WinThreshold" -DomainMode "WinThreshold" -SafeModeAdministratorPassword $safePass -InstallDNS -NoRebootOnCompletion -Force

Write-Host "[3/7] Configuring static IP (192.168.70.10)..." -ForegroundColor Cyan
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress 192.168.70.10 -PrefixLength 24 -DefaultGateway 192.168.70.1
Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses "127.0.0.1"

Write-Host "[4/7] Creating OUs..." -ForegroundColor Cyan
$root = "DC=supernova,DC=vulnlab"
New-ADOrganizationalUnit -Name "GMI" -Path $root -ProtectedFromAccidentalDeletion $false
New-ADOrganizationalUnit -Name "Users" -Path "OU=GMI,$root"
New-ADOrganizationalUnit -Name "Computers" -Path "OU=GMI,$root"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=GMI,$root"
New-ADOrganizationalUnit -Name "ServiceAccounts" -Path "OU=GMI,$root"

Write-Host "[5/7] Creating users..." -ForegroundColor Cyan
$userPass = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$svcPass  = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

New-ADUser -Name "Anaqie Mikael" -SamAccountName "anaqie.mikael" -UserPrincipalName "anaqie.mikael@supernova.vulnlab" -Path "OU=Users,OU=GMI,$root" -AccountPassword $userPass -Enabled $true
New-ADUser -Name "Sitee Hajarr" -SamAccountName "sitee.hajarr" -UserPrincipalName "sitee.hajarr@supernova.vulnlab" -Path "OU=Users,OU=GMI,$root" -AccountPassword $userPass -Enabled $true
New-ADUser -Name "Luqman Zafree" -SamAccountName "luqman.zafree" -UserPrincipalName "luqman.zafree@supernova.vulnlab" -Path "OU=Users,OU=GMI,$root" -AccountPassword $userPass -Enabled $true
New-ADUser -Name "SQL Service" -SamAccountName "sqlservice" -UserPrincipalName "sqlservice@supernova.vulnlab" -Path "OU=ServiceAccounts,OU=GMI,$root" -AccountPassword $svcPass -Enabled $true -PasswordNeverExpires $true
New-ADUser -Name "Backup Service" -SamAccountName "svc_backup" -UserPrincipalName "svc_backup@supernova.vulnlab" -Path "OU=ServiceAccounts,OU=GMI,$root" -AccountPassword $svcPass -Enabled $true -PasswordNeverExpires $true
New-ADUser -Name "ASREP Test User" -SamAccountName "asrep_user" -UserPrincipalName "asrep_user@supernova.vulnlab" -Path "OU=Users,OU=GMI,$root" -AccountPassword $svcPass -Enabled $true
New-ADUser -Name "Helpdesk" -SamAccountName "helpdesk" -UserPrincipalName "helpdesk@supernova.vulnlab" -Path "OU=Users,OU=GMI,$root" -AccountPassword $userPass -Enabled $true
New-ADUser -Name "Backup Admin" -SamAccountName "backup_admin" -UserPrincipalName "backup_admin@supernova.vulnlab" -Path "OU=Users,OU=GMI,$root" -AccountPassword $userPass -Enabled $true
New-ADUser -Name "Supernova Service" -SamAccountName "svc_supernova" -UserPrincipalName "svc_supernova@supernova.vulnlab" -Path "OU=ServiceAccounts,OU=GMI,$root" -AccountPassword (ConvertTo-SecureString "SupernovaSvc2026!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true

Write-Host "[6/7] Seeding misconfigurations..." -ForegroundColor Yellow

# AS-REP roastable
Set-ADAccountControl -Identity asrep_user -DoesNotRequirePreAuth $true

# SPN on svc_backup
Set-ADUser -Identity svc_backup -ServicePrincipalNames @{Add="MSSQLSvc/WS01:1433"}

# DCSync rights for sqlservice
$acl = Get-Acl -Path "AD:\$root"
$identity = New-Object System.Security.Principal.NTAccount("SUPERNOVA", "sqlservice")
$rights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
$guid = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, "Allow", $guid)
$acl.AddAccessRule($ace); Set-Acl -Path "AD:\$root" -AclObject $acl

# GenericAll on Domain Admins for sqlservice
$daAcl = Get-Acl -Path "AD:\CN=Domain Admins,CN=Users,$root"
$daAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, "GenericAll", "Allow")
$daAcl.AddAccessRule($daAce); Set-Acl -Path "AD:\CN=Domain Admins,CN=Users,$root" -AclObject $daAcl

# WriteDacl for anaqie.mikael
$anaqie = New-Object System.Security.Principal.NTAccount("SUPERNOVA", "anaqie.mikael")
$rootAcl = Get-Acl -Path "AD:\$root"
$wDacl = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($anaqie, "WriteDacl", "Allow")
$rootAcl.AddAccessRule($wDacl); Set-Acl -Path "AD:\$root" -AclObject $rootAcl

# Account Operators: helpdesk
Add-ADGroupMember -Identity "Account Operators" -Members helpdesk

# Backup Operators: backup_admin
Add-ADGroupMember -Identity "Backup Operators" -Members backup_admin

# sqlservice in Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members sqlservice

# Weak password policy
Set-ADDefaultDomainPasswordPolicy -Identity supernova.vulnlab -MinPasswordLength 7 -ComplexityEnabled $false -PasswordHistoryCount 0 -LockoutThreshold 0

Write-Host "[7/7] REBOOT REQUIRED. Run: Restart-Computer -Force" -ForegroundColor Yellow
Write-Host "  Users: Password123! | Services: P@ssw0rd123! | Supernova svc: SupernovaSvc2026!" -ForegroundColor White
Write-Host "  Seeded: weak policy, DCSync, GenericAll, WriteDacl, AS-REP, SPNs, Operators" -ForegroundColor White
