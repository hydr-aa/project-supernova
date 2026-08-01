# GPP Password Seeder — creates Group Policy Preference with cpassword in SYSVOL
# Run AFTER DC promotion and reboot

$root = (Get-ADDomain).DistinguishedName
$dns = (Get-ADDomain).DNSRoot
Write-Host "[1/3] Creating GPO with cpassword..." -ForegroundColor Cyan
$gpo = New-GPO -Name "Deploy Backup Account"
New-GPLink -Name "Deploy Backup Account" -Target "OU=GMI,$root"
$guid = $gpo.Id.ToString()
Write-Host "  GPO GUID: $guid" -ForegroundColor Gray

$path = "\\$dns\SYSVOL\$dns\Policies\$guid\MACHINE\Preferences\Groups"
New-Item -ItemType Directory -Path $path -Force | Out-Null

$xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)" image="2" changed="2025-01-15 08:00:00" uid="{ABC12345-ABCD-ABCD-ABCD-ABCDEF123456}">
        <Properties action="U" newName="" fullName="" description="" cpassword="cAoIkM8F+RBgNsBGbQG2V9vNLRpm/X9qB/WNGdFR0aY" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="svc_backup"/>
    </User>
</Groups>
'@
Set-Content -Path "$path\Groups.xml" -Value $xml

Write-Host "[2/3] Groups.xml written" -ForegroundColor Green
Write-Host "[3/3] Done. SYSVOL contains decryptable cpassword." -ForegroundColor Green
