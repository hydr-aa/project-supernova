"""Remediation command generator — returns PowerShell commands per finding ID."""


REMEDIATION_COMMANDS = {
    "AUDIT-ACC-001": (
        "$domain = (Get-ADDomain).DNSRoot\n"
        "Set-ADDefaultDomainPasswordPolicy -Identity $domain -MinPasswordLength 14"
    ),
    "AUDIT-ACC-002": (
        "Set-ADDefaultDomainPasswordPolicy -Identity $((Get-ADDomain).DNSRoot) -ComplexityEnabled $true"
    ),
    "AUDIT-ACC-003": (
        "Set-ADDefaultDomainPasswordPolicy -Identity $((Get-ADDomain).DNSRoot) -PasswordHistoryCount 24"
    ),
    "AUDIT-ACC-006": (
        "$domain = (Get-ADDomain).DNSRoot\n"
        "Set-ADDefaultDomainPasswordPolicy -Identity $domain -LockoutThreshold 5 -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00"
    ),
    "AUDIT-KRB-001": (
        "# Remove unconstrained delegation from non-DC accounts:\n"
        "Get-ADComputer -Filter {TrustedForDelegation -eq $true} |\n"
        "    Where-Object { $_.DistinguishedName -notmatch 'Domain Controllers' } |\n"
        "    Set-ADAccountControl -TrustedForDelegation $false"
    ),
    "AUDIT-KRB-004": (
        "# Migrate to gMSA (Group Managed Service Accounts):\n"
        "$acct = Read-Host 'Enter service account name'\n"
        "$domain = (Get-ADDomain).DNSRoot\n"
        "New-ADServiceAccount -Name \"$acct-gMSA\" -DNSHostName \"DC01.$domain\" -PrincipalsAllowedToRetrieveManagedPassword 'Domain Computers'"
    ),
    "AUDIT-PRV-001": (
        "# Audit Domain Admins membership:\n"
        "Get-ADGroupMember -Identity 'Domain Admins' | Format-Table SamAccountName, ObjectClass"
    ),
    "AUDIT-GPO-001": (
        "# Scan SYSVOL for GPP cpassword entries:\n"
        "Get-ChildItem -Path \"\\\\$env:USERDNSDOMAIN\\SYSVOL\" -Recurse -Include '*.xml' |\n"
        "    Select-String -Pattern 'cpassword' | Select-Object Path, Line"
    ),
    "AUDIT-PRT-001": (
        "# Enforce LDAP signing on DC:\n"
        "$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters'\n"
        "Set-ItemProperty -Path $path -Name 'LDAPServerIntegrity' -Value 2 -Type DWord"
    ),
    "AUDIT-PRT-002": (
        "$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters'\n"
        "Set-ItemProperty -Path $path -Name 'LdapEnforceChannelBinding' -Value 2 -Type DWord"
    ),
    "AUDIT-PRT-003": (
        "Set-SmbServerConfiguration -EnableSecuritySignature $true -Force\n"
        "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"
    ),
    "AUDIT-PRT-004": (
        "# Disable LLMNR via Group Policy:\n"
        "# Computer Configuration -> Admin Templates -> Network -> DNS Client\n"
        "# Set 'Turn off multicast name resolution' = Enabled"
    ),
    "AUDIT-PRT-007": (
        "Stop-Service -Name Spooler -Force\n"
        "Set-Service -Name Spooler -StartupType Disabled"
    ),
    "AUDIT-EPT-001": (
        "# Deploy LAPS:\n"
        "Install-WindowsFeature RSAT-LAPS\n"
        "Update-LapsADSchema\n"
        "Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=...'"
    ),
    "AUDIT-EPT-002": (
        "# Add privileged accounts to Protected Users:\n"
        "Get-ADGroupMember 'Domain Admins' | ForEach-Object {\n"
        "    Add-ADGroupMember -Identity 'Protected Users' -Members $_.SamAccountName -ErrorAction SilentlyContinue\n"
        "}"
    ),
    "AUDIT-EPT-003": (
        "# Reset KRBTGT password (TWICE with 10-hour wait between):\n"
        "$ticket = New-Object Microsoft.PowerShell.Commands.ResetADComputerServiceAccountPasswordCommand\n"
        "# Run TWICE: Invoke-Expression 'Reset-ADComputerServiceAccountPassword -Identity krbtgt'"
    ),
}


def get_remediation(finding_id: str, extra: str = "") -> str:
    """Return a PowerShell remediation command for a given finding ID."""
    cmd = REMEDIATION_COMMANDS.get(finding_id, "")
    if extra:
        cmd = extra
    return cmd if cmd else "# No automated remediation available. Review manually."
