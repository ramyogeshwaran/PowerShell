<#
.SYNOPSIS
    Generates a CSV report of permissions (ACLs) on OUs, Containers, and GPOs.

.DESCRIPTION
    - Collects all Organizational Units (OUs), Containers, and Group Policy Objects (GPOs).
    - Reads their Access Control Lists (ACLs).
    - Exports results to a CSV file for auditing.

.NOTES
    Author : Yogesh
    Usage  : Run in PowerShell with AD module loaded
#>

Import-Module ActiveDirectory

$Report = @()

# --- 1. Collect OU Permissions ---
$OUs = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName
foreach ($OU in $OUs) {
    $acl = Get-Acl "AD:$($OU.DistinguishedName)"
    foreach ($entry in $acl.Access) {
        $Report += [PSCustomObject]@{
            ObjectType         = "OU"
            ObjectName         = $OU.Name
            DistinguishedName  = $OU.DistinguishedName
            Identity           = $entry.IdentityReference
            Rights             = $entry.ActiveDirectoryRights
            AccessType         = $entry.AccessControlType
            Inheritance        = $entry.InheritanceType
        }
    }
}

# --- 2. Collect Container Permissions ---
$Containers = Get-ADObject -LDAPFilter "(objectClass=container)" -Properties DistinguishedName
foreach ($C in $Containers) {
    $acl = Get-Acl "AD:$($C.DistinguishedName)"
    foreach ($entry in $acl.Access) {
        $Report += [PSCustomObject]@{
            ObjectType         = "Container"
            ObjectName         = $C.Name
            DistinguishedName  = $C.DistinguishedName
            Identity           = $entry.IdentityReference
            Rights             = $entry.ActiveDirectoryRights
            AccessType         = $entry.AccessControlType
            Inheritance        = $entry.InheritanceType
        }
    }
}

# --- 3. Collect GPO Permissions ---
$DomainDN = (Get-ADDomain).DistinguishedName
$GPOContainer = "CN=Policies,CN=System,$DomainDN"

$GPOs = Get-ADObject -LDAPFilter "(objectClass=groupPolicyContainer)" -SearchBase $GPOContainer -Properties DisplayName, DistinguishedName
foreach ($GPO in $GPOs) {
    $acl = Get-Acl "AD:$($GPO.DistinguishedName)"
    foreach ($entry in $acl.Access) {
        $Report += [PSCustomObject]@{
            ObjectType         = "GPO"
            ObjectName         = $GPO.DisplayName
            DistinguishedName  = $GPO.DistinguishedName
            Identity           = $entry.IdentityReference
            Rights             = $entry.ActiveDirectoryRights
            AccessType         = $entry.AccessControlType
            Inheritance        = $entry.InheritanceType
        }
    }
}

# --- 4. (Optional) Collect Domain Root Permissions ---
$DomainRoot = (Get-ADDomain).DistinguishedName
$acl = Get-Acl "AD:$DomainRoot"
foreach ($entry in $acl.Access) {
    $Report += [PSCustomObject]@{
        ObjectType         = "DomainRoot"
        ObjectName         = $DomainRoot
        DistinguishedName  = $DomainRoot
        Identity           = $entry.IdentityReference
        Rights             = $entry.ActiveDirectoryRights
        AccessType         = $entry.AccessControlType
        Inheritance        = $entry.InheritanceType
    }
}

# --- Export Final Report ---
$OutputPath = "C:\Reports\AD_Permissions_Report.csv"
$Report | Export-Csv $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Report generated: $OutputPath"
