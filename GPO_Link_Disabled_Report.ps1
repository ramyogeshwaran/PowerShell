<#
.SYNOPSIS
    Reports all GPO links that are disabled in the domain's OUs.
.AUTHOR
    Raghav
.VERSION
    1.3
#>

Import-Module GroupPolicy
Import-Module ActiveDirectory

# Fixed output folder
$basePath = "C:\temp"
if (-not (Test-Path $basePath)) {
    New-Item -Path $basePath -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmm'
$csvPath = Join-Path -Path $basePath -ChildPath "GPO_Links_Disabled_$timestamp.csv"

# Initialize report
$reportRows = @()
$domainName = (Get-ADDomain).DNSRoot

Write-Host "`n[+] Scanning domain: $domainName"

# Get all OUs in the domain
$OUs = Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
Write-Host "[+] Found $($OUs.Count) OUs to scan..."

foreach ($ou in $OUs) {
    try {
        $inheritance = Get-GPInheritance -Target $ou
        foreach ($link in $inheritance.GpoLinks) {
            if (-not $link.Enabled) {  # Only if LinkEnabled is False
                try {
                    $gpo = Get-GPO -Guid $link.GpoId -ErrorAction Stop
                    $reportRows += [PSCustomObject]@{
                        GPOName              = $gpo.DisplayName
                        GPOGUID              = $gpo.Id
                        OU_DistinguishedName = $ou
                        LinkEnabled          = $link.Enabled
                        LinkEnforced         = $link.Enforced
                        CreationTime         = $gpo.CreationTime
                        ModificationTime     = $gpo.ModificationTime
                        Owner                = $gpo.Owner
                        Domain               = $domainName
                    }
                } catch {
                    Write-Warning "⚠️ Failed to get GPO with ID: $($link.GpoId) in OU: $ou"
                }
            }
        }
    } catch {
        Write-Warning "❌ Failed to get inheritance for OU: $ou"
    }
}

# Export results
$reportRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# Summary output
Write-Host "`n[✔] Disabled GPO Link Report Generated"
Write-Host "    → Output CSV : $csvPath"
Write-Host "    → Disabled GPO Links Found: $($reportRows.Count)"
