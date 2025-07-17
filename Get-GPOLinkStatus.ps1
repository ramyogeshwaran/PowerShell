# Output paths
$ReportDir = "C:\Temp"
$LinkedCsv = Join-Path $ReportDir "LinkedGPOs.csv"
$UnlinkedCsv = Join-Path $ReportDir "UnlinkedGPOs.csv"

# Ensure report folder exists
if (-not (Test-Path $ReportDir)) {
    New-Item -Path $ReportDir -ItemType Directory | Out-Null
}

# Hashtable for fast lookup
$linkedGPOHash = @{}
$domains = (Get-ADForest).Domains

foreach ($domain in $domains) {
    # OU-level links
    Get-ADOrganizationalUnit -Filter * -Server $domain | ForEach-Object {
        try {
            $inheritance = Get-GPInheritance -Target $_.DistinguishedName -ErrorAction Stop
            foreach ($link in $inheritance.GpoLinks) {
                if ($link.Enabled -and -not $linkedGPOHash.ContainsKey($link.DisplayName)) {
                    $linkedGPOHash[$link.DisplayName] = $true
                }
            }
        } catch {
            Write-Warning "Failed to query OU inheritance on $_.DistinguishedName in $domain"
        }
    }

    # Domain-root links
    try {
        $domainRootDN = (Get-ADDomain -Server $domain).DistinguishedName
        $inheritance = Get-GPInheritance -Target $domainRootDN -ErrorAction Stop
        foreach ($link in $inheritance.GpoLinks) {
            if ($link.Enabled -and -not $linkedGPOHash.ContainsKey($link.DisplayName)) {
                $linkedGPOHash[$link.DisplayName] = $true
            }
        }
    } catch {
        Write-Warning "Failed to query domain root inheritance on $domain"
    }
}

# Collect all GPOs
$allGPOs = Get-GPO -All

# Separate linked and unlinked
$linkedList = @()
$unlinkedList = @()

foreach ($gpo in $allGPOs) {
    $obj = [pscustomobject]@{
        DisplayName = $gpo.DisplayName
        GUID        = $gpo.Id
    }

    if ($linkedGPOHash.ContainsKey($gpo.DisplayName)) {
        $linkedList += $obj
    } else {
        $unlinkedList += $obj
    }
}

# Export both reports
$linkedList | Sort-Object DisplayName | Export-Csv -Path $LinkedCsv -NoTypeInformation -Encoding UTF8
$unlinkedList | Sort-Object DisplayName | Export-Csv -Path $UnlinkedCsv -NoTypeInformation -Encoding UTF8

Write-Host "`n✅ Linked GPOs saved to: $LinkedCsv" -ForegroundColor Green
Write-Host "✅ Unlinked GPOs saved to: $UnlinkedCsv" -ForegroundColor Green
