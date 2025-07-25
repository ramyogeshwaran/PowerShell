# 🛡️ Run with appropriate permissions on the domain controller or with RSAT tools installed

$domain = "Test.com"

# 📦 Get all GPO GUIDs from Active Directory (bulk query)
$gpoObjs = Get-GPO -All -Domain $domain
$gpoGuids = $gpoObjs | Select-Object -ExpandProperty ID | ForEach-Object { $_.ToString() }

# 🗂️ Get all policy folder GUIDs from SYSVOL
$polPath = "\\$domain\SYSVOL\$domain\Policies"
try {
    $sysvolGuids = Get-ChildItem -Path $polPath -Directory -ErrorAction Stop | Where-Object {
        $_.Name -match '^[{]?[0-9a-fA-F\-]{36}[}]?$'
    } | Select-Object -ExpandProperty Name
    $sysvolGuids = $sysvolGuids -replace '[{}]', ''  # Remove braces if present
}
catch {
    Write-Host "❌ Failed to enumerate SYSVOL path: $polPath" -ForegroundColor Red
    exit 1
}

# 🔍 Identify orphaned GUIDs

# In SYSVOL but not in AD (orphaned folders)
$orphanedInSysvol = Compare-Object -ReferenceObject $sysvolGuids -DifferenceObject $gpoGuids |
    Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject

# In AD but not in SYSVOL (orphaned GPOs)
$orphanedInAD = Compare-Object -ReferenceObject $gpoGuids -DifferenceObject $sysvolGuids |
    Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject

# 📝 Prepare the report data
$report = @()

# Add orphaned SYSVOL folders (no display name available)
foreach ($guid in $orphanedInSysvol) {
    $report += [PSCustomObject]@{
        OrphanType = "SYSVOL"
        GUID       = $guid
        Name       = ""
    }
}

# Add orphaned AD GPOs with display names fetched individually
foreach ($guid in $orphanedInAD) {
    $gpoName = ""
    try {
        $gpoObj = Get-GPO -Guid $guid -Domain $domain -ErrorAction Stop
        $gpoName = $gpoObj.DisplayName
    }
    catch {
        $gpoName = "Not found"
    }
    $report += [PSCustomObject]@{
        OrphanType = "AD"
        GUID       = $guid
        Name       = $gpoName
    }
}

# 📢 Output results to console

Write-Host "`n🗃️ Orphaned folders in SYSVOL (present in SYSVOL, missing in AD):" -ForegroundColor Yellow
if ($orphanedInSysvol.Count -eq 0) {
    Write-Host "✅ None found" -ForegroundColor Green
}
else {
    foreach ($guid in $orphanedInSysvol) {
        Write-Host $guid -ForegroundColor Cyan
    }
}

Write-Host "`n📄 Orphaned objects in AD (present in AD, missing in SYSVOL):" -ForegroundColor Yellow
if ($orphanedInAD.Count -eq 0) {
    Write-Host "✅ None found" -ForegroundColor Green
}
else {
    foreach ($gpo in $report | Where-Object { $_.OrphanType -eq "AD" }) {
        Write-Host "$($gpo.GUID) : $($gpo.Name)" -ForegroundColor Magenta
    }
}

# 💾 Export report to CSV
$csvPath = "C:\temp\GPO_Orphan_Report.csv"

try {
    $report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n📁 Results exported to: $csvPath" -ForegroundColor Green
}
catch {
    Write-Host "❌ Failed to export CSV to $csvPath" -ForegroundColor Red
}
