
$machines = @("S1", "S2")

# Output file
$outputFile = "C:\temp\SMBMappings.csv"

$results = @()


$scriptBlock = {
    Get-SmbMapping | Select-Object PSComputerName, LocalPath, RemotePath, Status
}

# Loop through the machines
foreach ($machine in $machines) {
    try {
        Write-Host "Fetching SMB Mappings for $machine..."
        $results += Invoke-Command -ComputerName $machine -ScriptBlock $scriptBlock
    } catch {
        Write-Host "Failed to connect to $machine $_"
    }
}

# Export results to CSV
$results | Export-Csv -Path $outputFile -NoTypeInformation
Write-Host "Results exported to $outputFile"
