# Server the servers list
$servers = Get-Content -Path "C:\temp\servers.txt"

# Define the service name
$sccmServiceName = "CcmExec"

# Define paths to directories to be cleared
$ccmcachePath = "C:\windows\ccmcache"
$softwareDistPath = "C:\windows\softwaredistribution\download"


$reportData = @()

foreach ($server in $servers) {
    $status = ""
    
    try {
        # Check if the server is reachable
        if (Test-Connection -ComputerName $server -Count 1 -Quiet) {
            # Connect to the remote server
            $status = Invoke-Command -ComputerName $server -ScriptBlock {
                param ($sccmServiceName, $ccmcachePath, $softwareDistPath)

                # Check if SCCM service exists
                $sccmService = Get-Service -Name $sccmServiceName -ErrorAction SilentlyContinue
                if ($sccmService -eq $null) {
                    return "SCCM agent not present"
                }
                
                # Step 1: Stop SCCM Service
                if ($sccmService.Status -ne 'Stopped') {
                    Stop-Service -Name $sccmServiceName -Force -ErrorAction Stop
                    $status = "SCCM Service stopped; "
                } else {
                    $status = "SCCM Service already stopped; "
                }

                # Step 2: Clear files in c:\windows\ccmcache
                if (Test-Path -Path $ccmcachePath) {
                    Remove-Item -Path "$ccmcachePath\*" -Recurse -Force -ErrorAction Stop
                    $status += "Cleared ccmcache folder; "
                } else {
                    $status += "ccmcache folder not found; "
                }

                # Step 3: Clear files in c:\windows\softwaredistribution\download
                if (Test-Path -Path $softwareDistPath) {
                    Remove-Item -Path "$softwareDistPath\*" -Recurse -Force -ErrorAction Stop
                    $status += "Cleared SoftwareDistribution folder; "
                } else {
                    $status += "SoftwareDistribution folder not found; "
                }

                # Step 4: Start SCCM Service
                Start-Service -Name $sccmServiceName -ErrorAction Stop
                $status += "SCCM Service started."

                
                return $status
            } -ArgumentList $sccmServiceName, $ccmcachePath, $softwareDistPath
        }
        else {
            # If Server is offline
            $status = "Offline"
        }
    }
    catch {
        
        $status += "Error: $_"
    }

    
    $reportData += [PSCustomObject]@{
        ServerName = $server
        Status     = $status
    }
}

# Export report to CSV
$reportData | Export-Csv -Path "C:\temp\SCCMMaintenanceReport.csv" -NoTypeInformation -Encoding UTF8

Write-Output "SCCM Maintenance Report generated successfully at C:\temp\SCCMMaintenanceReport.csv"
