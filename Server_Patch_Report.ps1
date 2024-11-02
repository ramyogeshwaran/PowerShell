$servers = Get-Content -Path "C:\temp\servers.txt"   # Path to your server list file

$outputFile = "C:\temp\ServerReport.csv"


$reportData = @()


foreach ($server in $servers) {
    try {
        
        if (Test-Connection -ComputerName $server -Count 1 -Quiet) {
            # Get disk space information
            $diskInfo = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $server | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
                [PSCustomObject]@{
                    ServerName       = $server
                    DriveLetter      = $_.DeviceID
                    TotalSpaceGB     = "{0:N2}" -f ($_.Size / 1GB)
                    FreeSpaceGB      = "{0:N2}" -f ($_.FreeSpace / 1GB)
                }
            }
            
            # Get OS information
            $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $server
            $osDetails = [PSCustomObject]@{
                ServerName       = $server
                OSVersion        = $osInfo.Caption
                OSBuildNumber    = $osInfo.BuildNumber
            }

            # Get ReleaseId from registry
            $releaseId = Invoke-Command -ComputerName $server -ScriptBlock {
                try {
                    (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
                }
                catch {
                    "N/A"
                }
            }

            # Add ReleaseId to OS details
            $osDetails | Add-Member -MemberType NoteProperty -Name ReleaseId -Value $releaseId

            # Get installed patches information
            $patches = Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName $server | ForEach-Object {
                [PSCustomObject]@{
                    ServerName       = $server
                    PatchID          = $_.HotFixID
                    PatchDescription = $_.Description
                    InstalledOn      = $_.InstalledOn
                }
            }
            
            
            foreach ($disk in $diskInfo) {
                $reportItem = [PSCustomObject]@{
                    ServerName       = $server
                    DriveLetter      = $disk.DriveLetter
                    TotalSpaceGB     = $disk.TotalSpaceGB
                    FreeSpaceGB      = $disk.FreeSpaceGB
                    OSVersion        = $osDetails.OSVersion
                    OSBuildNumber    = $osDetails.OSBuildNumber
                    ReleaseId        = $osDetails.ReleaseId
                    PatchID          = $null
                    PatchDescription = $null
                    InstalledOn      = $null
                }
                $reportData += $reportItem
            }

            # patch information details
            foreach ($patch in $patches) {
                $reportData += [PSCustomObject]@{
                    ServerName       = $patch.ServerName
                    DriveLetter      = $null
                    TotalSpaceGB     = $null
                    FreeSpaceGB      = $null
                    OSVersion        = $osDetails.OSVersion
                    OSBuildNumber    = $osDetails.OSBuildNumber
                    ReleaseId        = $osDetails.ReleaseId
                    PatchID          = $patch.PatchID
                    PatchDescription = $patch.PatchDescription
                    InstalledOn      = $patch.InstalledOn
                }
            }
        }
        else {
            Write-Output "Server $server is unreachable."
        }
    }
    catch {
        Write-Output "Error gathering data from $server $_"
    }
}

# Export report to CSV
$reportData | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

Write-Output "Report generated successfully: $outputFile"
