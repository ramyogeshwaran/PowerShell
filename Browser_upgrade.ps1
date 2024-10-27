$upgradePath = "\\test.com\SYSVOL\test.com\scripts"
$reportPath = Join-Path -Path $upgradePath -ChildPath "BrowserUpgradeReport.csv"

$chromeInstaller = Join-Path -Path $upgradePath -ChildPath "Chrome.msi"
$edgeInstaller = Join-Path -Path $upgradePath -ChildPath "EdgeUpgrade.msi"  # Update if Edge installer is in a different location

$report = @()

# Get list of computers
$computers = Get-Content -Path "$upgradePath\computers.txt" # List of computers to update, modify this path as needed

foreach ($computer in $computers) {
    Write-Output "Processing $computer..."

    # Define browser versions
    $chromeVersion = "130.0.6723.70"
    $edgeVersion = "130.0.2849.52"

    Invoke-Command -ComputerName $computer -ScriptBlock {
        param ($chromeInstaller)

        $chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
       
        if (Test-Path $chromePath) {
         
            $chromeInfo = (Get-Item $chromePath).VersionInfo
            $chromeVersion = $chromeInfo.ProductVersion
           
            # Check the installed version
            if ($chromeVersion -eq "130.0.6723.70") {
                return "Already Installed - $chromeVersion"
            } else {
                # upgrade using the MSI installer
                Start-Process "msiexec.exe" -ArgumentList "/i `"$chromeInstaller`" /qn" -Wait
                Start-Sleep -Seconds 10

                $chromeInfo = (Get-Item $chromePath).VersionInfo
                return $chromeInfo.ProductVersion
            }
        } else {
            # Chrome is not installed, proceed with installation
            Start-Process "msiexec.exe" -ArgumentList "/i `"$chromeInstaller`" /qn" -Wait
            Start-Sleep -Seconds 10

            # Get the Chrome version after installation
            $chromeInfo = (Get-Item $chromePath).VersionInfo
            return $chromeInfo.ProductVersion
        }
    } -ArgumentList $chromeInstaller -ErrorAction SilentlyContinue | ForEach-Object {
        $chromeVersion = $_
    }

   
    Invoke-Command -ComputerName $computer -ScriptBlock {
        param ($edgeInstaller)

        $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
       
        if (Test-Path $edgePath) {
           
            $edgeInfo = (Get-Item $edgePath).VersionInfo
            $edgeVersion = $edgeInfo.ProductVersion
           
           
            if ($edgeVersion -eq "130.0.2849.52") {
                return "Already Installed - $edgeVersion"
            } else {
               
                Start-Process "msiexec.exe" -ArgumentList "/i `"$edgeInstaller`" /qn" -Wait
                Start-Sleep -Seconds 10

               
                $edgeInfo = (Get-Item $edgePath).VersionInfo
                return $edgeInfo.ProductVersion
            }
        } else {
           
            Start-Process "msiexec.exe" -ArgumentList "/i `"$edgeInstaller`" /qn" -Wait
            Start-Sleep -Seconds 10

           
            $edgeInfo = (Get-Item $edgePath).VersionInfo
            return $edgeInfo.ProductVersion
        }
    } -ArgumentList $edgeInstaller -ErrorAction SilentlyContinue | ForEach-Object {
        $edgeVersion = $_
    }

   
    $report += [PSCustomObject]@{
        ServerName    = $computer
        ChromeVersion = $chromeVersion
        EdgeVersion   = $edgeVersion
    }
}


$report | Export-Csv -Path $reportPath -NoTypeInformation -Force
Write-Output "Report saved to $reportPath"
