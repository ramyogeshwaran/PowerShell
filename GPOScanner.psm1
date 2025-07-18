# GPOScanner.psm1
# Version: 1.8.7
# Author: Yogesh
# ----------------------------------------
# DESCRIPTION:
#   High-performance GPO scanner that searches for ADMX-based or raw string matches.
#   Supports cache mode, report-only mode, threaded scanning, safe job cleanup.
# ----------------------------------------
# FEATURES:
#   - ADMX mode: HTML report search
#   - XML mode: Raw policy string search
#   - Threaded job processing with safe cleanup
#   - Report caching (LastModifiedTime check)
#   - Separate folders for XML and HTML reports
#   - Report-only export mode
#   - Logs failures and exports results as CSV
# ----------------------------------------
# USAGE EXAMPLES:
#   Import-Module .\GPOScanner.psm1
#   Search-GPOString -SearchStrings "LDAP", "Kerberos"
#   Search-GPOString -SearchStrings "Maximum password age" -ADMX
#   Search-GPOString -SearchStrings "Audit" -ReportOnly
#   Search-GPOString -SearchStrings "Netlogon" -UseCacheOnly -Domain "corp.example.com"
# ----------------------------------------

function Show-GPOScannerBanner {
    Write-Host "`n=============================" -ForegroundColor DarkCyan
    Write-Host "   GPO Scanner v1.8.7" -ForegroundColor Cyan
    Write-Host "   Author: Raghav" -ForegroundColor DarkGray
    Write-Host "=============================`n" -ForegroundColor DarkCyan
}

function Search-GPOString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$SearchStrings,

        [switch]$ADMX,
        [switch]$UseCacheOnly,
        [switch]$ReportOnly,
        [string]$Domain = $null
    )

    Show-GPOScannerBanner
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $BaseReportPath = "C:\tools\GPOScanner\GPOReports"
    if (-not (Test-Path $BaseReportPath)) {
        New-Item -Path $BaseReportPath -ItemType Directory | Out-Null
    }

    $ReportSubFolder = if ($ADMX) { "HTML" } else { "XML" }
    $ReportPath = Join-Path $BaseReportPath $ReportSubFolder
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory | Out-Null
    }

    $logFilePath = Join-Path $BaseReportPath "GPOScanner_Failures.log"
    if (Test-Path $logFilePath) { Remove-Item $logFilePath -Force }

    $DomainToQuery = if ($Domain) { $Domain } else { ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name }

    function Get-AllGPOs {
        Get-GPO -All -Domain $DomainToQuery
    }

    function Search-GPOReports {
        param (
            [array]$GPOs,
            [string[]]$SearchStrings,
            [string]$Mode,
            [string]$ReportPath,
            [switch]$UseCacheOnly,
            [switch]$ReportOnly
        )

        $throttleLimit = 10
        $jobList = @()
        $results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        $total = $GPOs.Count
        $scanned = 0
        $startTime = Get-Date

        foreach ($gpo in $GPOs) {
            $jobList += Start-ThreadJob -ScriptBlock {
                param($gpoName, $gpoId, $gpoModTime, $SearchStrings, $Mode, $UseCacheOnly, $ReportOnly, $ReportPath)

                try {
                    $ext = if ($Mode -eq 'Html') { 'html' } else { 'xml' }
                    $reportFile = Join-Path -Path $ReportPath -ChildPath "$gpoId.$ext"
                    $reuseReport = $false

                    if (Test-Path $reportFile) {
                        $existingTime = (Get-Item $reportFile).LastWriteTimeUtc
                        if ($UseCacheOnly -or ($gpoModTime.ToUniversalTime() -lt $existingTime)) {
                            $reuseReport = $true
                        } else {
                            Remove-Item $reportFile -Force -ErrorAction SilentlyContinue
                        }
                    }

                    if (-not $reuseReport) {
                        $report = Get-GPOReport -Guid $gpoId -ReportType $Mode -ErrorAction Stop
                        $report | Out-File -LiteralPath $reportFile -Encoding UTF8
                    } else {
                        $report = Get-Content -LiteralPath $reportFile -Raw
                    }

                    if ($ReportOnly) { return }

                    $matches = @()
                    foreach ($str in $SearchStrings) {
                        $regex = [regex]::new($str, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                        if ($regex.IsMatch($report)) {
                            $matches += [pscustomobject]@{
                                GPOName = $gpoName
                                GPOGuid = $gpoId
                                Match   = $str
                            }
                        }
                    }
                    return $matches
                } catch {
                    throw "$gpoName ($gpoId) failed: $_"
                }
            } -ArgumentList $gpo.DisplayName, $gpo.Id, $gpo.ModificationTime, $SearchStrings, $Mode, $UseCacheOnly, $ReportOnly, $ReportPath

            while ($jobList.Count -ge $throttleLimit) {
                $completed = Wait-Job -Job $jobList -Any -Timeout 5
                if ($completed -and $completed.State -in 'Completed','Failed','Stopped') {
                    try {
                        $output = Receive-Job -Job $completed -ErrorAction Stop
                        if ($output) {
                            foreach ($item in $output) { $results.Add($item) }
                        }
                    } catch {
                        Add-Content -Path $logFilePath -Value "[FAILURE] $($_.Exception.Message)"
                    } finally {
                        $scanned++
                        $elapsed = (Get-Date) - $startTime
                        $eta = if ($scanned -gt 0) {
                            [TimeSpan]::FromSeconds(($elapsed.TotalSeconds / $scanned) * ($total - $scanned))
                        } else { [TimeSpan]::Zero }

                        Write-Progress -Activity "Scanning GPOs" `
                                       -Status "$scanned of $total scanned | ETA: $($eta.ToString("hh\:mm\:ss"))" `
                                       -PercentComplete (($scanned / $total) * 100)
                        Remove-Job -Job $completed -Force -ErrorAction SilentlyContinue
                        $jobList = $jobList | Where-Object { $_.Id -ne $completed.Id }
                    }
                }
            }
        }

        $jobList | Wait-Job

        foreach ($job in $jobList) {
            try {
                $output = Receive-Job -Job $job -ErrorAction Stop
                if ($output) {
                    foreach ($item in $output) { $results.Add($item) }
                }
            } catch {
                Add-Content -Path $logFilePath -Value "[FAILURE] $($_.Exception.Message)"
            } finally {
                if ($job.State -in 'Running', 'NotStarted') {
                    Stop-Job -Job $job -Force -ErrorAction SilentlyContinue
                }
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                $scanned++
                Write-Progress -Activity "Finalizing GPOs" `
                               -Status "$scanned of $total scanned" `
                               -PercentComplete (($scanned / $total) * 100)
            }
        }

        Write-Progress -Activity "Scanning GPOs" -Completed
        return $results
    }

    # DISPLAY SUMMARY
    $scanMode   = if ($ADMX) { "ADMX (HTML report search)" } else { "XML (raw policy search)" }
    $cacheMode  = if ($UseCacheOnly) { "Enabled" } else { "Disabled" }
    $reportMode = if ($ReportOnly) { "Yes" } else { "No" }

    Write-Host "Domain Target : $DomainToQuery" -ForegroundColor DarkGray
    Write-Host "Scan Mode     : $scanMode" -ForegroundColor Gray
    Write-Host "Cache Mode    : $cacheMode" -ForegroundColor Gray
    Write-Host "Report Only   : $reportMode" -ForegroundColor Gray

    Write-Host "`nCollecting GPOs..." -ForegroundColor Cyan
    $allGPOs = Get-AllGPOs
    Write-Host "GPOs to scan: $($allGPOs.Count)`n" -ForegroundColor Yellow

    $mode = if ($ADMX) { 'Html' } else { 'Xml' }

    # Clean up old reports only in this mode's subfolder
    Get-ChildItem -Path $ReportPath -Include *.xml, *.html -File | ForEach-Object {
        if ($allGPOs.Id -notcontains $_.BaseName) {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "Exporting GPOs..." -ForegroundColor Cyan
    $searchResults = Search-GPOReports -GPOs $allGPOs `
                                       -SearchStrings $SearchStrings `
                                       -Mode $mode `
                                       -ReportPath $ReportPath `
                                       -UseCacheOnly:$UseCacheOnly `
                                       -ReportOnly:$ReportOnly

    Write-Host "`nScan complete." -ForegroundColor Green

    if ($ReportOnly) {
        Write-Host "`nReport export only. No scanning performed." -ForegroundColor Yellow
        $stopwatch.Stop()
        Write-Host "Total execution time: $($stopwatch.Elapsed)" -ForegroundColor DarkGray
        return
    }

    if ($searchResults.Count -eq 0) {
        Write-Host "No matches found." -ForegroundColor Yellow
    } else {
        $searchResults = $searchResults | Sort-Object GPOName, Match -Unique
        $searchResults | Format-Table -AutoSize

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path $BaseReportPath "GPO_Report_$timestamp.csv"
        $searchResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nResults exported to: $csvPath" -ForegroundColor Cyan
    }

    if (Test-Path $logFilePath) {
        Write-Host "`nSome GPOs failed during scanning. See log:" -ForegroundColor Red
        Write-Host $logFilePath -ForegroundColor Yellow
    }

    $stopwatch.Stop()
    Write-Host "`nTotal execution time: $($stopwatch.Elapsed)" -ForegroundColor DarkGray
}
