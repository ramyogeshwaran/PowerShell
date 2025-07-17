# GPOScanner.psm1
# Version: 1.8.1
# Author: Yogesh
# Purpose: High-performance GPO scanner for ADMX-based and string-based policies
# Date: 2025-07-17

function Show-GPOScannerBanner {
    Write-Host "`n=============================" -ForegroundColor DarkCyan
    Write-Host "   GPO Scanner v1.8.1" -ForegroundColor Cyan
    Write-Host "   Author: Yogesh" -ForegroundColor DarkGray
    Write-Host "=============================`n" -ForegroundColor DarkCyan
}

function Search-GPOString {
<#
.SYNOPSIS
    Scans GPOs for specific search strings in XML or ADMX (HTML) reports.

.PARAMETER SearchStrings
    One or more strings or regex patterns to search for in GPO reports.

.PARAMETER ADMX
    Switch to use HTML reports for ADMX display name-based search.

.PARAMETER UseCacheOnly
    Uses existing report files if available and not modified since.

.PARAMETER ReportOnly
    Only generates and caches GPO reports, does not perform scanning.

.PARAMETER Domain
    Optional domain override for targeting specific domain in a multi-domain forest.

.EXAMPLE
    Search-GPOString -SearchStrings "LDAP"

.EXAMPLE
    Search-GPOString -SearchStrings "Account lockout duration" -ADMX

.EXAMPLE
    Search-GPOString -SearchStrings ".*password.*age" -Domain "corp.contoso.com"
#>

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
    $ReportPath = "C:\Temp\GPOReports"
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory | Out-Null
    }

    # Determine domain context
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

        foreach ($gpo in $GPOs) {
            $jobList += Start-ThreadJob -ScriptBlock {
                param($gpoName, $gpoId, $gpoModTime, $SearchStrings, $Mode, $UseCacheOnly, $ReportOnly, $ReportPath)

                try {
                    $reportFile = Join-Path -Path $ReportPath -ChildPath "$gpoId.$Mode"
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

                    foreach ($str in $SearchStrings) {
                        $regex = [regex]::new($str, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                        if ($regex.IsMatch($report)) {
                            [pscustomobject]@{
                                GPOName = $gpoName
                                GPOGuid = $gpoId
                                Match   = $str
                            }
                        }
                    }
                } catch {
                    Write-Warning "[ERROR] $gpoName failed: $_"
                }
            } -ArgumentList $gpo.DisplayName, $gpo.Id, $gpo.ModificationTime, $SearchStrings, $Mode, $UseCacheOnly, $ReportOnly, $ReportPath

            while ($jobList.Count -ge $throttleLimit) {
                $completed = Wait-Job -Job $jobList -Any -Timeout 5
                if ($completed) {
                    $output = Receive-Job -Job $completed -ErrorAction SilentlyContinue
                    if ($output) {
                        foreach ($item in $output) {
                            $results.Add($item)
                        }
                    }
                    Remove-Job -Job $completed
                    $jobList = $jobList | Where-Object { $_.State -eq 'Running' }
                }
            }
        }

        $jobList | Wait-Job | ForEach-Object {
            $output = Receive-Job -Job $_ -ErrorAction SilentlyContinue
            if ($output) {
                foreach ($item in $output) {
                    $results.Add($item)
                }
            }
            Remove-Job -Job $_
        }

        return $results
    }

    Write-Host "Domain Target: $DomainToQuery" -ForegroundColor DarkGray
    Write-Host "Collecting GPOs..." -ForegroundColor Cyan
    $allGPOs = Get-AllGPOs
    Write-Host "GPOs to scan: $($allGPOs.Count)`n" -ForegroundColor Yellow

    $mode = if ($ADMX) { 'Html' } else { 'Xml' }

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
        $searchResults | Sort-Object GPOName | Format-Table -AutoSize

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path $ReportPath "GPO_Report_$timestamp.csv"
        $searchResults | Sort-Object GPOName | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nResults exported to: $csvPath" -ForegroundColor Cyan
    }

    $stopwatch.Stop()
    Write-Host "`nTotal execution time: $($stopwatch.Elapsed)" -ForegroundColor DarkGray
}
