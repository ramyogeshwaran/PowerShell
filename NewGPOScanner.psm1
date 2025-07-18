# GPOScanner.psm1
# Version: 1.9.0
# Author: Raghav

function Show-GPOScannerBanner {
    Write-Host "`n=============================" -ForegroundColor DarkCyan
    Write-Host "   GPO Scanner v1.9.0" -ForegroundColor Cyan
    Write-Host "   Author: Raghav" -ForegroundColor DarkGray
    Write-Host "=============================`n" -ForegroundColor DarkCyan
}

function Search-GPOString {
<#
.SYNOPSIS
    Scans GPOs for specific search strings (regex or plain) in XML or ADMX reports.

.PARAMETER SearchStrings
    One or more strings or regex patterns to search for in GPO reports.

.PARAMETER ADMX
    Uses HTML reports to match ADMX display names.

.PARAMETER Domain
    Specifies the domain to target (required for multi-domain environments).

.PARAMETER UseCacheOnly
    Reuses cached reports if GPO not modified.

.PARAMETER ReportOnly
    Only generates reports, no searching.

.PARAMETER Linked
    Only scan GPOs that are linked to OUs/domains in the selected domain.

.PARAMETER Unlinked
    Only scan GPOs that are not linked anywhere.

.EXAMPLE
    Search-GPOString -SearchStrings "LDAP" -Domain "corp.local"

.EXAMPLE
    Search-GPOString -SearchStrings "Minimum password age" -ADMX -Domain "example.com" -Linked

.EXAMPLE
    Search-GPOString -SearchStrings "TLS1.0" -ReportOnly -Domain "ad.forest.com"
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$SearchStrings,

        [Parameter(Mandatory)]
        [string]$Domain,

        [switch]$ADMX,
        [switch]$UseCacheOnly,
        [switch]$ReportOnly,
        [switch]$Linked,
        [switch]$Unlinked
    )

    Show-GPOScannerBanner
    $ReportPath = "C:\Tools\GPOScan\Reports"
    $mode = if ($ADMX) { "Html" } else { "Xml" }
    $ReportExtension = if ($ADMX) { ".html" } else { ".xml" }

    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory | Out-Null
    }

    function Get-AllGPOs {
        Get-GPO -All -Domain $Domain
    }

    function Get-LinkedGPOs {
        $linked = @{}
        Get-ADOrganizationalUnit -Filter * -Server $Domain | ForEach-Object {
            try {
                $inheritance = Get-GPInheritance -Target $_.DistinguishedName -Domain $Domain
                foreach ($gpo in $inheritance.GpoLinks) {
                    if ($gpo.Enabled) {
                        $linked[$gpo.DisplayName] = $true
                    }
                }
            } catch {}
        }
        return $linked.Keys
    }

    Write-Host "Collecting GPO list from $Domain..." -ForegroundColor Cyan
    $allGPOs = Get-AllGPOs

    if ($Linked) {
        $linkedNames = Get-LinkedGPOs
        $filteredGPOs = $allGPOs | Where-Object { $linkedNames -contains $_.DisplayName }
    } elseif ($Unlinked) {
        $linkedNames = Get-LinkedGPOs
        $filteredGPOs = $allGPOs | Where-Object { $linkedNames -notcontains $_.DisplayName }
    } else {
        $filteredGPOs = $allGPOs
    }

    $totalCount = $filteredGPOs.Count
    Write-Host "GPOs to scan: $totalCount" -ForegroundColor Yellow

    $results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $startTime = Get-Date
    $processed = 0

    $jobs = foreach ($gpo in $filteredGPOs) {
        Start-ThreadJob -ScriptBlock {
            param($gpo, $SearchStrings, $mode, $ReportPath, $UseCacheOnly, $ReportOnly)

            $output = @()
            $fileName = "$($gpo.Id)$($mode -eq 'Html' ? '.html' : '.xml')"
            $reportFile = Join-Path $ReportPath $fileName
            $reuse = $false

            if (Test-Path $reportFile) {
                $existingTime = (Get-Item $reportFile).LastWriteTimeUtc
                if ($UseCacheOnly -or ($gpo.ModificationTime.ToUniversalTime() -lt $existingTime)) {
                    $reuse = $true
                } else {
                    Remove-Item $reportFile -Force -ErrorAction SilentlyContinue
                }
            }

            if (-not $reuse) {
                $report = Get-GPOReport -Guid $gpo.Id -ReportType $mode -Domain $using:Domain
                $report | Out-File -Encoding UTF8 -LiteralPath $reportFile
            } else {
                $report = Get-Content $reportFile -Raw
            }

            if ($ReportOnly) { return }

            foreach ($str in $SearchStrings) {
                $regex = [regex]::new($str, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if ($regex.IsMatch($report)) {
                    $output += [pscustomobject]@{
                        GPOName = $gpo.DisplayName
                        GPOGuid = $gpo.Id
                        Match   = $str
                    }
                }
            }

            return $output

        } -ArgumentList $gpo, $SearchStrings, $mode, $ReportPath, $UseCacheOnly, $ReportOnly
    }

    while (@(Get-Job -State Running).Count -gt 0) {
        Start-Sleep -Milliseconds 500
        $done = @(Get-Job | Where-Object { $_.HasMoreData -or $_.State -eq 'Completed' }).Count
        $pct = [math]::Round(($done / $totalCount) * 100)
        $elapsed = (Get-Date) - $startTime
        $eta = if ($done -gt 0) {
            $remain = $elapsed.TotalSeconds / $done * ($totalCount - $done)
            [TimeSpan]::FromSeconds($remain)
        } else { [TimeSpan]::FromSeconds(0) }

        $bar = '#' * ($pct / 10) + '-' * (10 - ($pct / 10))
        Write-Host -NoNewline "`r[$bar] $pct% ($done/$totalCount) GPOs scanned... Estimated time left: $($eta.ToString("hh\:mm\:ss"))"
    }

    Write-Host ""

    foreach ($j in $jobs) {
        $output = Receive-Job $j -ErrorAction SilentlyContinue
        foreach ($item in $output) {
            $results.Add($item)
        }
        Remove-Job $j
    }

    if ($ReportOnly) {
        Write-Host "`nReports generated only. No search performed." -ForegroundColor Yellow
        return
    }

    if ($results.Count -eq 0) {
        Write-Host "No matches found." -ForegroundColor Yellow
    } else {
        $results | Sort-Object GPOName | Format-Table -AutoSize
        $csvPath = Join-Path $ReportPath ("GPO_Result_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nResults exported to: $csvPath" -ForegroundColor Cyan
    }
}
