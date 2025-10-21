#requires -module GroupPolicy,ActiveDirectory
<#
.SYNOPSIS
Retrieve Group Policy Object (GPO) links from a domain, specific OUs, or sites.

.DESCRIPTION
Queries all GPO links in a domain, specific OU(s), or AD sites.
Supports filtering by Enabled/Disabled state, GPO name, TargetDomain, TargetOU, and recursive OU scanning.
Optimized for both Windows PowerShell 5.1 and PowerShell 7 with parallel execution.
Output is a custom object [myGPOLink] with properties like DisplayName, GPO_GUID, Enabled, Enforced, Order, Target, TargetType, and DomainName.

.PARAMETER TargetDomain
The domain to query. Defaults to the current domain if not specified.

.PARAMETER TargetOU
One or more OUs to query. If omitted, all OUs in the domain are scanned.

.PARAMETER Recurse
Include all child OUs recursively when using TargetOU.

.PARAMETER Name
Filter results by GPO name (supports wildcards).

.PARAMETER Enabled
Filter results to show only enabled GPO links.

.PARAMETER Disabled
Filter results to show only disabled GPO links.

.EXAMPLE
# Get all GPO links in the current domain
Get-GPLink

.EXAMPLE
# Get all enabled GPO links in a specific OU and its child OUs
Get-GPLink -TargetOU "OU=Finance,DC=contoso,DC=com" -Recurse -Enabled

.EXAMPLE
# Get GPO links containing "Password" in the name
Get-GPLink -Name "*Password*"

.NOTES
Requires the modules: GroupPolicy, ActiveDirectory
Supports parallel execution in PowerShell 7 for faster processing.
#>

Function Get-GPLink {
<#
.Synopsis
Retrieve Group Policy Object (GPO) links in a domain or specific OU(s).

.Description
Queries all GPO links in a domain, specific OU(s), or sites.
Supports filtering by Enabled/Disabled, GPO name, TargetDomain, TargetOU, and recursive OU scanning.
Output is read-only and safe for Production.

.Parameters
- TargetDomain: Query a specific domain (default is current domain).
- TargetOU: Query specific OU(s) only.
- Recurse: Include all child OUs recursively.
- Name: Filter GPO links by name (wildcards supported).
- Enabled: Show only enabled GPOs.
- Disabled: Show only disabled GPOs.
#>
[CmdletBinding(DefaultParameterSetName = "All")]
[OutputType("myGPOLink")]
Param(
    [Parameter(ValueFromPipelineByPropertyName)]
    [string]$TargetDomain,

    [Parameter(ValueFromPipelineByPropertyName)]
    [string[]]$TargetOU,

    [Parameter()]
    [switch]$Recurse,

    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [alias("gpo")]
    [string]$Name,

    [Parameter(ParameterSetName = "enabled")]
    [switch]$Enabled,

    [Parameter(ParameterSetName = "disabled")]
    [switch]$Disabled
)

Begin {
    Write-Verbose "Starting Get-GPLink..."

    # Determine domain
    if ($TargetDomain) {
        Try { $mydomain = Get-ADDomain -Identity $TargetDomain -ErrorAction Stop } 
        Catch { Write-Warning "Failed to get domain $TargetDomain. ${_.Exception.Message}"; return }
    } else {
        Try { $mydomain = Get-ADDomain -ErrorAction Stop } 
        Catch { Write-Warning "Failed to get current domain. ${_.Exception.Message}"; return }
    }

    # Prepare targets list
    $targets = [System.Collections.Generic.List[string]]::new()
    
    if ($TargetOU) {
        foreach ($ou in $TargetOU) {
            $targets.Add($ou)
            if ($Recurse) {
                Try {
                    $childOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $ou | Select-Object -ExpandProperty DistinguishedName
                    $targets.AddRange([string[]]$childOUs)
                } Catch { Write-Warning "Failed to get child OUs for $ou ${_.Exception.Message}" }
            }
        }
    } else {
        # All OUs in domain
        Try { 
            (Get-ADOrganizationalUnit -Filter * -SearchBase $mydomain.DistinguishedName).DistinguishedName | ForEach-Object { $targets.Add($_) } 
        } Catch { Write-Warning "Failed to get OUs: ${_.Exception.Message}" }
    }

    # Add domain as target
    $targets.Add($mydomain.DistinguishedName)

    # Retrieve sites
    Try { 
        $sites = (Get-ADObject -LDAPFilter "(ObjectClass=site)" -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Properties Name).Name 
    } Catch { Write-Warning "Failed to get AD sites: ${_.Exception.Message}"; $sites=@() }

    # Determine PowerShell version
    $isPS7 = $PSVersionTable.PSVersion.Major -ge 7
}

Process {
    $resultsOU = @()
    $resultsSites = @()

    if ($isPS7) {
        # --- Parallel OU/Domain GPO links ---
        $resultsOU = $targets | ForEach-Object -Parallel {
            param($target)
            try {
                $gpoLinks = (Get-GPInheritance -Target $target -ErrorAction Stop).GpoLinks
                foreach ($link in $gpoLinks) {
                    [PSCustomObject]@{
                        DisplayName = $link.DisplayName
                        GPO_GUID    = $link.GPOId
                        Enabled     = $link.Enabled
                        Enforced    = $link.Enforced
                        Order       = $link.Order
                        Target      = $link.Target
                        DomainName  = $link.GpoDomainName
                    }
                }
            } catch {
                Write-Warning "Failed to get GPO links for target $target $_"
            }
        } -ThrottleLimit 10

        # --- Parallel Site GPO links ---
        if ($sites) {
            $forestName = (Get-ADForest).Name
            $resultsSites = $sites | ForEach-Object -Parallel {
                param($siteName, $domain, $forest)
                try {
                    $gpm = New-Object -ComObject "GPMGMT.GPM"
                    $gpmConstants = $gpm.GetConstants()
                    $gpmDomain = $gpm.GetDomain($domain, $null, $gpmConstants.UseAnyDC)
                    $siteContainer = $gpm.GetSitesContainer($forest, $domain, $null, $gpmConstants.UseAnyDC)
                    $site = $siteContainer.GetSite($siteName)
                    if ($site) {
                        foreach ($link in $site.GetGPOLinks()) {
                            [PSCustomObject]@{
                                DisplayName = ($gpmDomain.GetGPO($link.GPOID)).DisplayName
                                GPO_GUID    = $link.GPOId
                                Enabled     = $link.Enabled
                                Enforced    = $link.Enforced
                                Order       = $link.somlinkorder
                                Target      = $link.som.path
                                DomainName  = $domain
                            }
                        }
                    }
                } catch {
                    Write-Warning "Failed site $siteName $_"
                }
            } -ArgumentList $_, $mydomain.DNSRoot, $forestName -ThrottleLimit 5
        }

    } else {
        # --- Serial execution for Windows PowerShell 5.1 ---
        foreach ($target in $targets) {
            try {
                $gpoLinks = (Get-GPInheritance -Target $target -ErrorAction Stop).GpoLinks
                foreach ($link in $gpoLinks) {
                    $resultsOU += [PSCustomObject]@{
                        DisplayName = $link.DisplayName
                        GPO_GUID    = $link.GPOId
                        Enabled     = $link.Enabled
                        Enforced    = $link.Enforced
                        Order       = $link.Order
                        Target      = $link.Target
                        DomainName  = $link.GpoDomainName
                    }
                }
            } catch {
                Write-Warning "Failed to get GPO links for target $target $_"
            }
        }

        if ($sites) {
            $forestName = (Get-ADForest).Name
            foreach ($siteName in $sites) {
                try {
                    $gpm = New-Object -ComObject "GPMGMT.GPM"
                    $gpmConstants = $gpm.GetConstants()
                    $gpmDomain = $gpm.GetDomain($mydomain.DNSRoot, $null, $gpmConstants.UseAnyDC)
                    $siteContainer = $gpm.GetSitesContainer($forestName, $mydomain.DNSRoot, $null, $gpmConstants.UseAnyDC)
                    $site = $siteContainer.GetSite($siteName)
                    if ($site) {
                        foreach ($link in $site.GetGPOLinks()) {
                            $resultsSites += [PSCustomObject]@{
                                DisplayName = ($gpmDomain.GetGPO($link.GPOID)).DisplayName
                                GPO_GUID    = $link.GPOId
                                Enabled     = $link.Enabled
                                Enforced    = $link.Enforced
                                Order       = $link.somlinkorder
                                Target      = $link.som.path
                                DomainName  = $mydomain.DNSRoot
                            }
                        }
                    }
                } catch {
                    Write-Warning "Failed site $siteName $_"
                }
            }
        }
    }

    # Combine results
    $allLinks = @($resultsOU + $resultsSites)

    # Apply filters
    if ($Enabled) { $allLinks = $allLinks.Where({ $_.Enabled }) }
    if ($Disabled) { $allLinks = $allLinks.Where({ -not $_.Enabled }) }
    if ($Name) { $allLinks = $allLinks.Where({ $_.DisplayName -like "$Name" }) }

    # Output
    if ($allLinks.Count -gt 0) {
        $allLinks | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                GPO_GUID    = $_.GPO_GUID
                Enabled     = $_.Enabled
                Enforced    = $_.Enforced
                Order       = $_.Order
                Target      = $_.Target
                TargetType  = switch -regex ($_.Target) {
                                   "^((ou)|(OU)=)" { "OU" }
                                   "^((dc)|(DC)=)" { "Domain" }
                                   "^((cn)|(CN)=)" { "Site" }
                                   Default { "Unknown"}
                                }
                DomainName  = $_.DomainName
            }
        }
    } else { Write-Warning "No GPO links found for the given parameters." }
}

End { Write-Verbose "Ending Get-GPLink..." }
}

# --- Custom Type Aliases ---
Update-TypeData -MemberType ScriptProperty -MemberName TargetType -Value {
    switch -regex ($this.Target) {
        "^((ou)|(OU)=)" { "OU" }
        "^((dc)|(DC)=)" { "Domain" }
        "^((cn)|(CN)=)" { "Site" }
        Default { "Unknown"}
    }
} -TypeName myGPOLink -Force
