<#
Same header unchanged

Get-Credential | Export-Clixml -Path C:\Temp\mail_credential.clixml

$Username   = "yogeshmailzone@gmail.com"
$Password   = "ihdm kjee dolt avbd"
#>

param(
    [string]$Download = $null
)

$ScriptVersion = "1.1"

# ---------------- CONFIG ----------------

$VersionFile = Join-Path $PSScriptRoot "7zip_version.txt"
$LogFile     = Join-Path $PSScriptRoot "7zip_monitor.log"

$HistoryUrl   = "https://www.7-zip.org/history.txt"
$DownloadBase = "https://www.7-zip.org/a"

# Email Settings
$SmtpServer = "smtp.gmail.com"
$SmtpPort   = 587
$UseSsl     = $true

$From = "yogeshmailzone@gmail.com"
$To   = "yogeshmailzone@gmail.com"
$cc = "ramyogeshwaran@gmail.com"
$bcc = "yogeshmailzone@gmail.com"
# ================= SECURITY FIX =================
# ================= SECURITY FIX =================
$CredPath = Join-Path $PSScriptRoot "mail_credential.clixml"

function Write-Log {
    param([string]$Message)

    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$TimeStamp | $Message"
}

if (!(Test-Path $CredPath)) {

    $ErrorMsg = "Credential file missing. Run: Get-Credential | Export-Clixml $CredPath"

    Write-Log "ERROR: $ErrorMsg"
    Write-Error $ErrorMsg

    exit 1
}

try {
    $Credential = Import-Clixml -Path $CredPath

    if (-not $Credential -or -not $Credential.UserName -or -not $Credential.Password) {
        throw "Invalid credential file content"
    }
}
catch {
    Write-Log "ERROR TYPE: $($_.Exception.GetType().FullName)"
    Write-Log "ERROR MESSAGE: Failed to load credential file - $($_.Exception.Message)"
    Write-Error $_.Exception.Message
    exit 1
}
# ===============================================
try {
    $Credential = Import-Clixml -Path $CredPath
}
catch {
    Write-Log "ERROR TYPE: $($_.Exception.GetType().FullName)"
    Write-Log "ERROR MESSAGE: Failed to load credential file - $($_.Exception.Message)"
    Write-Error $_.Exception.Message
    exit 1
}
# ===============================================

function Cleanup-Log {

    if (!(Test-Path $LogFile)) { return }

    $CutoffDate = (Get-Date).AddDays(-30)

    $FilteredLines = foreach ($Line in Get-Content $LogFile) {

        if ($Line -match '^(\d{4}-\d{2}-\d{2})') {

            $LogDate = [datetime]::ParseExact(
                $Matches[1],
                'yyyy-MM-dd',
                $null
            )

            if ($LogDate -ge $CutoffDate) {
                $Line
            }
        }
    }

    $FilteredLines | Set-Content $LogFile
}

function Get-Latest7ZipVersion {

    $content = (Invoke-WebRequest -Uri $HistoryUrl -UseBasicParsing).Content

    $match = [regex]::Match(
        $content,
        '(?m)^(\d+(?:\.\d+)*)\s+\d{4}-\d{2}-\d{2}'
    )

    if ($match.Success) {
        return $match.Groups[1].Value
    }

    throw "Unable to determine latest 7-Zip version."
}

function Get-DownloadUrl {
    param([string]$Version)

    $VersionNumber = $Version -replace '\.', ''
    return "$DownloadBase/7z$VersionNumber-x64.exe"
}

function Get-StoredVersion {

    if (Test-Path $VersionFile) {
        return (Get-Content $VersionFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    }

    return $null
}

function Save-Version {
    param([string]$Version)

    Set-Content -Path $VersionFile -Value $Version
}

function Send-Email {
    param(
        [string]$Subject,
        [string]$Body
    )

    Send-MailMessage `
        -From $From `
        -To $To `
        -Cc $cc `
        -Bcc $bcc `
        -Subject $Subject `
        -Body $Body `
        -BodyAsHtml `
        -SmtpServer $SmtpServer `
        -Port $SmtpPort `
        -UseSsl:$UseSsl `
        -Credential $Credential `
        -Priority High `
        -ErrorAction Stop
}

function Download-Installer {
    param(
        [string]$Path,
        [string]$Version
    )

    if (!(Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }

    $Url = Get-DownloadUrl -Version $Version

    $VersionNumber = $Version -replace '\.', ''
    $FileName = "7z$VersionNumber-x64.exe"
    $FilePath = Join-Path $Path $FileName

    Write-Host "Downloading from: $Url"

    Invoke-WebRequest -Uri $Url -OutFile $FilePath

    return $FilePath
}

try {

    Cleanup-Log
    Write-Log "Script Started"

    $Latest = Get-Latest7ZipVersion
    $Stored = Get-StoredVersion

    Write-Host "Latest Version : $Latest"
    Write-Host "Stored Version : $Stored"

    Write-Log "Latest Version: $Latest"
    Write-Log "Stored Version: $Stored"

    if ([string]::IsNullOrWhiteSpace($Stored) -or $Latest -ne $Stored) {

        Write-Log "New version detected. Old: $Stored New: $Latest"

        $DownloadStatus = "Not Requested"
        $DownloadedFile = ""

        Save-Version $Latest

        if ($Download) {
            $DownloadedFile = Download-Installer -Path $Download -Version $Latest
            $DownloadStatus = "Completed"
            Write-Log "Downloaded File: $DownloadedFile"
        }

        $DetectionTime = Get-Date -Format "dd-MMM-yyyy HH:mm:ss"

        # ===== YOUR ORIGINAL EMAIL BODY (UNCHANGED) =====
        $Body = @"
<html>
<head><style>
body{font-family:Segoe UI,Arial,sans-serif;background-color:#f4f4f4;}
.container{max-width:800px;margin:20px auto;background:#ffffff;border:1px solid #dcdcdc;border-radius:8px;}
.header{background-color:#2b579a;color:white;padding:15px;font-size:22px;font-weight:bold;}
.content{padding:20px;}
.status{background-color:#d4edda;border-left:5px solid #28a745;padding:10px;margin-bottom:15px;}
table{border-collapse:collapse;width:100%;}
th,td{border:1px solid #dcdcdc;padding:10px;text-align:left;}
th{background-color:#f2f2f2;}
.footer{margin-top:20px;font-size:12px;color:#666666;}
</style></head>
<body>
<div class='container'>
<div class='header'>7-Zip Update Notification</div>
<div class='content'>
<p>Hello Team,</p>
<p>The software monitoring system has detected the availability of a new 7-Zip release during the scheduled version check.</p>
<div class='status'><b>Status:</b> New Version Available</div>
<table>
<tr><th>Item</th><th>Value</th></tr>
<tr><td>Application</td><td>7-Zip</td></tr>
<tr><td>Script Version</td><td>$ScriptVersion</td></tr>
<tr><td>Current Version</td><td>$Stored</td></tr>
<tr><td>Latest Version</td><td>$Latest</td></tr>
<tr><td>Detection Time</td><td>$DetectionTime</td></tr>
<tr><td>Computer Name</td><td>$env:COMPUTERNAME</td></tr>
<tr><td>Download Status</td><td>$DownloadStatus</td></tr>
</table>
</div>
</div>
</body>
</html>
"@

        try {
            Send-Email -Subject "[Software Monitor] 7-Zip Update Available - Version $Latest" -Body $Body

            Write-Log "Notification email sent successfully"
            Write-Host "Notification email sent."
        }
        catch {
            Write-Log "EMAIL ERROR TYPE: $($_.Exception.GetType().FullName)"
            Write-Log "EMAIL ERROR MESSAGE: $($_.Exception.Message)"
            Write-Error $_.Exception.Message
        }

        if ($DownloadedFile) {
            Write-Host "Downloaded File : $DownloadedFile"
        }
    }
    else {
        Write-Host "No new version found."
        Write-Log "No new version found"
    }
}
catch {
    Write-Log "ERROR TYPE: $($_.Exception.GetType().FullName)"
    Write-Log "ERROR MESSAGE: $($_.Exception.Message)"
    Write-Error $_.Exception.Message
}
