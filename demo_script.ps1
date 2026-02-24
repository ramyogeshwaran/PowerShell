# ==============================================================
# ENTERPRISE SECURE BOOT FLEET COLLECTOR (BEST PRACTICE)
# Compatible: PowerShell 5.1 & 7
# ==============================================================

$ComputerList = Get-Content "E:\computers.txt"
$SuccessFile  = "E:\SecureBoot_Fleet_Report.csv"
$FailFile     = "E:\SecureBoot_Unreachable.csv"

$SuccessResults = @()
$FailedResults  = @()

Write-Host "Starting Enterprise Secure Boot Collection..."
Write-Host "------------------------------------------------"

foreach ($Computer in $ComputerList) {

    Write-Host "Collecting from $Computer ..."

    try {

        # ==========================================================
        # 1️⃣ DNS VALIDATION
        # ==========================================================
        try {
            Resolve-DnsName $Computer -ErrorAction Stop | Out-Null
        }
        catch {
            throw "DNS resolution failed"
        }

        # ==========================================================
        # 2️⃣ ICMP VALIDATION
        # ==========================================================
        if (-not (Test-Connection $Computer -Count 1 -Quiet)) {
            throw "Host not reachable (ICMP failed)"
        }

        # ==========================================================
        # 3️⃣ WINRM VALIDATION
        # ==========================================================
        if (-not (Test-WSMan $Computer -ErrorAction SilentlyContinue)) {
            throw "WinRM not responding"
        }

        # ==========================================================
        # 4️⃣ REMOTE DATA COLLECTION
        # ==========================================================

        $data = Invoke-Command -ComputerName $Computer -ScriptBlock {

            $hostname = $env:COMPUTERNAME
            $collectionTime = Get-Date

            # === STRICT HOST VALIDATION (NO FAKE SUCCESS) ===
            if ($hostname -ne $using:Computer) {
                throw "Connected to wrong host ($hostname)"
            }

            # ================= BIOS MODE (ENTERPRISE SAFE) =================
            try {
                Confirm-SecureBootUEFI -ErrorAction Stop | Out-Null
                $biosMode = "UEFI"
            }
            catch {
                $biosMode = "Legacy"
            }

            # ================= SECURE BOOT =================
            try {
                $secureBootEnabled = Confirm-SecureBootUEFI
            } catch {
                $secureBootEnabled = "Not Supported"
            }

            # ================= TPM =================
            try {
                $tpm = Get-Tpm
                $tpmPresent = $tpm.TpmPresent
                $tpmReady   = $tpm.TpmReady
                $tpmVersion = $tpm.SpecVersion
            } catch {
                $tpmPresent = "Not Detected"
                $tpmReady   = "N/A"
                $tpmVersion = "N/A"
            }

            # ================= BITLOCKER =================
            try {
                $bl = Get-BitLockerVolume -MountPoint "C:"
                $bitlockerStatus = $bl.ProtectionStatus
            } catch {
                $bitlockerStatus = "Not Available"
            }

            # ================= OEM / BIOS =================
            $cs   = Get-CimInstance Win32_ComputerSystem
            $bios = Get-CimInstance Win32_BIOS
            $bb   = Get-CimInstance Win32_BaseBoard
            $os   = Get-CimInstance Win32_OperatingSystem

            # Safe firmware date conversion
            try {
                if ($bios.ReleaseDate -match '^\d{14}') {
                    $firmwareDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($bios.ReleaseDate)
                }
                else {
                    $firmwareDate = "Not Available"
                }
            }
            catch {
                $firmwareDate = "Not Available"
            }

            # ================= EVENT LOG =================
            try {
                $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1801,1808} -MaxEvents 50
                $event1801 = ($events | Where-Object {$_.Id -eq 1801}).Count
                $event1808 = ($events | Where-Object {$_.Id -eq 1808}).Count
                $latest = $events | Sort-Object TimeCreated -Descending | Select -First 1

                if ($latest.Message -match "BucketId:\s*(\S+)") {
                    $bucketId = $matches[1]
                } else {
                    $bucketId = "Not Available"
                }

                $latestEventId = if ($latest) { $latest.Id } else { "Not Available" }

            } catch {
                $event1801 = 0
                $event1808 = 0
                $bucketId = "Not Available"
                $latestEventId = "Not Available"
            }

            # ================= OUTPUT =================
            [PSCustomObject]@{
                Hostname              = $hostname
                CollectionTime        = $collectionTime
                BIOSMode              = $biosMode
                SecureBootEnabled     = $secureBootEnabled
                TPM_Present           = $tpmPresent
                TPM_Ready             = $tpmReady
                TPM_Version           = $tpmVersion
                BitLockerStatus       = $bitlockerStatus
                Manufacturer          = $cs.Manufacturer
                Model                 = $cs.Model
                FirmwareVersion       = $bios.SMBIOSBIOSVersion
                FirmwareReleaseDate   = $firmwareDate
                OSArchitecture        = $os.OSArchitecture
                OSVersion             = $os.Version
                LastBootTime          = $os.LastBootUpTime
                BaseBoardManufacturer = $bb.Manufacturer
                BaseBoardProduct      = $bb.Product
                LatestEventId         = $latestEventId
                BucketID              = $bucketId
                Event1801Count        = $event1801
                Event1808Count        = $event1808
            }

        } -ErrorAction Stop

        Write-Host "$Computer SUCCESS"
        $SuccessResults += $data

    }
    catch {
        Write-Host "$Computer FAILED"

        $FailedResults += [PSCustomObject]@{
            Hostname = $Computer
            Status   = "Unreachable"
            ErrorMsg = $_.Exception.Message
        }
    }
}

# ==============================================================
# EXPORT RESULTS
# ==============================================================

$SuccessResults | Export-Csv $SuccessFile -NoTypeInformation -Force
$FailedResults  | Export-Csv $FailFile -NoTypeInformation -Force

Write-Host ""
Write-Host "------------------------------------------------"
Write-Host "Collection Complete"
Write-Host "Success Report: $SuccessFile"
Write-Host "Unreachable:    $FailFile"
Write-Host "------------------------------------------------"