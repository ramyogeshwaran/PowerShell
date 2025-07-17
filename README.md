# GPOScanner PowerShell Module

## Overview
`GPOScanner` is a high-performance, **read-only** PowerShell module designed for safely scanning Group Policy Objects (GPOs) across an Active Directory environment. It supports plain text and ADMX (HTML) display name searches with powerful features such as multi-threading, domain targeting, and caching.

---

## Features
- 🔍 Scan GPOs for one or more plain strings or regex patterns
- 🌐 Supports domain targeting (for multi-domain/forest environments)
- 📄 Supports both XML (raw GPO setting) and HTML (ADMX display name) modes
- 🧠 Regex pattern support for advanced matching
- ⚡ Multi-threaded GPO export and scanning
- 💾 Report caching to avoid redundant exports (`-UseCacheOnly`)
- 📁 Local CSV export with timestamp
- 🔒 100% **read-only** – safe for production use
- 🧪 `-ReportOnly` mode to generate reports without scanning
- 📤 Future-ready: supports centralized logging integration

---

Requirements:

✅ PowerShell 7+ (for ThreadJob)

✅ RSAT tools with Group Policy module (Get-GPO, Get-GPOReport)

✅ Domain access permissions to read GPOs

## Installation

1. Save the script as `GPOScanner.psm1`
2. Create the folder structure:
C:\Program Files\WindowsPowerShell\Modules\GPOScanner\

Copy
Edit
3. Place `GPOScanner.psm1` inside the `GPOScanner` folder.

---

## Importing the Module
```powershell
Import-Module GPOScanner

******Usage******

Search-GPOString -SearchStrings "LDAP"

earch-GPOString -SearchStrings "Account lockout duration" -ADMX

Search-GPOString -SearchStrings "LDAP", "Kerberos"

Report-only mode (generate reports without scanning)
Search-GPOString -SearchStrings "x" -ReportOnly

Output
C:\Temp\GPOReports\GPO_Report_YYYYMMDD_HHMMSS.csv

