# Active Directory Privileged Group Audit & Reporting Script

A PowerShell utility that audits high-privilege Active Directory groups across all domains in a forest, generates structured CSV exports, and emails an HTML summary report to system administrators. Set it to a scheduled task and get regular reports for easy auditing.

---

## Overview

The script automates recursive membership checks for critical administrative groups across the entire AD forest:

- **Forest Root Level:** Audits `Enterprise Admins` and `Schema Admins`.
- **Domain Level:** Iterates across every domain in the forest to audit `Domain Admins`.

For each group, it collects user details (`Name`, `Enabled`, `DistinguishedName`, `UserPrincipalName`), generates a plain-text table inside an HTML email body, and attaches individual CSV files for deeper offline analysis.

---

## Features

- **Forest-Wide Discovery:** Automatically identifies all domains in the current Active Directory forest.
- **Recursive Membership Resolution:** Expands nested group memberships using `-Recursive` to reveal effective members.
- **Dual Output:**
  - Formatted HTML body containing quick-reference ASCII tables within `<pre>` tags.
  - CSV exports generated per group and domain in `C:\temp\`.
- **Automated Delivery:** Sends an HTML email with all generated CSV reports attached.

---

## Prerequisites

1. **PowerShell 5.1+** or **PowerShell 7+** (with Windows compatibility).
2. **ActiveDirectory PowerShell Module** (included in Remote Server Administration Tools / RSAT).
3. **Permissions:**- Read access to the target Active Directory domains and catalog.- Write permissions to local disk directory `C:\temp\`.- Relay permissions on the specified SMTP relay server.

---

## Configuration

Before running the script in production, update the environment-specific variables:

| Setting | Location in Script | Description |
| --- | --- | --- |
| **Recipient Email** | `-To "you@example.com"` | Target email address or distribution list for the audit report. |
| **Sender Email** | `-From "NoReply@example.com"` | From address used in the notification. |
| **SMTP Server** | `-SmtpServer "mail.example.com"` | Internal mail relay host. *(Replace demo host)* |
| **Export Directory** | `C:\temp\` | Output directory for the generated CSV files. Ensure this folder exists. |

---

## Usage

1. Open an elevated PowerShell session (or run via a scheduled task with a service account).
2. Ensure the export directory exists:
  
  ```powershell
  New-Item -ItemType Directory -Force -Path "C:\temp"
  ```
  
3. Execute the script:
  
  ```powershell
  .\Get-ADAdminReport.ps1
  ```
  

---

## Generated Artifacts

For each audited group, a CSV file is saved locally and attached to the email using the following naming convention:

- `C:\temp\<RootDomain> - Schema Admins Members.csv`
- `C:\temp\<RootDomain> - Enterprise Admins Members.csv`
- `C:\temp\<Domain> - Domain Admins Members.csv`
