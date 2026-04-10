# Consultim-IT Active Directory Security Assessment Tool

Production-ready PowerShell tool for assessing Active Directory security posture and generating a consulting-style HTML report with interactive attack-path analysis.

## Overview

This script performs an Active Directory security assessment and produces a polished report package that can be used for internal reviews or client delivery. It includes:

- Executive security dashboard
- Findings grouped by severity and category
- MITRE ATT&CK technique mapping
- Domain and identity hygiene analysis
- Privilege escalation and delegation analysis
- Interactive **Potential Attack Paths / Attack Surface** visualization
- Optional Excel workbook export
- Optional Microsoft Sentinel JSON export
- Attack graph JSON export

## Main Script

`ConsultimIT-AD-Assessment-fixed.ps1`

## Requirements

- Windows PowerShell **5.1** or later
- **ActiveDirectory** PowerShell module (required)
- **GroupPolicy** module (optional, for GPO analysis)
- **ImportExcel** module (optional, only needed with `-ExportExcel`)
- Permissions equivalent to **Domain Administrator** or a delegated account with sufficient read access across AD

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-Domain` | `string` | Target domain FQDN. Defaults to the current domain. |
| `-ScanMode` | `Quick` / `Full` | `Quick` runs lighter identity/password checks. `Full` runs the full assessment. Default: `Full`. |
| `-LogoPath` | `string` | Path to a PNG logo that will be embedded into the HTML report. |
| `-OutputPath` | `string` | Output folder for reports and export files. Default: `./ConsultimIT-Reports`. |
| `-ReportTitle` | `string` | Custom report title shown in the HTML report. |
| `-ClientCompany` | `string` | Client/company name displayed in the report title and header. If omitted, the script prompts for it. |
| `-ExportExcel` | `switch` | Generates an Excel workbook report. Requires `ImportExcel`. |
| `-ExportSentinel` | `switch` | Generates Microsoft Sentinel JSON output. |
| `-SkipPasswordPolicy` | `switch` | Skips password policy checks. |
| `-SkipPrivilegeEscalation` | `switch` | Skips privilege escalation checks. |
| `-SkipLateralMovement` | `switch` | Skips lateral movement checks. |
| `-SkipKerberos` | `switch` | Skips Kerberos-related checks. |
| `-SkipGPO` | `switch` | Skips GPO analysis. |
| `-SkipDelegation` | `switch` | Skips ACL/delegation analysis. |

## Basic Usage

### Full assessment

```powershell
.\ConsultimIT-AD-Assessment-fixed.ps1 -ClientCompany "Contoso" -Domain contoso.local
```

### Quick assessment

```powershell
.\ConsultimIT-AD-Assessment-fixed.ps1 -ScanMode Quick -ClientCompany "Contoso"
```

### Full assessment with all exports

```powershell
.\ConsultimIT-AD-Assessment-fixed.ps1 \
  -Domain contoso.local \
  -ClientCompany "Contoso" \
  -OutputPath "C:\Reports\AD" \
  -ExportExcel \
  -ExportSentinel
```

### Full assessment with selected checks skipped

```powershell
.\ConsultimIT-AD-Assessment-fixed.ps1 \
  -ClientCompany "Contoso" \
  -SkipGPO \
  -SkipDelegation
```

## Output Files

The script writes output into the folder specified by `-OutputPath`.

Typical generated files include:

- `ConsultimIT-AD-Report_<timestamp>.html` — primary HTML report
- `ConsultimIT-AD-Report_<timestamp>.xlsx` — Excel workbook export (optional)
- `ConsultimIT-Sentinel_<timestamp>.json` — Sentinel export (optional)
- `ConsultimIT-AttackGraph_<timestamp>.json` — attack graph export
- `ConsultimIT-AttackSurface_<timestamp>.html` — attack surface / graph-focused HTML output

## Potential Attack Paths / Attack Surface

The report contains an interactive attack-path interface that:

- Builds complete and partial attack chains
- Correlates relationships such as:
  - `MemberOf`
  - `AdminTo`
  - `HasAccessTo`
  - `CanRDP`
  - delegation-related relationships
- Assigns per-entity exposure and risk scoring
- Highlights high-risk paths and privilege relationships
- Renders an embedded JavaScript graph directly inside the generated HTML
- Falls back to a minimal placeholder graph when the environment has very little data

## Notes

- If `-ClientCompany` is not supplied, the script prompts for it using `Read-Host`.
- The company name is included in the HTML report title and header.
- The script is designed to remain a **single executable PowerShell file** while embedding the required HTML/CSS/JavaScript inside the generated report.

## Recommended Execution Context

Run the script:

- On a domain-joined administrative workstation or management server
- With RSAT / AD module available
- Using an account that can enumerate users, groups, computers, policies, delegations, and privileged relationships

## Troubleshooting

### ActiveDirectory module not found
Install RSAT / AD PowerShell tools and rerun the script.

### Excel export does not work
Install the `ImportExcel` module:

```powershell
Install-Module ImportExcel -Scope CurrentUser
```

### Company name prompt appears unexpectedly
Pass the parameter explicitly:

```powershell
-ClientCompany "Your Company Name"
```

## Version

- Tool version referenced in script header: **2.5.0**

## Author

**Ranim Hassine — Consultim-IT Security Practice**
