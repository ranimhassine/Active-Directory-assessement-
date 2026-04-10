#Requires -Version 5.1
<#
.SYNOPSIS
    Consultim-IT Active Directory Security Assessment Tool — Version 2.5
.DESCRIPTION
    Enterprise-grade Active Directory security assessment tool.
    Features: Deep AD security analysis, MITRE ATT&CK mapping, weighted risk scoring,
    multi-tab HTML dashboard with embedded branding, Base64 logo embedding,
    Microsoft Sentinel JSON export, Excel workbook export, Quick/Full scan modes,
    and a rich interactive HTML report worthy of Big-4 consulting delivery.
.AUTHOR
    Ranim Hassine — Consultim-IT Security Practice
.VERSION
    2.5.0
.NOTES
    Requires  : ActiveDirectory PowerShell Module (RSAT)
    Optional  : GroupPolicy module, ImportExcel module
    Run As    : Domain Administrator or equivalent
    Compatible: PowerShell 5.1+
    Logo Path : C:\Users\Administrator\SophisticatedADSAT\Assets\consultim_it_logo.png

.PARAMETER Domain
    Target domain FQDN. Defaults to current domain.
.PARAMETER ScanMode
    'Quick' (identity/password checks only) or 'Full' (all checks). Default: Full
.PARAMETER OutputPath
    Directory for report output. Default: .\ConsultimIT-Reports
.PARAMETER LogoPath
    Path to PNG logo file. Embedded as Base64 in the HTML report.
    Default: C:\Users\Administrator\SophisticatedADSAT\Assets\consultim_it_logo.png
.PARAMETER ExportExcel
    Generate Excel workbook alongside HTML report (requires ImportExcel module)
.PARAMETER ExportSentinel
    Export findings as JSON for Microsoft Sentinel ingestion
.PARAMETER SkipPasswordPolicy
    Skip password policy checks
.PARAMETER SkipPrivilegeEscalation
    Skip privilege escalation checks
.PARAMETER SkipLateralMovement
    Skip lateral movement checks
.PARAMETER SkipKerberos
    Skip Kerberos security checks
.PARAMETER SkipGPO
    Skip GPO analysis
.PARAMETER SkipDelegation
    Skip ACL/delegation analysis
.PARAMETER ReportTitle
    Custom title for the HTML report

.EXAMPLE
    .\ConsultimIT-AD-Assessment-v2.5.ps1
    Run full assessment against the current domain.

.EXAMPLE
    .\ConsultimIT-AD-Assessment-v2.5.ps1 -ScanMode Quick -Domain contoso.local
    Run a quick scan against a specific domain.

.EXAMPLE
    .\ConsultimIT-AD-Assessment-v2.5.ps1 -ExportExcel -ExportSentinel
    Full scan with Excel and Sentinel JSON export.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$Domain,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Quick","Full")]
    [string]$ScanMode = "Full",

    [Parameter(Mandatory=$false)]
    [string]$LogoPath = "C:\Users\Administrator\SophisticatedADSAT\Assets\consultim_it_logo.png",

    [Parameter(Mandatory=$false)]
    [switch]$SkipPasswordPolicy,

    [Parameter(Mandatory=$false)]
    [switch]$SkipPrivilegeEscalation,

    [Parameter(Mandatory=$false)]
    [switch]$SkipLateralMovement,

    [Parameter(Mandatory=$false)]
    [switch]$SkipKerberos,

    [Parameter(Mandatory=$false)]
    [switch]$SkipGPO,

    [Parameter(Mandatory=$false)]
    [switch]$SkipDelegation,

    [Parameter(Mandatory=$false)]
    [switch]$ExportExcel,

    [Parameter(Mandatory=$false)]
    [switch]$ExportSentinel,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ConsultimIT-Reports",

    [Parameter(Mandatory=$false)]
    [string]$ReportTitle = "Active Directory Security Assessment",

    [Parameter(Mandatory=$false)]
    [string]$ClientCompany
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 0 — LOGGING ENGINE
# ════════════════════════════════════════════════════════════════════════════
$script:LogLines   = [System.Collections.Generic.List[string]]::new()
$script:ScanErrors = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS","SECTION","DEBUG")]
        [string]$Level = "INFO"
    )
    $ts      = Get-Date -Format "HH:mm:ss.fff"
    $logLine = "[$ts][$Level] $Message"
    $script:LogLines.Add($logLine)
    if ($Level -eq "ERROR") { $script:ScanErrors.Add($Message) }

    $fgColor = switch ($Level) {
        "INFO"    { "Cyan" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
        "SECTION" { "Magenta" }
        "DEBUG"   { "DarkGray" }
        default   { "White" }
    }
    $prefix = switch ($Level) {
        "INFO"    { "  [•]" }
        "WARN"    { "  [!]" }
        "ERROR"   { "  [✗]" }
        "SUCCESS" { "  [✓]" }
        "SECTION" { "  [▶]" }
        "DEBUG"   { "  [~]" }
        default   { "     " }
    }
    Write-Host "$prefix $Message" -ForegroundColor $fgColor
}

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — PROFESSIONAL CONSOLE BANNER (v2.1)
# ════════════════════════════════════════════════════════════════════════════
Clear-Host

# Resolve client company name before displaying the banner
if ([string]::IsNullOrWhiteSpace($ClientCompany)) {
    Write-Host ""
    Write-Host "  Enter the name of the company being assessed: " -NoNewline -ForegroundColor DarkYellow
    $ClientCompany = Read-Host
}
if ([string]::IsNullOrWhiteSpace($ClientCompany)) { $ClientCompany = "N/A" }

Clear-Host
$bannerWidth = 72

function Write-BannerLine { param([string]$Text, [ConsoleColor]$Color = "DarkYellow")
    Write-Host $Text -ForegroundColor $Color }

$line = "═" * $bannerWidth
Write-BannerLine "  ╔$line╗"
Write-BannerLine "  ║$((" " * $bannerWidth))║"
Write-BannerLine "  ║   ██████╗ ██████╗ ███╗  ██╗███████╗██╗   ██╗██╗ ████████╗██╗███╗   ███╗    ██╗████████╗$((" " * 0))║"
Write-BannerLine "  ║  ██╔════╝██╔═══██╗████╗ ██║██╔════╝██║   ██║██║ ╚══██╔══╝██║████╗ ████║    ██║╚══██╔══╝$((" " * 0))║"
Write-BannerLine "  ║  ██║     ██║   ██║██╔██╗██║███████╗██║   ██║██║    ██║   ██║██╔████╔██║    ██║   ██║   $((" " * 0))║"
Write-BannerLine "  ║  ██║     ██║   ██║██║╚████║╚════██║██║   ██║██║    ██║   ██║██║╚██╔╝██║    ██║   ██║   $((" " * 0))║"
Write-BannerLine "  ║  ╚██████╗╚██████╔╝██║ ╚███║███████║╚██████╔╝███████╗██║  ██║██║ ╚═╝ ██║ ██╗██║   ██║   $((" " * 0))║"
Write-BannerLine "  ║   ╚═════╝ ╚═════╝ ╚═╝  ╚══╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═╝╚═╝   ╚═╝   $((" " * 0))║"
Write-BannerLine "  ║$((" " * $bannerWidth))║"
Write-BannerLine "  ║   ┌─────────────────────────────────────────────────────────────┐ ║"
Write-BannerLine "  ║   │  Active Directory Security Assessment Tool  ·  Version 2.5  │ ║"
Write-BannerLine "  ║   │  CONSULTIM-IT Security Practice  ·  Author: Ranim Hassine   │ ║"
Write-BannerLine "  ║   │  MITRE ATT&CK Mapping  ·  Risk Scoring  ·  Tabbed Report   │ ║"
Write-BannerLine "  ║   └─────────────────────────────────────────────────────────────┘ ║"
Write-BannerLine "  ║$((" " * $bannerWidth))║"

# Client company line — centered inside the banner
$clientLabel = "  Assessment Target: $ClientCompany  "
$padded = $clientLabel.PadRight($bannerWidth)
Write-BannerLine "  ║$padded║"

Write-BannerLine "  ║$((" " * $bannerWidth))║"
Write-BannerLine "  ╚$line╝"
Write-Host ""
Write-Host "  Scan Mode  : " -NoNewline -ForegroundColor DarkGray
Write-Host $ScanMode -ForegroundColor Yellow
Write-Host "  Client     : " -NoNewline -ForegroundColor DarkGray
Write-Host $ClientCompany -ForegroundColor DarkYellow
Write-Host "  Started At : " -NoNewline -ForegroundColor DarkGray
Write-Host (Get-Date -Format "yyyy-MM-dd  HH:mm:ss") -ForegroundColor White
Write-Host "  Output Path: " -NoNewline -ForegroundColor DarkGray
Write-Host $OutputPath -ForegroundColor White
Write-Host ""

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — PREREQUISITES & ENVIRONMENT
# ════════════════════════════════════════════════════════════════════════════
Write-Log "Validating prerequisites..." "SECTION"

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ActiveDirectory module not found. Run: Install-WindowsFeature RSAT-AD-PowerShell" "ERROR"
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop
Write-Log "ActiveDirectory module loaded." "SUCCESS"

if ($ExportExcel) {
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        Write-Log "ImportExcel module not found (Install-Module ImportExcel). Excel export disabled." "WARN"
        $ExportExcel = $false
    } else {
        Import-Module ImportExcel -ErrorAction SilentlyContinue
        Write-Log "ImportExcel module loaded." "SUCCESS"
    }
}

# Quick scan shortcut
if ($ScanMode -eq "Quick") {
    Write-Log "QUICK SCAN MODE: Skipping GPO, ACL, Lateral Movement, and Kerberos checks." "WARN"
    $SkipGPO             = $true
    $SkipDelegation      = $true
    $SkipLateralMovement = $true
    $SkipKerberos        = $true
}

# Output directory
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Log "Created output directory: $OutputPath" "INFO"
}

$StartTime = Get-Date
$Timestamp = $StartTime.ToString("yyyy-MM-dd_HH-mm-ss")

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — BASE64 LOGO EMBEDDING
# ════════════════════════════════════════════════════════════════════════════
Write-Log "Embedding corporate logo..." "SECTION"

$LogoBase64   = ""
$LogoDataURI  = ""

if (Test-Path -Path $LogoPath) {
    try {
        $logoBytes    = [System.IO.File]::ReadAllBytes($LogoPath)
        $LogoBase64   = [Convert]::ToBase64String($logoBytes)
        $ext          = [System.IO.Path]::GetExtension($LogoPath).ToLower().TrimStart('.')
        $mimeType     = switch ($ext) {
            "png"  { "image/png" }
            "jpg"  { "image/jpeg" }
            "jpeg" { "image/jpeg" }
            "gif"  { "image/gif" }
            "svg"  { "image/svg+xml" }
            default{ "image/png" }
        }
        $LogoDataURI  = "data:$mimeType;base64,$LogoBase64"
        Write-Log "Logo embedded successfully ($([math]::Round($logoBytes.Length/1KB,1)) KB → Base64)." "SUCCESS"
    } catch {
        Write-Log "Could not read logo file: $_" "WARN"
    }
} else {
    Write-Log "Logo not found at: $LogoPath — using text fallback." "WARN"
}

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — DOMAIN CONNECTION
# ════════════════════════════════════════════════════════════════════════════
Write-Log "Connecting to Active Directory..." "SECTION"
try {
    if ($Domain) { $DomainObj = Get-ADDomain -Identity $Domain -ErrorAction Stop }
    else         { $DomainObj = Get-ADDomain -ErrorAction Stop; $Domain = $DomainObj.DNSRoot }
    $ForestObj = Get-ADForest -ErrorAction Stop
    $DomainDN  = $DomainObj.DistinguishedName
    Write-Log "Connected: $Domain  (Forest: $($ForestObj.RootDomain))" "SUCCESS"
} catch {
    Write-Log "Domain connection failed: $_" "ERROR"; exit 1
}

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — FINDINGS ENGINE
# ════════════════════════════════════════════════════════════════════════════
$script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:Stats    = @{}

# MITRE ATT&CK technique library
$MitreLib = @{
    Kerberoast          = @{ ID="T1558.003"; Name="Steal or Forge Kerberos Tickets: Kerberoasting";       Tactic="Credential Access";      URL="https://attack.mitre.org/techniques/T1558/003/" }
    ASREPRoast          = @{ ID="T1558.004"; Name="Steal or Forge Kerberos Tickets: AS-REP Roasting";     Tactic="Credential Access";      URL="https://attack.mitre.org/techniques/T1558/004/" }
    DCSync              = @{ ID="T1003.006"; Name="OS Credential Dumping: DCSync";                         Tactic="Credential Access";      URL="https://attack.mitre.org/techniques/T1003/006/" }
    GoldenTicket        = @{ ID="T1558.001"; Name="Steal or Forge Kerberos Tickets: Golden Ticket";        Tactic="Credential Access";      URL="https://attack.mitre.org/techniques/T1558/001/" }
    UnconstrainedDeleg  = @{ ID="T1134.001"; Name="Access Token Manipulation: Token Impersonation/Theft";  Tactic="Defense Evasion";        URL="https://attack.mitre.org/techniques/T1134/001/" }
    PasswordSpray       = @{ ID="T1110.003"; Name="Brute Force: Password Spraying";                        Tactic="Credential Access";      URL="https://attack.mitre.org/techniques/T1110/003/" }
    BruteForce          = @{ ID="T1110.001"; Name="Brute Force: Password Guessing";                        Tactic="Credential Access";      URL="https://attack.mitre.org/techniques/T1110/001/" }
    CredDumping         = @{ ID="T1003";     Name="OS Credential Dumping";                                 Tactic="Credential Access";      URL="https://attack.mitre.org/techniques/T1003/" }
    NTLMRelay           = @{ ID="T1557.001"; Name="Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning";       Tactic="Credential Access";      URL="https://attack.mitre.org/techniques/T1557/001/" }
    AccountManipulation = @{ ID="T1098";     Name="Account Manipulation";                                  Tactic="Persistence";            URL="https://attack.mitre.org/techniques/T1098/" }
    ValidAccounts       = @{ ID="T1078.002"; Name="Valid Accounts: Domain Accounts";                       Tactic="Privilege Escalation";   URL="https://attack.mitre.org/techniques/T1078/002/" }
    PrintNightmare      = @{ ID="T1210";     Name="Exploitation of Remote Services";                       Tactic="Lateral Movement";       URL="https://attack.mitre.org/techniques/T1210/" }
    MachineAcctAbuse    = @{ ID="T1136.002"; Name="Create Account: Domain Account";                        Tactic="Persistence";            URL="https://attack.mitre.org/techniques/T1136/002/" }
    AdminSDHolder       = @{ ID="T1484.001"; Name="Domain Policy Modification: Group Policy Modification"; Tactic="Defense Evasion";        URL="https://attack.mitre.org/techniques/T1484/001/" }
    WeakEncryption      = @{ ID="T1600";     Name="Weaken Encryption";                                     Tactic="Defense Evasion";        URL="https://attack.mitre.org/techniques/T1600/" }
}

function Add-Finding {
    param(
        [string]$Category,
        [ValidateSet("Critical","High","Medium","Low","Informational")]
        [string]$Severity,
        [ValidateSet("P1","P2","P3","P4")]
        [string]$Priority = "P3",
        [string]$Title,
        [string]$Description,
        [string]$Impact,
        [string]$Remediation,
        [string]$Details     = "",
        [string]$MitreKey    = "",
        [string]$PSFix       = "",
        [string]$Effort      = "TBD",
        [string[]]$Tags      = @()
    )
    $m = if ($MitreKey -and $MitreLib.ContainsKey($MitreKey)) { $MitreLib[$MitreKey] } else { $null }

    $script:Findings.Add([PSCustomObject]@{
        Category    = $Category
        Severity    = $Severity
        Priority    = $Priority
        Title       = $Title
        Description = $Description
        Impact      = $Impact
        Remediation = $Remediation
        Details     = $Details
        MitreID     = if ($m) { $m.ID }     else { "" }
        MitreName   = if ($m) { $m.Name }   else { "" }
        MitreTactic = if ($m) { $m.Tactic } else { "" }
        MitreURL    = if ($m) { $m.URL }    else { "" }
        PSFix       = $PSFix
        Effort      = $Effort
        Tags        = $Tags -join ","
        Timestamp   = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    })
}

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — PROGRESS TRACKING
# ════════════════════════════════════════════════════════════════════════════
$TotalSteps  = 10
$CurrentStep = 0

function Step-Progress { param([string]$Activity, [string]$Status)
    $script:CurrentStep++
    $pct = [int](($script:CurrentStep / $script:TotalSteps) * 100)
    Write-Progress -Activity "Consultim-IT AD Assessment v2.5" -Status $Status -PercentComplete $pct -CurrentOperation $Activity
}

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — DATA COLLECTION: DOMAIN INVENTORY
# ════════════════════════════════════════════════════════════════════════════
Step-Progress "Domain Inventory" "Collecting AD objects..."
Write-Log "Collecting domain object inventory..." "SECTION"

$AllUsers          = Get-ADUser -Filter * -Properties * -Server $Domain
$EnabledUsers      = $AllUsers | Where-Object Enabled
$DisabledUsers     = $AllUsers | Where-Object { -not $_.Enabled }
$NeverLogonUsers   = $AllUsers | Where-Object { $null -eq $_.LastLogonDate -and $_.Enabled }
$StaleUsers30      = $AllUsers | Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-30)  -and $_.Enabled -and $null -ne $_.LastLogonDate }
$StaleUsers60      = $AllUsers | Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-60)  -and $_.Enabled -and $null -ne $_.LastLogonDate }
$StaleUsers90      = $AllUsers | Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-90)  -and $_.Enabled -and $null -ne $_.LastLogonDate }
$PwdNeverExpires   = $AllUsers | Where-Object { $_.PasswordNeverExpires -and $_.Enabled }
$PwdNotRequired    = $AllUsers | Where-Object { $_.PasswordNotRequired  -and $_.Enabled }
$ReversiblePwd     = $AllUsers | Where-Object { $_.AllowReversiblePasswordEncryption }
$SensitiveAccts    = $AllUsers | Where-Object { $_.AccountNotDelegated -and $_.Enabled }
$LockedOut         = $AllUsers | Where-Object { $_.LockedOut -and $_.Enabled }
$PwdExpired        = $AllUsers | Where-Object { $_.PasswordExpired -and $_.Enabled }
$SmartcardRequired = $AllUsers | Where-Object { $_.SmartcardLogonRequired -and $_.Enabled }

$AllComputers      = Get-ADComputer -Filter * -Properties * -Server $Domain
$DomainControllers = Get-ADDomainController -Filter * -Server $Domain
$AllGroups         = Get-ADGroup -Filter * -Properties * -Server $Domain
$EmptyGroups       = $AllGroups | Where-Object { (Get-ADGroupMember $_ -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0 }

$PrivGroupNames    = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators",
                       "Account Operators","Backup Operators","Print Operators","Server Operators",
                       "Group Policy Creator Owners","DNSAdmins")
$PrivGroups        = $AllGroups | Where-Object { $_.Name -in $PrivGroupNames }

$AllGPOs           = Get-GPO -All -Domain $Domain -ErrorAction SilentlyContinue
$GPOCount          = if ($AllGPOs) { @($AllGPOs).Count } else { 0 }

$DomainAdmins      = Get-ADGroupMember "Domain Admins"     -Recursive -Server $Domain -ErrorAction SilentlyContinue
$EnterpriseAdmins  = Get-ADGroupMember "Enterprise Admins" -Recursive -Server $Domain -ErrorAction SilentlyContinue
$SchemaAdmins      = Get-ADGroupMember "Schema Admins"     -Recursive -Server $Domain -ErrorAction SilentlyContinue

# Machine account quota
try {
    $DomainRoot   = [ADSI]"LDAP://$DomainDN"
    $MachineQuota = [int]($DomainRoot.Properties["ms-DS-MachineAccountQuota"] | Select-Object -First 1)
} catch { $MachineQuota = 10 }

# KRBTGT
$KrbtgtAccount = Get-ADUser krbtgt -Properties PasswordLastSet,ServicePrincipalNames -Server $Domain
$KrbtgtAgeDays = [int]((Get-Date) - $KrbtgtAccount.PasswordLastSet).TotalDays

# Password policy
$DefaultPwdPolicy = Get-ADDefaultDomainPasswordPolicy -Server $Domain

# OS breakdown of computers
$OSBreakdown = $AllComputers | Group-Object -Property OperatingSystem | Sort-Object Count -Descending | Select-Object -First 8

# Populate stats hashtable
$script:Stats = @{
    TotalUsers        = @($AllUsers).Count
    EnabledUsers      = @($EnabledUsers).Count
    DisabledUsers     = @($DisabledUsers).Count
    NeverLogon        = @($NeverLogonUsers).Count
    StaleUsers30      = @($StaleUsers30).Count
    StaleUsers60      = @($StaleUsers60).Count
    StaleUsers90      = @($StaleUsers90).Count
    PwdNeverExpires   = @($PwdNeverExpires).Count
    PwdNotRequired    = @($PwdNotRequired).Count
    ReversiblePwd     = @($ReversiblePwd).Count
    LockedOut         = @($LockedOut).Count
    PwdExpired        = @($PwdExpired).Count
    SmartcardRequired = @($SmartcardRequired).Count
    SensitiveAccts    = @($SensitiveAccts).Count
    TotalComputers    = @($AllComputers).Count
    DomainControllers = @($DomainControllers).Count
    TotalGroups       = @($AllGroups).Count
    EmptyGroups       = @($EmptyGroups).Count
    TotalGPOs         = $GPOCount
    DomainAdmins      = if ($DomainAdmins)     { @($DomainAdmins).Count }     else { 0 }
    EnterpriseAdmins  = if ($EnterpriseAdmins) { @($EnterpriseAdmins).Count } else { 0 }
    SchemaAdmins      = if ($SchemaAdmins)     { @($SchemaAdmins).Count }     else { 0 }
    ForestFunctional  = $ForestObj.ForestMode.ToString()
    DomainFunctional  = $DomainObj.DomainMode.ToString()
    MachineQuota      = $MachineQuota
    KrbtgtAgeDays     = $KrbtgtAgeDays
    MinPwdLength      = $DefaultPwdPolicy.MinPasswordLength
    LockoutThreshold  = [int]$DefaultPwdPolicy.LockoutThreshold
    PwdComplexity     = $DefaultPwdPolicy.ComplexityEnabled
    MaxPwdAgeDays     = $DefaultPwdPolicy.MaxPasswordAge.Days
    PwdHistoryCount   = $DefaultPwdPolicy.PasswordHistoryCount
    OSBreakdown       = $OSBreakdown
}

Write-Log "Inventory: $($script:Stats.TotalUsers) users | $($script:Stats.TotalComputers) computers | $($script:Stats.TotalGroups) groups" "SUCCESS"

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — SECURITY CHECKS
# ════════════════════════════════════════════════════════════════════════════

# ── 8.1 PASSWORD POLICY ────────────────────────────────────────────────────
if (-not $SkipPasswordPolicy) {
    Step-Progress "Password Policy" "Analyzing password configuration..."
    Write-Log "Analyzing password policies..." "SECTION"

    if ($script:Stats.MinPwdLength -lt 12) {
        Add-Finding -Category "Password Policy" -Severity "High" -Priority "P2" -Effort "2 hours" -MitreKey "BruteForce" `
            -Title "Minimum Password Length Below Threshold" `
            -Description "Domain minimum password length is $($script:Stats.MinPwdLength) characters. CIS Benchmark L1 requires 14+." `
            -Impact "Short passwords are cracked in minutes with modern GPU-accelerated tools. Increases successful credential stuffing risk." `
            -Remediation "Raise minimum length to 14+ characters via Default Domain Policy. Consider Microsoft Entra Password Protection for banned-word enforcement." `
            -Details "Current: $($script:Stats.MinPwdLength) chars  |  CIS Recommended: 14+" `
            -PSFix "Set-ADDefaultDomainPasswordPolicy -Identity '$Domain' -MinPasswordLength 14" `
            -Tags @("CIS-L1","NIST-SP800-63")
    }

    if ($script:Stats.LockoutThreshold -eq 0) {
        Add-Finding -Category "Password Policy" -Severity "High" -Priority "P2" -Effort "30 min" -MitreKey "PasswordSpray" `
            -Title "Account Lockout Policy Disabled" `
            -Description "Lockout threshold = 0 — unlimited password attempts against any account without ever triggering a lockout." `
            -Impact "Enables unlimited password spraying (1 password × N users) and brute-force attacks. Zero detection, zero blocking. Primary initial access vector in ransomware campaigns." `
            -Remediation "Set threshold to 5-10 attempts, duration to 15 min, observation window to 15 min. Deploy Microsoft Entra Smart Lockout for hybrid environments." `
            -Details "Threshold: 0 (disabled)  |  Recommended: 5-10 attempts / 15 min lockout" `
            -PSFix "Set-ADDefaultDomainPasswordPolicy -Identity '$Domain' -LockoutThreshold 5 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00" `
            -Tags @("CIS-L1","PCI-DSS-8.3")
    } elseif ($script:Stats.LockoutThreshold -gt 20) {
        Add-Finding -Category "Password Policy" -Severity "Medium" -Priority "P3" -Effort "30 min" -MitreKey "PasswordSpray" `
            -Title "Account Lockout Threshold Too Permissive" `
            -Description "Lockout threshold is $($script:Stats.LockoutThreshold) — excessive for effective spray protection." `
            -Impact "Attackers can attempt many passwords before triggering lockout, making detection difficult." `
            -Remediation "Reduce lockout threshold to 5-10 failed attempts." `
            -Details "Current: $($script:Stats.LockoutThreshold)  |  Recommended: 5-10"
    }

    if (-not $script:Stats.PwdComplexity) {
        Add-Finding -Category "Password Policy" -Severity "High" -Priority "P2" -Effort "30 min" -MitreKey "BruteForce" `
            -Title "Password Complexity Requirements Disabled" `
            -Description "Domain password complexity is disabled. Users may set trivially simple passwords." `
            -Impact "Trivially guessable passwords are cracked instantly with dictionary attacks. Dramatically expands susceptible population." `
            -Remediation "Enable complexity requirements. Supplement with a banned-password list (Microsoft Entra Password Protection)." `
            -Details "Complexity: Disabled  |  Recommended: Enabled + banned-password enforcement" `
            -PSFix "Set-ADDefaultDomainPasswordPolicy -Identity '$Domain' -ComplexityEnabled `$true" `
            -Tags @("CIS-L1","ISO27001")
    }

    if ($script:Stats.PwdHistoryCount -lt 10) {
        Add-Finding -Category "Password Policy" -Severity "Medium" -Priority "P3" -Effort "30 min" `
            -Title "Insufficient Password History Count" `
            -Description "Password history is $($script:Stats.PwdHistoryCount). Microsoft and CIS recommend 24." `
            -Impact "Users can cycle through a small set of passwords, defeating rotation policies and enabling long-term credential reuse." `
            -Remediation "Set password history to 24." `
            -Details "Current: $($script:Stats.PwdHistoryCount)  |  Recommended: 24" `
            -PSFix "Set-ADDefaultDomainPasswordPolicy -Identity '$Domain' -PasswordHistoryCount 24"
    }

    if ($script:Stats.MaxPwdAgeDays -eq 0 -or $script:Stats.MaxPwdAgeDays -gt 365) {
        Add-Finding -Category "Password Policy" -Severity "Medium" -Priority "P3" -Effort "1 hour" `
            -Title "Password Expiration Incorrectly Configured" `
            -Description "Maximum password age is $($script:Stats.MaxPwdAgeDays) days (0 = never expires)." `
            -Impact "Credentials may remain static indefinitely, extending the window of exploitation after compromise." `
            -Remediation "Set max password age to 90-180 days, or adopt a breach-detection based rotation strategy per NIST SP 800-63B." `
            -Details "Max age: $($script:Stats.MaxPwdAgeDays) days  |  Recommended: 90-180 days"
    }

    if ($script:Stats.PwdNotRequired -gt 0) {
        $names = (($PwdNotRequired | Select-Object -First 10 | ForEach-Object { $_.SamAccountName }) -join ", ")
        Add-Finding -Category "Password Policy" -Severity "Critical" -Priority "P1" -Effort "1 hour" -MitreKey "CredDumping" `
            -Title "Accounts with Password Not Required (PASSWD_NOTREQD)" `
            -Description "$($script:Stats.PwdNotRequired) enabled accounts have the PASSWD_NOTREQD UAC flag — they can authenticate without any password." `
            -Impact "Complete authentication bypass. Any of these accounts can be logged into with an empty password string, requiring no credentials at all." `
            -Remediation "Immediately clear the PASSWD_NOTREQD flag and set strong random passwords on all affected accounts. Audit how these accounts were created." `
            -Details "Accounts: $names" `
            -PSFix "Get-ADUser -Filter {PasswordNotRequired -eq `$true} | Set-ADUser -PasswordNotRequired `$false" `
            -Tags @("CRITICAL-IMMEDIATE")
    }

    if ($script:Stats.ReversiblePwd -gt 0) {
        $names = (($ReversiblePwd | ForEach-Object { $_.SamAccountName }) -join ", ")
        Add-Finding -Category "Password Policy" -Severity "Critical" -Priority "P1" -Effort "1 hour" -MitreKey "CredDumping" `
            -Title "Reversible Password Encryption Enabled" `
            -Description "$($script:Stats.ReversiblePwd) accounts store passwords in a reversibly encrypted format — effectively plaintext." `
            -Impact "Any attacker with directory read access (or a stolen backup) can recover these passwords in plaintext without cracking. Equivalent to storing cleartext credentials." `
            -Remediation "Disable reversible encryption on all accounts and immediately force password resets. Check Fine-Grained PSOs for the same misconfiguration." `
            -Details "Accounts: $names" `
            -PSFix "Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq `$true} | Set-ADUser -AllowReversiblePasswordEncryption `$false" `
            -Tags @("CRITICAL-IMMEDIATE")
    }

    if ($script:Stats.PwdNeverExpires -gt 0) {
        $sample = (($PwdNeverExpires | Select-Object -First 15 | ForEach-Object { $_.SamAccountName }) -join ", ")
        Add-Finding -Category "Password Policy" -Severity "High" -Priority "P2" -Effort "1-2 days" -MitreKey "ValidAccounts" `
            -Title "Accounts with Password Never Expires ($($script:Stats.PwdNeverExpires) accounts)" `
            -Description "$($script:Stats.PwdNeverExpires) enabled accounts have PasswordNeverExpires set ($([math]::Round(($script:Stats.PwdNeverExpires/$script:Stats.EnabledUsers)*100,1))% of enabled users)." `
            -Impact "Static long-lived credentials are targeted by credential stuffing using breached password databases. Compromised accounts remain exploitable indefinitely." `
            -Remediation "Remove flag from standard users and enforce rotation. Migrate service accounts to gMSA. PAM vault for break-glass accounts." `
            -Details "Sample: $sample" `
            -PSFix "Get-ADUser -Filter {PasswordNeverExpires -eq `$true -and Enabled -eq `$true} | Set-ADUser -PasswordNeverExpires `$false"
    }

    # Fine-Grained Password Policies
    try {
        $FGPPs = Get-ADFineGrainedPasswordPolicy -Filter * -Server $Domain -ErrorAction SilentlyContinue
        if (-not $FGPPs) {
            Add-Finding -Category "Password Policy" -Severity "Low" -Priority "P4" -Effort "4 hours" `
                -Title "No Fine-Grained Password Policies (FGPPs) Configured" `
                -Description "No FGPPs exist. Privileged accounts use the same password policy as regular users." `
                -Impact "Privileged accounts should have stricter requirements (longer passwords, no expiry with PAM rotation). Without FGPPs, admin accounts are subject to the same weak defaults." `
                -Remediation "Create FGPPs for service accounts (25+ chars, extended expiry), admin accounts (20+ chars), and standard users (14+ chars, 90-day rotation)." `
                -PSFix "New-ADFineGrainedPasswordPolicy -Name 'Admin-PSO' -Precedence 10 -MinPasswordLength 20 -ComplexityEnabled `$true -LockoutThreshold 3"
        }
    } catch {}

    Write-Log "Password policy checks complete." "SUCCESS"
}

# ── 8.2 PRIVILEGE ESCALATION ───────────────────────────────────────────────
if (-not $SkipPrivilegeEscalation) {
    Step-Progress "Privilege Escalation" "Analyzing privilege escalation paths..."
    Write-Log "Analyzing privilege escalation paths..." "SECTION"

    # Kerberoastable
    $Kerberoastable = $AllUsers | Where-Object {
        $_.ServicePrincipalNames.Count -gt 0 -and $_.Enabled -and $_.SamAccountName -ne "krbtgt"
    }
    if (@($Kerberoastable).Count -gt 0) {
        $kNames = (($Kerberoastable | ForEach-Object { $_.SamAccountName }) -join ", ")
        Add-Finding -Category "Privilege Escalation" -Severity "High" -Priority "P2" -Effort "1-2 days" -MitreKey "Kerberoast" `
            -Title "Kerberoastable Service Accounts ($(@($Kerberoastable).Count) accounts)" `
            -Description "$(@($Kerberoastable).Count) enabled accounts have registered SPNs. Any domain user can request TGS tickets for these accounts and crack them offline — no elevated privileges required." `
            -Impact "Offline cracking success depends only on password strength. Service accounts with common passwords (Company123!, Summer2024) are cracked in seconds with Hashcat on modern GPUs." `
            -Remediation "Migrate to gMSA (automatic 240-char rotating passwords, eliminates Kerberoasting entirely). For remaining SPN accounts, enforce 25+ char random passwords and monitor 4769 events." `
            -Details "Accounts: $kNames" `
            -PSFix "Get-ADUser -Filter {ServicePrincipalNames -like '*'} -Properties ServicePrincipalNames,PasswordLastSet | Select-Object Name,ServicePrincipalNames,PasswordLastSet | Format-Table -AutoSize"
    }

    # AS-REP Roastable
    $ASREPRoastable = $AllUsers | Where-Object { $_.DoesNotRequirePreAuth -and $_.Enabled }
    if (@($ASREPRoastable).Count -gt 0) {
        $arpNames = (($ASREPRoastable | ForEach-Object { $_.SamAccountName }) -join ", ")
        Add-Finding -Category "Privilege Escalation" -Severity "High" -Priority "P1" -Effort "2 hours" -MitreKey "ASREPRoast" `
            -Title "AS-REP Roastable Accounts — Pre-Auth Disabled ($(@($ASREPRoastable).Count))" `
            -Description "$(@($ASREPRoastable).Count) accounts have DoesNotRequirePreAuth=True. Attackers need zero credentials to obtain an offline-crackable hash for these accounts." `
            -Impact "No authentication needed to target these accounts from any domain-joined machine. Hash is returned by the KDC to anyone who asks. Frequently exploited in ransomware initial access." `
            -Remediation "Enable Kerberos pre-authentication on all accounts. Document exceptions with business justification. Verify regularly via scheduled PowerShell audit." `
            -Details "Accounts: $arpNames" `
            -PSFix "Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true} | Set-ADUser -DoesNotRequirePreAuth `$false"
    }

    # AdminCount orphans
    $AdminCountUsers = $AllUsers | Where-Object { $_.AdminCount -eq 1 -and $_.Enabled }
    $ProtectedMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($pg in $PrivGroups) {
        try {
            (Get-ADGroupMember -Identity $pg.DistinguishedName -Recursive -Server $Domain -ErrorAction SilentlyContinue) |
                ForEach-Object { [void]$ProtectedMembers.Add($_.SamAccountName) }
        } catch {}
    }
    $AdminCountOrphans = $AdminCountUsers | Where-Object { -not $ProtectedMembers.Contains($_.SamAccountName) }
    if (@($AdminCountOrphans).Count -gt 0) {
        $acNames = (($AdminCountOrphans | Select-Object -First 10 | ForEach-Object { $_.SamAccountName }) -join ", ")
        Add-Finding -Category "Privilege Escalation" -Severity "High" -Priority "P2" -Effort "4-8 hours" -MitreKey "AdminSDHolder" `
            -Title "AdminCount=1 Orphaned Accounts ($(@($AdminCountOrphans).Count))" `
            -Description "$(@($AdminCountOrphans).Count) accounts have AdminCount=1 but are not current members of any protected group. SDProp has frozen their ACLs permanently." `
            -Impact "These accounts have hardened ACLs that block normal inheritance, creating hidden, unexpected access paths. Former admins who left the protected group still have these escalated ACLs indefinitely." `
            -Remediation "Clear AdminCount, re-enable ACL inheritance via ADSI Edit, re-run SDProp to propagate correct permissions." `
            -Details "Orphaned accounts (sample): $acNames" `
            -PSFix "Get-ADUser -Filter {AdminCount -eq 1 -and Enabled -eq `$true} | Set-ADUser -Clear AdminCount"
    }

    # Excessive Domain Admins
    if ($script:Stats.DomainAdmins -gt 5) {
        $daNames = if ($DomainAdmins) { (($DomainAdmins | Select-Object -First 10 | ForEach-Object { $_.SamAccountName }) -join ", ") } else { "N/A" }
        Add-Finding -Category "Privilege Escalation" -Severity "High" -Priority "P2" -Effort "1-2 weeks" -MitreKey "ValidAccounts" `
            -Title "Excessive Domain Administrator Accounts ($($script:Stats.DomainAdmins))" `
            -Description "$($script:Stats.DomainAdmins) accounts in Domain Admins. Best practice is ≤5 break-glass accounts with JIT access." `
            -Impact "Every DA account is a potential full domain compromise path. Compromising any single account yields: all user credentials, all computers, all data, persistence across password resets." `
            -Remediation "Remove all non-essential DA members. Implement Just-In-Time access (Microsoft PAM or CyberArk). Separate daily-use accounts from privileged accounts. Implement AD Tiering Model." `
            -Details "Members (sample): $daNames  |  Total: $($script:Stats.DomainAdmins)" `
            -PSFix "Get-ADGroupMember 'Domain Admins' -Recursive | Select-Object SamAccountName, distinguishedName, objectClass | Sort-Object SamAccountName"
    }

    # Privileged accounts not marked sensitive (not AccountNotDelegated)
    $NotSensitivePriv = [System.Collections.Generic.List[string]]::new()
    foreach ($pg in $PrivGroups) {
        try {
            $members = Get-ADGroupMember -Identity $pg.DistinguishedName -Recursive -Server $Domain -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                try {
                    $u = Get-ADUser $m -Properties AccountNotDelegated,Enabled -ErrorAction SilentlyContinue
                    if ($u -and $u.Enabled -and -not $u.AccountNotDelegated) { $NotSensitivePriv.Add($u.SamAccountName) }
                } catch {}
            }
        } catch {}
    }
    $NotSensitivePriv = @($NotSensitivePriv | Select-Object -Unique)
    if ($NotSensitivePriv.Count -gt 0) {
        Add-Finding -Category "Privilege Escalation" -Severity "Medium" -Priority "P2" -Effort "2-4 hours" -MitreKey "UnconstrainedDeleg" `
            -Title "Privileged Accounts Not Marked as Sensitive ($($NotSensitivePriv.Count))" `
            -Description "$($NotSensitivePriv.Count) privileged group members lack the AccountNotDelegated flag. Their credentials can be delegated through Kerberos." `
            -Impact "DA credentials delegated to intermediate systems (IIS, SQL, RDP) can be stolen from memory by an attacker with SYSTEM on those systems — escalating from server-level to domain-level compromise." `
            -Remediation "Set AccountNotDelegated=True on all privileged accounts. Add to Protected Users security group for additional Kerberos protections (no RC4, no delegation, no credential caching)." `
            -Details "Accounts: $($NotSensitivePriv -join ', ')" `
            -PSFix "Get-ADGroupMember 'Domain Admins' -Recursive | ForEach-Object { Set-ADUser `$_ -AccountNotDelegated `$true }"
    }

    # Service accounts in privileged groups
    $SvcInPriv = [System.Collections.Generic.List[string]]::new()
    foreach ($pg in $PrivGroups) {
        try {
            $members = Get-ADGroupMember -Identity $pg.DistinguishedName -Recursive -Server $Domain -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                if ($m.SamAccountName -match "svc[_\-\.]|service|sa_|_sa|robot|api[_\-\.]|app[_\-\.]|bot") {
                    $SvcInPriv.Add("$($m.SamAccountName) (in: $($pg.Name))")
                }
            }
        } catch {}
    }
    if ($SvcInPriv.Count -gt 0) {
        Add-Finding -Category "Privilege Escalation" -Severity "High" -Priority "P2" -Effort "2-4 hours" -MitreKey "ValidAccounts" `
            -Title "Service Accounts in Privileged Groups ($($SvcInPriv.Count))" `
            -Description "$($SvcInPriv.Count) service accounts detected in privileged groups — a common persistence and escalation path." `
            -Impact "Application compromise yields domain admin rights. Service account credentials are often embedded in scripts, config files, and deployed to many servers — dramatically increasing the attack surface." `
            -Remediation "Remove service accounts from privileged groups immediately. Create dedicated OUs with minimal, scoped permissions. Use gMSA where possible." `
            -Details "$($SvcInPriv -join ' | ')"
    }

    Write-Log "Privilege escalation checks complete." "SUCCESS"
}

# ── 8.3 STALE ACCOUNT HYGIENE ──────────────────────────────────────────────
Step-Progress "Account Hygiene" "Analyzing account staleness..."
Write-Log "Analyzing account hygiene..." "SECTION"

if ($script:Stats.StaleUsers90 -gt 0) {
    $stNames = (($StaleUsers90 | Select-Object -First 10 | ForEach-Object { $_.SamAccountName }) -join ", ")
    Add-Finding -Category "Account Hygiene" -Severity "Medium" -Priority "P3" -Effort "1-2 days" -MitreKey "ValidAccounts" `
        -Title "Stale Enabled Accounts — 90+ Days Inactive ($($script:Stats.StaleUsers90))" `
        -Description "$($script:Stats.StaleUsers90) enabled accounts have not authenticated in 90+ days and remain active targets." `
        -Impact "Stale accounts are overlooked in access reviews, accumulate valid credentials from past employees and contractors, and are prime targets for credential stuffing using breached password databases." `
        -Remediation "Disable accounts inactive for 60+ days. Move to a Quarantine OU. Delete after 30-day hold with no tickets filed. Automate via Identity Governance." `
        -Details "Sample: $stNames  |  30d: $($script:Stats.StaleUsers30)  |  60d: $($script:Stats.StaleUsers60)  |  90d: $($script:Stats.StaleUsers90)" `
        -PSFix "Get-ADUser -Filter {LastLogonDate -lt ((Get-Date).AddDays(-90)) -and Enabled -eq `$true} | Disable-ADAccount"
}

if ($script:Stats.NeverLogon -gt 0) {
    $nlNames = (($NeverLogonUsers | Select-Object -First 10 | ForEach-Object { $_.SamAccountName }) -join ", ")
    Add-Finding -Category "Account Hygiene" -Severity "Low" -Priority "P3" -Effort "4 hours" `
        -Title "Accounts That Have Never Logged On ($($script:Stats.NeverLogon))" `
        -Description "$($script:Stats.NeverLogon) enabled accounts have no recorded logon history — provisioned but never used." `
        -Impact "Orphaned provisioned accounts represent latent attack surface. They often have default or weak initial passwords set during provisioning that were never changed." `
        -Remediation "Review and disable accounts with no business justification. Implement a provisioning workflow that verifies first-use within 14 days." `
        -Details "Sample: $nlNames" `
        -PSFix "Get-ADUser -Filter {LastLogonDate -eq `$null -and Enabled -eq `$true} | Disable-ADAccount"
}

Write-Log "Account hygiene checks complete." "SUCCESS"

# ── 8.4 LATERAL MOVEMENT ──────────────────────────────────────────────────
if (-not $SkipLateralMovement) {
    Step-Progress "Lateral Movement" "Analyzing lateral movement vectors..."
    Write-Log "Analyzing lateral movement vectors..." "SECTION"

    # Machine Account Quota
    if ($script:Stats.MachineQuota -gt 0) {
        Add-Finding -Category "Lateral Movement" -Severity "Medium" -Priority "P3" -Effort "30 min" -MitreKey "MachineAcctAbuse" `
            -Title "Non-Zero Machine Account Quota ($($script:Stats.MachineQuota))" `
            -Description "ms-DS-MachineAccountQuota = $($script:Stats.MachineQuota). Any authenticated domain user can create up to $($script:Stats.MachineQuota) computer accounts." `
            -Impact "Enables Resource-Based Constrained Delegation (RBCD) attacks. A standard domain user can create a computer account, configure it for delegation to any target, and compromise that target without any admin rights (noPac/Sam-the-Admin attacks)." `
            -Remediation "Set quota to 0. Delegate computer account creation to a single dedicated service account restricted to specific OUs." `
            -Details "Current: $($script:Stats.MachineQuota)  |  Recommended: 0" `
            -PSFix "Set-ADDomain -Identity '$Domain' -Replace @{'ms-DS-MachineAccountQuota'='0'}"
    }

    # Unconstrained delegation — computers
    $UnconstrainedPC = $AllComputers | Where-Object {
        $_.TrustedForDelegation -and
        $_.DNSHostName -notin ($DomainControllers | ForEach-Object { $_.HostName })
    }
    if (@($UnconstrainedPC).Count -gt 0) {
        $ucNames = (($UnconstrainedPC | ForEach-Object { $_.Name }) -join ", ")
        Add-Finding -Category "Lateral Movement" -Severity "Critical" -Priority "P1" -Effort "4-8 hours" -MitreKey "UnconstrainedDeleg" `
            -Title "Unconstrained Kerberos Delegation — Non-DC Computers ($(@($UnconstrainedPC).Count))" `
            -Description "$(@($UnconstrainedPC).Count) non-DC machines have TrustedForDelegation=True, caching TGTs of every authenticating user including Domain Admins." `
            -Impact "SYSTEM on any of these servers = full domain compromise. SpoolSample, Petitpotam, and DFSCoerce can force DC authentication to these servers, caching DC machine TGTs that enable Golden Ticket forgery." `
            -Remediation "Disable TrustedForDelegation on all non-DC computers. Test for application impact. Replace with RBCD or constrained delegation where needed." `
            -Details "Servers: $ucNames" `
            -PSFix "Get-ADComputer -Filter {TrustedForDelegation -eq `$true} | Where-Object {`$_.Name -notin (Get-ADDomainController -Filter *).Name} | Set-ADComputer -TrustedForDelegation `$false"
    }

    # Unconstrained delegation — users
    $UnconstrainedUsers = $AllUsers | Where-Object { $_.TrustedForDelegation -and $_.Enabled }
    if (@($UnconstrainedUsers).Count -gt 0) {
        $uuNames = (($UnconstrainedUsers | ForEach-Object { $_.SamAccountName }) -join ", ")
        Add-Finding -Category "Lateral Movement" -Severity "Critical" -Priority "P1" -Effort "4-8 hours" -MitreKey "UnconstrainedDeleg" `
            -Title "Unconstrained Kerberos Delegation — User Accounts ($(@($UnconstrainedUsers).Count))" `
            -Description "$(@($UnconstrainedUsers).Count) user accounts have unconstrained delegation — the highest-risk delegation setting for non-DC objects." `
            -Impact "These accounts cache TGTs of all authenticating users. An attacker who authenticates as or to these accounts can impersonate any user to any service with no time limit." `
            -Remediation "Remove unconstrained delegation from all user accounts. Use RBCD or constrained delegation instead." `
            -Details "Accounts: $uuNames" `
            -PSFix "Get-ADUser -Filter {TrustedForDelegation -eq `$true} | Set-ADUser -TrustedForDelegation `$false"
    }

    # Print Spooler on DCs
    foreach ($dc in $DomainControllers) {
        try {
            $svc = Get-Service -ComputerName $dc.HostName -Name "Spooler" -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                Add-Finding -Category "Lateral Movement" -Severity "Critical" -Priority "P1" -Effort "30 min" -MitreKey "PrintNightmare" `
                    -Title "Print Spooler Active on DC: $($dc.HostName)" `
                    -Description "Print Spooler is Running on domain controller $($dc.HostName). Enables PrintNightmare (CVE-2021-34527) and SpoolSample coercion." `
                    -Impact "Remote code execution as SYSTEM on DCs. SpoolSample forces DC machine account authentication enabling NTLM relay to DCs, DCSYNC, and Golden Ticket creation with zero user interaction required." `
                    -Remediation "Stop and disable Print Spooler on all DCs immediately. Deploy via GPO for persistence of the setting." `
                    -Details "DC: $($dc.HostName)  |  Service: Running  |  CVE: 2021-34527, 2021-1675" `
                    -PSFix "Invoke-Command -ComputerName '$($dc.HostName)' { Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled }"
            }
        } catch {}
    }

    # NTLM LmCompatibilityLevel
    foreach ($dc in $DomainControllers) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $dc.HostName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Lsa")
            if ($key) {
                $lmc = $key.GetValue("LmCompatibilityLevel")
                if ($null -ne $lmc -and [int]$lmc -lt 3) {
                    Add-Finding -Category "Lateral Movement" -Severity "High" -Priority "P2" -Effort "1 day" -MitreKey "NTLMRelay" `
                        -Title "Weak NTLM Authentication Level on DC: $($dc.HostName) (Level: $lmc)" `
                        -Description "LmCompatibilityLevel = $lmc on $($dc.HostName). NTLMv1/LM authentication is permitted." `
                        -Impact "NTLMv1 hashes are cracked in <2 seconds with rainbow tables. Enables NTLM relay attacks even on patched systems. Required for Responder, ntlmrelayx, and similar tools to succeed." `
                        -Remediation "Set LmCompatibilityLevel to 5 (NTLMv2 only, refuse LM and NTLM) on all DCs via GPO. Test with a pilot group of legacy clients first." `
                        -Details "DC: $($dc.HostName)  |  Level: $lmc  |  Required: 5  |  GPO: Computer Config > Security Settings > Network Security: LAN Manager authentication level"
                }
            }
        } catch {}
    }

    Write-Log "Lateral movement checks complete." "SUCCESS"
}

# ── 8.5 KERBEROS SECURITY ─────────────────────────────────────────────────
if (-not $SkipKerberos) {
    Step-Progress "Kerberos Security" "Analyzing Kerberos configuration..."
    Write-Log "Analyzing Kerberos security..." "SECTION"

    if ($script:Stats.KrbtgtAgeDays -gt 180) {
        Add-Finding -Category "Kerberos Security" -Severity "High" -Priority "P2" -Effort "2-4 hours" -MitreKey "GoldenTicket" `
            -Title "KRBTGT Password Stale — $($script:Stats.KrbtgtAgeDays) Days Since Rotation" `
            -Description "KRBTGT password last changed $($script:Stats.KrbtgtAgeDays) days ago. Microsoft recommends maximum 180-day rotation cadence." `
            -Impact "Any Golden Ticket forged with the current KRBTGT hash remains valid until rotation. If the environment was compromised within this window, attackers may still hold active undetectable persistence via forged tickets." `
            -Remediation "Rotate KRBTGT password twice (10h+ between rotations for replication). Use Microsoft's New-KrbtgtKeys.ps1. Schedule every 180 days. Each rotation invalidates all existing Kerberos tickets." `
            -Details "Last changed: $($KrbtgtAccount.PasswordLastSet)  |  Age: $($script:Stats.KrbtgtAgeDays) days  |  Max recommended: 180 days"
    }

    if ($KrbtgtAccount.ServicePrincipalNames.Count -gt 2) {
        $spnList = ($KrbtgtAccount.ServicePrincipalNames -join ", ")
        Add-Finding -Category "Kerberos Security" -Severity "Critical" -Priority "P1" -Effort "1 hour" -MitreKey "GoldenTicket" `
            -Title "KRBTGT Account Has Unexpected SPNs — Kerberoastable!" `
            -Description "KRBTGT has $($KrbtgtAccount.ServicePrincipalNames.Count) SPNs registered. This makes the most sensitive account in the domain a Kerberoast target." `
            -Impact "A cracked KRBTGT hash enables unlimited Golden Ticket generation — permanent, undetectable domain persistence that survives password resets and group removals. The ultimate Active Directory backdoor." `
            -Remediation "Remove all non-default SPNs from KRBTGT immediately. Rotate KRBTGT password twice after cleanup." `
            -Details "SPNs: $spnList" `
            -PSFix "Set-ADUser krbtgt -ServicePrincipalNames @{Remove='<SPN_TO_REMOVE>'}"
    }

    # Protocol Transition (T2A4D)
    $ProtocolTransition = $AllUsers | Where-Object { $_.TrustedToAuthForDelegation -and $_.Enabled }
    if (@($ProtocolTransition).Count -gt 0) {
        $ptNames = (($ProtocolTransition | ForEach-Object { $_.SamAccountName }) -join ", ")
        Add-Finding -Category "Kerberos Security" -Severity "High" -Priority "P2" -Effort "1-2 days" -MitreKey "Kerberoast" `
            -Title "S4U2Self Protocol Transition Enabled ($(@($ProtocolTransition).Count) accounts)" `
            -Description "$(@($ProtocolTransition).Count) accounts have TrustedToAuthForDelegation (T2A4D/S4U2Self), enabling user impersonation without credentials." `
            -Impact "These accounts can obtain a service ticket on behalf of any user to any constrained service — including privileged users — without knowing their credentials. Powerful escalation vector." `
            -Remediation "Review all T2A4D accounts. Replace with Resource-Based Constrained Delegation (RBCD) where technically required. Remove the flag where not needed." `
            -Details "Accounts: $ptNames"
    }

    # RC4 / weak encryption detection
    $RC4Accounts = $AllUsers | Where-Object {
        $_.Enabled -and
        ([int]($_.SupportedEncryptionTypes -as [int]) -band 4) -and    # RC4_HMAC supported
        -not ([int]($_.SupportedEncryptionTypes -as [int]) -band 24)   # AES not set
    }
    if (@($RC4Accounts).Count -gt 0) {
        $rcNames = (($RC4Accounts | Select-Object -First 10 | ForEach-Object { $_.SamAccountName }) -join ", ")
        Add-Finding -Category "Kerberos Security" -Severity "Medium" -Priority "P3" -Effort "2-4 hours" -MitreKey "WeakEncryption" `
            -Title "Accounts Supporting Only RC4 Kerberos Encryption ($(@($RC4Accounts).Count))" `
            -Description "$(@($RC4Accounts).Count) accounts use RC4 without AES. RC4 tickets are faster to crack and required for Overpass-the-Hash attacks." `
            -Impact "RC4-only tickets are cracked significantly faster than AES. Many detection solutions alert on Kerberoast requests that specifically downgrade to RC4 (Event 4769 etype=23)." `
            -Remediation "Enable AES 128/256 Kerberos encryption on all accounts. Configure 'Network security: Configure encryption types allowed for Kerberos' GPO setting." `
            -Details "Sample RC4-only accounts: $rcNames"
    }

    # Domain functional level
    $DomainMode = $DomainObj.DomainMode.ToString()
    if ($DomainMode -match "2003|2008") {
        Add-Finding -Category "Kerberos Security" -Severity "Medium" -Priority "P3" -Effort "2-4 weeks" `
            -Title "Legacy Domain Functional Level: $DomainMode" `
            -Description "Domain functional level '$DomainMode' prevents use of modern Kerberos security features." `
            -Impact "Cannot use: Protected Users security group, Authentication Policy Silos, Kerberos armoring (FAST), or credential roaming protections. These are critical defenses against Pass-the-Hash and Golden Ticket attacks." `
            -Remediation "Plan DFL upgrade to Windows Server 2016+. Test in a lab environment first. Requires all DCs to run Server 2016+." `
            -Details "Current DFL: $DomainMode  |  Target: Windows2016Domain or higher"
    }

    Write-Log "Kerberos checks complete." "SUCCESS"
}

# ── 8.6 GPO ANALYSIS ──────────────────────────────────────────────────────
if (-not $SkipGPO) {
    Step-Progress "GPO Analysis" "Auditing Group Policy configuration..."
    Write-Log "Analyzing Group Policy configuration..." "SECTION"
    try {
        $AllGPOs = Get-GPO -All -Domain $Domain -ErrorAction Stop

        $UnlinkedGPOs = [System.Collections.Generic.List[string]]::new()
        foreach ($gpo in $AllGPOs) {
            try {
                $xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain -ErrorAction SilentlyContinue
                if ($xml -and $xml -notmatch "<LinksTo>") { $UnlinkedGPOs.Add($gpo.DisplayName) }
            } catch {}
        }
        if ($UnlinkedGPOs.Count -gt 5) {
            Add-Finding -Category "GPO Configuration" -Severity "Low" -Priority "P4" -Effort "1-2 days" `
                -Title "Excessive Unlinked Group Policy Objects ($($UnlinkedGPOs.Count))" `
                -Description "$($UnlinkedGPOs.Count) GPOs are not linked to any OU, site, or domain object." `
                -Impact "Unlinked GPOs may contain sensitive configuration (credentials in scripts, server paths, network details) accessible to all users via SYSVOL read access. Also creates configuration drift confusion." `
                -Remediation "Review all unlinked GPOs. Archive or delete those with no business purpose. Implement quarterly GPO lifecycle reviews." `
                -Details "Unlinked count: $($UnlinkedGPOs.Count)  |  Sample: $(($UnlinkedGPOs | Select-Object -First 5) -join ', ')"
        }

        Add-Finding -Category "GPO Configuration" -Severity "Informational" -Priority "P4" -Effort "1-2 weeks" `
            -Title "GPO Baseline Alignment Review Required ($GPOCount GPOs)" `
            -Description "$GPOCount Group Policy Objects. CIS Benchmark and Microsoft SCT alignment has not been verified." `
            -Impact "Missing security baselines (LSA Protection, Credential Guard, WDigest disabled, NTLM restrictions) leave credential protection ungoverned and inconsistently applied." `
            -Remediation "Run Microsoft Security Compliance Toolkit quarterly. Compare via Policy Analyzer. Apply CIS Level 1 baselines in audit mode, then enforce. Implement Credential Guard and WDAC." `
            -Details "Total GPOs: $GPOCount  |  Tools: Microsoft SCT, CIS CAT Pro, Policy Analyzer"
    } catch {
        Write-Log "GPO analysis error: $_" "WARN"
    }
    Write-Log "GPO checks complete." "SUCCESS"
}

# ── 8.7 ACL / DELEGATION ──────────────────────────────────────────────────
if (-not $SkipDelegation) {
    Step-Progress "ACL Audit" "Auditing domain root ACLs and DCSync rights..."
    Write-Log "Analyzing ACL delegation and DCSync rights..." "SECTION"

    $DCSyncAccounts = [System.Collections.Generic.List[string]]::new()
    try {
        $DomainACL        = Get-ACL -Path "AD:\$DomainDN" -ErrorAction SilentlyContinue
        $ReplicateAllGuid = [guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
        $ReplicateChgGuid = [guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        if ($DomainACL) {
            foreach ($ace in $DomainACL.Access) {
                if ($ace.ObjectType -in @($ReplicateAllGuid,$ReplicateChgGuid) -and
                    $ace.ActiveDirectoryRights -match "ExtendedRight" -and
                    $ace.AccessControlType -eq "Allow") {
                    $id = $ace.IdentityReference.ToString()
                    if ($id -notmatch "Domain Controllers|Enterprise Domain Controllers|Administrators|SYSTEM|Enterprise Read-Only") {
                        $DCSyncAccounts.Add($id)
                    }
                }
            }
        }
    } catch {}

    if ($DCSyncAccounts.Count -gt 0) {
        Add-Finding -Category "ACL Delegation" -Severity "Critical" -Priority "P1" -Effort "2-4 hours" -MitreKey "DCSync" `
            -Title "Unauthorized DCSync Rights on Domain Root ($($DCSyncAccounts.Count) principals)" `
            -Description "$($DCSyncAccounts.Count) non-standard principal(s) hold Replicating Directory Changes All rights on the domain naming context root." `
            -Impact "ABSOLUTE HIGHEST RISK: These accounts can extract every password hash in the domain silently over the network. This includes KRBTGT, all DAs, all service accounts. No footprint left on DCs. Treat as active breach until proven otherwise." `
            -Remediation "Immediately remove unauthorized DCSync ACEs using ADSI Edit. Investigate who added these rights, when, and why — this is a high-fidelity indicator of compromise. Implement monthly ACL monitoring." `
            -Details "Unauthorized principals: $($DCSyncAccounts -join ' | ')" `
            -PSFix "(Get-ACL 'AD:\$DomainDN').Access | Where-Object { `$_.ObjectType -in '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' } | Format-Table IdentityReference,ActiveDirectoryRights"
    }

    # AdminSDHolder ACL abuse
    try {
        $ASDHolder = "CN=AdminSDHolder,CN=System,$DomainDN"
        $ASDHolderACL = Get-ACL -Path "AD:\$ASDHolder" -ErrorAction SilentlyContinue
        $SuspiciousACEs = [System.Collections.Generic.List[string]]::new()
        if ($ASDHolderACL) {
            foreach ($ace in $ASDHolderACL.Access) {
                if ($ace.AccessControlType -eq "Allow" -and
                    $ace.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite" -and
                    $ace.IdentityReference -notmatch "Domain Admins|Enterprise Admins|Administrators|SYSTEM|CREATOR OWNER") {
                    $SuspiciousACEs.Add($ace.IdentityReference.ToString())
                }
            }
        }
        if ($SuspiciousACEs.Count -gt 0) {
            Add-Finding -Category "ACL Delegation" -Severity "Critical" -Priority "P1" -Effort "2-4 hours" -MitreKey "AdminSDHolder" `
                -Title "Unauthorized Write Access on AdminSDHolder Object" `
                -Description "$($SuspiciousACEs.Count) non-privileged principal(s) have Write/Owner rights on AdminSDHolder — a persistent, hard-to-detect domain backdoor." `
                -Impact "SDProp runs every 60 minutes and propagates AdminSDHolder ACLs to ALL protected accounts. Write access here is equivalent to persistent, automatic re-gaining of rights over every privileged account in the domain — surviving all remediation attempts." `
                -Remediation "Immediately remove unauthorized ACEs from AdminSDHolder via ADSI Edit. Trigger SDProp to propagate changes. Audit who made this change and when via AD audit logs." `
                -Details "Suspicious principals: $($SuspiciousACEs -join ' | ')"
        }
    } catch {}

    Write-Log "ACL delegation checks complete." "SUCCESS"
}

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 8.8 — ATTACK SURFACE ENUMERATION, GRAPH MODEL & ATTACK PATHS
# ════════════════════════════════════════════════════════════════════════════
Step-Progress "Attack Surface & Path Analysis" "Enumerating advanced attack paths and building relationship graph..."
Write-Log "Launching advanced attack surface enumeration and attack path analysis..." "SECTION"

$script:GraphNodes = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:GraphEdges = [System.Collections.Generic.List[object]]::new()
$script:AttackPaths = [System.Collections.Generic.List[object]]::new()
$script:ExposureInventory = [ordered]@{
    Kerberoastable          = @()
    ASREPRoastable          = @()
    UnconstrainedDelegation = @()
    ConstrainedDelegation   = @()
    ResourceDelegation      = @()
    ShadowAdmins            = @()
    PrivilegedExposure      = @()
    ACLAbusePaths           = @()
}

function Invoke-Safe {
    param(
        [scriptblock]$ScriptBlock,
        [object]$Default = $null,
        [string]$Label = "Operation"
    )
    try { & $ScriptBlock }
    catch {
        Write-Log "$Label failed: $($_.Exception.Message)" "WARN"
        $Default
    }
}

function Get-IdentityNameFromReference {
    param([object]$IdentityReference)
    if ($null -eq $IdentityReference) { return $null }
    $id = $IdentityReference.ToString()
    if ($id -match '\\') { return ($id -split '\\')[-1] }
    return $id
}

function Get-DirectoryNodeId {
    param(
        [string]$Type,
        [string]$Name
    )
    if ([string]::IsNullOrWhiteSpace($Type) -or [string]::IsNullOrWhiteSpace($Name)) { return $null }
    return ("{0}:{1}" -f $Type.ToLowerInvariant(), $Name.ToLowerInvariant())
}

function Add-GraphNode {
    param(
        [string]$Id,
        [string]$Type,
        [string]$Name,
        [hashtable]$Properties = @{}
    )
    if ([string]::IsNullOrWhiteSpace($Id)) { return }
    if (-not $script:GraphNodes.ContainsKey($Id)) {
        $script:GraphNodes[$Id] = [PSCustomObject]@{
            id         = $Id
            type       = $Type
            name       = $Name
            properties = [ordered]@{}
        }
    }
    foreach ($key in $Properties.Keys) {
        $script:GraphNodes[$Id].properties[$key] = $Properties[$key]
    }
}

function Add-GraphEdge {
    param(
        [string]$From,
        [string]$To,
        [string]$Relation,
        [ValidateSet("Critical","High","Medium","Low","Informational")]
        [string]$Risk = "Medium",
        [string]$Mitre = "",
        [string]$Description = "",
        [double]$Weight = 1,
        [hashtable]$Properties = @{}
    )
    if ([string]::IsNullOrWhiteSpace($From) -or [string]::IsNullOrWhiteSpace($To)) { return }
    $script:GraphEdges.Add([PSCustomObject]@{
        source      = $From
        target      = $To
        relation    = $Relation
        risk        = $Risk
        mitre       = $Mitre
        description = $Description
        weight      = $Weight
        properties  = $Properties
    })
}

function Get-PrimaryMemberName {
    param([object]$Member)
    if ($null -eq $Member) { return $null }
    if ($Member.PSObject.Properties['SamAccountName']) { return $Member.SamAccountName }
    if ($Member.PSObject.Properties['Name']) { return $Member.Name }
    return $Member.ToString()
}

function Get-SeverityWeight {
    param([string]$Severity)
    switch ($Severity) {
        "Critical"      { return 4 }
        "High"          { return 3 }
        "Medium"        { return 2 }
        "Low"           { return 1 }
        default         { return 0.5 }
    }
}

function Get-RiskWeight {
    param([string]$Severity)
    return (Get-SeverityWeight -Severity $Severity)
}

function Get-GraphNodeName {
    param([string]$NodeId)
    if ([string]::IsNullOrWhiteSpace($NodeId)) { return $null }
    if ($script:GraphNodes.ContainsKey($NodeId)) { return $script:GraphNodes[$NodeId].name }
    return $NodeId
}

function Get-GraphNodeType {
    param([string]$NodeId)
    if ([string]::IsNullOrWhiteSpace($NodeId)) { return "Unknown" }
    if ($script:GraphNodes.ContainsKey($NodeId)) { return $script:GraphNodes[$NodeId].type }
    if ($NodeId -match '^(?<type>[^:]+):') { return $matches.type }
    return "Unknown"
}

function Get-PathNumericScore {
    param(
        [object[]]$Edges,
        [string]$EndNode
    )
    $score = 0.0
    foreach ($edge in @($Edges)) {
        $score += ((Get-SeverityWeight -Severity $edge.risk) * 10)
        if ($null -ne $edge.weight) { $score += [double]$edge.weight }
        switch -Regex ([string]$edge.relation) {
            'Privileged|Admin|DCSync|ACL|Write|Backdoor' { $score += 8; break }
            'Delegation|Kerberoast|ASREP|Roast|RBCD'     { $score += 6; break }
            'RDP|Access|HasAccess|CanRDP'                { $score += 4; break }
            default                                      { $score += 1; break }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($EndNode) -and $script:GraphNodes.ContainsKey($EndNode)) {
        $endProps = $script:GraphNodes[$EndNode].properties
        if ($endProps.Contains('critical') -and $endProps['critical']) { $score += 20 }
        if ($endProps.Contains('isPrivileged') -and $endProps['isPrivileged']) { $score += 14 }
        if ($endProps.Contains('adminCount') -and [int]$endProps['adminCount'] -eq 1) { $score += 10 }
        if ($script:GraphNodes[$EndNode].type -eq 'Computer') { $score += 4 }
    }

    return [math]::Round($score, 2)
}

function Get-PathRiskFromNodes {
    param([object[]]$Edges)
    $score = 0
    foreach ($edge in @($Edges)) { $score += (Get-SeverityWeight -Severity $edge.risk) }
    if ($score -ge 10) { return "Critical" }
    elseif ($score -ge 7) { return "High" }
    elseif ($score -ge 4) { return "Medium" }
    else { return "Low" }
}

function Add-AttackPath {
    param(
        [string]$StartNode,
        [string]$EndNode,
        [object[]]$PathEdges,
        [string]$Summary,
        [string[]]$Techniques,
        [string]$Remediation,
        [switch]$Partial,
        [string]$PathType = "Full"
    )
    if (-not $PathEdges -or $PathEdges.Count -eq 0) { return }

    $nodeSequence = New-Object System.Collections.Generic.List[string]
    $nodeSequence.Add($StartNode) | Out-Null
    foreach ($edge in @($PathEdges)) { $nodeSequence.Add($edge.target) | Out-Null }

    $pathSignature = ("{0}|{1}" -f $PathType, ($nodeSequence.ToArray() -join '>')).ToLowerInvariant()
    if ($script:AttackPaths | Where-Object { $_.signature -eq $pathSignature }) { return }

    $prettySteps = @()
    foreach ($edge in @($PathEdges)) {
        $prettySteps += [PSCustomObject]@{
            From        = Get-GraphNodeName -NodeId $edge.source
            FromType    = Get-GraphNodeType -NodeId $edge.source
            To          = Get-GraphNodeName -NodeId $edge.target
            ToType      = Get-GraphNodeType -NodeId $edge.target
            Relation    = $edge.relation
            Risk        = $edge.risk
            Mitre       = $edge.mitre
            Description = $edge.description
        }
    }

    $startName = Get-GraphNodeName -NodeId $StartNode
    $endName   = Get-GraphNodeName -NodeId $EndNode
    $numericRisk = Get-PathNumericScore -Edges $PathEdges -EndNode $EndNode
    $risk = Get-PathRiskFromNodes -Edges $PathEdges
    if ($Partial.IsPresent -and $risk -eq 'Low') { $risk = 'Medium' }

    $script:AttackPaths.Add([PSCustomObject]@{
        signature         = $pathSignature
        pathId            = [guid]::NewGuid().ToString()
        startNode         = $StartNode
        endNode           = $EndNode
        startNodeName     = $startName
        endNodeName       = $endName
        nodeSequence      = $nodeSequence.ToArray()
        steps             = $prettySteps
        techniqueMappings = ($Techniques | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        summary           = $Summary
        risk              = $risk
        riskScore         = $numericRisk
        remediation       = $Remediation
        hopCount          = $PathEdges.Count
        isPartial         = [bool]$Partial
        pathType          = $PathType
    })
}

function Find-AttackPaths {
    param(
        [string[]]$StartNodes,
        [string[]]$TargetNodes,
        [int]$MaxDepth = 5
    )

    $adjacency = @{}
    foreach ($edge in @($script:GraphEdges)) {
        if (-not $adjacency.ContainsKey($edge.source)) {
            $adjacency[$edge.source] = New-Object System.Collections.Generic.List[object]
        }
        $adjacency[$edge.source].Add($edge) | Out-Null
    }

    foreach ($start in ($StartNodes | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not $adjacency.ContainsKey($start)) { continue }

        $queue = New-Object System.Collections.Queue
        $queue.Enqueue([PSCustomObject]@{
            Node    = $start
            Path    = @()
            Visited = @($start)
        })

        $fullPathAdded = $false
        $bestPartial = $null

        while ($queue.Count -gt 0) {
            $state = $queue.Dequeue()
            if ($state.Path.Count -ge $MaxDepth) { continue }

            foreach ($edge in @($adjacency[$state.Node])) {
                if ($state.Visited -contains $edge.target) { continue }

                $newPath  = @($state.Path + $edge)
                $endNode  = $edge.target
                $pathRisk = Get-PathNumericScore -Edges $newPath -EndNode $endNode
                $targetHit = ($TargetNodes -contains $endNode)

                $targetProps = if ($script:GraphNodes.ContainsKey($endNode)) { $script:GraphNodes[$endNode].properties } else { @{} }
                $isInterestingPartial = (
                    $newPath.Count -ge 1 -and (
                        [string]$edge.relation -match 'Privileged|Admin|DCSync|ACL|Write|Delegation|Kerberoast|ASREP|RBCD|RDP|Access' -or
                        ($targetProps.Contains('critical') -and $targetProps['critical']) -or
                        ($targetProps.Contains('isPrivileged') -and $targetProps['isPrivileged']) -or
                        ($targetProps.Contains('adminCount') -and [int]$targetProps['adminCount'] -eq 1)
                    )
                )

                if ($targetHit) {
                    $summary = "Potential escalation from $((Get-GraphNodeName -NodeId $start)) to $((Get-GraphNodeName -NodeId $endNode)) through $($newPath.Count) relationship hop(s)."
                    $remediation = (($newPath | ForEach-Object { $_.description } | Where-Object { $_ } | Select-Object -Unique) -join " | ")
                    if ([string]::IsNullOrWhiteSpace($remediation)) {
                        $remediation = "Break one or more relationships in this chain, starting with the highest-risk edge and the final privileged control step."
                    }
                    $techs = @($newPath | ForEach-Object { $_.mitre } | Where-Object { $_ })
                    Add-AttackPath -StartNode $start -EndNode $endNode -PathEdges $newPath -Summary $summary -Techniques $techs -Remediation $remediation -PathType "Full"
                    $fullPathAdded = $true
                }

                if ($isInterestingPartial -and (
                    $null -eq $bestPartial -or
                    $pathRisk -gt $bestPartial.Score -or
                    ($pathRisk -eq $bestPartial.Score -and $newPath.Count -lt $bestPartial.Path.Count)
                )) {
                    $bestPartial = [PSCustomObject]@{
                        EndNode = $endNode
                        Path    = $newPath
                        Score   = $pathRisk
                    }
                }

                if ($newPath.Count -lt $MaxDepth) {
                    $queue.Enqueue([PSCustomObject]@{
                        Node    = $endNode
                        Path    = $newPath
                        Visited = @($state.Visited + $endNode)
                    })
                }
            }
        }

        if (-not $fullPathAdded -and $null -ne $bestPartial) {
            $partialSummary = "Partial attack path from $((Get-GraphNodeName -NodeId $start)) toward $((Get-GraphNodeName -NodeId $bestPartial.EndNode)) through $($bestPartial.Path.Count) relationship hop(s). No direct Tier-0 destination was discovered, but the chain still exposes meaningful privilege escalation opportunities."
            $partialRemediation = (($bestPartial.Path | ForEach-Object { $_.description } | Where-Object { $_ } | Select-Object -Unique) -join " | ")
            if ([string]::IsNullOrWhiteSpace($partialRemediation)) {
                $partialRemediation = "Contain the exposed principal, remove the mapped delegated/control relationship, and validate whether the destination object should remain reachable."
            }
            $partialTechs = @($bestPartial.Path | ForEach-Object { $_.mitre } | Where-Object { $_ })
            Add-AttackPath -StartNode $start -EndNode $bestPartial.EndNode -PathEdges $bestPartial.Path -Summary $partialSummary -Techniques $partialTechs -Remediation $partialRemediation -Partial -PathType "Partial"
        }
    }
}

function Get-FallbackAttackStartNodes {
    $candidates = New-Object System.Collections.Generic.List[string]

    foreach ($node in @($script:GraphNodes.Values)) {
        $props = $node.properties
        $incidentEdges = @($script:GraphEdges | Where-Object { $_.source -eq $node.id -or $_.target -eq $node.id })
        $highRiskEdges = @($incidentEdges | Where-Object { (Get-RiskWeight $_.risk) -ge 3 })
        $interesting = $false

        if ($props.Contains('hasSpn') -and $props['hasSpn']) { $interesting = $true }
        if ($props.Contains('doesNotRequirePreAuth') -and $props['doesNotRequirePreAuth']) { $interesting = $true }
        if ($props.Contains('trustedForDelegation') -and $props['trustedForDelegation']) { $interesting = $true }
        if ($props.Contains('adminCount') -and [int]$props['adminCount'] -eq 1) { $interesting = $true }
        if ($props.Contains('isPrivileged') -and $props['isPrivileged']) { $interesting = $true }
        if ($highRiskEdges.Count -gt 0) { $interesting = $true }
        if ($node.name -match '(^svc_|service|sql|backup|exchange|sharepoint|mssql|gmsa|msa|krbtgt)') { $interesting = $true }

        if ($interesting) {
            $candidates.Add($node.id) | Out-Null
        }
    }

    return @($candidates | Select-Object -Unique)
}

function Add-CandidateAttackPathsFromEdges {
    param([int]$MaxCandidates = 10)

    $interestingRelations = 'Privileged|Admin|DCSync|ACL|Write|Delegation|Kerberoast|ASREP|RBCD|RDP|Access|Backdoor'
    $candidateEdges = @(
        $script:GraphEdges |
        Where-Object {
            (Get-RiskWeight $_.risk) -ge 2 -or
            ([string]$_.relation -match $interestingRelations)
        } |
        Sort-Object @{ Expression = { Get-PathNumericScore -Edges @($_) -EndNode $_.target }; Descending = $true }, @{ Expression = { Get-RiskWeight $_.risk }; Descending = $true }
    ) | Select-Object -First $MaxCandidates

    foreach ($edge in $candidateEdges) {
        $summary = "Candidate escalation path from $((Get-GraphNodeName -NodeId $edge.source)) to $((Get-GraphNodeName -NodeId $edge.target)) via $($edge.relation). No full Tier-0 chain was derived, but this relationship remains operationally significant for privilege escalation or lateral movement analysis."
        $remediation = if ([string]::IsNullOrWhiteSpace($edge.description)) {
            'Review and reduce the exposed relationship, validate whether it is required, and apply compensating controls if it must remain.'
        } else {
            $edge.description
        }
        Add-AttackPath -StartNode $edge.source -EndNode $edge.target -PathEdges @($edge) -Summary $summary -Techniques @($edge.mitre) -Remediation $remediation -Partial -PathType 'Candidate'
    }
}

# Core graph: users, groups, computers
foreach ($u in $AllUsers) {
    $uid = Get-DirectoryNodeId -Type 'user' -Name $u.SamAccountName
    Add-GraphNode -Id $uid -Type 'User' -Name $u.SamAccountName -Properties @{
        enabled               = [bool]$u.Enabled
        distinguishedName     = $u.DistinguishedName
        adminCount            = [int]($u.AdminCount | ForEach-Object { $_ } | Select-Object -First 1)
        passwordNeverExpires  = [bool]$u.PasswordNeverExpires
        doesNotRequirePreAuth = [bool]$u.DoesNotRequirePreAuth
        hasSpn                = [bool](@($u.ServicePrincipalNames).Count -gt 0)
    }
}
foreach ($g in $AllGroups) {
    $gid = Get-DirectoryNodeId -Type 'group' -Name $g.Name
    Add-GraphNode -Id $gid -Type 'Group' -Name $g.Name -Properties @{
        distinguishedName = $g.DistinguishedName
        adminCount        = [int]($g.AdminCount | ForEach-Object { $_ } | Select-Object -First 1)
        isPrivileged      = [bool]($g.Name -in $PrivGroupNames)
    }
}
foreach ($c in $AllComputers) {
    $cid = Get-DirectoryNodeId -Type 'computer' -Name $c.Name
    Add-GraphNode -Id $cid -Type 'Computer' -Name $c.Name -Properties @{
        distinguishedName        = $c.DistinguishedName
        operatingSystem          = $c.OperatingSystem
        trustedForDelegation     = [bool]$c.TrustedForDelegation
        allowedToDelegateToCount = @($c.'msDS-AllowedToDelegateTo').Count
    }
}

foreach ($g in $AllGroups) {
    $gid = Get-DirectoryNodeId -Type 'group' -Name $g.Name
    $members = Invoke-Safe -Label "Get-ADGroupMember $($g.Name)" -Default @() -ScriptBlock {
        @(Get-ADGroupMember -Identity $g.DistinguishedName -Recursive:$false -Server $Domain -ErrorAction Stop)
    }
    foreach ($member in $members) {
        $mName = Get-PrimaryMemberName -Member $member
        if ([string]::IsNullOrWhiteSpace($mName)) { continue }
        $mType = switch ($member.objectClass) { 'user' {'user'} 'computer' {'computer'} default {'group'} }
        $mid = Get-DirectoryNodeId -Type $mType -Name $mName
        Add-GraphEdge -From $mid -To $gid -Relation "MemberOf" -Risk "Low" -Description "Membership in $($g.Name)." -Weight 0.5
        if ($g.Name -in $PrivGroupNames) {
            $script:ExposureInventory.PrivilegedExposure += [PSCustomObject]@{
                Principal = $mName
                PrincipalType = $member.objectClass
                Group = $g.Name
            }
            Add-GraphEdge -From $mid -To $gid -Relation "PrivilegedMemberOf" -Risk "High" -Mitre $MitreLib.ValidAccounts.ID -Description "Direct or nested privileged group membership exposes privileged control." -Weight 3
        }
    }
}

# Kerberoast / AS-REP nodes
$KerberoastableAdvanced = @($AllUsers | Where-Object { $_.Enabled -and @($_.ServicePrincipalNames).Count -gt 0 -and $_.SamAccountName -ne 'krbtgt' })
$ASREPRoastableAdvanced = @($AllUsers | Where-Object { $_.Enabled -and $_.DoesNotRequirePreAuth })

$CriticalTargetNodes = New-Object System.Collections.Generic.List[string]
foreach ($name in @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')) {
    $gid = Get-DirectoryNodeId -Type 'group' -Name $name
    if ($script:GraphNodes.ContainsKey($gid)) { $CriticalTargetNodes.Add($gid) | Out-Null }
}
$krbNode = Get-DirectoryNodeId -Type 'user' -Name 'krbtgt'
if ($script:GraphNodes.ContainsKey($krbNode)) { $CriticalTargetNodes.Add($krbNode) | Out-Null }

foreach ($dc in @($DomainControllers)) {
    $dcName = if ($dc.Name) { $dc.Name } elseif ($dc.HostName) { ($dc.HostName -split '\.')[0] } else { $null }
    if (-not [string]::IsNullOrWhiteSpace($dcName)) {
        $dcNode = Get-DirectoryNodeId -Type 'computer' -Name $dcName
        if ($script:GraphNodes.ContainsKey($dcNode)) { $CriticalTargetNodes.Add($dcNode) | Out-Null }
    }
}

foreach ($acct in $KerberoastableAdvanced) {
    $uid = Get-DirectoryNodeId -Type 'user' -Name $acct.SamAccountName
    $pwdAge = if ($acct.PasswordLastSet) { [int]((Get-Date) - $acct.PasswordLastSet).TotalDays } else { $null }
    $script:ExposureInventory.Kerberoastable += [PSCustomObject]@{
        SamAccountName   = $acct.SamAccountName
        SPNs             = @($acct.ServicePrincipalNames)
        PasswordAgeDays  = $pwdAge
        AdminCount       = $acct.AdminCount
    }
    Add-GraphEdge -From $uid -To $uid -Relation "Kerberoastable" -Risk "High" -Mitre $MitreLib.Kerberoast.ID -Description "SPN-bearing service account can be kerberoasted from any authenticated user context." -Weight 3 -Properties @{ attack='Kerberoast'; passwordAgeDays=$pwdAge }
    if ($acct.AdminCount -eq 1) {
        Add-Finding -Category "Privilege Escalation" -Severity "Critical" -Priority "P1" -Effort "4-8 hours" -MitreKey "Kerberoast" `
            -Title "Tier-0 / Protected Kerberoastable Account: $($acct.SamAccountName)" `
            -Description "Protected or historically privileged account $($acct.SamAccountName) exposes SPNs and is directly kerberoastable." `
            -Impact "Offline cracking of a privileged service account can provide immediate privileged access without endpoint interaction." `
            -Remediation "Migrate the account to gMSA or rotate to a 25+ character random credential immediately. Remove unnecessary SPNs and validate delegation requirements." `
            -Details "SPNs: $(@($acct.ServicePrincipalNames) -join ', ') | AdminCount=$($acct.AdminCount)"
    }
}
foreach ($acct in $ASREPRoastableAdvanced) {
    $uid = Get-DirectoryNodeId -Type 'user' -Name $acct.SamAccountName
    $script:ExposureInventory.ASREPRoastable += [PSCustomObject]@{
        SamAccountName = $acct.SamAccountName
        AdminCount     = $acct.AdminCount
        Description    = "Kerberos pre-authentication disabled"
    }
    Add-GraphEdge -From $uid -To $uid -Relation "ASREPRoastable" -Risk "High" -Mitre $MitreLib.ASREPRoast.ID -Description "Pre-auth disabled enables offline AS-REP roasting with zero credentials." -Weight 3
    if ($acct.AdminCount -eq 1) {
        Add-Finding -Category "Privilege Escalation" -Severity "Critical" -Priority "P1" -Effort "2 hours" -MitreKey "ASREPRoast" `
            -Title "Protected Account Is AS-REP Roastable: $($acct.SamAccountName)" `
            -Description "Protected account $($acct.SamAccountName) does not require Kerberos pre-authentication." `
            -Impact "An unauthenticated attacker can obtain material to crack a privileged credential offline." `
            -Remediation "Re-enable pre-authentication immediately and rotate the account password after confirmation of no business dependency."
    }
}

# Delegation analysis
$UnconstrainedComputers = @($AllComputers | Where-Object { $_.TrustedForDelegation -eq $true })
$ConstrainedComputers   = @($AllComputers | Where-Object { @($_.'msDS-AllowedToDelegateTo').Count -gt 0 })
$UnconstrainedUsers     = @($AllUsers | Where-Object { $_.TrustedForDelegation -eq $true -and $_.Enabled })
$ConstrainedUsers       = @($AllUsers | Where-Object { @($_.'msDS-AllowedToDelegateTo').Count -gt 0 -and $_.Enabled })

foreach ($obj in @($UnconstrainedComputers + $UnconstrainedUsers)) {
    $otype = if ($obj.objectClass -eq 'computer') { 'computer' } else { 'user' }
    $nid = Get-DirectoryNodeId -Type $otype -Name $(if ($otype -eq 'user') { $obj.SamAccountName } else { $obj.Name })
    $script:ExposureInventory.UnconstrainedDelegation += [PSCustomObject]@{
        Name = if ($otype -eq 'user') { $obj.SamAccountName } else { $obj.Name }
        Type = $obj.objectClass
        TrustedForDelegation = $true
    }
    Add-GraphEdge -From $nid -To $nid -Relation "UnconstrainedDelegation" -Risk "Critical" -Mitre $MitreLib.UnconstrainedDeleg.ID -Description "System caches forwardable TGTs for incoming users and is a prime target for privilege theft." -Weight 4
}
foreach ($obj in @($ConstrainedComputers + $ConstrainedUsers)) {
    $otype = if ($obj.objectClass -eq 'computer') { 'computer' } else { 'user' }
    $name = if ($otype -eq 'user') { $obj.SamAccountName } else { $obj.Name }
    $nid = Get-DirectoryNodeId -Type $otype -Name $name
    foreach ($svc in @($obj.'msDS-AllowedToDelegateTo')) {
        $script:ExposureInventory.ConstrainedDelegation += [PSCustomObject]@{
            Name = $name
            Type = $obj.objectClass
            Service = $svc
        }
        Add-GraphEdge -From $nid -To $nid -Relation "ConstrainedDelegation" -Risk "Medium" -Mitre $MitreLib.Kerberoast.ID -Description "Object can present delegated Kerberos tickets to $svc." -Weight 2 -Properties @{ service=$svc }
    }
}

# RBCD detection via security descriptor presence
$RBCDObjects = @($AllComputers | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' })
foreach ($comp in $RBCDObjects) {
    $cid = Get-DirectoryNodeId -Type 'computer' -Name $comp.Name
    $script:ExposureInventory.ResourceDelegation += [PSCustomObject]@{
        Name = $comp.Name
        Type = "computer"
        Description = "Resource-based constrained delegation is configured."
    }
    Add-GraphEdge -From $cid -To $cid -Relation "ResourceBasedConstrainedDelegation" -Risk "High" -Mitre $MitreLib.ValidAccounts.ID -Description "RBCD present; principals controlling this computer object may impersonate inbound users to hosted services." -Weight 3
}

if ($script:ExposureInventory.UnconstrainedDelegation.Count -gt 0) {
    Add-Finding -Category "ACL Delegation" -Severity "High" -Priority "P2" -Effort "1-3 days" -MitreKey "UnconstrainedDeleg" `
        -Title "Unconstrained Delegation Exposure ($($script:ExposureInventory.UnconstrainedDelegation.Count) objects)" `
        -Description "$($script:ExposureInventory.UnconstrainedDelegation.Count) user/computer object(s) are trusted for unconstrained delegation." `
        -Impact "Any attacker with code execution on one of these systems can capture forwardable TGTs from privileged users and pivot quickly to Tier-0." `
        -Remediation "Remove unconstrained delegation everywhere except documented legacy exceptions, migrate to RBCD/constrained delegation, and prevent privileged logons to these assets." `
        -Details (($script:ExposureInventory.UnconstrainedDelegation | Select-Object -First 15 | ForEach-Object { $_.Name }) -join ', ')
}

if ($script:ExposureInventory.ConstrainedDelegation.Count -gt 0) {
    Add-Finding -Category "ACL Delegation" -Severity "Medium" -Priority "P3" -Effort "1-2 days" `
        -Title "Constrained Delegation Requires Validation ($($script:ExposureInventory.ConstrainedDelegation.Count) service mappings)" `
        -Description "Constrained delegation is configured for one or more principals and should be reviewed for protocol transition, service sprawl, and tiering alignment." `
        -Impact "Mis-scoped constrained delegation can still enable privilege escalation and service impersonation across trust boundaries." `
        -Remediation "Validate each allowed SPN, remove stale targets, prefer RBCD, and ensure privileged identities cannot authenticate to these systems." `
        -Details (($script:ExposureInventory.ConstrainedDelegation | Select-Object -First 10 | ForEach-Object { "$($_.Name)->$($_.Service)" }) -join ' | ')
}

if ($script:ExposureInventory.ResourceDelegation.Count -gt 0) {
    Add-Finding -Category "ACL Delegation" -Severity "High" -Priority "P2" -Effort "1-2 days" `
        -Title "Resource-Based Constrained Delegation Present ($($script:ExposureInventory.ResourceDelegation.Count) computer objects)" `
        -Description "RBCD is present on one or more computer objects and may permit impersonation if control over the delegating principal is obtained." `
        -Impact "Combined with ms-DS-MachineAccountQuota abuse or computer object takeover, RBCD can create reliable privilege-escalation paths." `
        -Remediation "Review security descriptors on msDS-AllowedToActOnBehalfOfOtherIdentity, set MachineAccountQuota to 0, and tightly scope computer creation rights." `
        -Details (($script:ExposureInventory.ResourceDelegation | Select-Object -First 10 | ForEach-Object { $_.Name }) -join ', ')
}

# Shadow admin / ACL abuse detection on sensitive objects
$SensitiveObjectMap = [ordered]@{
    "DomainRoot"        = "AD:\$DomainDN"
    "AdminSDHolder"     = "AD:\CN=AdminSDHolder,CN=System,$DomainDN"
    "Domain Admins"     = "AD:\CN=Domain Admins,CN=Users,$DomainDN"
    "Enterprise Admins" = "AD:\CN=Enterprise Admins,CN=Users,$DomainDN"
    "Administrators"    = "AD:\CN=Administrators,CN=Builtin,$DomainDN"
}

$HighRiskAclRights = 'GenericAll|GenericWrite|WriteDacl|WriteOwner|ExtendedRight|AllExtendedRights|Self'
$BenignIdentitiesPattern = 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|LOCAL SYSTEM|NT AUTHORITY|Enterprise Domain Controllers|Domain Controllers|CREATOR OWNER|Authenticated Users|Pre-Windows 2000 Compatible Access'

foreach ($objName in $SensitiveObjectMap.Keys) {
    $path = $SensitiveObjectMap[$objName]
    $acl = Invoke-Safe -Label "ACL read $objName" -Default $null -ScriptBlock { Get-Acl -Path $path -ErrorAction Stop }
    if ($null -eq $acl) { continue }
    foreach ($ace in $acl.Access) {
        $identityName = Get-IdentityNameFromReference -IdentityReference $ace.IdentityReference
        if ([string]::IsNullOrWhiteSpace($identityName)) { continue }
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ($ace.ActiveDirectoryRights.ToString() -notmatch $HighRiskAclRights) { continue }
        if ($ace.IdentityReference.ToString() -match $BenignIdentitiesPattern) { continue }

        $principalType = if ($AllUsers.SamAccountName -contains $identityName) { 'user' } elseif ($AllGroups.Name -contains $identityName) { 'group' } else { 'principal' }
        $sourceId = if ($principalType -eq 'user') { Get-DirectoryNodeId -Type 'user' -Name $identityName } elseif ($principalType -eq 'group') { Get-DirectoryNodeId -Type 'group' -Name $identityName } else { Get-DirectoryNodeId -Type 'principal' -Name $identityName }
        $targetType = if ($objName -eq 'DomainRoot' -or $objName -eq 'AdminSDHolder') { 'asset' } else { 'group' }
        $targetId = Get-DirectoryNodeId -Type $targetType -Name $objName
        Add-GraphNode -Id $targetId -Type ($targetType.Substring(0,1).ToUpper()+$targetType.Substring(1)) -Name $objName -Properties @{ critical=$true }
        Add-GraphEdge -From $sourceId -To $targetId -Relation "ACLControl" -Risk "Critical" -Mitre $MitreLib.AccountManipulation.ID -Description "$identityName holds $($ace.ActiveDirectoryRights) over $objName." -Weight 4 -Properties @{ rights=$ace.ActiveDirectoryRights.ToString() }
        $entry = [PSCustomObject]@{
            Principal = $identityName
            Rights    = $ace.ActiveDirectoryRights.ToString()
            Target    = $objName
        }
        $script:ExposureInventory.ShadowAdmins += $entry
        $script:ExposureInventory.ACLAbusePaths += $entry
    }
}

$ShadowAdminDistinct = @($script:ExposureInventory.ShadowAdmins | Group-Object Principal,Target | ForEach-Object { $_.Group[0] })
if ($ShadowAdminDistinct.Count -gt 0) {
    Add-Finding -Category "Privilege Escalation" -Severity "Critical" -Priority "P1" -Effort "4-8 hours" -MitreKey "AccountManipulation" `
        -Title "Shadow Admin / Hidden Control Paths Detected ($($ShadowAdminDistinct.Count) ACEs)" `
        -Description "One or more non-obvious principals have direct control rights over Tier-0 objects such as Domain Admins, AdminSDHolder, or the domain root." `
        -Impact "These principals can often grant themselves membership, replicate secrets, alter ACLs, or create durable backdoors without being in a privileged group." `
        -Remediation "Review and remove all unauthorized high-risk ACEs, reset inheritance where appropriate, and baseline Tier-0 ACLs for change monitoring." `
        -Details (($ShadowAdminDistinct | Select-Object -First 12 | ForEach-Object { "$($_.Principal)[$($_.Rights)]=>$($_.Target)" }) -join ' | ')
}

# Privileged group exposure
foreach ($pg in $PrivGroups) {
    $members = Invoke-Safe -Label "Privileged group member enumeration $($pg.Name)" -Default @() -ScriptBlock {
        @(Get-ADGroupMember -Identity $pg.DistinguishedName -Recursive -Server $Domain -ErrorAction Stop)
    }
    $userMembers = @($members | Where-Object objectClass -eq 'user')
    $enabledAdminUsers = @()
    foreach ($member in $userMembers) {
        $aduser = $AllUsers | Where-Object SamAccountName -eq $member.SamAccountName | Select-Object -First 1
        if ($aduser -and $aduser.Enabled) { $enabledAdminUsers += $aduser }
    }
    if ($enabledAdminUsers.Count -gt 0 -and $pg.Name -eq 'Domain Admins' -and $enabledAdminUsers.Count -gt 5) {
        $sample = ($enabledAdminUsers | Select-Object -First 10 | ForEach-Object SamAccountName) -join ', '
        Add-Finding -Category "Privilege Escalation" -Severity "High" -Priority "P2" -Effort "1-2 weeks" -MitreKey "ValidAccounts" `
            -Title "Privileged Group Exposure Review Required: $($pg.Name)" `
            -Description "$($enabledAdminUsers.Count) enabled user accounts hold effective membership in $($pg.Name)." `
            -Impact "Every exposed Tier-0 membership meaningfully increases attack paths and blast radius." `
            -Remediation "Enforce strict membership control, JIT elevation, separate admin accounts, and Protected Users/PAW usage." `
            -Details "Sample members: $sample"
    }
}

# Attack path seed construction
$StartNodes = New-Object System.Collections.Generic.List[string]
foreach ($entry in $script:ExposureInventory.Kerberoastable) {
    $sid = Get-DirectoryNodeId -Type 'user' -Name $entry.SamAccountName
    if ($script:GraphNodes.ContainsKey($sid)) { $StartNodes.Add($sid) | Out-Null }
}
foreach ($entry in $script:ExposureInventory.ASREPRoastable) {
    $sid = Get-DirectoryNodeId -Type 'user' -Name $entry.SamAccountName
    if ($script:GraphNodes.ContainsKey($sid)) { $StartNodes.Add($sid) | Out-Null }
}
foreach ($entry in $script:ExposureInventory.ShadowAdmins) {
    $ptype = if ($AllUsers.SamAccountName -contains $entry.Principal) { 'user' } elseif ($AllGroups.Name -contains $entry.Principal) { 'group' } else { 'principal' }
    $sid = Get-DirectoryNodeId -Type $ptype -Name $entry.Principal
    if ($script:GraphNodes.ContainsKey($sid)) { $StartNodes.Add($sid) | Out-Null }
}
foreach ($entry in $script:ExposureInventory.UnconstrainedDelegation) {
    $ptype = if ($entry.Type -eq 'user') { 'user' } else { 'computer' }
    $sid = Get-DirectoryNodeId -Type $ptype -Name $entry.Name
    if ($script:GraphNodes.ContainsKey($sid)) { $StartNodes.Add($sid) | Out-Null }
}

# Enrich attack graph with direct paths to critical assets
foreach ($edge in @($script:GraphEdges)) {
    if ($edge.relation -eq 'PrivilegedMemberOf') { continue }
    if ($edge.relation -in @('Kerberoastable','ASREPRoastable') -and $script:GraphNodes[$edge.source].properties.adminCount -eq 1) {
        $da = Get-DirectoryNodeId -Type 'group' -Name 'Domain Admins'
        if ($script:GraphNodes.ContainsKey($da)) {
            Add-GraphEdge -From $edge.source -To $da -Relation 'PotentialPrivilegeEscalation' -Risk 'Critical' -Mitre $edge.mitre -Description 'Compromise of a protected roastable account may provide a short path to Domain Admin equivalent access.' -Weight 4
        }
    }
}
foreach ($entry in $script:ExposureInventory.ShadowAdmins) {
    $ptype = if ($AllUsers.SamAccountName -contains $entry.Principal) { 'user' } elseif ($AllGroups.Name -contains $entry.Principal) { 'group' } else { 'principal' }
    $sid = Get-DirectoryNodeId -Type $ptype -Name $entry.Principal
    switch ($entry.Target) {
        'DomainRoot' {
            if ($script:GraphNodes.ContainsKey($krbNode)) {
                Add-GraphEdge -From $sid -To $krbNode -Relation 'DCSyncPotential' -Risk 'Critical' -Mitre $MitreLib.DCSync.ID -Description 'Control of domain root ACLs may permit replication rights and secret extraction (DCSync).' -Weight 4
            }
        }
        'AdminSDHolder' {
            $da = Get-DirectoryNodeId -Type 'group' -Name 'Domain Admins'
            if ($script:GraphNodes.ContainsKey($da)) {
                Add-GraphEdge -From $sid -To $da -Relation 'AdminSDHolderBackdoor' -Risk 'Critical' -Mitre $MitreLib.AdminSDHolder.ID -Description 'AdminSDHolder control enables durable privilege over protected groups and users.' -Weight 4
            }
        }
        default {
            $tid = Get-DirectoryNodeId -Type 'group' -Name $entry.Target
            if ($script:GraphNodes.ContainsKey($tid)) {
                Add-GraphEdge -From $sid -To $tid -Relation 'WritePrivilegedGroup' -Risk 'Critical' -Mitre $MitreLib.AccountManipulation.ID -Description "ACL control over $($entry.Target) can allow membership manipulation or rights persistence." -Weight 4
            }
        }
    }
}


# Synthetic privilege-to-asset relationships to surface realistic lateral movement and control paths
$TierZeroBridgeGroups = @('Domain Admins','Enterprise Admins','Administrators','Server Operators','Backup Operators','Account Operators')
$RemoteDesktopBridgeGroups = @('Remote Desktop Users','Domain Admins','Administrators')

foreach ($computer in @($AllComputers)) {
    $computerId = Get-DirectoryNodeId -Type 'computer' -Name $computer.Name
    if (-not $script:GraphNodes.ContainsKey($computerId)) { continue }

    $isDomainController = [bool](@($DomainControllers | Where-Object { $_.Name -eq $computer.Name -or $_.HostName -eq $computer.DNSHostName }).Count -gt 0)
    foreach ($groupName in $TierZeroBridgeGroups) {
        $groupId = Get-DirectoryNodeId -Type 'group' -Name $groupName
        if (-not $script:GraphNodes.ContainsKey($groupId)) { continue }

        if ($isDomainController) {
            Add-GraphEdge -From $groupId -To $computerId -Relation 'AdminTo' -Risk 'Critical' -Mitre $MitreLib.ValidAccounts.ID -Description "$groupName commonly confers administrative control over the domain controller $($computer.Name)." -Weight 4
            Add-GraphEdge -From $groupId -To $computerId -Relation 'HasAccessTo' -Risk 'High' -Mitre $MitreLib.ValidAccounts.ID -Description "$groupName can interact with the high-value asset $($computer.Name), creating a practical lateral movement bridge." -Weight 3
        } elseif ($groupName -in @('Domain Admins','Enterprise Admins','Administrators')) {
            Add-GraphEdge -From $groupId -To $computerId -Relation 'AdminTo' -Risk 'High' -Mitre $MitreLib.ValidAccounts.ID -Description "$groupName is expected to hold administrative control over $($computer.Name)." -Weight 3
        }
    }

    foreach ($groupName in $RemoteDesktopBridgeGroups) {
        $groupId = Get-DirectoryNodeId -Type 'group' -Name $groupName
        if (-not $script:GraphNodes.ContainsKey($groupId)) { continue }
        Add-GraphEdge -From $groupId -To $computerId -Relation 'CanRDP' -Risk $(if ($isDomainController) { 'High' } else { 'Medium' }) -Mitre $MitreLib.ValidAccounts.ID -Description "$groupName can potentially obtain interactive access to $($computer.Name) via Remote Desktop or equivalent remote logon rights." -Weight $(if ($isDomainController) { 3 } else { 2 })
    }
}

$PrimaryStartNodes = @($StartNodes.ToArray() | Select-Object -Unique)
Find-AttackPaths -StartNodes $PrimaryStartNodes -TargetNodes ($CriticalTargetNodes.ToArray() | Select-Object -Unique) -MaxDepth 5

if ($script:AttackPaths.Count -eq 0) {
    $FallbackStartNodes = @($PrimaryStartNodes + (Get-FallbackAttackStartNodes)) | Select-Object -Unique
    if ($FallbackStartNodes.Count -gt 0) {
        Find-AttackPaths -StartNodes $FallbackStartNodes -TargetNodes ($CriticalTargetNodes.ToArray() | Select-Object -Unique) -MaxDepth 4
    }
}

if ($script:AttackPaths.Count -eq 0) {
    Add-CandidateAttackPathsFromEdges -MaxCandidates 12
}

# Compute per-entity exposure scoring for graph rendering and summaries
foreach ($node in @($script:GraphNodes.Values)) {
    $props = $node.properties
    $score = 0

    switch ($node.type) {
        'User'     { $score += 6 }
        'Group'    { $score += 8 }
        'Computer' { $score += 10 }
        'Asset'    { $score += 12 }
        default    { $score += 4 }
    }

    if ($props.Contains('critical') -and $props['critical']) { $score += 30 }
    if ($props.Contains('isPrivileged') -and $props['isPrivileged']) { $score += 24 }
    if ($props.Contains('adminCount') -and [int]$props['adminCount'] -eq 1) { $score += 18 }
    if ($props.Contains('hasSpn') -and $props['hasSpn']) { $score += 10 }
    if ($props.Contains('doesNotRequirePreAuth') -and $props['doesNotRequirePreAuth']) { $score += 16 }
    if ($props.Contains('passwordNeverExpires') -and $props['passwordNeverExpires']) { $score += 6 }
    if ($props.Contains('trustedForDelegation') -and $props['trustedForDelegation']) { $score += 20 }
    if ($props.Contains('allowedToDelegateToCount')) { $score += [math]::Min(12, ([int]$props['allowedToDelegateToCount'] * 3)) }

    if ($node.name -match '(^svc_|service|sql|backup|krbtgt|exchange|sharepoint)') { $score += 8 }

    $incidentEdges = @($script:GraphEdges | Where-Object { $_.source -eq $node.id -or $_.target -eq $node.id })
    foreach ($edge in $incidentEdges) {
        $score += [math]::Min(8, ((Get-RiskWeight $edge.risk) * 2))
    }

    $pathHits = @($script:AttackPaths | Where-Object { $_.nodeSequence -contains $node.id }).Count
    $score += [math]::Min(30, ($pathHits * 6))

    $riskScore = [int][math]::Min(100, [math]::Round($score, 0))
    $exposureLevel = if     ($riskScore -ge 80) { 'Critical' }
                     elseif ($riskScore -ge 60) { 'High' }
                     elseif ($riskScore -ge 35) { 'Medium' }
                     else                       { 'Low' }

    $props['entityRiskScore'] = $riskScore
    $props['exposureLevel']   = $exposureLevel
    $props['pathHits']        = $pathHits
}

if ($script:AttackPaths.Count -gt 0) {
    foreach ($path in @($script:AttackPaths)) {
        foreach ($nodeId in @($path.nodeSequence | Select-Object -Unique)) {
            if ($script:GraphNodes.ContainsKey($nodeId)) {
                $nodeProps = $script:GraphNodes[$nodeId].properties
                $existingHits = if ($nodeProps.Contains('pathHits')) { [int]$nodeProps['pathHits'] } else { 0 }
                $nodeProps['pathHits'] = [math]::Max($existingHits, @($script:AttackPaths | Where-Object { $_.nodeSequence -contains $nodeId }).Count)
                $existingRisk = if ($nodeProps.Contains('entityRiskScore')) { [int]$nodeProps['entityRiskScore'] } else { 0 }
                $nodeProps['entityRiskScore'] = [math]::Min(100, $existingRisk + $(if ($path.isPartial) { 4 } else { 8 }))
                $nodeProps['exposureLevel'] = if     ([int]$nodeProps['entityRiskScore'] -ge 80) { 'Critical' }
                                              elseif ([int]$nodeProps['entityRiskScore'] -ge 60) { 'High' }
                                              elseif ([int]$nodeProps['entityRiskScore'] -ge 35) { 'Medium' }
                                              else                                                 { 'Low' }
            }
        }
    }
}

$CriticalAttackPaths = @($script:AttackPaths | Where-Object risk -eq 'Critical')
$HighAttackPaths     = @($script:AttackPaths | Where-Object risk -eq 'High')

if ($script:AttackPaths.Count -gt 0) {
    $samplePath = $script:AttackPaths | Sort-Object @{Expression='hopCount';Ascending=$true}, @{Expression='risk';Descending=$true} | Select-Object -First 1
    $sampleText = ($samplePath.steps | ForEach-Object { "$($_.From) --[$($_.Relation)]--> $($_.To)" }) -join ' | '
    Add-Finding -Category "Attack Paths" -Severity $(if($CriticalAttackPaths.Count -gt 0){"Critical"}else{"High"}) -Priority "P1" -Effort "1-2 weeks" `
        -Title "Independent Attack Path Engine Identified Privilege Escalation Chains ($($script:AttackPaths.Count) paths)" `
        -Description "Graph-driven relationship analysis identified $($script:AttackPaths.Count) realistic path(s) from exposed principals to Tier-0 assets." `
        -Impact "These chains represent actionable attacker movement across the directory rather than isolated misconfigurations. Multiple lower-level weaknesses can combine into direct domain compromise." `
        -Remediation "Prioritize remediation of the shortest critical paths first, especially those ending in Domain Admins, KRBTGT, or AdminSDHolder control. Break edges by removing delegation, cleaning ACLs, reducing privileged membership, and hardening service accounts." `
        -Details "Shortest sample path: $sampleText"
}

Write-Log "Advanced attack surface enumeration complete: $($script:AttackPaths.Count) attack path(s), $($script:GraphNodes.Count) nodes, $($script:GraphEdges.Count) edges." "SUCCESS"


# ════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — RISK SCORING
# ════════════════════════════════════════════════════════════════════════════
Write-Progress -Activity "Consultim-IT AD Assessment v2.5" -Completed
Write-Log "Computing risk score and building report..." "SECTION"

$EndTime     = Get-Date
$Duration    = $EndTime - $StartTime
$DurationStr = "{0:D2}h {1:D2}m {2:D2}s" -f $Duration.Hours, $Duration.Minutes, $Duration.Seconds

$CriticalCount = @($script:Findings | Where-Object { $_.Severity -eq "Critical" }).Count
$HighCount     = @($script:Findings | Where-Object { $_.Severity -eq "High" }).Count
$MediumCount   = @($script:Findings | Where-Object { $_.Severity -eq "Medium" }).Count
$LowCount      = @($script:Findings | Where-Object { $_.Severity -eq "Low" }).Count
$InfoCount     = @($script:Findings | Where-Object { $_.Severity -eq "Informational" }).Count
$TotalFindings = $script:Findings.Count

# Weighted risk algorithm (matching enterprise scoring frameworks)
$RiskScore = [math]::Min(100,
    ($CriticalCount * 20) +
    ($HighCount     *  8) +
    ($MediumCount   *  3) +
    ($LowCount      *  1)
)
$RiskLevel = if     ($RiskScore -ge 80) { "CRITICAL" }
             elseif ($RiskScore -ge 50) { "HIGH" }
             elseif ($RiskScore -ge 25) { "MEDIUM" }
             else                       { "LOW" }

$RiskColor = @{ "CRITICAL"="#c0392b"; "HIGH"="#e74c3c"; "MEDIUM"="#f39c12"; "LOW"="#27ae60" }[$RiskLevel]
$RiskGaugeDash = [math]::Round($RiskScore * 2.39, 1)

# Category breakdown for charts
$CatBreakdown   = $script:Findings | Group-Object Category | Sort-Object Count -Descending
$CatLabelsJS    = ($CatBreakdown | ForEach-Object { "'$($_.Name)'" }) -join ","
$CatCountsJS    = ($CatBreakdown | ForEach-Object { $_.Count }) -join ","

# Findings as JSON for JavaScript tab
$FindingsJSON = $script:Findings | ConvertTo-Json -Depth 4 -Compress

# MITRE techniques found
$MitreTechs = $script:Findings | Where-Object { $_.MitreID -ne "" } |
              Select-Object MitreID, MitreName, MitreTactic, MitreURL -Unique |
              Sort-Object MitreID

# DC list
$DCList = ($DomainControllers | ForEach-Object { $_.HostName }) -join ", "

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — RECOMMENDATIONS ENGINE
# ════════════════════════════════════════════════════════════════════════════
$RecCatalog = @(
@{ Phase="Immediate"; Priority="P1"; Color="#c0392b"; Label="Critical"
   Title="Remove Unauthorized DCSync Rights"
   What="Non-DC accounts with DCSync rights can extract every password hash in the domain silently — the highest-fidelity indicator of domain compromise."
   How="1. Enumerate: (Get-ACL 'AD:\$DomainDN').Access | Where ObjectType -in '1131f6ad...','1131f6aa...'\n2. ADSI Edit > Default Naming Context > Properties > Security > Advanced\n3. Remove unauthorized ACEs\n4. Deploy monthly ACL monitoring (Event 5136 on domain root object)\n5. Treat as active breach — initiate IR process"
   Tools="ADSI Edit, PowerShell, BloodHound, Microsoft Defender for Identity"
   Effort="2-4 hours"
   Triggers=@("Unauthorized DCSync") },

@{ Phase="Immediate"; Priority="P1"; Color="#c0392b"; Label="Critical"
   Title="Disable Print Spooler on All Domain Controllers"
   What="Print Spooler on DCs enables PrintNightmare (CVE-2021-34527), SpoolSample, and DFSCoerce — all enabling SYSTEM access or DC credential coercion with zero domain user interaction required."
   How="1. Emergency stop: Invoke-Command -ComputerName (Get-ADDomainController -Filter *).HostName { Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled }\n2. Verify: Invoke-Command -ComputerName (Get-ADDomainController -Filter *).HostName { Get-Service Spooler | Select Name,Status,StartType }\n3. Enforce via GPO: Computer Config > Windows Settings > System Services > Print Spooler = Disabled\n4. Monitor for re-enablement via audit policy"
   Tools="PowerShell, GPMC, Microsoft Defender for Endpoint"
   Effort="30 minutes"
   Triggers=@("Print Spooler") },

@{ Phase="Immediate"; Priority="P1"; Color="#c0392b"; Label="Critical"
   Title="Remove PASSWD_NOTREQD Flag and Disable Reversible Encryption"
   What="Accounts without password requirements can be logged into with an empty string. Reversibly encrypted accounts expose cleartext credentials. Both are direct, no-effort compromise paths."
   How="1. Clear PASSWD_NOTREQD: Get-ADUser -Filter {PasswordNotRequired -eq `$true} | Set-ADUser -PasswordNotRequired `$false\n2. Set random passwords: ... | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(24,4)) -AsPlainText -Force)\n3. Disable reversible encryption: Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq `$true} | Set-ADUser -AllowReversiblePasswordEncryption `$false\n4. Force password reset for reversible encryption accounts\n5. Audit Fine-Grained PSOs for same settings"
   Tools="PowerShell AD module, ADUC"
   Effort="1-2 hours"
   Triggers=@("PASSWD_NOTREQD","Reversible Password") },

@{ Phase="Immediate"; Priority="P1"; Color="#c0392b"; Label="Critical"
   Title="Disable Unconstrained Kerberos Delegation on Non-DC Systems"
   What="Non-DC systems with unconstrained delegation cache TGTs of all authenticating users. An attacker with SYSTEM can steal Domain Admin TGTs and compromise the entire domain."
   How="1. Identify: Get-ADComputer -Filter {TrustedForDelegation -eq `$true} | Where-Object Name -notin (Get-ADDomainController -Filter *).Name\n2. Coordinate with application teams for impact assessment\n3. Disable: Set-ADComputer <name> -TrustedForDelegation `$false\n4. For apps requiring delegation: configure constrained delegation or RBCD\n5. Add privileged accounts to Protected Users security group"
   Tools="PowerShell AD module, BloodHound, Rubeus (validation)"
   Effort="4-8 hours (includes testing)"
   Triggers=@("Unconstrained Kerberos Delegation") },

@{ Phase="Short-Term"; Priority="P2"; Color="#e74c3c"; Label="High"
   Title="Reduce Domain Admins and Implement JIT Privileged Access"
   What="Excessive DA accounts exponentially increase blast radius. Every DA credential is a full domain takeover path — and most are never actually used for DA-level tasks."
   How="1. Audit: Get-ADGroupMember 'Domain Admins' -Recursive | Export-Csv 'DA-Review.csv'\n2. Remove all accounts without documented daily DA need\n3. Implement JIT: Microsoft PAM (AD 2016+): New-ADAuthenticationPolicySilo...\n4. Create dedicated Tier 0 accounts (admin.t0.firstname@domain) for true admin tasks\n5. Deploy Privileged Access Workstations (PAWs) for Tier 0 admins\n6. Enable alerting: Event 4728 (DA group add) via SIEM"
   Tools="PowerShell, Microsoft PAM, CyberArk, BeyondTrust, PAW deployment guide"
   Effort="1-2 weeks"
   Triggers=@("Excessive Domain Administrator") },

@{ Phase="Short-Term"; Priority="P2"; Color="#e74c3c"; Label="High"
   Title="Remediate Kerberoastable and AS-REP Roastable Accounts"
   What="These accounts are offline-crackable targets. Kerberoasting requires only domain user rights; AS-REP roasting requires zero authentication. Both are top-5 initial access and lateral movement techniques."
   How="1. Kerberoastable: Identify weak-password SPN accounts: Get-ADUser -Filter {ServicePrincipalNames -like '*'} -Properties PasswordLastSet\n2. Migrate to gMSA (ideal — eliminates the attack surface entirely)\n3. For remaining SPN accounts: rotate to 25+ char random password\n4. AS-REP: Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true} | Set-ADUser -DoesNotRequirePreAuth `$false\n5. Monitor Event 4769 (TGS-REQ) spikes for ongoing Kerberoasting"
   Tools="PowerShell AD module, gMSA, Hashcat (testing), Microsoft Defender for Identity"
   Effort="1-3 days"
   Triggers=@("Kerberoastable","AS-REP Roastable") },

@{ Phase="Short-Term"; Priority="P2"; Color="#e74c3c"; Label="High"
   Title="Rotate KRBTGT Password and Remediate Kerberos Configuration"
   What="A stale KRBTGT means any Golden Ticket forged during the inactive period remains valid. Rotation invalidates all existing tickets and eliminates this persistence vector."
   How="1. Download New-KrbtgtKeys.ps1 from Microsoft GitHub (AskPFEPlatt/New-KrbtgtKeys.ps1)\n2. Run in WhatIf mode: .\New-KrbtgtKeys.ps1 -Mode WhatIf -TargetDomainController <PDC>\n3. Rotation 1: .\New-KrbtgtKeys.ps1 -Mode Reset\n4. Wait minimum 10-12 hours for full AD replication convergence\n5. Rotation 2: .\New-KrbtgtKeys.ps1 -Mode Reset\n6. Calendar task: repeat every 180 days\n7. Remove any unexpected SPNs from KRBTGT before rotation"
   Tools="New-KrbtgtKeys.ps1 (Microsoft GitHub), Event Viewer (4769 monitoring)"
   Effort="2-4 hours + 12h replication window"
   Triggers=@("KRBTGT Password") },

@{ Phase="Short-Term"; Priority="P2"; Color="#e74c3c"; Label="High"
   Title="Enforce NTLMv2, Strengthen Password Policy, and Set Machine Account Quota to Zero"
   What="Legacy NTLM enables relay attacks even on patched systems. Weak password policy makes brute-force trivial. Nonzero machine quota enables RBCD attacks by any domain user."
   How="NTLM: GPO > Computer Config > Security Settings > Local Policies > Security Options\n  - LAN Manager level: Send NTLMv2 only; refuse LM & NTLM\n  - Minimum session security: Require NTLMv2 + 128-bit\n\nPassword Policy: Set-ADDefaultDomainPasswordPolicy ... (see findings for exact values)\n\nMachine Quota: Set-ADDomain -Identity '$Domain' -Replace @{'ms-DS-MachineAccountQuota'='0'}"
   Tools="GPMC, PowerShell AD module, Network Monitor (legacy client audit)"
   Effort="1 day (includes legacy client testing)"
   Triggers=@("Weak NTLM","Machine Account Quota","Account Lockout","Password Complexity","Minimum Password") },

@{ Phase="Medium-Term"; Priority="P3"; Color="#e67e22"; Label="Medium"
   Title="Clean Up Stale Accounts and Implement Identity Lifecycle Management"
   What="Stale accounts are invisible attack vectors that bypass access reviews and accumulate credentials from past employees and contractors."
   How="1. Export: Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddDays(-90) -and Enabled -eq `$true} | Export-Csv 'Stale.csv'\n2. Review against HR system for active employees\n3. Disable accounts not matched to active employees\n4. Move to Quarantine OU (retain for 30 days, then delete)\n5. Integrate with ITSM: trigger disable on HR offboarding event\n6. Implement quarterly access reviews via Entra ID Governance or SailPoint"
   Tools="PowerShell, Microsoft Entra ID Governance, SailPoint, Saviynt"
   Effort="1-2 days initial; ongoing process"
   Triggers=@("Stale Enabled Accounts","Never Logged On") },

@{ Phase="Medium-Term"; Priority="P3"; Color="#e67e22"; Label="Medium"
   Title="Remediate AdminCount Orphans and AdminSDHolder ACL"
   What="AdminCount=1 orphans have permanently frozen ACLs creating hidden escalation paths. AdminSDHolder write access is a persistent backdoor that SDProp enforces every 60 minutes."
   How="1. Find orphans: Get-ADUser -Filter {AdminCount -eq 1} (cross-ref against protected groups)\n2. Clear AdminCount: Set-ADUser <user> -Clear AdminCount\n3. Re-enable ACL inheritance via ADSI Edit\n4. Trigger SDProp: Restart-Service NetLogon -Force (or use SDPropForce tool)\n5. Verify AdminSDHolder ACL: (Get-ACL 'AD:\CN=AdminSDHolder,CN=System,$DomainDN').Access\n6. Remove unauthorized ACEs from AdminSDHolder"
   Tools="PowerShell, ADSI Edit, SDProp, BloodHound"
   Effort="4-8 hours"
   Triggers=@("AdminCount=1","AdminSDHolder") },

@{ Phase="Long-Term"; Priority="P4"; Color="#2980b9"; Label="Strategic"
   Title="Implement Active Directory Tiering Model (PAW + Admin Accounts)"
   What="Without tiering, privileged credentials routinely touch untrusted systems through lateral movement, enabling credential theft at scale."
   How="Tier 0: AD/DCs — administered only from dedicated PAWs with MFA\nTier 1: Member servers — Tier 1 admins only, deny logon to DCs\nTier 2: Workstations — helpdesk accounts, no server/DC logon rights\n\nEnforcement:\n- Authentication Policy Silos (Windows Server 2012 R2+)\n- Separate admin accounts per tier (admin.t0.user, admin.t1.user)\n- GPO: Deny log on locally + Deny log on through RD Services for wrong-tier admins\n- Deploy LAPS for local admin password management"
   Tools="GPMC, Authentication Policy Silos, Microsoft PAW Guidance, LAPS"
   Effort="2-4 weeks"
   AlwaysInclude=$false
   Triggers=@("Excessive Domain Administrator","Privileged Accounts Not Marked") },

@{ Phase="Long-Term"; Priority="P4"; Color="#2980b9"; Label="Strategic"
   Title="Deploy Continuous AD Security Monitoring and SIEM Integration"
   What="Point-in-time assessments miss attacks occurring between scans. Continuous monitoring detects Golden Tickets, DCSync, privilege escalation, and lateral movement in near real-time."
   How="Key Event IDs to monitor:\n- 4662 + ObjectType 1131f6a*: DCSync activity\n- 4769 etype=23 spike: Kerberoasting\n- 4624 + DA group on non-DC: Credential abuse\n- 4728/4756: Privileged group changes\n- AdminCount attribute change: Hidden privilege escalation\n- 4776 + NTLMv1: Legacy authentication\n\nTools: Forward via WEF to Microsoft Sentinel or Splunk\nDeploy MDI for behavioral AD analytics"
   Tools="Microsoft Defender for Identity (MDI), Azure Sentinel, Splunk, Netwrix Auditor, Semperis DSP"
   Effort="2-4 weeks"
   AlwaysInclude=$true
   Triggers=@() }
)

$ActiveTitles = $script:Findings | ForEach-Object { $_.Title }
$Recommendations = @()
foreach ($rec in $RecCatalog) {
    $always = $rec.ContainsKey('AlwaysInclude') -and $rec['AlwaysInclude'] -eq $true
    $matched = $false
    foreach ($trig in $rec.Triggers) {
        foreach ($at in $ActiveTitles) {
            if ($at -like "*$trig*" -or $trig -like "*$at*") { $matched = $true; break }
        }
        if ($matched) { break }
    }
    if ($matched -or $always) { $Recommendations += $rec }
}

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 11 — OPTIONAL EXPORTS
# ════════════════════════════════════════════════════════════════════════════

# ── Sentinel JSON ──────────────────────────────────────────────────────────
if ($ExportSentinel) {
    $SentinelFile = Join-Path $OutputPath "ConsultimIT-Sentinel_$Timestamp.json"
    @{
        SchemaVersion  = "2.1"
        AssessmentId   = [guid]::NewGuid().ToString()
        Domain         = $Domain
        AssessmentDate = $StartTime.ToString("o")
        Tool           = "Consultim-IT AD Assessment Tool v2.1"
        AssessedBy     = "Ranim Hassine - Consultim-IT"
        RiskScore      = $RiskScore
        RiskLevel      = $RiskLevel
        ScanMode       = $ScanMode
        TotalFindings  = $TotalFindings
        Summary        = @{ Critical=$CriticalCount; High=$HighCount; Medium=$MediumCount; Low=$LowCount; Informational=$InfoCount }
        Findings       = @($script:Findings | ForEach-Object {
            @{
                Title       = $_.Title
                Category    = $_.Category
                Severity    = $_.Severity
                Priority    = $_.Priority
                Description = $_.Description
                Impact      = $_.Impact
                Remediation = $_.Remediation
                Details     = $_.Details
                MitreATTACK = @{ ID=$_.MitreID; Name=$_.MitreName; Tactic=$_.MitreTactic; URL=$_.MitreURL }
                Effort      = $_.Effort
                Timestamp   = $_.Timestamp
            }
        })
    } | ConvertTo-Json -Depth 10 | Out-File -FilePath $SentinelFile -Encoding UTF8
    Write-Log "Sentinel JSON exported: $SentinelFile" "SUCCESS"
}

# ── Excel Workbook ─────────────────────────────────────────────────────────
if ($ExportExcel) {
    $ExcelFile = Join-Path $OutputPath "ConsultimIT-AD-Report_$Timestamp.xlsx"
    try {
        # Executive Summary
        @(
            [PSCustomObject]@{ Metric="Domain";         Value=$Domain }
            [PSCustomObject]@{ Metric="Forest";         Value=$ForestObj.RootDomain }
            [PSCustomObject]@{ Metric="Assessment Date";Value=$StartTime.ToString("yyyy-MM-dd HH:mm") }
            [PSCustomObject]@{ Metric="Risk Score";     Value="$RiskScore / 100" }
            [PSCustomObject]@{ Metric="Risk Level";     Value=$RiskLevel }
            [PSCustomObject]@{ Metric="Total Findings"; Value=$TotalFindings }
            [PSCustomObject]@{ Metric="Critical";       Value=$CriticalCount }
            [PSCustomObject]@{ Metric="High";           Value=$HighCount }
            [PSCustomObject]@{ Metric="Medium";         Value=$MediumCount }
            [PSCustomObject]@{ Metric="Low";            Value=$LowCount }
            [PSCustomObject]@{ Metric="Total Users";    Value=$script:Stats.TotalUsers }
            [PSCustomObject]@{ Metric="Domain Admins";  Value=$script:Stats.DomainAdmins }
            [PSCustomObject]@{ Metric="Stale (90d)";    Value=$script:Stats.StaleUsers90 }
            [PSCustomObject]@{ Metric="KRBTGT Age";     Value="$($script:Stats.KrbtgtAgeDays) days" }
            [PSCustomObject]@{ Metric="Scan Duration";  Value=$DurationStr }
        ) | Export-Excel -Path $ExcelFile -WorksheetName "Executive Summary" -AutoSize -TableName "Summary" -TableStyle Medium9

        # All Findings
        $script:Findings | Select-Object Severity,Priority,Category,Title,Description,Impact,Remediation,MitreID,MitreName,MitreTactic,Effort,Details |
            Export-Excel -Path $ExcelFile -WorksheetName "All Findings" -AutoSize -TableName "Findings" -TableStyle Medium6

        # Critical & High Only
        $critHigh = $script:Findings | Where-Object { $_.Severity -in "Critical","High" }
        if ($critHigh) {
            $critHigh | Select-Object Severity,Priority,Category,Title,Impact,Remediation,PSFix,Effort |
                Export-Excel -Path $ExcelFile -WorksheetName "Critical-High" -AutoSize -TableName "CritHigh" -TableStyle Medium2
        }

        # Stale Users
        if ($StaleUsers90) {
            $StaleUsers90 | Select-Object SamAccountName,DisplayName,EmailAddress,LastLogonDate,PasswordLastSet,Enabled,DistinguishedName |
                Export-Excel -Path $ExcelFile -WorksheetName "Stale Users" -AutoSize -TableName "StaleUsers" -TableStyle Medium9
        }

        # Privileged Accounts
        $privReport = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($pg in $PrivGroups) {
            try {
                (Get-ADGroupMember -Identity $pg.DistinguishedName -Recursive -Server $Domain -ErrorAction SilentlyContinue) |
                    ForEach-Object { $privReport.Add([PSCustomObject]@{ Group=$pg.Name; SamAccountName=$_.SamAccountName; Name=$_.Name; ObjectClass=$_.ObjectClass }) }
            } catch {}
        }
        if ($privReport.Count -gt 0) {
            $privReport | Export-Excel -Path $ExcelFile -WorksheetName "Privileged Accounts" -AutoSize -TableName "PrivAccounts" -TableStyle Medium9
        }

        # MITRE ATT&CK
        if ($MitreTechs) {
            $MitreTechs | Export-Excel -Path $ExcelFile -WorksheetName "MITRE ATT&CK" -AutoSize -TableName "Mitre" -TableStyle Medium6
        }

        Write-Log "Excel workbook exported: $ExcelFile" "SUCCESS"
    } catch { Write-Log "Excel export error: $_" "WARN" }
}

# ── Attack Graph / Neo4j JSON ─────────────────────────────────────────────
$GraphExportFile         = Join-Path $OutputPath "ConsultimIT-AttackGraph_$Timestamp.json"
$AttackSurfaceReportFile = Join-Path $OutputPath "ConsultimIT-AttackSurface_$Timestamp.html"

$GraphExport = [ordered]@{
    schemaVersion   = "2.5"
    assessmentDate  = $StartTime.ToString("o")
    domain          = $Domain
    client          = $ClientCompany
    riskScore       = $RiskScore
    riskLevel       = $RiskLevel
    stats           = $script:Stats
    neo4j           = [ordered]@{
        nodes = @($script:GraphNodes.Values | ForEach-Object {
            [ordered]@{
                id         = $_.id
                labels     = @($_.type)
                name       = $_.name
                properties = $_.properties
            }
        })
        relationships = @($script:GraphEdges | ForEach-Object {
            [ordered]@{
                type       = $_.relation
                startNode  = $_.source
                endNode    = $_.target
                properties = [ordered]@{
                    risk        = $_.risk
                    mitre       = $_.mitre
                    description = $_.description
                    weight      = $_.weight
                }
            }
        })
    }
    attackPaths     = @($script:AttackPaths)
    exposureSummary = $script:ExposureInventory
}

# Build lightweight UI data separately so the HTML dashboard stays responsive and clickable.
$EntitySummary = @(
    $script:GraphNodes.Values |
    ForEach-Object {
        [ordered]@{
            id        = $_.id
            name      = $_.name
            type      = $_.type
            count     = $(if ($_.properties.Contains('pathHits')) { [int]$_.properties['pathHits'] } else { 0 })
            risk      = $(if ($_.properties.Contains('exposureLevel')) { [string]$_.properties['exposureLevel'] } else { 'Low' })
            riskScore = $(if ($_.properties.Contains('entityRiskScore')) { [int]$_.properties['entityRiskScore'] } else { 0 })
        }
    } |
    Sort-Object @{ Expression = 'riskScore'; Descending = $true }, @{ Expression = 'count'; Descending = $true }, @{ Expression = 'name'; Descending = $false } |
    Select-Object -First 20
)

$RelationshipSummary = @{}
foreach ($edge in @($script:GraphEdges)) {
    $relationType = if ($edge.relation) { [string]$edge.relation } else { 'UNKNOWN' }
    if (-not $RelationshipSummary.ContainsKey($relationType)) {
        $RelationshipSummary[$relationType] = [ordered]@{
            relation = $relationType
            count    = 0
            risk     = 'Low'
        }
    }
    $RelationshipSummary[$relationType].count++
    if ((Get-RiskWeight $edge.risk) -gt (Get-RiskWeight $RelationshipSummary[$relationType].risk)) {
        $RelationshipSummary[$relationType].risk = $(if ($edge.risk) { $edge.risk } else { 'Low' })
    }
}

$ExposureSummaryCompact = [ordered]@{
    Kerberoastable          = @($script:ExposureInventory.Kerberoastable | ForEach-Object { $_.SamAccountName })
    ASREPRoastable          = @($script:ExposureInventory.ASREPRoastable | ForEach-Object { $_.SamAccountName })
    UnconstrainedDelegation = @($script:ExposureInventory.UnconstrainedDelegation | ForEach-Object { if ($_.SamAccountName) { $_.SamAccountName } elseif ($_.Name) { $_.Name } else { $_.DistinguishedName } })
    ConstrainedDelegation   = @($script:ExposureInventory.ConstrainedDelegation | ForEach-Object { if ($_.SamAccountName) { $_.SamAccountName } elseif ($_.Name) { $_.Name } else { $_.DistinguishedName } })
    ResourceDelegation      = @($script:ExposureInventory.ResourceDelegation | ForEach-Object { if ($_.Computer) { $_.Computer } elseif ($_.Name) { $_.Name } else { $_.DistinguishedName } })
    ShadowAdmins            = @($script:ExposureInventory.ShadowAdmins | ForEach-Object { if ($_.Principal) { $_.Principal } elseif ($_.IdentityReference) { $_.IdentityReference } else { $_.ObjectDN } })
    TopRiskEntities         = @($EntitySummary | Select-Object -First 10)
}

$GraphNodesForUi = @($script:GraphNodes.Values | ForEach-Object {
    [ordered]@{
        id            = $_.id
        label         = $_.name
        name          = $_.name
        type          = $_.type
        riskScore     = $(if ($_.properties.Contains('entityRiskScore')) { [int]$_.properties['entityRiskScore'] } else { 0 })
        exposureLevel = $(if ($_.properties.Contains('exposureLevel')) { [string]$_.properties['exposureLevel'] } else { 'Low' })
        pathHits      = $(if ($_.properties.Contains('pathHits')) { [int]$_.properties['pathHits'] } else { 0 })
        properties    = $_.properties
    }
})

$GraphEdgesForUi = @($script:GraphEdges | ForEach-Object {
    [ordered]@{
        id          = ([guid]::NewGuid().ToString())
        from        = $_.source
        to          = $_.target
        relation    = $_.relation
        label       = $_.relation
        risk        = $_.risk
        mitre       = $_.mitre
        description = $_.description
        weight      = $_.weight
        properties  = $_.properties
    }
})

if (@($GraphNodesForUi).Count -eq 0) {
    $GraphNodesForUi = @(
        [ordered]@{
            id            = 'placeholder:start'
            label         = 'Directory Review'
            name          = 'Directory Review'
            type          = 'Assessment'
            riskScore     = 0
            exposureLevel = 'Low'
            pathHits      = 0
            properties    = [ordered]@{ placeholder = $true }
        },
        [ordered]@{
            id            = 'placeholder:end'
            label         = 'No attack paths identified'
            name          = 'No attack paths identified'
            type          = 'Assessment'
            riskScore     = 0
            exposureLevel = 'Low'
            pathHits      = 0
            properties    = [ordered]@{ placeholder = $true }
        }
    )
    $GraphEdgesForUi = @(
        [ordered]@{
            id          = 'placeholder:edge'
            from        = 'placeholder:start'
            to          = 'placeholder:end'
            relation    = 'AssessmentResult'
            label       = 'AssessmentResult'
            risk        = 'Low'
            mitre       = ''
            description = 'Attack path engine did not identify a viable full or partial chain from the available directory relationships.'
            weight      = 1
            properties  = [ordered]@{ placeholder = $true }
        }
    )
}

$AttackSurfaceData = [ordered]@{
    schemaVersion   = "2.5"
    assessmentDate  = $StartTime.ToString("o")
    domain          = $Domain
    client          = $ClientCompany
    riskScore       = $RiskScore
    riskLevel       = $RiskLevel
    graphSummary    = [ordered]@{
        nodeCount = @($GraphNodesForUi).Count
        edgeCount = @($GraphEdgesForUi).Count
    }
    graph           = [ordered]@{
        nodes = $GraphNodesForUi
        edges = $GraphEdgesForUi
    }
    attackPaths     = @($script:AttackPaths | Sort-Object @{ Expression = 'isPartial'; Descending = $false }, @{ Expression = 'riskScore'; Descending = $true }, @{ Expression = 'hopCount'; Descending = $false } | ForEach-Object {
        [ordered]@{
            pathId             = $_.pathId
            startNode          = $_.startNode
            endNode            = $_.endNode
            startNodeName      = $_.startNodeName
            endNodeName        = $_.endNodeName
            nodeSequence       = @($_.nodeSequence)
            summary            = $_.summary
            risk               = $_.risk
            riskScore          = $_.riskScore
            hopCount           = $_.hopCount
            isPartial          = $_.isPartial
            pathType           = $_.pathType
            techniqueMappings  = @($_.techniqueMappings)
            remediation        = $_.remediation
            steps              = @($_.steps | ForEach-Object {
                [ordered]@{
                    From        = $_.From
                    FromType    = $_.FromType
                    To          = $_.To
                    ToType      = $_.ToType
                    Relation    = $_.Relation
                    Risk        = $_.Risk
                    Mitre       = $_.Mitre
                    Description = $_.Description
                }
            })
        }
    })
    entitySummary   = @($EntitySummary)
    edgeSummary     = @($RelationshipSummary.Values | Sort-Object @{ Expression = { Get-RiskWeight $_.risk }; Descending = $true }, @{ Expression = 'count'; Descending = $true })
    exposureSummary = $ExposureSummaryCompact
}

try {
    $GraphExport | ConvertTo-Json -Depth 8 | Out-File -FilePath $GraphExportFile -Encoding UTF8 -Force
    Write-Log "Attack graph JSON exported: $GraphExportFile" "SUCCESS"
} catch {
    Write-Log "Attack graph JSON export warning: $_" "WARN"
    try {
        $FallbackGraphExport = [ordered]@{
            schemaVersion   = $GraphExport.schemaVersion
            assessmentDate  = $GraphExport.assessmentDate
            domain          = $GraphExport.domain
            client          = $GraphExport.client
            riskScore       = $GraphExport.riskScore
            riskLevel       = $GraphExport.riskLevel
            neo4j           = [ordered]@{
                nodes = @($GraphExport.neo4j.nodes | ForEach-Object {
                    [ordered]@{
                        id     = $_.id
                        labels = $_.labels
                        name   = $_.name
                    }
                })
                relationships = @($GraphExport.neo4j.relationships | ForEach-Object {
                    [ordered]@{
                        type      = $_.type
                        startNode = $_.startNode
                        endNode   = $_.endNode
                        properties = [ordered]@{
                            risk  = $_.properties.risk
                            mitre = $_.properties.mitre
                            weight= $_.properties.weight
                        }
                    }
                })
            }
            attackPaths     = $AttackSurfaceData.attackPaths
            exposureSummary = $AttackSurfaceData.exposureSummary
        }
        $FallbackGraphExport | ConvertTo-Json -Depth 6 | Out-File -FilePath $GraphExportFile -Encoding UTF8 -Force
        Write-Log "Attack graph JSON exported in compact mode: $GraphExportFile" "SUCCESS"
    } catch {
        Write-Log "Attack graph JSON export failed: $_" "WARN"
    }
}

$AttackSurfaceJSON = $AttackSurfaceData | ConvertTo-Json -Depth 10 -Compress
$AttackSurfaceHTML = @"
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Consultim-IT | Attack Surface Interface | $ClientCompany | $Domain</title>
<style>
*,*::before,*::after{box-sizing:border-box} body{margin:0;font-family:'Segoe UI',system-ui,sans-serif;background:#07101f;color:#dbe8ff}
a{color:#74b3ff;text-decoration:none} a:hover{text-decoration:underline}
.header{padding:22px 28px;border-bottom:1px solid #163055;background:linear-gradient(135deg,#06101e,#0c1f3e)}
.header h1{margin:0 0 6px;font-size:1.9rem}.header p{margin:0;color:#94acd6}
.header-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
.header-btn{display:inline-block;background:#1a67d1;color:#fff;padding:10px 14px;border-radius:10px;font-weight:700}
.header-btn.secondary{background:#173256}
.layout{display:grid;grid-template-columns:320px 1fr;min-height:calc(100vh - 112px)}
.sidebar{border-right:1px solid #163055;padding:18px;background:#0a1529}
.main{padding:18px}
.panel{background:#0d1a33;border:1px solid #19345e;border-radius:14px;padding:16px;box-shadow:0 10px 30px rgba(0,0,0,.25);margin-bottom:16px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.kpi{background:#112345;border:1px solid #1a3965;border-radius:12px;padding:14px}
.kpi .v{font-size:1.4rem;font-weight:700;margin-top:6px}
.filters label{display:block;font-size:.88rem;margin:.7rem 0 .35rem;color:#8eabd8}
select,input{width:100%;background:#071425;color:#e4efff;border:1px solid #244574;border-radius:10px;padding:10px}
button{background:#1a67d1;color:#fff;border:0;border-radius:10px;padding:10px 12px;font-weight:600;cursor:pointer}
button.secondary{background:#173256}
.path-card{border:1px solid #21406c;border-radius:12px;padding:14px;background:#0b1730;margin-bottom:12px}
.path-card.critical{border-color:#b43a31;box-shadow:0 0 0 1px rgba(180,58,49,.28)}
.path-card.high{border-color:#c56d1f}.path-card.medium{border-color:#275f9c}.path-card.low{border-color:#2a7b4f}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.78rem;margin-right:6px;font-weight:700}
.badge.Critical{background:#b43a31;color:#fff}.badge.High{background:#c56d1f;color:#fff}.badge.Medium{background:#275f9c;color:#fff}.badge.Low{background:#2a7b4f;color:#fff}
.step{padding:10px 12px;border-left:3px solid #2e7de9;background:#0f213f;border-radius:8px;margin-top:8px}
.edge-list{max-height:260px;overflow:auto}
.graph-grid{display:grid;grid-template-columns:1.25fr .9fr;gap:16px}
.table{width:100%;border-collapse:collapse}.table th,.table td{padding:8px 10px;border-bottom:1px solid #183152;text-align:left;font-size:.9rem}
.note{color:#9ab2da;font-size:.9rem}.mono{font-family:Consolas,monospace}
.empty-state{padding:18px;border:1px dashed #305689;border-radius:12px;background:#0a1527;color:#9ab2da}
.exposure-item{padding:8px 0;border-bottom:1px solid #183152}
.exposure-item:last-child{border-bottom:0}
@media (max-width:1100px){.layout{grid-template-columns:1fr}.sidebar{border-right:0;border-bottom:1px solid #163055}.graph-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="header">
  <h1>Attack Surface & Attack Path Interface</h1>
  <p>$ClientCompany · $Domain · Independent graph-driven privilege escalation analysis</p>
  <div class="header-actions">
    <a class="header-btn" href="ConsultimIT-AD-Assessment_$Timestamp.html">Open detailed assessment report</a>
    <a class="header-btn secondary" href="ConsultimIT-AttackGraph_$Timestamp.json">Open graph JSON</a>
  </div>
</div>
<div class="layout">
  <aside class="sidebar">
    <div class="panel">
      <div class="filters">
        <label for="riskFilter">Risk level</label>
        <select id="riskFilter"><option value="All">All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>
        <label for="techFilter">MITRE technique</label>
        <input id="techFilter" placeholder="e.g. T1558.003">
        <label for="nodeFilter">Node / asset search</label>
        <input id="nodeFilter" placeholder="Search user, group, computer...">
        <div style="display:flex;gap:8px;margin-top:12px">
          <button onclick="renderAll()">Apply</button>
          <button class="secondary" onclick="resetFilters()">Reset</button>
        </div>
      </div>
    </div>
    <div class="panel note">
      <strong>How to read this page</strong><br><br>
      Each path represents a consultant-curated sequence of exploitable relationships. Prioritize the shortest Tier-0 compromise routes and the paths with reusable credentials, delegation abuse, or direct control over privileged principals.
    </div>
  </aside>
  <main class="main">
    <div class="panel kpis" id="kpis"></div>
    <div class="graph-grid">
      <div class="panel">
        <h3 style="margin-top:0">Attack Paths</h3>
        <div id="paths"></div>
      </div>
      <div>
        <div class="panel">
          <h3 style="margin-top:0">Relationship Summary</h3>
          <div class="edge-list"><table class="table"><thead><tr><th>Relation</th><th>Count</th><th>Highest risk</th></tr></thead><tbody id="edgeSummary"></tbody></table></div>
        </div>
        <div class="panel">
          <h3 style="margin-top:0">Critical Exposures</h3>
          <div id="exposureSummary" class="note"></div>
        </div>
      </div>
    </div>
  </main>
</div>
<script>
const data = $AttackSurfaceJSON;
function uniq(arr){ return Array.from(new Set((arr || []).filter(Boolean))); }
function esc(value){
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function renderKpis(paths){
  const critical = paths.filter(p => p.risk === 'Critical').length;
  const high = paths.filter(p => p.risk === 'High').length;
  const cards = [
    ['Graph nodes', data.graphSummary && data.graphSummary.nodeCount ? data.graphSummary.nodeCount : 0],
    ['Graph edges', data.graphSummary && data.graphSummary.edgeCount ? data.graphSummary.edgeCount : 0],
    ['Attack paths', paths.length],
    ['Critical paths', critical],
    ['High paths', high],
    ['Directory risk', (data.riskLevel || 'Unknown') + ' (' + (data.riskScore || 0) + '/100)']
  ];
  document.getElementById('kpis').innerHTML = cards.map(function(card){
    return '<div class="kpi"><div>' + esc(card[0]) + '</div><div class="v">' + esc(card[1]) + '</div></div>';
  }).join('');
}
function getFilteredPaths(){
  const risk = document.getElementById('riskFilter').value;
  const tech = document.getElementById('techFilter').value.trim().toLowerCase();
  const node = document.getElementById('nodeFilter').value.trim().toLowerCase();
  const allPaths = Array.isArray(data.attackPaths) ? data.attackPaths : [];
  return allPaths.filter(function(p){
    const riskOk = risk === 'All' || p.risk === risk;
    const techOk = !tech || uniq(p.techniqueMappings || []).join(' ').toLowerCase().includes(tech);
    const nodeOk = !node || JSON.stringify(p).toLowerCase().includes(node);
    return riskOk && techOk && nodeOk;
  }).sort(function(a,b){
    const order = {Critical:0, High:1, Medium:2, Low:3};
    return (order[a.risk] ?? 9) - (order[b.risk] ?? 9) || ((a.hopCount || 99) - (b.hopCount || 99));
  });
}
function renderPaths(paths){
  const container = document.getElementById('paths');
  if(!paths.length){
    container.innerHTML = '<div class="empty-state">No attack paths matched the current filters. If the page remains empty with the default filters, reset Risk level to <strong>All</strong> to include non-critical paths.</div>';
    return;
  }
  container.innerHTML = paths.map(function(p){
    const riskClass = String((p.risk || 'Low')).toLowerCase();
    const techniques = uniq(p.techniqueMappings || []).join(', ') || 'None mapped';
    const steps = (p.steps || []).map(function(s, idx){
      const mitre = s.Mitre ? ' · ' + esc(s.Mitre) : '';
      return '<div class="step">'
        + '<div><strong>Step ' + (idx + 1) + ':</strong> <span class="mono">' + esc(s.From) + '</span> → <span class="mono">' + esc(s.To) + '</span></div>'
        + '<div>' + esc(s.Relation) + ' · ' + esc(s.Risk) + mitre + '</div>'
        + '<div class="note">' + esc(s.Description || '') + '</div>'
        + '</div>';
    }).join('');
    return '<div class="path-card ' + riskClass + '">' 
      + '<div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start"><div>'
      + '<span class="badge ' + esc(p.risk || 'Low') + '">' + esc(p.risk || 'Low') + '</span>'
      + '<span class="badge Medium">Hops: ' + esc(p.hopCount || 0) + '</span>'
      + '<div style="font-weight:700;margin-top:8px">' + esc(p.summary || 'Attack path') + '</div>'
      + '<div class="note" style="margin-top:6px">MITRE: ' + esc(techniques) + '</div>'
      + '</div></div>'
      + steps
      + '<div class="step" style="border-left-color:#c8922a"><strong>Consultant remediation focus</strong><br>' + esc(p.remediation || 'Break the shortest path by removing the exploitable relationship and validating compensating controls.') + '</div>'
      + '</div>';
  }).join('');
}
function renderEdgeSummary(){
  const rows = Array.isArray(data.edgeSummary) ? data.edgeSummary : [];
  document.getElementById('edgeSummary').innerHTML = rows.map(function(rel){
    return '<tr><td>' + esc(rel.relation || rel.type || 'Unknown') + '</td><td>' + esc(rel.count || 0) + '</td><td>' + esc(rel.risk || 'Low') + '</td></tr>';
  }).join('') || '<tr><td colspan="3">No relationship data available.</td></tr>';
}
function renderExposureSummary(){
  const ex = data.exposureSummary || {};
  const items = [
    ['Kerberoastable accounts', (ex.Kerberoastable || []).length],
    ['AS-REP roastable accounts', (ex.ASREPRoastable || []).length],
    ['Unconstrained delegation objects', (ex.UnconstrainedDelegation || []).length],
    ['Constrained delegation mappings', (ex.ConstrainedDelegation || []).length],
    ['RBCD objects', (ex.ResourceDelegation || []).length],
    ['Shadow admin / ACL control entries', (ex.ShadowAdmins || []).length]
  ];
  document.getElementById('exposureSummary').innerHTML = items.map(function(item){
    return '<div class="exposure-item">' + esc(item[0]) + ': <strong>' + esc(item[1]) + '</strong></div>';
  }).join('');
}
function renderAll(){ const paths = getFilteredPaths(); renderKpis(paths); renderPaths(paths); renderEdgeSummary(); renderExposureSummary(); }
function resetFilters(){ document.getElementById('riskFilter').value='All'; document.getElementById('techFilter').value=''; document.getElementById('nodeFilter').value=''; renderAll(); }
window.addEventListener('DOMContentLoaded', function(){
  if(Array.isArray(data.attackPaths) && data.attackPaths.length && document.getElementById('riskFilter').options.length){
    const hasCritical = data.attackPaths.some(p => p.risk === 'Critical');
    document.getElementById('riskFilter').value = hasCritical ? 'Critical' : 'All';
  }
  renderAll();
});
</script>
</body>
</html>
"@
$AttackSurfaceHTML | Out-File -FilePath $AttackSurfaceReportFile -Encoding UTF8 -Force
Write-Log "Attack surface interface exported: $AttackSurfaceReportFile" "SUCCESS"


# ════════════════════════════════════════════════════════════════════════════
#  SECTION 12 — HTML REPORT BUILDERS
# ════════════════════════════════════════════════════════════════════════════

# Severity colour map
$SevBg = @{ Critical="#c0392b"; High="#e74c3c"; Medium="#e67e22"; Low="#2980b9"; Informational="#636e72" }

# ── Findings HTML (for Tab 2) ──────────────────────────────────────────────
function Build-FindingsHTML {
    $CatIcons = @{
        "Password Policy"     = "🔒"
        "Privilege Escalation"= "⬆"
        "Account Hygiene"     = "👤"
        "Lateral Movement"    = "↔"
        "Kerberos Security"   = "🗝"
        "GPO Configuration"   = "📋"
        "ACL Delegation"      = "🛡"
        "Attack Paths"        = "🕸"
    }
    $SevOrder = @{ Critical=0; High=1; Medium=2; Low=3; Informational=4 }

    $html  = @"
<div class="findings-toolbar">
  <input type="text" id="searchBox" class="search-input" placeholder="🔍  Search findings by title, category, or description…" oninput="filterFindings()">
  <div class="filter-group">
    <button class="f-btn active" onclick="filterSev('all',this)">All ($TotalFindings)</button>
    <button class="f-btn f-critical" onclick="filterSev('Critical',this)">● Critical ($CriticalCount)</button>
    <button class="f-btn f-high"     onclick="filterSev('High',this)">● High ($HighCount)</button>
    <button class="f-btn f-medium"   onclick="filterSev('Medium',this)">● Medium ($MediumCount)</button>
    <button class="f-btn f-low"      onclick="filterSev('Low',this)">● Low ($LowCount)</button>
    <button class="f-btn f-info"     onclick="filterSev('Informational',this)">● Info ($InfoCount)</button>
  </div>
</div>
<div id="findings-wrap">
"@

    $fi = 0
    foreach ($cat in ($script:Findings | ForEach-Object Category | Select-Object -Unique | Sort-Object)) {
        $catF  = $script:Findings | Where-Object Category -eq $cat | Sort-Object { $SevOrder[$_.Severity] }
        $icon  = if ($CatIcons[$cat]) { $CatIcons[$cat] } else { "▸" }
        $html += "<div class='cat-block'><div class='cat-heading'><span class='cat-icon'>$icon</span><span class='cat-name'>$cat</span><span class='cat-badge'>$(@($catF).Count) finding$(if(@($catF).Count -ne 1){'s'})</span></div>"
        foreach ($f in $catF) {
            $fi++
            $fid    = "fd$fi"
            $bg     = $SevBg[$f.Severity]
            $mitreH = if ($f.MitreID) { "<a class='mitre-tag' href='$($f.MitreURL)' target='_blank' title='$($f.MitreName)'>ATT&amp;CK $($f.MitreID)</a>" } else { "" }
            $psH    = if ($f.PSFix) {
                $esc = [System.Web.HttpUtility]::HtmlEncode($f.PSFix)
                "<div class='ps-block'><div class='ps-bar'><span>PowerShell Remediation</span><button class='copy-ps-btn' onclick=""copyText('ps$fi')"">⧉ Copy</button></div><pre class='ps-code' id='ps$fi'>$esc</pre></div>"
            } else { "" }
            $detH = if ($f.Details) { "<div class='detail-box'>ℹ&nbsp; $([System.Web.HttpUtility]::HtmlEncode($f.Details))</div>" } else { "" }
            $tagsH = ""
            if ($f.Tags) { $f.Tags -split "," | Where-Object { $_ } | ForEach-Object { $tagsH += "<span class='tag'>$_</span>" } }

            $html += @"
<div class='finding-card' data-sev='$($f.Severity)' data-cat='$cat'>
  <div class='fc-header' style='background:$bg' onclick="toggleFc('$fid')">
    <div class='fc-left'>
      <span class='sev-dot'></span>
      <div class='fc-title-wrap'>
        <span class='fc-title'>$([System.Web.HttpUtility]::HtmlEncode($f.Title))</span>
        <div class='fc-badges'>
          <span class='badge-sev'>$($f.Severity)</span>
          <span class='badge-pri'>$($f.Priority)</span>
          <span class='badge-eff'>⏱ $($f.Effort)</span>
          $mitreH
          $tagsH
        </div>
      </div>
    </div>
    <span class='fc-expand' id='icon-$fid'>▼</span>
  </div>
  <div class='fc-preview'>$([System.Web.HttpUtility]::HtmlEncode($f.Description))</div>
  <div class='fc-body' id='$fid'>
    <div class='fc-grid'>
      <div class='fc-field'><div class='fc-field-label'>Business Impact</div><div class='fc-field-val'>$([System.Web.HttpUtility]::HtmlEncode($f.Impact))</div></div>
      <div class='fc-field'><div class='fc-field-label'>Remediation</div><div class='fc-field-val'>$([System.Web.HttpUtility]::HtmlEncode($f.Remediation))</div></div>
    </div>
    $detH
    $psH
  </div>
</div>
"@
        }
        $html += "</div>"
    }
    $html += "</div>"
    return $html
}

# ── Recommendations HTML (for Tab 4) ──────────────────────────────────────
function Build-RecsHTML {
    $Phases = @("Immediate","Short-Term","Medium-Term","Long-Term")
    $PhaseIcon = @{ Immediate="⚠"; "Short-Term"="▶"; "Medium-Term"="●"; "Long-Term"="◆" }
    $ri   = 0
    $html = ""
    foreach ($phase in $Phases) {
        $pr = @($Recommendations | Where-Object { $_['Phase'] -eq $phase })
        if ($pr.Count -eq 0) { continue }
        $pc = $pr.Count
        $phaseColor = $pr[0]['Color']
        $html += "<div class='rec-phase'><div class='rec-phase-hdr' style='border-left-color:$phaseColor'><span class='rph-icon' style='color:$phaseColor'>$($PhaseIcon[$phase])</span><span class='rph-title'>$phase Actions</span><span class='rph-cnt' style='background:$phaseColor'>$pc item$(if($pc -ne 1){'s'})</span></div>"
        foreach ($rec in $pr) {
            $ri++
            $rid  = "r$ri"
            $recColor    = $rec['Color']
            $recPriority = $rec['Priority']
            $recLabel    = $rec['Label']
            $recEffort   = $rec['Effort']
            $recTitle    = $rec['Title']
            $recWhat     = $rec['What']
            $recHow      = $rec['How']
            $recTools    = $rec['Tools']
            $howH = [System.Web.HttpUtility]::HtmlEncode($recHow) -replace "`n","<br>"
            $html += @"
<div class='rec-card'>
  <div class='rec-hdr'>
    <div class='rec-hl'>
      <span class='rec-num' style='background:$recColor'>$ri</span>
      <div><div class='rec-title'>$([System.Web.HttpUtility]::HtmlEncode($recTitle))</div>
        <div class='rec-meta'><span class='rec-badge' style='background:$recColor'>$recPriority — $recLabel</span><span class='rec-eff'>⏱ $recEffort</span></div>
      </div>
    </div>
    <button class='rec-btn' onclick="toggleRec('$rid',this)">Show Details</button>
  </div>
  <div class='rec-body' id='$rid' style='display:none'>
    <div class='rec-row'><div class='rec-lbl'>What &amp; Why</div><div class='rec-txt'>$([System.Web.HttpUtility]::HtmlEncode($recWhat))</div></div>
    <div class='rec-row'><div class='rec-lbl'>Step-by-Step Remediation</div><div class='rec-code'>$howH</div></div>
    <div class='rec-row'><div class='rec-lbl'>Recommended Tools</div><div class='rec-txt'>$([System.Web.HttpUtility]::HtmlEncode($recTools))</div></div>
  </div>
</div>
"@
        }
        $html += "</div>"
    }
    return $html
}

# ── MITRE Table ────────────────────────────────────────────────────────────
function Build-MitreHTML {
    if (-not $MitreTechs) { return "<p style='color:var(--text-muted)'>No MITRE techniques mapped in this scan.</p>" }
    $html = "<table class='data-table'><thead><tr><th>Technique ID</th><th>Technique Name</th><th>Tactic</th><th>Reference</th></tr></thead><tbody>"
    foreach ($m in $MitreTechs) {
        $html += "<tr><td><span class='mitre-cell'>$($m.MitreID)</span></td><td>$($m.MitreName)</td><td><span class='tactic-cell'>$($m.MitreTactic)</span></td><td><a href='$($m.MitreURL)' target='_blank' class='ext-link'>View ↗</a></td></tr>"
    }
    $html += "</tbody></table>"
    return $html
}

# ── OS Breakdown ───────────────────────────────────────────────────────────
function Build-OSBreakdownHTML {
    $html = "<table class='data-table'><thead><tr><th>Operating System</th><th>Count</th><th>Share</th></tr></thead><tbody>"
    foreach ($os in $script:Stats.OSBreakdown) {
        $share = if ($script:Stats.TotalComputers -gt 0) { [math]::Round(($os.Count / $script:Stats.TotalComputers) * 100, 1) } else { 0 }
        $html += "<tr><td>$(if($os.Name){$os.Name}else{'Unknown / Not Set'})</td><td>$($os.Count)</td><td><div class='share-bar'><div class='share-fill' style='width:${share}%'></div><span>$share%</span></div></td></tr>"
    }
    $html += "</tbody></table>"
    return $html
}

$FindingsHTML = Build-FindingsHTML
$RecsHTML     = Build-RecsHTML
$MitreHTML    = Build-MitreHTML
$OSBreakHTML  = Build-OSBreakdownHTML
$TopAttackPath = $null
if ($script:AttackPaths.Count -gt 0) {
    $TopAttackPath = $script:AttackPaths |
        Sort-Object             @{ Expression = {
                    if ($_.risk -eq "Critical") { 0 }
                    elseif ($_.risk -eq "High") { 1 }
                    elseif ($_.risk -eq "Medium") { 2 }
                    else { 3 }
                }; Ascending = $true },             @{ Expression = { $_.hopCount }; Ascending = $true } |
        Select-Object -First 1
}
$TopAttackSummary = if ($TopAttackPath) { [System.Web.HttpUtility]::HtmlEncode($TopAttackPath.summary) } else { 'No consultant-validated privilege escalation chain was derived from the current dataset.' }
$AttackSurfaceWidget = @"
<div class='attack-widget'>
  <div class='attack-widget-h'>
    <div>
      <div class='attack-widget-t'>Potential Attack Paths</div>
      <div class='attack-widget-s'>Interactive attack-path dashboard embedded in this report. Review the most exposed users, groups, devices, and privilege escalation routes without leaving the main board.</div>
    </div>
    <button type='button' class='attack-widget-btn' onclick="switchTab('t5')">Open Dashboard →</button>
  </div>
  <div class='attack-widget-grid'>
    <div class='attack-widget-kpi'><span>Attack Paths</span><strong>$($script:AttackPaths.Count)</strong></div>
    <div class='attack-widget-kpi'><span>Critical Paths</span><strong>$($CriticalAttackPaths.Count)</strong></div>
    <div class='attack-widget-kpi'><span>Graph Nodes</span><strong>$($script:GraphNodes.Count)</strong></div>
    <div class='attack-widget-kpi'><span>Graph Edges</span><strong>$($script:GraphEdges.Count)</strong></div>
  </div>
  <div class='attack-widget-note'><strong>Most urgent path:</strong> $TopAttackSummary</div>
</div>
"@

# Logo HTML
$LogoImgHTML = if ($LogoDataURI) {
    "<img src='$LogoDataURI' alt='Consultim-IT Logo' class='brand-logo-img'>"
} else {
    "<div class='brand-logo-fallback'>C</div>"
}

# Stale sparkline bar percentages
$staleMax = [math]::Max(1, $script:Stats.StaleUsers30)
$s30pct   = 100
$s60pct   = if ($staleMax -gt 0) { [math]::Round(($script:Stats.StaleUsers60 / $staleMax) * 100) } else { 0 }
$s90pct   = if ($staleMax -gt 0) { [math]::Round(($script:Stats.StaleUsers90 / $staleMax) * 100) } else { 0 }

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 13 — FULL HTML REPORT
# ════════════════════════════════════════════════════════════════════════════
$DetailedReportFile = Join-Path $OutputPath "ConsultimIT-AD-Assessment_$Timestamp.html"
$ReportFile = Join-Path $OutputPath "ConsultimIT-AD-Report_$Timestamp.html"

$HTML = @"
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Consultim-IT | $ReportTitle | $ClientCompany | $Domain</title>
<style>
/* ═══ RESET & TOKENS ═══════════════════════════════════════════════════════ */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth;font-size:15px}

:root{
  /* Enterprise Blue Dark palette */
  --bg:          #080e1c;
  --bg2:         #0c1528;
  --surface:     #101e36;
  --surface2:    #152444;
  --surface3:    #1a2c52;
  --border:      #1e3060;
  --border2:     #263870;
  --text:        #d8e4f8;
  --text-muted:  #6e8ab8;
  --text-light:  #3d5a8a;
  --gold:        #c8922a;
  --gold2:       #e0b54a;
  --gold3:       #f0d080;
  --accent:      #2e7de9;
  --accent2:     #1a5cc0;
  --accent3:     #5aa0f5;
  --c-critical:  #c0392b;
  --c-high:      #e74c3c;
  --c-medium:    #e67e22;
  --c-low:       #2980b9;
  --c-info:      #636e72;
  --c-ok:        #27ae60;
  --shadow:      0 4px 28px rgba(0,0,0,.55);
  --shadow-sm:   0 2px 12px rgba(0,0,0,.40);
  --shadow-lg:   0 8px 48px rgba(0,0,0,.65);
  --r:14px; --r-sm:8px; --r-xs:5px;
}

body{
  font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
  background:var(--bg);
  color:var(--text);
  line-height:1.7;
  min-height:100vh;
}
a{color:var(--accent3);text-decoration:none}
a:hover{text-decoration:underline}
button{font-family:inherit;cursor:pointer}

/* ═══ SCROLLBAR ═══════════════════════════════════════════════════════════ */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--accent2)}

/* ═══ HEADER ══════════════════════════════════════════════════════════════ */
.header{
  background:linear-gradient(135deg,#050c1a 0%,#08142a 50%,#0a1c38 100%);
  border-bottom:1px solid var(--border);
  box-shadow:0 4px 40px rgba(0,0,0,.6);
  position:relative;overflow:hidden;
}
.header::before{
  content:'';position:absolute;top:-60px;right:-80px;
  width:400px;height:400px;
  background:radial-gradient(circle,rgba(200,146,42,.12) 0%,transparent 65%);
  pointer-events:none;
}
.header::after{
  content:'';position:absolute;bottom:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,var(--gold),var(--gold2),var(--gold),transparent);
}
.header-inner{
  max-width:1400px;margin:0 auto;
  padding:20px 32px;
  display:flex;align-items:center;justify-content:space-between;
  flex-wrap:wrap;gap:16px;
  position:relative;
}
.brand{display:flex;align-items:center;gap:16px}
.brand-logo-img{height:44px;width:auto;object-fit:contain;filter:drop-shadow(0 2px 6px rgba(0,0,0,.5))}
.brand-logo-fallback{
  width:44px;height:44px;border-radius:10px;
  background:linear-gradient(135deg,rgba(200,146,42,.3),rgba(200,146,42,.1));
  border:1.5px solid rgba(200,146,42,.4);
  display:flex;align-items:center;justify-content:center;
  font-size:1.4em;font-weight:900;color:var(--gold2);
}
.brand-name{font-size:1.35em;font-weight:800;color:#fff;letter-spacing:-.3px}
.brand-name span{color:var(--gold2)}
.brand-sub{font-size:.76em;color:var(--text-muted);margin-top:1px;letter-spacing:.4px}
.header-meta{
  text-align:right;font-size:.78em;color:var(--text-muted);
  line-height:1.9;
  background:rgba(255,255,255,.03);
  border:1px solid var(--border);
  padding:10px 16px;border-radius:var(--r-sm);
}
.header-meta strong{color:var(--gold3)}

/* ═══ RISK BANNER ═════════════════════════════════════════════════════════ */
.risk-banner{
  background:linear-gradient(135deg,$RiskColor 0%,rgba(0,0,0,.3) 100%);
  border-radius:var(--r);
  padding:22px 32px;
  margin-bottom:24px;
  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px;
  box-shadow:0 6px 36px rgba(0,0,0,.4);
  position:relative;overflow:hidden;
  border:1px solid rgba(255,255,255,.08);
}
.risk-banner::after{
  content:'';position:absolute;right:-40px;top:-40px;
  width:180px;height:180px;border-radius:50%;
  background:rgba(255,255,255,.06);pointer-events:none;
}
.attack-widget{margin:0 0 24px;background:linear-gradient(135deg,rgba(18,33,61,.94),rgba(8,18,35,.96));border:1px solid var(--border2);border-radius:var(--r);padding:18px 20px;box-shadow:var(--shadow-sm)}
.attack-widget-h{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap}
.attack-widget-t{font-size:1.05em;font-weight:800;color:#fff}
.attack-widget-s{color:var(--text-muted);font-size:.92em;margin-top:4px;max-width:820px}
.attack-widget-btn{display:inline-flex;align-items:center;justify-content:center;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff!important;padding:10px 14px;border-radius:10px;font-weight:700;box-shadow:0 6px 18px rgba(46,125,233,.22)}
.attack-widget-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:14px}
.attack-widget-kpi{background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:12px;padding:12px 14px}
.attack-widget-kpi span{display:block;color:var(--text-muted);font-size:.82em}
.attack-widget-kpi strong{display:block;margin-top:4px;font-size:1.35em;color:#fff}
.attack-widget-note{margin-top:10px;color:var(--gold3);font-size:.82em;word-break:break-all}
.risk-group{display:flex;flex-direction:column;gap:3px}
.risk-label{font-size:.75em;text-transform:uppercase;letter-spacing:1.2px;opacity:.8}
.risk-value{font-size:2.1em;font-weight:900;line-height:1.05;color:#fff}
.risk-sub{font-size:.78em;opacity:.65;margin-top:2px}
.gauge-wrap svg{width:88px;height:88px;filter:drop-shadow(0 2px 8px rgba(0,0,0,.4))}

/* ═══ CONTAINER ═══════════════════════════════════════════════════════════ */
.page-wrap{max-width:1400px;margin:0 auto;padding:28px 24px 80px}

/* ═══ TAB NAVIGATION ══════════════════════════════════════════════════════ */
.tab-nav{
  display:flex;gap:2px;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--r);
  padding:5px;
  margin-bottom:24px;
  box-shadow:var(--shadow-sm);
}
.tab-btn{
  flex:1;padding:11px 16px;border:none;border-radius:var(--r-sm);
  background:transparent;color:var(--text-muted);
  font-size:.84em;font-weight:700;letter-spacing:.3px;
  transition:all .25s;white-space:nowrap;
  display:flex;align-items:center;justify-content:center;gap:7px;
}
.tab-btn:hover{background:var(--surface2);color:var(--text)}
.tab-btn.active{
  background:linear-gradient(135deg,var(--accent2),var(--accent));
  color:#fff;
  box-shadow:0 3px 14px rgba(46,125,233,.45);
}
.tab-btn .tab-badge{
  background:rgba(255,255,255,.2);border-radius:10px;
  padding:1px 7px;font-size:.78em;
}
.tab-btn.active .tab-badge{background:rgba(255,255,255,.25)}
.tab-panel{display:none;animation:fadeIn .25s ease}
.tab-panel.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

/* ═══ CARDS ═══════════════════════════════════════════════════════════════ */
.card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r);padding:24px 28px;
  margin-bottom:20px;box-shadow:var(--shadow-sm);
}
.card-title{
  font-size:.82em;font-weight:800;text-transform:uppercase;
  letter-spacing:1.2px;color:var(--text-muted);
  margin-bottom:18px;padding-bottom:10px;
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:9px;
}

/* ═══ SEVERITY STRIP ══════════════════════════════════════════════════════ */
.sev-strip{
  display:grid;grid-template-columns:repeat(5,1fr);
  gap:12px;margin-bottom:24px;
}
@media(max-width:700px){.sev-strip{grid-template-columns:repeat(3,1fr)}}
.sev-chip{
  border-radius:var(--r-sm);padding:16px 12px;text-align:center;
  color:#fff;box-shadow:var(--shadow-sm);
  cursor:pointer;transition:transform .2s,box-shadow .2s;
  position:relative;overflow:hidden;
}
.sev-chip:hover{transform:translateY(-3px);box-shadow:var(--shadow)}
.sev-chip::after{content:'';position:absolute;bottom:-8px;right:-8px;width:50px;height:50px;border-radius:50%;background:rgba(255,255,255,.1)}
.sev-n{font-size:2.8em;font-weight:900;line-height:1}
.sev-l{font-size:.7em;text-transform:uppercase;letter-spacing:.8px;opacity:.9;margin-top:4px}
.sev-critical{background:linear-gradient(135deg,#8b1a1a,var(--c-critical))}
.sev-high    {background:linear-gradient(135deg,var(--c-critical),var(--c-high))}
.sev-medium  {background:linear-gradient(135deg,#b8600a,var(--c-medium))}
.sev-low     {background:linear-gradient(135deg,#1a5580,var(--c-low))}
.sev-info    {background:linear-gradient(135deg,#3a3f42,var(--c-info))}

/* ═══ KPI GRID ════════════════════════════════════════════════════════════ */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(158px,1fr));gap:14px;margin-bottom:24px}
.kpi{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r);padding:18px 14px;text-align:center;
  box-shadow:var(--shadow-sm);transition:transform .2s,box-shadow .2s;
  position:relative;overflow:hidden;
}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent)}
.kpi:hover{transform:translateY(-3px);box-shadow:var(--shadow)}
.kpi-n{font-size:2.1em;font-weight:900;color:var(--accent3);line-height:1.1}
.kpi-n.danger{color:var(--c-high)}.kpi-n.warn{color:var(--c-medium)}.kpi-n.ok{color:var(--c-ok)}
.kpi-l{font-size:.69em;color:var(--text-muted);margin-top:6px;text-transform:uppercase;letter-spacing:.6px;font-weight:700}

/* ═══ CHARTS ══════════════════════════════════════════════════════════════ */
.charts-row{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}
@media(max-width:860px){.charts-row{grid-template-columns:1fr}}
.chart-box{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:22px;box-shadow:var(--shadow-sm)}
.chart-lbl{font-size:.78em;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:14px}
.chart-wrap{position:relative;height:210px}

/* ═══ STALE BARS ══════════════════════════════════════════════════════════ */
.stale-row{display:flex;gap:1px;border-radius:var(--r-sm);overflow:hidden;border:1px solid var(--border);margin-bottom:20px}
.stale-seg{flex:1;padding:16px;text-align:center}
.stale-seg-n{font-size:2em;font-weight:900;color:#fff}
.stale-seg-l{font-size:.7em;color:rgba(255,255,255,.8);text-transform:uppercase;letter-spacing:.5px;margin-top:3px}
.s30{background:linear-gradient(135deg,#8a5500,#f39c12)}
.s60{background:linear-gradient(135deg,#7a3a00,#e67e22)}
.s90{background:linear-gradient(135deg,#7a1a1a,#e74c3c)}

/* ═══ INFO TABLE ══════════════════════════════════════════════════════════ */
.info-table{width:100%;border-collapse:collapse;font-size:.86em}
.info-table th{
  padding:9px 14px;background:var(--surface2);color:var(--text-muted);
  font-size:.72em;text-transform:uppercase;letter-spacing:.8px;
  border-bottom:2px solid var(--border);text-align:left;font-weight:800;
}
.info-table td{
  padding:9px 14px;border-bottom:1px solid var(--border);color:var(--text);
  vertical-align:top;
}
.info-table td:first-child{font-weight:700;color:var(--text-muted);background:var(--surface2);width:36%;white-space:nowrap}
.info-table tr:last-child td{border-bottom:none}
.info-table tr:hover td{background:var(--surface3)}

/* DATA TABLE */
.data-table{width:100%;border-collapse:collapse;font-size:.85em}
.data-table th{padding:9px 14px;background:var(--surface2);color:var(--text-muted);font-size:.72em;text-transform:uppercase;letter-spacing:.8px;border-bottom:2px solid var(--border);text-align:left;font-weight:800}
.data-table td{padding:9px 14px;border-bottom:1px solid var(--border);color:var(--text)}
.data-table tr:last-child td{border-bottom:none}
.data-table tr:hover td{background:var(--surface2)}
.mitre-cell{background:linear-gradient(135deg,var(--c-critical),var(--c-high));color:#fff;padding:3px 9px;border-radius:20px;font-size:.82em;font-weight:900;font-family:monospace}
.tactic-cell{background:var(--surface3);border:1px solid var(--border);padding:2px 9px;border-radius:20px;font-size:.8em;color:var(--text-muted);font-weight:600}
.ext-link{color:var(--accent3);font-weight:600}

/* SHARE BAR */
.share-bar{display:flex;align-items:center;gap:8px;width:100%}
.share-fill{height:6px;background:linear-gradient(90deg,var(--accent2),var(--accent3));border-radius:3px;min-width:2px;max-width:200px}
.share-bar span{font-size:.82em;color:var(--text-muted);white-space:nowrap}

/* ═══ FINDINGS ════════════════════════════════════════════════════════════ */
.findings-toolbar{
  display:flex;gap:14px;align-items:center;flex-wrap:wrap;
  margin-bottom:20px;padding:14px 18px;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);
}
.search-input{
  flex:1;min-width:220px;
  padding:9px 14px;
  background:var(--bg2);border:1px solid var(--border2);border-radius:var(--r-sm);
  color:var(--text);font-size:.87em;font-family:inherit;
  transition:border-color .2s;
}
.search-input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(46,125,233,.2)}
.search-input::placeholder{color:var(--text-light)}
.filter-group{display:flex;gap:6px;flex-wrap:wrap}
.f-btn{
  padding:6px 12px;border-radius:20px;
  border:1.5px solid var(--border2);background:var(--surface);
  color:var(--text-muted);font-size:.77em;font-weight:700;
  transition:all .2s;white-space:nowrap;
}
.f-btn:hover,.f-btn.active{color:#fff;border-color:transparent}
.f-btn.active{background:var(--text-muted)}
.f-critical:hover,.f-critical.active{background:var(--c-critical)}
.f-high:hover,.f-high.active    {background:var(--c-high)}
.f-medium:hover,.f-medium.active{background:var(--c-medium)}
.f-low:hover,.f-low.active      {background:var(--c-low)}
.f-info:hover,.f-info.active    {background:var(--c-info)}

.cat-block{margin-bottom:8px}
.cat-heading{
  display:flex;align-items:center;gap:10px;
  padding:10px 0;margin-bottom:12px;
  border-bottom:1px solid var(--border);
}
.cat-icon{font-size:1.1em}
.cat-name{font-size:1.05em;font-weight:800;color:var(--accent3)}
.cat-badge{
  font-size:.72em;background:var(--surface2);border:1px solid var(--border);
  padding:2px 10px;border-radius:20px;color:var(--text-muted);font-weight:700;
}

.finding-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r-sm);margin-bottom:12px;overflow:hidden;
  box-shadow:var(--shadow-sm);transition:transform .18s,box-shadow .18s;
}
.finding-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.finding-card.hidden{display:none}

.fc-header{
  padding:12px 18px;color:#fff;
  display:flex;align-items:center;justify-content:space-between;
  gap:12px;cursor:pointer;user-select:none;
  position:relative;
}
.fc-header::after{
  content:'';position:absolute;top:0;right:0;bottom:0;
  width:4px;background:rgba(255,255,255,.15);
}
.fc-left{display:flex;align-items:center;gap:12px;flex:1;min-width:0}
.sev-dot{width:8px;height:8px;border-radius:50%;background:rgba(255,255,255,.7);flex-shrink:0}
.fc-title-wrap{flex:1;min-width:0}
.fc-title{font-size:.93em;font-weight:700;display:block;margin-bottom:5px;line-height:1.3}
.fc-badges{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.badge-sev,.badge-pri,.badge-eff{
  font-size:.66em;font-weight:800;padding:2px 8px;border-radius:20px;
  background:rgba(255,255,255,.2);text-transform:uppercase;letter-spacing:.6px;white-space:nowrap;
}
.mitre-tag{
  font-size:.66em;font-weight:800;padding:2px 8px;border-radius:20px;
  background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.3);
  color:#fff;font-family:monospace;letter-spacing:.4px;
}
.mitre-tag:hover{background:rgba(255,255,255,.22);text-decoration:none;color:#fff}
.tag{
  font-size:.64em;font-weight:700;padding:1px 7px;border-radius:20px;
  background:rgba(255,255,255,.1);color:rgba(255,255,255,.8);
  border:1px solid rgba(255,255,255,.2);
}
.fc-expand{font-size:.8em;opacity:.7;flex-shrink:0;transition:transform .2s}
.fc-expand.open{transform:rotate(180deg)}
.fc-preview{
  padding:10px 18px;
  background:var(--surface2);border-top:1px solid var(--border);
  font-size:.86em;color:var(--text-muted);line-height:1.5;
}
.fc-body{
  padding:16px 18px;border-top:1px solid var(--border);font-size:.87em;
}
.fc-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:12px}
@media(max-width:700px){.fc-grid{grid-template-columns:1fr}}
.fc-field-label{font-size:.72em;font-weight:800;text-transform:uppercase;letter-spacing:.8px;color:var(--accent3);margin-bottom:5px}
.fc-field-val{color:var(--text);line-height:1.65}
.detail-box{
  background:var(--bg2);border-left:3px solid var(--gold);
  padding:9px 14px;border-radius:0 var(--r-xs) var(--r-xs) 0;
  font-size:.82em;color:var(--text-muted);
  margin-top:12px;word-break:break-word;
}
.ps-block{margin-top:14px;background:var(--bg);border:1px solid var(--border2);border-radius:var(--r-sm);overflow:hidden}
.ps-bar{
  display:flex;align-items:center;justify-content:space-between;
  padding:7px 14px;
  background:var(--surface2);border-bottom:1px solid var(--border);
  font-size:.74em;font-weight:800;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);
}
.ps-code{
  padding:12px 16px;
  font-family:'Cascadia Code','Consolas','Courier New',monospace;
  font-size:.82em;color:#a8d8a8;
  white-space:pre-wrap;word-break:break-word;line-height:1.65;
}
.copy-ps-btn{
  background:var(--accent);color:#fff;border:none;
  border-radius:4px;padding:3px 10px;font-size:.8em;font-weight:700;
  transition:opacity .2s;
}
.copy-ps-btn:hover{opacity:.85}

/* ═══ RECOMMENDATIONS ═════════════════════════════════════════════════════ */
.rec-phase{margin-bottom:28px}
.rec-phase-hdr{
  display:flex;align-items:center;gap:12px;
  padding:11px 18px;background:var(--surface2);
  border-radius:var(--r-sm);margin-bottom:14px;
  border-left:4px solid transparent;
}
.rph-icon{font-size:1.1em}
.rph-title{font-weight:800;font-size:.98em;color:var(--text)}
.rph-cnt{font-size:.72em;padding:3px 10px;border-radius:20px;color:#fff;font-weight:700;margin-left:auto}
.rec-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r-sm);margin-bottom:10px;overflow:hidden;
  box-shadow:var(--shadow-sm);transition:box-shadow .2s;
}
.rec-card:hover{box-shadow:var(--shadow)}
.rec-hdr{
  display:flex;align-items:center;justify-content:space-between;
  padding:14px 18px;gap:14px;flex-wrap:wrap;
}
.rec-hl{display:flex;align-items:flex-start;gap:13px;flex:1;min-width:0}
.rec-num{
  width:30px;height:30px;border-radius:50%;color:#fff;
  display:flex;align-items:center;justify-content:center;
  font-weight:900;font-size:.82em;flex-shrink:0;margin-top:2px;
}
.rec-title{font-weight:700;font-size:.91em;color:var(--text);margin-bottom:5px}
.rec-meta{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.rec-badge{font-size:.67em;padding:2px 8px;border-radius:12px;color:#fff;font-weight:800;text-transform:uppercase;letter-spacing:.5px}
.rec-eff{font-size:.76em;color:var(--text-muted)}
.rec-btn{
  background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--r-sm);padding:6px 14px;font-size:.78em;
  color:var(--text-muted);font-weight:700;transition:all .2s;white-space:nowrap;
}
.rec-btn:hover{background:var(--accent);color:#fff;border-color:var(--accent)}
.rec-body{padding:4px 18px 18px;border-top:1px solid var(--border)}
.rec-row{margin-bottom:12px;padding-top:12px}
.rec-lbl{font-size:.72em;font-weight:800;text-transform:uppercase;letter-spacing:.9px;color:var(--gold2);margin-bottom:5px}
.rec-txt{font-size:.87em;color:var(--text);line-height:1.75}
.rec-code{
  background:var(--bg);border:1px solid var(--border2);
  border-radius:var(--r-sm);padding:12px 16px;
  font-family:'Cascadia Code','Consolas',monospace;
  font-size:.81em;color:#a8d8a8;
  white-space:pre-wrap;word-break:break-word;line-height:1.75;
}

/* ═══ CONTROLS ════════════════════════════════════════════════════════════ */
.controls-bar{
  position:fixed;bottom:14px;right:14px;z-index:999;
  display:flex;gap:7px;align-items:center;
}
.ctrl-btn{
  background:var(--surface2);border:1px solid var(--border2);
  border-radius:50px;padding:7px 15px;
  font-size:.78em;color:var(--text-muted);
  display:flex;align-items:center;gap:7px;
  box-shadow:var(--shadow-sm);transition:all .2s;
  white-space:nowrap;
}
.ctrl-btn:hover{background:var(--accent);color:#fff;border-color:var(--accent)}

/* ═══ TOAST ═══════════════════════════════════════════════════════════════ */
.toast{
  position:fixed;bottom:22px;left:50%;transform:translateX(-50%);
  background:var(--c-ok);color:#fff;padding:10px 22px;
  border-radius:50px;font-size:.83em;font-weight:700;
  z-index:9999;opacity:0;pointer-events:none;
  transition:opacity .3s;box-shadow:var(--shadow);
}
.toast.show{opacity:1}

/* ═══ PROGRESS RING ═══════════════════════════════════════════════════════ */
.risk-score-ring{
  display:flex;flex-direction:column;align-items:center;gap:4px;
}
.risk-score-ring text{font-family:inherit}

/* ═══ FOOTER ══════════════════════════════════════════════════════════════ */
.footer{
  background:var(--surface);border:1px solid var(--border);
  border-top:2px solid var(--gold);
  border-radius:var(--r);padding:24px 32px;margin-top:40px;
  display:flex;align-items:center;justify-content:space-between;
  flex-wrap:wrap;gap:16px;
}
.footer-brand{font-size:1em;font-weight:800;color:var(--text)}
.footer-brand span{color:var(--gold2)}
.footer-meta{font-size:.77em;color:var(--text-muted);margin-top:4px;line-height:1.9}
.footer-right{text-align:right;font-size:.77em;color:var(--text-muted)}
.footer-pills{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.fpill{
  background:var(--surface2);border:1px solid var(--border);
  padding:3px 10px;border-radius:20px;
  font-size:.74em;color:var(--text-muted);font-weight:600;
}


.as-layout{display:grid;grid-template-columns:320px 1fr;gap:18px;align-items:start}
.as-sidebar{display:flex;flex-direction:column;gap:16px}
.as-main{display:flex;flex-direction:column;gap:16px}
.as-grid{display:grid;grid-template-columns:1.2fr .9fr;gap:16px;align-items:start}
.as-panel{background:linear-gradient(180deg,rgba(15,23,42,.88),rgba(7,15,30,.92));border:1px solid var(--border);border-radius:18px;padding:18px;box-shadow:var(--shadow)}
.as-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.as-kpi{background:rgba(15,23,42,.72);border:1px solid var(--border);border-radius:14px;padding:14px}
.as-kpi .v{font-size:1.35rem;font-weight:800;margin-top:6px;color:var(--text)}
.as-filters label{display:block;font-size:.88rem;margin:.7rem 0 .35rem;color:var(--text-muted)}
.as-filters select,.as-filters input{width:100%;background:#071425;color:#e4efff;border:1px solid #244574;border-radius:10px;padding:10px}
.as-path-card{border:1px solid #21406c;border-radius:14px;padding:14px;background:#0b1730;margin-bottom:12px}
.as-path-card.critical{border-color:#b43a31;box-shadow:0 0 0 1px rgba(180,58,49,.25)}
.as-path-card.high{border-color:#c56d1f}.as-path-card.medium{border-color:#275f9c}.as-path-card.low{border-color:#2a7b4f}
.as-badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.78rem;margin-right:6px;font-weight:700}
.as-badge.Critical{background:#b43a31;color:#fff}.as-badge.High{background:#c56d1f;color:#fff}.as-badge.Medium{background:#275f9c;color:#fff}.as-badge.Low{background:#2a7b4f;color:#fff}
.as-step{padding:10px 12px;border-left:3px solid #2e7de9;background:#0f213f;border-radius:8px;margin-top:8px}
.as-empty-state{padding:18px;border:1px dashed #305689;border-radius:12px;background:#0a1527;color:#9ab2da}
.exposure-item{padding:8px 0;border-bottom:1px solid var(--border)}
.exposure-item:last-child{border-bottom:0}
.mono{font-family:Consolas,monospace}
.as-graph-shell{height:560px;min-height:420px;border:1px solid var(--border);border-radius:16px;background:linear-gradient(180deg,rgba(7,18,36,.98),rgba(10,22,43,.96));overflow:hidden;position:relative}
.as-graph-canvas{width:100%;height:100%}
.as-legend{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.as-legend span{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;background:rgba(255,255,255,.04);border:1px solid var(--border);font-size:.76rem;color:var(--text-muted)}
.as-legend i{display:inline-block;width:10px;height:10px;border-radius:50%}
.as-node-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:12px}
.as-node-tile{background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:12px;padding:10px 12px}
.as-node-tile .k{font-size:.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em}
.as-node-tile .v{font-size:.96rem;color:var(--text);font-weight:700;margin-top:4px}
@media (max-width:1100px){.as-layout,.as-grid{grid-template-columns:1fr}}

/* ═══ PRINT ═══════════════════════════════════════════════════════════════ */
@media print{
  .controls-bar,.findings-toolbar,.tab-nav,.ctrl-btn,.rec-btn,.copy-ps-btn{display:none!important}
  .tab-panel{display:block!important}
  .fc-body,.rec-body{display:block!important}
  body{background:#fff;color:#000}
  .card,.finding-card,.rec-card,.kpi,.chart-box{border:1px solid #ccc;box-shadow:none}
}
</style>
</head>
<body>

<!-- CONTROLS -->
<div class="controls-bar">
  <button class="ctrl-btn" onclick="toggleTheme()">◑ Toggle Theme</button>
  <button class="ctrl-btn" onclick="exportCSV()">↓ Export CSV</button>
  <button class="ctrl-btn" onclick="window.print()">⎙ Print</button>
</div>

<div class="toast" id="toast"></div>

<!-- HEADER -->
<div class="header">
  <div class="header-inner">
    <div class="brand">
      $LogoImgHTML
      <div>
        <div class="brand-name">consultim<span>-it</span></div>
        <div class="brand-sub">Active Directory Security Assessment &nbsp;·&nbsp; v2.1</div>
      </div>
    </div>
    <div class="header-meta">
      <div><strong>Client:</strong> $ClientCompany</div>
      <div><strong>Domain:</strong> $Domain &nbsp;·&nbsp; <strong>Forest:</strong> $($ForestObj.RootDomain)</div>
      <div><strong>Assessment Date:</strong> $($StartTime.ToString("yyyy-MM-dd  HH:mm:ss"))</div>
      <div><strong>Duration:</strong> $DurationStr &nbsp;·&nbsp; <strong>Mode:</strong> $ScanMode</div>
      <div><strong>Analyst:</strong> Ranim Hassine — Consultim-IT</div>
    </div>
  </div>
</div>

<div class="page-wrap">

  <!-- RISK BANNER -->
  <div class="risk-banner">
    <div class="risk-group">
      <div class="risk-label">Overall Risk Level</div>
      <div class="risk-value">$RiskLevel</div>
      <div class="risk-sub">$TotalFindings findings across $(@($CatBreakdown).Count) categories</div>
    </div>
    <div class="gauge-wrap">
      <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
        <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(255,255,255,.12)" stroke-width="10"/>
        <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(255,255,255,.85)" stroke-width="10"
          stroke-dasharray="$RiskGaugeDash 251.2" stroke-dashoffset="62.8"
          stroke-linecap="round" transform="rotate(-90 50 50)"/>
        <text x="50" y="53" text-anchor="middle" fill="white" font-size="20" font-weight="900">$RiskScore</text>
        <text x="50" y="65" text-anchor="middle" fill="rgba(255,255,255,.6)" font-size="8">/ 100</text>
      </svg>
    </div>
    <div class="risk-group">
      <div class="risk-label">Critical Findings</div>
      <div class="risk-value">$CriticalCount</div>
      <div class="risk-sub">Immediate remediation required</div>
    </div>
    <div class="risk-group">
      <div class="risk-label">MITRE Techniques</div>
      <div class="risk-value">$(@($MitreTechs).Count)</div>
      <div class="risk-sub">ATT&amp;CK framework coverage</div>
    </div>
    <div class="risk-group">
      <div class="risk-label">Recommendations</div>
      <div class="risk-value">$(@($Recommendations).Count)</div>
      <div class="risk-sub">Actionable roadmap items</div>
    </div>
  </div>

  $AttackSurfaceWidget

  <!-- SEVERITY STRIP (clickable) -->
  <div class="sev-strip">
    <div class="sev-chip sev-critical" onclick="switchTab('t2');setTimeout(()=>filterSev('Critical',null),200)"><div class="sev-n">$CriticalCount</div><div class="sev-l">Critical</div></div>
    <div class="sev-chip sev-high"     onclick="switchTab('t2');setTimeout(()=>filterSev('High',null),200)"><div class="sev-n">$HighCount</div><div class="sev-l">High</div></div>
    <div class="sev-chip sev-medium"   onclick="switchTab('t2');setTimeout(()=>filterSev('Medium',null),200)"><div class="sev-n">$MediumCount</div><div class="sev-l">Medium</div></div>
    <div class="sev-chip sev-low"      onclick="switchTab('t2');setTimeout(()=>filterSev('Low',null),200)"><div class="sev-n">$LowCount</div><div class="sev-l">Low</div></div>
    <div class="sev-chip sev-info"     onclick="switchTab('t2');setTimeout(()=>filterSev('Informational',null),200)"><div class="sev-n">$InfoCount</div><div class="sev-l">Info</div></div>
  </div>

  <!-- TAB NAVIGATION -->
  <nav class="tab-nav">
    <button type="button" class="tab-btn active" onclick="switchTab('t1')">📊 <span>Executive Dashboard</span></button>
    <button type="button" class="tab-btn" onclick="switchTab('t2')">🔍 <span>Security Findings</span> <span class="tab-badge">$TotalFindings</span></button>
    <button type="button" class="tab-btn" onclick="switchTab('t3')">🗄 <span>Domain Statistics</span></button>
    <button type="button" class="tab-btn" onclick="switchTab('t4')">📋 <span>Recommendations</span> <span class="tab-badge">$(@($Recommendations).Count)</span></button>
    <button type="button" class="tab-btn" onclick="switchTab('t5')">🕸 <span>Potential Attack Paths</span> <span class="tab-badge">$($script:AttackPaths.Count)</span></button>
  </nav>

  <!-- ══════════════════════════════════════════════════════════════════════
       TAB 1 — EXECUTIVE DASHBOARD
  ══════════════════════════════════════════════════════════════════════════ -->
  <div class="tab-panel active" id="t1">

    <!-- Charts row -->
    <div class="charts-row">
      <div class="chart-box">
        <div class="chart-lbl">Findings by Severity</div>
        <div class="chart-wrap"><canvas id="chartSev"></canvas></div>
      </div>
      <div class="chart-box">
        <div class="chart-lbl">Findings by Category</div>
        <div class="chart-wrap"><canvas id="chartCat"></canvas></div>
      </div>
    </div>

    <!-- KPI cards -->
    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-n">$($script:Stats.TotalUsers)</div><div class="kpi-l">Total Users</div></div>
      <div class="kpi"><div class="kpi-n ok">$($script:Stats.EnabledUsers)</div><div class="kpi-l">Enabled Users</div></div>
      <div class="kpi"><div class="kpi-n $(if($script:Stats.DomainAdmins -gt 5){'danger'}else{'ok'})">$($script:Stats.DomainAdmins)</div><div class="kpi-l">Domain Admins</div></div>
      <div class="kpi"><div class="kpi-n $(if($script:Stats.EnterpriseAdmins -gt 2){'warn'}else{'ok'})">$($script:Stats.EnterpriseAdmins)</div><div class="kpi-l">Enterprise Admins</div></div>
      <div class="kpi"><div class="kpi-n $(if($script:Stats.StaleUsers90 -gt 0){'danger'}else{'ok'})">$($script:Stats.StaleUsers90)</div><div class="kpi-l">Stale (90d)</div></div>
      <div class="kpi"><div class="kpi-n $(if($script:Stats.PwdNeverExpires -gt 0){'warn'}else{'ok'})">$($script:Stats.PwdNeverExpires)</div><div class="kpi-l">Pwd Never Expires</div></div>
      <div class="kpi"><div class="kpi-n $(if($script:Stats.PwdNotRequired -gt 0){'danger'}else{'ok'})">$($script:Stats.PwdNotRequired)</div><div class="kpi-l">No Pwd Required</div></div>
      <div class="kpi"><div class="kpi-n $(if($script:Stats.ReversiblePwd -gt 0){'danger'}else{'ok'})">$($script:Stats.ReversiblePwd)</div><div class="kpi-l">Reversible Pwd</div></div>
      <div class="kpi"><div class="kpi-n">$($script:Stats.TotalComputers)</div><div class="kpi-l">Computer Accounts</div></div>
      <div class="kpi"><div class="kpi-n">$($script:Stats.DomainControllers)</div><div class="kpi-l">Domain Controllers</div></div>
      <div class="kpi"><div class="kpi-n">$($script:Stats.TotalGPOs)</div><div class="kpi-l">GPO Objects</div></div>
      <div class="kpi"><div class="kpi-n $(if($script:Stats.KrbtgtAgeDays -gt 180){'danger'}else{'ok'})">$($script:Stats.KrbtgtAgeDays)</div><div class="kpi-l">KRBTGT Age (days)</div></div>
      <div class="kpi"><div class="kpi-n $(if($script:Stats.MachineQuota -gt 0){'warn'}else{'ok'})">$($script:Stats.MachineQuota)</div><div class="kpi-l">Machine Acct Quota</div></div>
      <div class="kpi"><div class="kpi-n">$($script:Stats.LockedOut)</div><div class="kpi-l">Currently Locked</div></div>
      <div class="kpi"><div class="kpi-n ok">$($script:Stats.SmartcardRequired)</div><div class="kpi-l">Smartcard Required</div></div>
      <div class="kpi"><div class="kpi-n ok">$($script:Stats.SensitiveAccts)</div><div class="kpi-l">Sensitive &amp; No Deleg.</div></div>
    </div>

    <!-- Stale account timeline -->
    <div class="card">
      <div class="card-title">⏱ Stale Account Inactivity Timeline</div>
      <div class="stale-row">
        <div class="stale-seg s30"><div class="stale-seg-n">$($script:Stats.StaleUsers30)</div><div class="stale-seg-l">30+ Days Inactive</div></div>
        <div class="stale-seg s60"><div class="stale-seg-n">$($script:Stats.StaleUsers60)</div><div class="stale-seg-l">60+ Days Inactive</div></div>
        <div class="stale-seg s90"><div class="stale-seg-n">$($script:Stats.StaleUsers90)</div><div class="stale-seg-l">90+ Days Inactive</div></div>
      </div>
      <p style="font-size:.82em;color:var(--text-muted)">Stale accounts represent latent attack surface that bypasses access reviews. Disable accounts at 60 days; delete after 30-day quarantine hold.</p>
    </div>

    <!-- MITRE ATT&CK coverage -->
    <div class="card">
      <div class="card-title">🌐 MITRE ATT&amp;CK Technique Coverage</div>
      $MitreHTML
    </div>

  </div>

  <!-- ══════════════════════════════════════════════════════════════════════
       TAB 2 — SECURITY FINDINGS
  ══════════════════════════════════════════════════════════════════════════ -->
  <div class="tab-panel" id="t2">
    <div class="card">
      <div class="card-title">🔍 Security Findings — $TotalFindings Total</div>
      $FindingsHTML
    </div>
  </div>

  <!-- ══════════════════════════════════════════════════════════════════════
       TAB 3 — DOMAIN STATISTICS
  ══════════════════════════════════════════════════════════════════════════ -->
  <div class="tab-panel" id="t3">

    <div class="card">
      <div class="card-title">🌐 Domain &amp; Forest Information</div>
      <table class="info-table">
        <tr><td>Domain Name</td><td>$Domain</td></tr>
        <tr><td>Domain DN</td><td>$DomainDN</td></tr>
        <tr><td>Forest Root</td><td>$($ForestObj.RootDomain)</td></tr>
        <tr><td>Forest Functional Level</td><td>$($script:Stats.ForestFunctional)</td></tr>
        <tr><td>Domain Functional Level</td><td>$($script:Stats.DomainFunctional)</td></tr>
        <tr><td>Domain Controllers</td><td>$DCList</td></tr>
        <tr><td>Domain Admins</td><td>$($script:Stats.DomainAdmins)</td></tr>
        <tr><td>Enterprise Admins</td><td>$($script:Stats.EnterpriseAdmins)</td></tr>
        <tr><td>Schema Admins</td><td>$($script:Stats.SchemaAdmins)</td></tr>
        <tr><td>Machine Account Quota</td><td>$($script:Stats.MachineQuota)</td></tr>
        <tr><td>KRBTGT Password Age</td><td>$($script:Stats.KrbtgtAgeDays) days (last set: $($KrbtgtAccount.PasswordLastSet))</td></tr>
        <tr><td>Total Users</td><td>$($script:Stats.TotalUsers) ($($script:Stats.EnabledUsers) enabled, $($script:Stats.DisabledUsers) disabled)</td></tr>
        <tr><td>Total Computers</td><td>$($script:Stats.TotalComputers) ($($script:Stats.DomainControllers) domain controllers)</td></tr>
        <tr><td>Total Groups</td><td>$($script:Stats.TotalGroups) ($($script:Stats.EmptyGroups) empty groups)</td></tr>
        <tr><td>Group Policy Objects</td><td>$($script:Stats.TotalGPOs)</td></tr>
        <tr><td>Scan Mode</td><td>$ScanMode</td></tr>
        <tr><td>Scan Duration</td><td>$DurationStr</td></tr>
        <tr><td>Assessed By</td><td>Ranim Hassine — Consultim-IT Security Practice</td></tr>
        <tr><td>Report Generated</td><td>$($EndTime.ToString("yyyy-MM-dd HH:mm:ss"))</td></tr>
      </table>
    </div>

    <div class="card">
      <div class="card-title">🔑 Password Policy Configuration</div>
      <table class="info-table">
        <tr><td>Minimum Password Length</td><td>$(if($script:Stats.MinPwdLength -lt 12){"<span style='color:var(--c-high)'>⚠ $($script:Stats.MinPwdLength) characters (Recommended: 14+)</span>"}else{"$($script:Stats.MinPwdLength) characters"})</td></tr>
        <tr><td>Password Complexity</td><td>$(if($script:Stats.PwdComplexity){"<span style='color:var(--c-ok)'>✓ Enabled</span>"}else{"<span style='color:var(--c-critical)'>✗ Disabled</span>"})</td></tr>
        <tr><td>Lockout Threshold</td><td>$(if($script:Stats.LockoutThreshold -eq 0){"<span style='color:var(--c-critical)'>✗ Disabled (0 — unlimited attempts)</span>"}else{"$($script:Stats.LockoutThreshold) attempts"})</td></tr>
        <tr><td>Max Password Age</td><td>$(if($script:Stats.MaxPwdAgeDays -eq 0){"<span style='color:var(--c-medium)'>Never expires</span>"}else{"$($script:Stats.MaxPwdAgeDays) days"})</td></tr>
        <tr><td>Password History</td><td>$(if($script:Stats.PwdHistoryCount -lt 10){"<span style='color:var(--c-medium)'>⚠ $($script:Stats.PwdHistoryCount) (Recommended: 24)</span>"}else{"$($script:Stats.PwdHistoryCount)"})</td></tr>
        <tr><td>Password Never Expires</td><td>$(if($script:Stats.PwdNeverExpires -gt 0){"<span style='color:var(--c-medium)'>⚠ $($script:Stats.PwdNeverExpires) accounts</span>"}else{"<span style='color:var(--c-ok)'>✓ None</span>"})</td></tr>
        <tr><td>Password Not Required</td><td>$(if($script:Stats.PwdNotRequired -gt 0){"<span style='color:var(--c-critical)'>✗ $($script:Stats.PwdNotRequired) accounts</span>"}else{"<span style='color:var(--c-ok)'>✓ None</span>"})</td></tr>
        <tr><td>Reversible Encryption</td><td>$(if($script:Stats.ReversiblePwd -gt 0){"<span style='color:var(--c-critical)'>✗ $($script:Stats.ReversiblePwd) accounts</span>"}else{"<span style='color:var(--c-ok)'>✓ None</span>"})</td></tr>
        <tr><td>Accounts Locked Out</td><td>$($script:Stats.LockedOut)</td></tr>
        <tr><td>Passwords Expired</td><td>$($script:Stats.PwdExpired)</td></tr>
        <tr><td>Smartcard Required</td><td><span style='color:var(--c-ok)'>$($script:Stats.SmartcardRequired)</span></td></tr>
      </table>
    </div>

    <div class="card">
      <div class="card-title">🖥 Computer Inventory by OS</div>
      $OSBreakHTML
    </div>

  </div>

  <!-- ══════════════════════════════════════════════════════════════════════
       TAB 4 — TECHNICAL RECOMMENDATIONS
  ══════════════════════════════════════════════════════════════════════════ -->
  <div class="tab-panel" id="t4">
    <div class="card">
      <div class="card-title">📋 Prioritized Remediation Roadmap — $(@($Recommendations).Count) Items</div>
      <p style="font-size:.85em;color:var(--text-muted);margin-bottom:20px">
        Recommendations are triggered by findings detected in this assessment and ordered by urgency.
        Address all <strong style="color:var(--c-critical)">Immediate</strong> items first to eliminate active compromise paths.
        Each recommendation includes step-by-step PowerShell remediation and tooling guidance.
      </p>
      $RecsHTML
    </div>
  </div>

  <!-- ══════════════════════════════════════════════════════════════════════
       TAB 5 — POTENTIAL ATTACK PATHS
  ══════════════════════════════════════════════════════════════════════════ -->
  <div class="tab-panel" id="t5">
    <div class="card">
      <div class="card-title">🕸 Potential Attack Paths & Attack Surface Graph</div>
      <p style="font-size:.85em;color:var(--text-muted);margin-bottom:18px">
        The attack-surface interface below correlates users, groups, machines, delegated permissions, and privileged control paths into a browser-rendered relationship graph. Prioritize the shortest critical chains and the entities with the highest exposure scores.
      </p>
      <div class="as-layout">
        <aside class="as-sidebar">
          <div class="as-panel">
            <div class="as-filters">
              <label for="asRiskFilter">Risk level</label>
              <select id="asRiskFilter"><option value="All">All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>
              <label for="asTechFilter">MITRE technique</label>
              <input id="asTechFilter" placeholder="e.g. T1558.003">
              <label for="asNodeFilter">Node / asset search</label>
              <input id="asNodeFilter" placeholder="Search user, group, computer...">
              <div style="display:flex;gap:8px;margin-top:12px">
                <button type="button" class="ctrl-btn" style="margin:0" onclick="renderAttackDashboard()">Apply</button>
                <button type="button" class="ctrl-btn" style="margin:0;background:linear-gradient(135deg,#334155,#1e293b)" onclick="resetAttackFilters()">Reset</button>
              </div>
            </div>
          </div>
          <div class="as-panel">
            <div class="card-title" style="margin-bottom:10px">Graph usage guidance</div>
            <div class="note">Red and orange edges indicate the highest-risk relationships. Hover for context, click a node to inspect its exposure score, and use the filters to isolate the shortest full and partial attack chains.</div>
            <div class="as-legend">
              <span><i style="background:#ef4444"></i> Critical / High edge</span>
              <span><i style="background:#f59e0b"></i> Medium edge</span>
              <span><i style="background:#60a5fa"></i> Low edge</span>
              <span><i style="background:#a78bfa"></i> Group node</span>
              <span><i style="background:#34d399"></i> User node</span>
              <span><i style="background:#38bdf8"></i> Machine node</span>
            </div>
          </div>
          <div class="as-panel">
            <div class="card-title" style="margin-bottom:10px">Selected node intelligence</div>
            <div id="asSelectedNode" class="note">Select a node in the graph to review its exposure score, path frequency, and object metadata.</div>
          </div>
          <div class="as-panel">
            <div class="card-title" style="margin-bottom:10px">Immediate actions</div>
            <div id="asImmediateActions" class="note"></div>
          </div>
        </aside>
        <div class="as-main">
          <div class="as-kpis" id="asKpis"></div>
          <div class="as-panel">
            <div class="card-title" style="margin-bottom:12px">Interactive privilege escalation graph</div>
            <div id="asGraphShell" class="as-graph-shell">
              <div id="asGraphCanvas" class="as-graph-canvas"></div>
            </div>
          </div>
          <div class="as-grid">
            <div class="as-panel">
              <div class="card-title" style="margin-bottom:12px">Attack chains</div>
              <div id="asPaths"></div>
            </div>
            <div>
              <div class="as-panel">
                <div class="card-title" style="margin-bottom:12px">Most vulnerable entities</div>
                <div class="edge-list"><table class="info-table"><thead><tr><th>Entity</th><th>Type</th><th>Path hits</th><th>Highest risk</th></tr></thead><tbody id="asEntitySummary"></tbody></table></div>
              </div>
              <div class="as-panel">
                <div class="card-title" style="margin-bottom:12px">Relationship summary</div>
                <div class="edge-list"><table class="info-table"><thead><tr><th>Relation</th><th>Count</th><th>Highest risk</th></tr></thead><tbody id="asEdgeSummary"></tbody></table></div>
              </div>
              <div class="as-panel">
                <div class="card-title" style="margin-bottom:12px">Critical exposures</div>
                <div id="asExposureSummary" class="note"></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- FOOTER -->
  <div class="footer">
    <div>
      <div class="footer-brand">consultim<span>-it</span> &nbsp;·&nbsp; Active Directory Security Assessment v2.1</div>
      <div class="footer-meta">Author: Ranim Hassine &nbsp;·&nbsp; Consultim-IT Security Practice &nbsp;·&nbsp; consultim-it.com</div>
      <div class="footer-meta">Client: $ClientCompany &nbsp;·&nbsp; Generated: $($EndTime.ToString("yyyy-MM-dd HH:mm:ss")) &nbsp;·&nbsp; CONFIDENTIAL — For authorized recipients only.</div>
      <div class="footer-pills">
        <span class="fpill">Client: $ClientCompany</span>
        <span class="fpill">Domain: $Domain</span>
        <span class="fpill">Risk Score: $RiskScore/100 ($RiskLevel)</span>
        <span class="fpill">Findings: $TotalFindings</span>
        <span class="fpill">Critical: $CriticalCount</span>
        <span class="fpill">Scan Mode: $ScanMode</span>
        <span class="fpill">Duration: $DurationStr</span>
      </div>
    </div>
    <div class="footer-right">
      <div style="color:var(--gold2);font-weight:800;font-size:1.05em">Consultim-IT</div>
      <div>Security Practice</div>
      <div style="margin-top:6px">consultim-it.com</div>
    </div>
  </div>

</div><!-- /page-wrap -->

<!-- ═══════════════════════════════════════════════════════════════════════
     JAVASCRIPT
═══════════════════════════════════════════════════════════════════════════ -->
<script>
// ── Tab Switching ─────────────────────────────────────────────────────────
var tabIds = ['t1','t2','t3','t4','t5'];
function switchTab(id) {
  tabIds.forEach(function(tid) {
    document.getElementById(tid).classList.toggle('active', tid === id);
  });
  document.querySelectorAll('.tab-btn').forEach(function(btn, i) {
    btn.classList.toggle('active', tabIds[i] === id);
  });
}

// ── Theme Toggle ─────────────────────────────────────────────────────────
var darkMode = true;
function toggleTheme() {
  darkMode = !darkMode;
  var r = document.documentElement;
  if (!darkMode) {
    r.style.setProperty('--bg',          '#f0f4f8');
    r.style.setProperty('--bg2',         '#e8eef8');
    r.style.setProperty('--surface',     '#ffffff');
    r.style.setProperty('--surface2',    '#f0f4fc');
    r.style.setProperty('--surface3',    '#e4eaf8');
    r.style.setProperty('--border',      '#c8d8f0');
    r.style.setProperty('--border2',     '#b0c4e8');
    r.style.setProperty('--text',        '#1a2a4a');
    r.style.setProperty('--text-muted',  '#5a7aaa');
    r.style.setProperty('--text-light',  '#8aaad8');
    r.style.setProperty('--accent3',     '#1a5cc0');
    r.style.setProperty('--shadow',      '0 4px 28px rgba(0,40,100,.12)');
    r.style.setProperty('--shadow-sm',   '0 2px 12px rgba(0,40,100,.08)');
  } else {
    r.style.cssText = '';
  }
  if (typeof renderCharts === 'function') renderCharts();
}

// ── Finding Card Expand ───────────────────────────────────────────────────
function toggleFc(id) {
  var body = document.getElementById(id);
  var icon = document.getElementById('icon-' + id);
  if (!body) return;
  var open = body.style.display !== 'none' && body.style.display !== '';
  body.style.display = open ? 'none' : 'block';
  if (icon) icon.classList.toggle('open', !open);
}

// ── Recommendation Expand ─────────────────────────────────────────────────
function toggleRec(id, btn) {
  var body = document.getElementById(id);
  if (!body) return;
  var open = body.style.display !== 'none' && body.style.display !== '';
  body.style.display = open ? 'none' : 'block';
  if (btn) btn.textContent = open ? 'Show Details' : 'Hide Details';
}

// ── Severity + Search Filter ──────────────────────────────────────────────
var curSev  = 'all';
var curSrch = '';
function filterSev(sev, btn) {
  curSev = sev;
  document.querySelectorAll('.f-btn').forEach(function(b) { b.classList.remove('active'); });
  if (btn) btn.classList.add('active');
  else {
    document.querySelectorAll('.f-btn').forEach(function(b) {
      if (b.textContent.indexOf('All') > -1) b.classList.add('active');
    });
  }
  applyFilter();
}
function filterFindings() {
  curSrch = document.getElementById('searchBox').value.toLowerCase();
  applyFilter();
}
function applyFilter() {
  var cards = document.querySelectorAll('.finding-card');
  cards.forEach(function(c) {
    var sevOk  = curSev === 'all' || c.getAttribute('data-sev') === curSev;
    var textOk = curSrch === '' || c.textContent.toLowerCase().indexOf(curSrch) > -1;
    c.classList.toggle('hidden', !(sevOk && textOk));
  });
}

// ── Copy to Clipboard ─────────────────────────────────────────────────────
function copyText(id) {
  var el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(function() { showToast('Copied to clipboard!'); });
}

// ── CSV Export ────────────────────────────────────────────────────────────
function exportCSV() {
  var findings = $FindingsJSON;
  var hdr = ['Severity','Priority','Category','Title','Description','Impact','Remediation','MitreID','MitreName','MitreTactic','Effort','Details'];
  var rows = [hdr];
  findings.forEach(function(f) {
    rows.push(hdr.map(function(k) {
      return '"' + (f[k] || '').toString().replace(/"/g,'""') + '"';
    }));
  });
  var blob = new Blob([rows.map(function(r){return r.join(',')}).join('\n')], {type:'text/csv'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'ConsultimIT-Findings-$Timestamp.csv';
  a.click();
  showToast('CSV exported — $TotalFindings findings');
}

// ── Toast ─────────────────────────────────────────────────────────────────
function showToast(msg) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(function() { t.classList.remove('show'); }, 2800);
}

// ── Integrated Attack Path Dashboard ───────────────────────────────────────
var attackData = $AttackSurfaceJSON;
var attackGraphReady = false;
var attackNetwork = null;

function apUniq(arr){ return Array.from(new Set((arr || []).filter(Boolean))); }
function apEsc(value){
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function apRiskRank(r){ return ({Critical:4, High:3, Medium:2, Low:1, Informational:0}[r] || 0); }
function apNodeColor(type, risk){
  var palette = {
    'User':'#34d399',
    'Group':'#a78bfa',
    'Computer':'#38bdf8',
    'Asset':'#f59e0b',
    'Principal':'#94a3b8',
    'Assessment':'#64748b'
  };
  var border = ({Critical:'#ef4444', High:'#f97316', Medium:'#f59e0b', Low:'#60a5fa'}[risk] || '#60a5fa');
  return { background: palette[type] || '#94a3b8', border: border, highlight:{ background: palette[type] || '#94a3b8', border: border }, hover:{ background: palette[type] || '#94a3b8', border: border } };
}
function apNodeShape(type){
  return ({User:'dot', Group:'hexagon', Computer:'box', Asset:'diamond', Principal:'ellipse', Assessment:'ellipse'}[type] || 'ellipse');
}
function apEdgeColor(risk){
  return ({Critical:'#ef4444', High:'#f97316', Medium:'#f59e0b', Low:'#60a5fa', Informational:'#94a3b8'}[risk] || '#60a5fa');
}
function getFilteredAttackPaths(){
  var risk = document.getElementById('asRiskFilter') ? document.getElementById('asRiskFilter').value : 'All';
  var tech = document.getElementById('asTechFilter') ? document.getElementById('asTechFilter').value.trim().toLowerCase() : '';
  var node = document.getElementById('asNodeFilter') ? document.getElementById('asNodeFilter').value.trim().toLowerCase() : '';
  var allPaths = Array.isArray(attackData.attackPaths) ? attackData.attackPaths : [];
  return allPaths.filter(function(p){
    var riskOk = risk === 'All' || p.risk === risk;
    var techOk = !tech || apUniq(p.techniqueMappings || []).join(' ').toLowerCase().includes(tech);
    var nodeOk = !node || JSON.stringify(p).toLowerCase().includes(node);
    return riskOk && techOk && nodeOk;
  }).sort(function(a,b){
    return apRiskRank(b.risk) - apRiskRank(a.risk) || ((b.riskScore || 0) - (a.riskScore || 0)) || ((a.hopCount || 99) - (b.hopCount || 99));
  });
}
function renderAttackKpis(paths){
  var critical = paths.filter(function(p){ return p.risk === 'Critical'; }).length;
  var partial  = paths.filter(function(p){ return !!p.isPartial; }).length;
  var cards = [
    ['Attack paths', paths.length],
    ['Critical paths', critical],
    ['Partial paths', partial],
    ['Graph nodes', attackData.graphSummary && attackData.graphSummary.nodeCount ? attackData.graphSummary.nodeCount : 0],
    ['Graph edges', attackData.graphSummary && attackData.graphSummary.edgeCount ? attackData.graphSummary.edgeCount : 0],
    ['Directory risk', (attackData.riskLevel || 'Unknown') + ' (' + (attackData.riskScore || 0) + '/100)']
  ];
  var el = document.getElementById('asKpis'); if(!el) return;
  el.innerHTML = cards.map(function(card){
    return '<div class="as-kpi"><div>' + apEsc(card[0]) + '</div><div class="v">' + apEsc(card[1]) + '</div></div>';
  }).join('');
}
function renderAttackPaths(paths){
  var container = document.getElementById('asPaths'); if(!container) return;
  if(!paths.length){
    container.innerHTML = '<div class="as-empty-state">No attack paths identified for the selected filters. The graph still renders the current directory relationship model so you can inspect high-risk entities manually. If zero paths persist after reset, treat the highest-risk nodes and relationships below as candidate escalation opportunities requiring analyst validation.</div>';
    return;
  }
  container.innerHTML = paths.map(function(p){
    var riskClass = String((p.risk || 'Low')).toLowerCase();
    var techniques = apUniq(p.techniqueMappings || []).join(', ') || 'None mapped';
    var pathLabel = p.isPartial ? 'Partial chain' : 'Full chain';
    var steps = (p.steps || []).map(function(s, idx){
      var mitre = s.Mitre ? ' · ' + apEsc(s.Mitre) : '';
      return '<div class="as-step">'
        + '<div><strong>Step ' + (idx + 1) + ':</strong> <span class="mono">' + apEsc(s.From) + '</span> → <span class="mono">' + apEsc(s.To) + '</span></div>'
        + '<div>' + apEsc(s.Relation) + ' · ' + apEsc(s.Risk) + mitre + '</div>'
        + '<div class="note">' + apEsc(s.Description || '') + '</div>'
        + '</div>';
    }).join('');
    return '<div class="as-path-card ' + riskClass + '">'
      + '<div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start"><div>'
      + '<span class="as-badge ' + apEsc(p.risk || 'Low') + '">' + apEsc(p.risk || 'Low') + '</span>'
      + '<span class="as-badge Medium">' + apEsc(pathLabel) + '</span>'
      + '<span class="as-badge Low">Hops: ' + apEsc(p.hopCount || 0) + '</span>'
      + '<div style="font-weight:800;margin-top:8px">' + apEsc(p.summary || 'Attack path') + '</div>'
      + '<div class="note" style="margin-top:6px">MITRE: ' + apEsc(techniques) + ' · Score: ' + apEsc(p.riskScore || 0) + '</div>'
      + '</div></div>'
      + steps
      + '<div class="as-step" style="border-left-color:#c8922a"><strong>Immediate consultant action</strong><br>' + apEsc(p.remediation || 'Break the shortest path by removing the exploitable relationship and validating compensating controls.') + '</div>'
      + '</div>';
  }).join('');
}
function renderAttackEntitySummary(paths){
  var byId = {};
  (attackData.entitySummary || []).forEach(function(node){
    byId[node.id || node.name] = {name: node.name || 'Unknown', type: node.type || 'Unknown', count: node.count || 0, risk: node.risk || 'Low', riskScore: node.riskScore || 0};
  });
  paths.forEach(function(p){
    (p.nodeSequence || []).forEach(function(nodeId){
      if(byId[nodeId]) byId[nodeId].count = Math.max(byId[nodeId].count || 0, byId[nodeId].count || 0);
    });
  });
  var rows = Object.keys(byId).map(function(k){ return byId[k]; }).sort(function(a,b){ return (b.riskScore || 0) - (a.riskScore || 0) || (b.count || 0) - (a.count || 0); }).slice(0,12);
  var el = document.getElementById('asEntitySummary'); if(!el) return;
  el.innerHTML = rows.map(function(r){
    return '<tr><td>' + apEsc(r.name) + '</td><td>' + apEsc(r.type) + '</td><td>' + apEsc(r.count || 0) + '</td><td>' + apEsc(r.risk) + '</td></tr>';
  }).join('') || '<tr><td colspan="4">No entity exposure data available.</td></tr>';
}
function renderAttackEdgeSummary(){
  var rows = Array.isArray(attackData.edgeSummary) ? attackData.edgeSummary : [];
  var el = document.getElementById('asEdgeSummary'); if(!el) return;
  el.innerHTML = rows.map(function(rel){
    return '<tr><td>' + apEsc(rel.relation || rel.type || 'Unknown') + '</td><td>' + apEsc(rel.count || 0) + '</td><td>' + apEsc(rel.risk || 'Low') + '</td></tr>';
  }).join('') || '<tr><td colspan="3">No relationship data available.</td></tr>';
}
function renderAttackExposureSummary(){
  var ex = attackData.exposureSummary || {};
  var items = [
    ['Kerberoastable accounts', (ex.Kerberoastable || []).length],
    ['AS-REP roastable accounts', (ex.ASREPRoastable || []).length],
    ['Unconstrained delegation objects', (ex.UnconstrainedDelegation || []).length],
    ['Constrained delegation mappings', (ex.ConstrainedDelegation || []).length],
    ['RBCD objects', (ex.ResourceDelegation || []).length],
    ['Shadow admin / ACL control entries', (ex.ShadowAdmins || []).length]
  ];
  var top = Array.isArray(ex.TopRiskEntities) ? ex.TopRiskEntities.slice(0,3).map(function(n){ return (n.name || 'Unknown') + ' [' + (n.risk || 'Low') + ' / ' + (n.riskScore || 0) + ']'; }) : [];
  var el = document.getElementById('asExposureSummary'); if(!el) return;
  el.innerHTML = items.map(function(item){
    return '<div class="exposure-item">' + apEsc(item[0]) + ': <strong>' + apEsc(item[1]) + '</strong></div>';
  }).join('') + (top.length ? '<div class="exposure-item"><strong>Top exposed entities:</strong><br>' + apEsc(top.join(' | ')) + '</div>' : '');
}
function renderAttackImmediateActions(paths){
  var top = paths.slice(0,3).map(function(p){ return p.remediation; }).filter(Boolean);
  var defaults = [
    'Break the shortest red path first by removing direct privileged group reachability or ACL-based control.',
    'Disable or rotate exposed service accounts and any privileged roastable identities.',
    'Remove unconstrained or unnecessary constrained delegation and validate every RBCD assignment.',
    'Reduce interactive access to Tier-0 systems and remove non-essential AdminTo / CanRDP relationships.'
  ];
  var actions = apUniq(top.concat(defaults)).slice(0,5);
  var el = document.getElementById('asImmediateActions'); if(!el) return;
  el.innerHTML = actions.map(function(a){ return '<div class="exposure-item">• ' + apEsc(a) + '</div>'; }).join('');
}
function renderSelectedNode(node){
  var el = document.getElementById('asSelectedNode'); if(!el) return;
  if(!node){
    el.innerHTML = 'Select a node in the graph to review its exposure score, path frequency, and object metadata.';
    return;
  }
  var props = node.properties || {};
  var detailKeys = Object.keys(props).filter(function(k){ return ['entityRiskScore','exposureLevel','pathHits'].indexOf(k) === -1; }).slice(0,8);
  var detailHtml = detailKeys.map(function(k){
    return '<div class="as-node-tile"><div class="k">' + apEsc(k) + '</div><div class="v">' + apEsc(props[k]) + '</div></div>';
  }).join('');
  el.innerHTML = ''
    + '<div style="font-weight:800;font-size:1rem">' + apEsc(node.name || node.label || 'Unknown') + '</div>'
    + '<div class="note" style="margin-top:4px">' + apEsc(node.type || 'Unknown') + ' · Exposure ' + apEsc(node.exposureLevel || node.risk || 'Low') + ' · Score ' + apEsc(node.riskScore || 0) + '</div>'
    + '<div class="as-node-meta">'
    +   '<div class="as-node-tile"><div class="k">Path hits</div><div class="v">' + apEsc(node.pathHits || 0) + '</div></div>'
    +   '<div class="as-node-tile"><div class="k">Node id</div><div class="v mono">' + apEsc(node.id || '') + '</div></div>'
    +   detailHtml
    + '</div>';
}
function buildGraphData(paths){
  var graph = attackData.graph || {nodes:[], edges:[]};
  var allNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  var allEdges = Array.isArray(graph.edges) ? graph.edges : [];
  var allowedNodes = new Set();
  var allowedEdges = [];

  if(paths.length){
    paths.forEach(function(path){
      (path.nodeSequence || []).forEach(function(id){ if(id) allowedNodes.add(id); });
    });
    allEdges.forEach(function(edge){
      if(allowedNodes.has(edge.from) && allowedNodes.has(edge.to)){ allowedEdges.push(edge); }
    });
  } else {
    allNodes.sort(function(a,b){ return (b.riskScore || 0) - (a.riskScore || 0) || (b.pathHits || 0) - (a.pathHits || 0); }).slice(0,12).forEach(function(node){ allowedNodes.add(node.id); });
    allEdges.forEach(function(edge){
      if(allowedNodes.has(edge.from) && allowedNodes.has(edge.to) && allowedEdges.length < 20){ allowedEdges.push(edge); }
    });
  }

  var selectedNodes = allNodes.filter(function(node){ return allowedNodes.has(node.id); });
  if(!selectedNodes.length){
    selectedNodes = [{
      id:'placeholder:start', label:'Directory Review', name:'Directory Review', type:'Assessment', riskScore:0, exposureLevel:'Low', pathHits:0, properties:{placeholder:true}
    },{
      id:'placeholder:end', label:'No attack paths identified', name:'No attack paths identified', type:'Assessment', riskScore:0, exposureLevel:'Low', pathHits:0, properties:{placeholder:true}
    }];
    allowedEdges = [{
      id:'placeholder:edge', from:'placeholder:start', to:'placeholder:end', relation:'AssessmentResult', label:'AssessmentResult', risk:'Low', description:'No attack paths identified from the current relationship data.', weight:1, properties:{placeholder:true}
    }];
  }

  return {
    nodes: selectedNodes.map(function(node){
      var value = Math.max(16, (node.riskScore || 0) + ((node.pathHits || 0) * 4));
      return {
        id: node.id,
        label: node.label || node.name,
        name: node.name,
        type: node.type,
        riskScore: node.riskScore || 0,
        exposureLevel: node.exposureLevel || 'Low',
        pathHits: node.pathHits || 0,
        properties: node.properties || {},
        shape: apNodeShape(node.type),
        value: value,
        color: apNodeColor(node.type, node.exposureLevel || 'Low'),
        borderWidth: apRiskRank(node.exposureLevel || 'Low') >= 3 ? 3 : 2,
        font: { color:'#e2e8f0', face:'Segoe UI', size:14, strokeWidth:0 },
        title: '<strong>' + apEsc(node.name || node.label || 'Unknown') + '</strong><br>'
          + 'Type: ' + apEsc(node.type || 'Unknown') + '<br>'
          + 'Exposure: ' + apEsc(node.exposureLevel || 'Low') + '<br>'
          + 'Risk score: ' + apEsc(node.riskScore || 0) + '<br>'
          + 'Path hits: ' + apEsc(node.pathHits || 0)
      };
    }),
    edges: allowedEdges.map(function(edge){
      var highRisk = apRiskRank(edge.risk) >= 3;
      return {
        id: edge.id,
        from: edge.from,
        to: edge.to,
        label: edge.label || edge.relation || '',
        arrows: 'to',
        color: { color: apEdgeColor(edge.risk), highlight: apEdgeColor(edge.risk), hover: apEdgeColor(edge.risk), opacity: highRisk ? 1 : 0.8 },
        width: highRisk ? 3.5 : (edge.risk === 'Medium' ? 2.5 : 2),
        dashes: !!(edge.properties && edge.properties.placeholder),
        smooth: { enabled:true, type:'dynamic' },
        font: { color:'#cbd5e1', size:11, strokeWidth:0, background:'rgba(15,23,42,0.85)' },
        title: '<strong>' + apEsc(edge.relation || 'Relationship') + '</strong><br>'
          + 'Risk: ' + apEsc(edge.risk || 'Low') + '<br>'
          + (edge.mitre ? ('MITRE: ' + apEsc(edge.mitre) + '<br>') : '')
          + apEsc(edge.description || '')
      };
    })
  };
}
function renderAttackGraph(paths){
  var canvas = document.getElementById('asGraphCanvas');
  if(!canvas) return;
  if(!window.vis || !window.vis.Network){
    canvas.innerHTML = '<div class="as-empty-state">The interactive graph library could not be loaded. The attack paths and entity summaries are still available below.</div>';
    return;
  }
  var graphData = buildGraphData(paths);
  var nodes = new vis.DataSet(graphData.nodes);
  var edges = new vis.DataSet(graphData.edges);
  var options = {
    autoResize:true,
    physics:{ stabilization:false, barnesHut:{ gravitationalConstant:-9000, springLength:180, springConstant:0.02, damping:0.18 } },
    interaction:{ hover:true, tooltipDelay:120, navigationButtons:true, keyboard:true, zoomView:true, dragView:true },
    nodes:{ shadow:true, scaling:{ min:16, max:42 } },
    edges:{ shadow:false, selectionWidth:2, color:{ inherit:false } },
    layout:{ improvedLayout:true }
  };
  if(attackNetwork){ attackNetwork.destroy(); }
  attackNetwork = new vis.Network(canvas, {nodes:nodes, edges:edges}, options);
  attackNetwork.once('stabilizationIterationsDone', function(){ attackNetwork.fit({animation:{duration:350}}); });
  attackNetwork.on('selectNode', function(params){
    var node = nodes.get(params.nodes[0]);
    renderSelectedNode(node);
  });
  attackNetwork.on('deselectNode', function(){ renderSelectedNode(null); });
}
function renderAttackDashboard(){
  var paths = getFilteredAttackPaths();
  renderAttackKpis(paths);
  renderAttackGraph(paths);
  renderAttackPaths(paths);
  renderAttackEntitySummary(paths);
  renderAttackEdgeSummary();
  renderAttackExposureSummary();
  renderAttackImmediateActions(paths);
}
function resetAttackFilters(){
  if(document.getElementById('asRiskFilter')) document.getElementById('asRiskFilter').value='All';
  if(document.getElementById('asTechFilter')) document.getElementById('asTechFilter').value='';
  if(document.getElementById('asNodeFilter')) document.getElementById('asNodeFilter').value='';
  renderAttackDashboard();
}

// ── Charts (Chart.js) ─────────────────────────────────────────────────────
var chartSevInst = null;
var chartCatInst = null;

function renderCharts() {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.color = darkMode ? '#6e8ab8' : '#5a7aaa';

  var gridColor = darkMode ? '#1e3060' : '#c8d8f0';
  var bgColor   = darkMode ? '#101e36' : '#ffffff';

  if (chartSevInst) chartSevInst.destroy();
  chartSevInst = new Chart(document.getElementById('chartSev').getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low','Informational'],
      datasets: [{
        data: [$CriticalCount,$HighCount,$MediumCount,$LowCount,$InfoCount],
        backgroundColor: ['#c0392b','#e74c3c','#e67e22','#2980b9','#636e72'],
        borderColor: bgColor,
        borderWidth: 3,
        hoverOffset: 10
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '68%',
      plugins: {
        legend: { position: 'right', labels: { boxWidth: 12, padding: 14, font: { size: 12 } } },
        tooltip: { callbacks: { label: function(c) { return ' '+c.label+': '+c.parsed+' findings'; } } }
      }
    }
  });

  if (chartCatInst) chartCatInst.destroy();
  chartCatInst = new Chart(document.getElementById('chartCat').getContext('2d'), {
    type: 'bar',
    data: {
      labels: [$CatLabelsJS],
      datasets: [{
        label: 'Findings',
        data: [$CatCountsJS],
        backgroundColor: [
          'rgba(200,146,42,.85)','rgba(192,57,43,.85)','rgba(231,76,60,.85)',
          'rgba(230,126,34,.85)','rgba(41,128,185,.85)','rgba(99,110,114,.85)',
          'rgba(46,125,233,.85)','rgba(39,174,96,.85)'
        ],
        borderRadius: 5,
        borderSkipped: false
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: gridColor }, ticks: { precision: 0 } },
        y: { grid: { display: false }, ticks: { font: { size: 11 } } }
      }
    }
  });
}

(function() {
  var chartLoader = document.createElement('script');
  chartLoader.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
  chartLoader.onload = function() { renderCharts(); };
  document.head.appendChild(chartLoader);

  var visLoader = document.createElement('script');
  visLoader.src = 'https://cdn.jsdelivr.net/npm/vis-network@9.1.9/dist/vis-network.min.js';
  visLoader.onload = function() { attackGraphReady = true; renderAttackDashboard(); };
  document.head.appendChild(visLoader);

  renderAttackDashboard();
})();
</script>
</body>
</html>
"@

$HTML | Out-File -FilePath $DetailedReportFile -Encoding UTF8 -Force
Write-Log "Detailed HTML assessment report generated: $DetailedReportFile" "SUCCESS"

$HTML | Out-File -FilePath $ReportFile -Encoding UTF8 -Force
Write-Log "Primary HTML report generated: $ReportFile" "SUCCESS"

# Save execution log
$LogFile = Join-Path $OutputPath "ConsultimIT-ScanLog_$Timestamp.txt"
$script:LogLines | Out-File -FilePath $LogFile -Encoding UTF8

# ════════════════════════════════════════════════════════════════════════════
#  SECTION 14 — CONSOLE SUMMARY
# ════════════════════════════════════════════════════════════════════════════
Write-Host ""
$w = 70
Write-Host "  ╔$("═"*$w)╗" -ForegroundColor DarkYellow
Write-Host "  ║$("  CONSULTIM-IT  ·  AD ASSESSMENT v2.1  ·  SCAN COMPLETE".PadRight($w))║" -ForegroundColor DarkYellow
Write-Host "  ╠$("═"*$w)╣" -ForegroundColor DarkYellow

$lines = @(
    @("  Client",    $ClientCompany),
    @("  Domain",    $Domain),
    @("  Forest",    $ForestObj.RootDomain),
    @("  Mode",      $ScanMode),
    @("  Duration",  $DurationStr),
    @("  Users",     "$($script:Stats.TotalUsers) total / $($script:Stats.EnabledUsers) enabled"),
    @("  Computers", "$($script:Stats.TotalComputers) / $($script:Stats.DomainControllers) DCs")
)
foreach ($l in $lines) {
    $key = $l[0].PadRight(14)
    $val = $l[1]
    $row = "  ║  ${key}: ${val}"
    Write-Host $row.PadRight($w+4) -ForegroundColor White
}

Write-Host "  ╠$("═"*$w)╣" -ForegroundColor DarkYellow

$rColor = if ($RiskLevel -in "CRITICAL","HIGH") { "Red" } elseif ($RiskLevel -eq "MEDIUM") { "Yellow" } else { "Green" }
Write-Host "  ║  Risk Score  : $RiskScore / 100  ($RiskLevel)".PadRight($w+4) -ForegroundColor $rColor
Write-Host "  ║  Findings    : $TotalFindings total".PadRight($w+4) -ForegroundColor White

$fc = @("  ║    ├─ Critical     : $CriticalCount","  ║    ├─ High         : $HighCount","  ║    ├─ Medium       : $MediumCount","  ║    ├─ Low          : $LowCount","  ║    └─ Informational: $InfoCount")
$fc | ForEach-Object { Write-Host $_.PadRight($w+4) -ForegroundColor $(if($_ -match "Critical"){"Red"}elseif($_ -match "High"){"DarkRed"}elseif($_ -match "Medium"){"Yellow"}elseif($_ -match "Low"){"Cyan"}else{"Gray"}) }

Write-Host "  ╠$("═"*$w)╣" -ForegroundColor DarkYellow
Write-Host "  ║  Launcher    : $ReportFile".PadRight($w+4) -ForegroundColor Green
Write-Host "  ║  Attack UI   : $AttackSurfaceReportFile".PadRight($w+4) -ForegroundColor Green
Write-Host "  ║  Assessment  : $DetailedReportFile".PadRight($w+4) -ForegroundColor Green
if ($ExportExcel -and (Test-Path (Join-Path $OutputPath "ConsultimIT-AD-Report_$Timestamp.xlsx"))) {
    Write-Host "  ║  Excel       : $(Join-Path $OutputPath "ConsultimIT-AD-Report_$Timestamp.xlsx")".PadRight($w+4) -ForegroundColor Green
}
if ($ExportSentinel -and (Test-Path (Join-Path $OutputPath "ConsultimIT-Sentinel_$Timestamp.json"))) {
    Write-Host "  ║  Sentinel    : $(Join-Path $OutputPath "ConsultimIT-Sentinel_$Timestamp.json")".PadRight($w+4) -ForegroundColor Green
}
Write-Host "  ║  Scan Log    : $LogFile".PadRight($w+4) -ForegroundColor DarkGray
Write-Host "  ╠$("═"*$w)╣" -ForegroundColor DarkYellow

if ($script:ScanErrors.Count -gt 0) {
    Write-Host "  ║  Scan Warnings: $($script:ScanErrors.Count) non-fatal errors occurred (see log)".PadRight($w+4) -ForegroundColor Yellow
    Write-Host "  ╠$("═"*$w)╣" -ForegroundColor DarkYellow
}

Write-Host "  ║$("  Consultim-IT Security Practice  ·  Author: Ranim Hassine".PadRight($w))║" -ForegroundColor DarkGray
Write-Host "  ╚$("═"*$w)╝" -ForegroundColor DarkYellow
Write-Host ""