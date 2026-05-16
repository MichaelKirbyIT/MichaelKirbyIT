<#
.SYNOPSIS
    This PowerShell script ensures 'Other Object Access Events' successes are audited and forces policy override persistence.

.DESCRIPTION
    The script targets Advanced Audit Policies to remediate STIG ID WN11-AU-000083. 
    It explicitly enables the master subcategory override switch (WN11-SO-000030) and injects 
    the 'Success' logging state directly into the local Group Policy audit database to clear the Tenable finding.

.NOTES
    Author          : Michael Kirby
    LinkedIn        : https://www.linkedin.com/in/wmkirby/
    GitHub          : https://github.com/MichaelKirbyIT
    Date Created    : 2026-05-16
    Last Modified   : 2026-05-16
    Version         : 2.0
    STIG-ID         : WN11-AU-000083
    Severity        : Medium (CAT II)
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000083/
#>

$subcategoryName = "Other Object Access Events"
$guid = "{0cce923c-69ae-11d9-bed3-505054503030}" # Subcategory GUID for Other Object Access Events

Write-Host "--- STIG Compliance Check: Advanced Audit Policy Infrastructure ---" -ForegroundColor Cyan

# Step 1: Enforce the Master Override Switch (WN11-SO-000030)
$overridePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\Operational"
$overrideValue = "ProcessSubcategoryAuditPolicy"

try {
    if (-not (Test-Path $overridePath)) {
        New-Item -Path $overridePath -Force | Out-Null
    }
    Set-ItemProperty -Path $overridePath -Name $overrideValue -Value 1 -Type DWord | Out-Null
    Write-Host "[SUCCESS] Master Override Switch enabled via Registry." -ForegroundColor Green
}
catch {
    Write-Host "[WARNING] Failed to write Master Override Switch registry key." -ForegroundColor Yellow
}

# Step 2: The Compliance Check
$currentConfig = auditpol /get /subcategory:$subcategoryName /r
$isCompliant = $currentConfig -match "Success" -and $currentConfig -notmatch "No Auditing"

if ($isCompliant) {
    Write-Host "[PASS] $subcategoryName is already logging Success events." -ForegroundColor Green
} 
else {
    Write-Host "[FAIL] $subcategoryName is non-compliant or unconfigured. Enforcing via GPO Database..." -ForegroundColor Yellow

    try {
        # Step 3: Run the live command
        auditpol /set /subcategory:$subcategoryName /success:enable | Out-Null

        # Step 4: Inject directly into the Local GPO filesystem file to make it permanent
        $gpoAuditDir = "$env:windir\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit"
        $gpoAuditFile = "$gpoAuditDir\audit.csv"

        if (-not (Test-Path $gpoAuditDir)) {
            New-Item -Path $gpoAuditDir -ItemType Directory -Force | Out-Null
        }

        # Format compliant text block for the system audit database file
        $csvHeader = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value"
        $csvLine = ",Machine,$subcategoryName,$guid,Success,No,,1"

        if (Test-Path $gpoAuditFile) {
            $content = Get-Content $gpoAuditFile
            if ($content -notmatch $guid) {
                Add-Content -Path $gpoAuditFile -Value $csvLine
            }
        }
        else {
            Set-Content -Path $gpoAuditFile -Value $csvHeader
            Add-Content -Path $gpoAuditFile -Value $csvLine
        }

        # Step 5: Verification and Final Engine Flush
        gpupdate /force | Out-Null
        
        $verifyConfig = auditpol /get /subcategory:$subcategoryName /r
        if ($verifyConfig -match "Success") {
            Write-Host "[SUCCESS] Advanced Audit Policy successfully committed to GPO engine database." -ForegroundColor Green
        }
        else {
            Write-Host "[ERROR] System engineering blocks changes from saving." -ForegroundColor Red
        }
    } 
    catch {
        Write-Host "[ERROR] Execution failure: $($_.Exception.Message)" -ForegroundColor Red
    }
}
