<#
.SYNOPSIS
    This PowerShell script ensures that Windows Group Policy registry processing is configured to 
    'Process even if the Group Policy objects have not changed' and does not skip during periodic background processing.

.DESCRIPTION
    The script targets the HKLM Policies hive to remediate STIG ID WN11-CC-000090. It verifies 
    the existence of the 'NoGPOListChanges' and 'NoBackgroundPolicy' DWORD values and sets 
    them to 0 if they are non-compliant or missing.

.NOTES
    Author          : Michael Kirby
    LinkedIn        : https://www.linkedin.com/in/wmkirby/
    GitHub          : https://github.com/MichaelKirbyIT
    Date Created    : 2026-05-14
    Last Modified   : 2026-05-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000090
    Severity        : Medium (CAT II)
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000090/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000090)
#>

# STIG ID: WN11-CC-000090
# Description: Registry Policy Processing (NoGPOListChanges & NoBackgroundPolicy)

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"

# Define the multiple settings required for this STIG
$stigSettings = @{
    "NoGPOListChanges"   = 0
    "NoBackgroundPolicy" = 0
}

Write-Host "--- STIG Compliance Check: Registry Policy Processing ---" -ForegroundColor Cyan

foreach ($valName in $stigSettings.Keys) {
    $desired = $stigSettings[$valName]
    
    # 1. THE CHECK: Check each value individually
    $currentValue = Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue

    if ($null -ne $currentValue -and $currentValue.$valName -eq $desired) {
        Write-Host "[PASS] $valName is already set to $desired." -ForegroundColor Green
    } 
    else {
        Write-Host "[FAIL] $valName is non-compliant. Remediating..." -ForegroundColor Yellow

        # 2. THE FIX
        try {
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
                Write-Host "Created missing registry path." -ForegroundColor Gray
            }

            Set-ItemProperty -Path $regPath -Name $valName -Value $desired -Type DWord
            
            # 3. VERIFICATION
            $verify = Get-ItemProperty -Path $regPath -Name $valName
            if ($verify.$valName -eq $desired) {
                Write-Host "[SUCCESS] $valName applied. Value set to $desired." -ForegroundColor Green
            }
        } 
        catch {
            Write-Host "[ERROR] Failed to remediate $valName : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Force Group Policy refresh once at the end if any changes were made
Write-Host "Refreshing Group Policy..." -ForegroundColor Gray
gpupdate /force
