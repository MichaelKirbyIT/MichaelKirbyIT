<#
.SYNOPSIS
    This PowerShell script ensures the Windows Installer 'AlwaysInstallElevated' feature is disabled.

.DESCRIPTION
    The script targets HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer to remediate STIG ID WN11-CC-000315. 
    It ensures the 'AlwaysInstallElevated' DWORD is set to 0, preventing standard users from 
    installing applications with elevated privileges.

.NOTES
    Author          : Michael Kirby
    LinkedIn        : https://www.linkedin.com/in/wmkirby/
    GitHub          : https://github.com/MichaelKirbyIT
    Date Created    : 2026-05-14
    Last Modified   : 2026-05-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315
    Severity        : High (CAT I)
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000315/
#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$valName = "AlwaysInstallElevated"
$desired = 0

Write-Host "--- STIG Compliance Check: Windows Installer Elevation ---" -ForegroundColor Cyan

# 1. THE CHECK: Does the value exist and match the STIG requirement?
$currentValue = Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue

if ($null -ne $currentValue -and $currentValue.$valName -eq $desired) {
    Write-Host "[PASS] $valName is already set to $desired (Disabled)." -ForegroundColor Green
} 
else {
    Write-Host "[FAIL] $valName is non-compliant or missing. Remediating..." -ForegroundColor Yellow

    # 2. THE FIX: Create path and set DWORD
    try {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-Host "Created missing registry path: $regPath" -ForegroundColor Gray
        }

        Set-ItemProperty -Path $regPath -Name $valName -Value $desired -Type DWord
        
        # 3. VERIFICATION: Confirm the change was written
        $verify = Get-ItemProperty -Path $regPath -Name $valName
        if ($verify.$valName -eq $desired) {
            Write-Host "[SUCCESS] $valName applied. Value set to $desired." -ForegroundColor Green
            
            # Force Group Policy to recognize the change
            gpupdate /force
        }
    } 
    catch {
        Write-Host "[ERROR] Failed to remediate $valName : $($_.Exception.Message)" -ForegroundColor Red
    }
}
