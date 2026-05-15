<#
.SYNOPSIS
    This PowerShell script ensures that printing over HTTP is disabled on Windows 11.

.DESCRIPTION
    The script targets HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers to remediate 
    STIG ID WN11-CC-000110. It ensures the 'DisableHTTPPrinting' DWORD is set to 1, 
    preventing potentially sensitive information from being sent outside the 
    enterprise and stopping uncontrolled updates via HTTP printing features.

.NOTES
    Author          : Michael Kirby
    LinkedIn        : https://www.linkedin.com/in/wmkirby/
    GitHub          : https://github.com/MichaelKirbyIT
    Date Created    : 2026-05-15
    Last Modified   : 2026-05-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000110
    Severity        : Medium (CAT II)
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000110/

#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$valName = "DisableHTTPPrinting"
$desired = 1

Write-Host "--- STIG Compliance Check: Disable HTTP Printing ---" -ForegroundColor Cyan

# 1. THE CHECK: Does the value exist and match the STIG requirement?
$currentValue = Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue

if ($null -ne $currentValue -and $currentValue.$valName -eq $desired) {
    Write-Host "[PASS] $valName is already set to $desired (Enabled/Blocked)." -ForegroundColor Green
} 
else {
    Write-Host "[FAIL] $valName is non-compliant or missing. Remediating..." -ForegroundColor Yellow

    # 2. THE FIX: Create path and set DWORD
    try {
        if (-not (Test-Path $regPath)) {
            # Use -Force to ensure the nested "Windows NT\Printers" path is created correctly
            New-Item -Path $regPath -Force | Out-Null
            Write-Host "Created missing registry path: $regPath" -ForegroundColor Gray
        }

        Set-ItemProperty -Path $regPath -Name $valName -Value $desired -Type DWord
        
        # 3. VERIFICATION: Confirm the change was written
        $verify = Get-ItemProperty -Path $regPath -Name $valName
        if ($verify.$valName -eq $desired) {
            Write-Host "[SUCCESS] $valName applied. Value set to $desired." -ForegroundColor Green
            
            # Refresh Group Policy to apply the setting immediately
            gpupdate /force
        }
    } 
    catch {
        Write-Host "[ERROR] Failed to remediate $valName : $($_.Exception.Message)" -ForegroundColor Red
    }
}
