<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.DESCRIPTION
    The script targets HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application to remediate STIG ID WN11-AU-000500. 
    It ensures the 'MaxSize' DWORD is set to 32768 KB, preventing the loss of audit data 
    due to inadequate log size and ensuring sufficient historical data for security investigations.

.NOTES
    Author          : Michael Kirby
    LinkedIn        : https://www.linkedin.com/in/wmkirby/
    GitHub          : https://github.com/MichaelKirbyIT
    Date Created    : 2026-05-15
    Last Modified   : 2026-05-15
    Version         : 1.0
    STIG-ID         : WN11-AU-000500
    Severity        : Medium (CAT II)
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000500/
#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$valName = "MaxSize"
$desired = 32768 # 32MB in KB (0x00008000)

Write-Host "--- STIG Compliance Check: Application Event Log Size ---" -ForegroundColor Cyan

# 1. THE CHECK: Does the value exist and is it at least the desired size?
$currentValue = Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue

if ($null -ne $currentValue -and $currentValue.$valName -ge $desired) {
    Write-Host "[PASS] $valName is already set to $($currentValue.$valName) KB." -ForegroundColor Green
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
        
        # 3. VERIFICATION: Confirm the change
        $verify = Get-ItemProperty -Path $regPath -Name $valName
        if ($verify.$valName -eq $desired) {
            Write-Host "[SUCCESS] $valName applied. Value set to $desired KB." -ForegroundColor Green
            
            # Apply changes
            gpupdate /force
        }
    } 
    catch {
        Write-Host "[ERROR] Failed to remediate $valName : $($_.Exception.Message)" -ForegroundColor Red
    }
}
