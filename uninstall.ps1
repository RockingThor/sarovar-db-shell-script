<#
.SYNOPSIS
    Uninstaller for SQL Server BAK to S3 Backup Solution
.DESCRIPTION
    Removes the scheduled task and optionally deletes installation files.
.PARAMETER KeepLogs
    Keep log files when uninstalling
.PARAMETER KeepConfig
    Keep configuration file when uninstalling
.PARAMETER InstallPath
    Installation directory (default: C:\SarovarBackup)
.PARAMETER Silent
    Run without prompts
.EXAMPLE
    .\uninstall.ps1
.EXAMPLE
    .\uninstall.ps1 -Silent -KeepLogs
#>

param(
    [switch]$KeepLogs,
    [switch]$KeepConfig,
    [string]$InstallPath = "C:\SarovarBackup",
    [switch]$Silent
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )
    
    switch ($Type) {
        "Success" { Write-Host "[OK] $Message" -ForegroundColor Green }
        "Warning" { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "[ERROR] $Message" -ForegroundColor Red }
        default   { Write-Host "[*] $Message" -ForegroundColor Cyan }
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Main {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  SQL BAK to S3 - Uninstaller" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Write-Status "This uninstaller requires Administrator privileges." "Error"
        Write-Status "Please run PowerShell as Administrator and try again." "Error"
        exit 1
    }
    
    # Confirm uninstallation
    if (-not $Silent) {
        Write-Host "This will remove:" -ForegroundColor Yellow
        Write-Host "  - Scheduled task: ASTechXSarovarBackup" -ForegroundColor White
        Write-Host "  - Installation directory: $InstallPath" -ForegroundColor White
        if (-not $KeepLogs) {
            Write-Host "  - Log files" -ForegroundColor White
        }
        if (-not $KeepConfig) {
            Write-Host "  - Configuration file (contains AWS credentials)" -ForegroundColor White
        }
        Write-Host ""
        $confirm = Read-Host "Are you sure you want to continue? (y/N)"
        if ($confirm -ne 'y') {
            Write-Status "Uninstallation cancelled" "Info"
            exit 0
        }
    }
    
    Write-Host ""
    
    # Remove scheduled task
    $taskName = "ASTechXSarovarBackup"
    Write-Status "Removing scheduled task..." "Info"
    
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        # Stop task if running
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Status "Scheduled task removed" "Success"
    }
    else {
        Write-Status "Scheduled task not found (already removed)" "Warning"
    }
    
    # Remove files
    if (Test-Path $InstallPath) {
        Write-Status "Removing installation files..." "Info"
        
        # Keep specific files if requested
        $filesToKeep = @()
        
        if ($KeepLogs) {
            $logsPath = Join-Path $InstallPath "logs"
            if (Test-Path $logsPath) {
                $tempLogsPath = Join-Path $env:TEMP "SarovarBackup_logs_backup"
                Copy-Item $logsPath $tempLogsPath -Recurse -Force
                $filesToKeep += @{ Source = $tempLogsPath; Dest = $logsPath }
            }
        }
        
        if ($KeepConfig) {
            $configPath = Join-Path $InstallPath "config.json"
            if (Test-Path $configPath) {
                $tempConfigPath = Join-Path $env:TEMP "SarovarBackup_config_backup.json"
                Copy-Item $configPath $tempConfigPath -Force
                $filesToKeep += @{ Source = $tempConfigPath; Dest = $configPath }
            }
        }
        
        # Remove directory
        Remove-Item $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Status "Installation directory removed" "Success"
        
        # Restore kept files
        foreach ($item in $filesToKeep) {
            if (Test-Path $item.Source) {
                $parentDir = Split-Path $item.Dest -Parent
                if (-not (Test-Path $parentDir)) {
                    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
                }
                Move-Item $item.Source $item.Dest -Force
            }
        }
        
        if ($KeepLogs -or $KeepConfig) {
            Write-Status "Kept requested files in: $InstallPath" "Info"
        }
    }
    else {
        Write-Status "Installation directory not found: $InstallPath" "Warning"
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Uninstallation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    
    if ($KeepLogs) {
        Write-Host "Log files preserved in: $(Join-Path $InstallPath 'logs')" -ForegroundColor Yellow
    }
    if ($KeepConfig) {
        Write-Host "Configuration preserved in: $(Join-Path $InstallPath 'config.json')" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# Run main function
Main
