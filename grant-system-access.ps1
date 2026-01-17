<#
.SYNOPSIS
    Grants NT AUTHORITY\SYSTEM access to SQL Server databases
.DESCRIPTION
    Run this script as Administrator on your Windows SQL Server machine
    to grant the SYSTEM account permission to access the backup databases.
.PARAMETER SqlServer
    SQL Server instance name (default: localhost)
.PARAMETER Database
    Database name to grant access to (default: NEXT70)
.EXAMPLE
    .\grant-system-access.ps1
.EXAMPLE
    .\grant-system-access.ps1 -SqlServer "SERVER\INSTANCE" -Database "MyDatabase"
#>

param(
    [string]$SqlServer = "localhost",
    [string]$Database = "NEXT70"
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

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Grant SYSTEM SQL Server Access" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Import SqlServer module
try {
    Import-Module SqlServer -ErrorAction SilentlyContinue
    if (-not (Get-Command Invoke-Sqlcmd -ErrorAction SilentlyContinue)) {
        Import-Module SQLPS -DisableNameChecking -ErrorAction SilentlyContinue
    }
}
catch {
    Write-Status "SqlServer module not found. Please install: Install-Module -Name SqlServer" "Error"
    exit 1
}

Write-Status "SQL Server: $SqlServer" "Info"
Write-Status "Database: $Database" "Info"
Write-Host ""

# Step 1: Create login in master database
Write-Status "Step 1: Creating SQL Server login for NT AUTHORITY\SYSTEM..." "Info"

$createLoginQuery = @"
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'NT AUTHORITY\SYSTEM')
BEGIN
    CREATE LOGIN [NT AUTHORITY\SYSTEM] FROM WINDOWS WITH DEFAULT_DATABASE=[master];
    SELECT 'CREATED' AS Result;
END
ELSE
BEGIN
    SELECT 'EXISTS' AS Result;
END
"@

try {
    $result = Invoke-Sqlcmd -ServerInstance $SqlServer -Database "master" -Query $createLoginQuery
    if ($result.Result -eq "CREATED") {
        Write-Status "Login created: NT AUTHORITY\SYSTEM" "Success"
    }
    else {
        Write-Status "Login already exists: NT AUTHORITY\SYSTEM" "Success"
    }
}
catch {
    Write-Status "Failed to create login: $_" "Error"
    exit 1
}

# Step 2: Create database user and grant permissions
Write-Status "Step 2: Granting access to $Database database..." "Info"

$createUserQuery = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'NT AUTHORITY\SYSTEM')
BEGIN
    CREATE USER [NT AUTHORITY\SYSTEM] FOR LOGIN [NT AUTHORITY\SYSTEM];
    SELECT 'CREATED' AS Result;
END
ELSE
BEGIN
    SELECT 'EXISTS' AS Result;
END
"@

try {
    $result = Invoke-Sqlcmd -ServerInstance $SqlServer -Database $Database -Query $createUserQuery
    if ($result.Result -eq "CREATED") {
        Write-Status "Database user created in $Database" "Success"
    }
    else {
        Write-Status "Database user already exists in $Database" "Success"
    }
}
catch {
    Write-Status "Failed to create database user: $_" "Error"
    exit 1
}

# Grant db_datareader role
$grantRoleQuery = "ALTER ROLE [db_datareader] ADD MEMBER [NT AUTHORITY\SYSTEM];"

try {
    Invoke-Sqlcmd -ServerInstance $SqlServer -Database $Database -Query $grantRoleQuery
    Write-Status "Granted db_datareader role to NT AUTHORITY\SYSTEM" "Success"
}
catch {
    # Role may already be granted, which throws an error
    if ($_.Exception.Message -match "already a member") {
        Write-Status "db_datareader role already granted" "Success"
    }
    else {
        Write-Status "Failed to grant role: $_" "Warning"
    }
}

# Step 3: Verify connection
Write-Host ""
Write-Status "Step 3: Verifying SYSTEM account can access $Database..." "Info"

$verifyQuery = "SELECT DB_NAME() AS DatabaseName, SYSTEM_USER AS LoginUser, USER_NAME() AS DatabaseUser;"

try {
    $verify = Invoke-Sqlcmd -ServerInstance $SqlServer -Database $Database -Query $verifyQuery
    Write-Status "Verification successful!" "Success"
    Write-Host "  Database: $($verify.DatabaseName)" -ForegroundColor Gray
    Write-Host "  Login: $($verify.LoginUser)" -ForegroundColor Gray
    Write-Host "  User: $($verify.DatabaseUser)" -ForegroundColor Gray
}
catch {
    Write-Status "Verification query failed: $_" "Warning"
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Configuration Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "The SYSTEM account now has read access to $Database." -ForegroundColor White
Write-Host ""
Write-Host "To test the backup, run:" -ForegroundColor Yellow
Write-Host '  & "C:\SarovarBackup\backup-to-s3.ps1" -ConfigPath "C:\SarovarBackup\config.json"' -ForegroundColor Gray
Write-Host ""
