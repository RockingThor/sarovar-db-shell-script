<#
.SYNOPSIS
    Installer for MSSQL to S3 Backup Solution
.DESCRIPTION
    One-command installer that sets up the backup script, configuration,
    and Windows Task Scheduler job for automated daily backups.
.PARAMETER Silent
    Run in silent mode without prompts (requires all parameters or ConfigFile)
.PARAMETER ConfigFile
    Path to an existing config.json file to use instead of prompting
.PARAMETER S3Bucket
    S3 bucket name
.PARAMETER S3Region
    AWS region (default: us-east-1)
.PARAMETER Databases
    Comma-separated list of database names to backup
.PARAMETER SqlServer
    SQL Server instance name (default: localhost)
.PARAMETER AwsAccessKey
    AWS Access Key ID
.PARAMETER AwsSecretKey
    AWS Secret Access Key
.PARAMETER BackupTime
    Time for daily backup in HH:mm format (default: 02:00)
.PARAMETER InstallPath
    Installation directory (default: C:\SarovarBackup)
.PARAMETER ServerIdentifier
    Unique server identifier (default: hostname)
.EXAMPLE
    # Interactive installation
    .\install.ps1
.EXAMPLE
    # Silent installation with parameters
    .\install.ps1 -Silent -S3Bucket "my-bucket" -Databases "DB1,DB2" -AwsAccessKey "AKIA..." -AwsSecretKey "xxx"
.EXAMPLE
    # Silent installation with config file
    .\install.ps1 -Silent -ConfigFile "\\server\share\config.json"
#>

param(
    [switch]$Silent,
    [string]$ConfigFile,
    [string]$S3Bucket,
    [string]$S3Region = "us-east-1",
    [string]$Databases,
    [string]$SqlServer = "localhost",
    [string]$AwsAccessKey,
    [string]$AwsSecretKey,
    [string]$BackupTime = "02:00",
    [string]$InstallPath = "C:\SarovarBackup",
    [string]$ServerIdentifier = $env:COMPUTERNAME,
    [string]$S3Prefix = "backups"
)

$ErrorActionPreference = "Stop"

#region ==================== HELPER FUNCTIONS ====================

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

function Test-SqlServerModule {
    try {
        $module = Get-Module -ListAvailable -Name SqlServer
        if ($module) {
            return $true
        }
        
        # Try SQLPS as fallback
        $sqlps = Get-Module -ListAvailable -Name SQLPS
        if ($sqlps) {
            return $true
        }
        
        return $false
    }
    catch {
        return $false
    }
}

function Install-SqlServerModule {
    Write-Status "Installing SqlServer PowerShell module..." "Info"
    try {
        # Try to install from PSGallery
        Install-Module -Name SqlServer -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
        Write-Status "SqlServer module installed successfully" "Success"
        return $true
    }
    catch {
        Write-Status "Could not auto-install SqlServer module: $_" "Warning"
        Write-Status "Please install manually: Install-Module -Name SqlServer" "Warning"
        return $false
    }
}

function Test-SqlConnection {
    param(
        [string]$ServerInstance,
        [string]$Database = "master"
    )
    
    try {
        Import-Module SqlServer -ErrorAction SilentlyContinue
        $query = "SELECT 1 AS Test"
        Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $query -ConnectionTimeout 10 | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

#region ==================== AWS SIGNATURE V4 HELPERS ====================

function Get-SHA256Hash {
    param([byte[]]$Data)
    
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha256.ComputeHash($Data)
    return [BitConverter]::ToString($hash).Replace("-", "").ToLower()
}

function Get-SHA256HashFromFile {
    param([string]$FilePath)
    
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($FilePath)
    try {
        $hash = $sha256.ComputeHash($stream)
        return [BitConverter]::ToString($hash).Replace("-", "").ToLower()
    }
    finally {
        $stream.Close()
    }
}

function Get-HMACSHA256 {
    param(
        [byte[]]$Key,
        [string]$Message
    )
    
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $Key
    return $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Message))
}

function Get-SignatureKey {
    param(
        [string]$SecretKey,
        [string]$DateStamp,
        [string]$Region,
        [string]$Service
    )
    
    $kSecret = [System.Text.Encoding]::UTF8.GetBytes("AWS4$SecretKey")
    $kDate = Get-HMACSHA256 -Key $kSecret -Message $DateStamp
    $kRegion = Get-HMACSHA256 -Key $kDate -Message $Region
    $kService = Get-HMACSHA256 -Key $kRegion -Message $Service
    $kSigning = Get-HMACSHA256 -Key $kService -Message "aws4_request"
    
    return $kSigning
}

function Get-AWSSignatureV4 {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$Region,
        [string]$Service,
        [string]$AccessKey,
        [string]$SecretKey,
        [hashtable]$Headers,
        [string]$PayloadHash,
        [string]$QueryString = ""
    )
    
    $now = [DateTime]::UtcNow
    $dateStamp = $now.ToString("yyyyMMdd")
    $amzDate = $now.ToString("yyyyMMddTHHmmssZ")
    
    # Parse URI
    $uriObj = [System.Uri]$Uri
    $canonicalUri = $uriObj.AbsolutePath
    if ([string]::IsNullOrEmpty($canonicalUri)) { $canonicalUri = "/" }
    
    # Canonical query string
    $canonicalQueryString = $QueryString
    
    # Canonical headers
    $Headers["x-amz-date"] = $amzDate
    $Headers["x-amz-content-sha256"] = $PayloadHash
    
    $sortedHeaders = $Headers.GetEnumerator() | Sort-Object Name
    $canonicalHeaders = ($sortedHeaders | ForEach-Object { "$($_.Name.ToLower()):$($_.Value.Trim())" }) -join "`n"
    $canonicalHeaders += "`n"
    
    $signedHeaders = ($sortedHeaders | ForEach-Object { $_.Name.ToLower() }) -join ";"
    
    # Create canonical request
    $canonicalRequest = @(
        $Method,
        $canonicalUri,
        $canonicalQueryString,
        $canonicalHeaders,
        $signedHeaders,
        $PayloadHash
    ) -join "`n"
    
    # Create string to sign
    $algorithm = "AWS4-HMAC-SHA256"
    $credentialScope = "$dateStamp/$Region/$Service/aws4_request"
    $canonicalRequestHash = Get-SHA256Hash -Data ([System.Text.Encoding]::UTF8.GetBytes($canonicalRequest))
    
    $stringToSign = @(
        $algorithm,
        $amzDate,
        $credentialScope,
        $canonicalRequestHash
    ) -join "`n"
    
    # Calculate signature
    $signingKey = Get-SignatureKey -SecretKey $SecretKey -DateStamp $dateStamp -Region $Region -Service $Service
    $signatureBytes = Get-HMACSHA256 -Key $signingKey -Message $stringToSign
    $signature = [BitConverter]::ToString($signatureBytes).Replace("-", "").ToLower()
    
    # Create authorization header
    $authorization = "$algorithm Credential=$AccessKey/$credentialScope, SignedHeaders=$signedHeaders, Signature=$signature"
    
    return @{
        Authorization = $authorization
        AmzDate = $amzDate
        AmzContentSha256 = $PayloadHash
    }
}

#endregion

function Test-S3Connectivity {
    param(
        [string]$BucketName,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region,
        [string]$S3Prefix = "backups"
    )
    
    try {
        Write-Status "Testing S3 connectivity and write permissions..." "Info"
        
        # Create test file
        $testKey = "$S3Prefix/_install_test_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
        $testContent = "Installation connectivity test - $(Get-Date -Format 'o')"
        $testFile = Join-Path $env:TEMP "_s3_test_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
        
        Set-Content -Path $testFile -Value $testContent -Encoding UTF8
        
        # Calculate payload hash from file
        $payloadHash = Get-SHA256HashFromFile -FilePath $testFile
        
        # Build endpoint URL (path-style for compatibility)
        $endpoint = "https://s3.$Region.amazonaws.com/$BucketName/$testKey"
        
        $headers = @{
            "Host" = "s3.$Region.amazonaws.com"
            "Content-Type" = "text/plain"
        }
        
        $authResult = Get-AWSSignatureV4 `
            -Method "PUT" `
            -Uri $endpoint `
            -Region $Region `
            -Service "s3" `
            -AccessKey $AccessKey `
            -SecretKey $SecretKey `
            -Headers $headers `
            -PayloadHash $payloadHash
        
        $requestHeaders = @{
            "Authorization" = $authResult.Authorization
            "x-amz-date" = $authResult.AmzDate
            "x-amz-content-sha256" = $authResult.AmzContentSha256
            "Content-Type" = "text/plain"
            "Host" = "s3.$Region.amazonaws.com"
        }
        
        # Upload test file
        $fileBytes = [System.IO.File]::ReadAllBytes($testFile)
        Invoke-RestMethod `
            -Uri $endpoint `
            -Method PUT `
            -Headers $requestHeaders `
            -Body $fileBytes `
            -ContentType "text/plain" `
            -ErrorAction Stop | Out-Null
        
        # Clean up local test file
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        
        # Try to delete the test file from S3 (optional cleanup)
        try {
            $deleteEndpoint = "https://s3.$Region.amazonaws.com/$BucketName/$testKey"
            $deletePayloadHash = Get-SHA256Hash -Data ([byte[]]@())
            
            $deleteHeaders = @{
                "Host" = "s3.$Region.amazonaws.com"
            }
            
            $deleteAuthResult = Get-AWSSignatureV4 `
                -Method "DELETE" `
                -Uri $deleteEndpoint `
                -Region $Region `
                -Service "s3" `
                -AccessKey $AccessKey `
                -SecretKey $SecretKey `
                -Headers $deleteHeaders `
                -PayloadHash $deletePayloadHash
            
            $deleteRequestHeaders = @{
                "Authorization" = $deleteAuthResult.Authorization
                "x-amz-date" = $deleteAuthResult.AmzDate
                "x-amz-content-sha256" = $deleteAuthResult.AmzContentSha256
                "Host" = "s3.$Region.amazonaws.com"
            }
            
            Invoke-RestMethod `
                -Uri $deleteEndpoint `
                -Method DELETE `
                -Headers $deleteRequestHeaders `
                -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            # Ignore delete errors - test file can remain in S3
        }
        
        Write-Status "S3 connectivity test successful - bucket is accessible and writable" "Success"
        return $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode.value__
            $errorMessage = "HTTP $statusCode : $errorMessage"
        }
        
        Write-Status "S3 connectivity test failed: $errorMessage" "Error"
        
        # Provide helpful error messages
        if ($errorMessage -like "*403*" -or $errorMessage -like "*Forbidden*") {
            Write-Status "Access denied - check AWS credentials and bucket permissions" "Error"
        }
        elseif ($errorMessage -like "*404*" -or $errorMessage -like "*Not Found*") {
            Write-Status "Bucket not found - verify bucket name and region" "Error"
        }
        elseif ($errorMessage -like "*401*" -or $errorMessage -like "*Unauthorized*") {
            Write-Status "Authentication failed - verify AWS Access Key and Secret Key" "Error"
        }
        elseif ($errorMessage -like "*timeout*" -or $errorMessage -like "*network*") {
            Write-Status "Network error - check internet connectivity and firewall settings" "Error"
        }
        
        return $false
    }
}

function Read-SecureInput {
    param([string]$Prompt)
    
    Write-Host "$Prompt" -NoNewline
    $secureString = Read-Host -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

#endregion

#region ==================== MAIN INSTALLATION ====================

function Main {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  MSSQL to S3 Backup - Installer" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Write-Status "This installer requires Administrator privileges." "Error"
        Write-Status "Please run PowerShell as Administrator and try again." "Error"
        exit 1
    }
    Write-Status "Running with Administrator privileges" "Success"
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-Status "PowerShell 5.1 or higher is required. Current version: $psVersion" "Error"
        exit 1
    }
    Write-Status "PowerShell version: $psVersion" "Success"
    
    # Check/Install SqlServer module
    if (-not (Test-SqlServerModule)) {
        Write-Status "SqlServer PowerShell module not found" "Warning"
        if (-not $Silent) {
            $installModule = Read-Host "Would you like to install it? (Y/n)"
            if ($installModule -ne 'n') {
                Install-SqlServerModule
            }
        }
        else {
            Install-SqlServerModule
        }
    }
    else {
        Write-Status "SqlServer PowerShell module found" "Success"
    }
    
    # Import module
    try {
        Import-Module SqlServer -ErrorAction SilentlyContinue
    }
    catch {
        Import-Module SQLPS -DisableNameChecking -ErrorAction SilentlyContinue
    }
    
    # Configuration
    $config = $null
    
    if ($ConfigFile -and (Test-Path $ConfigFile)) {
        # Load from config file
        Write-Status "Loading configuration from: $ConfigFile" "Info"
        $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    }
    elseif ($Silent) {
        # Build config from parameters
        if ([string]::IsNullOrEmpty($S3Bucket) -or 
            [string]::IsNullOrEmpty($Databases) -or 
            [string]::IsNullOrEmpty($AwsAccessKey) -or 
            [string]::IsNullOrEmpty($AwsSecretKey)) {
            Write-Status "Silent mode requires: S3Bucket, Databases, AwsAccessKey, AwsSecretKey" "Error"
            exit 1
        }
        
        $config = @{
            server_identifier = $ServerIdentifier
            sql_server = $SqlServer
            databases = $Databases -split ','
            s3_bucket = $S3Bucket
            s3_region = $S3Region
            s3_prefix = $S3Prefix
            aws_access_key = $AwsAccessKey
            aws_secret_key = $AwsSecretKey
            temp_directory = Join-Path $InstallPath "temp"
            log_directory = Join-Path $InstallPath "logs"
            log_retention_days = 30
            backup_time = $BackupTime
        }
    }
    else {
        # Interactive mode
        Write-Host ""
        Write-Host "--- Configuration ---" -ForegroundColor Yellow
        Write-Host ""
        
        # Server identifier
        $inputServerIdentifier = Read-Host "Server identifier [$ServerIdentifier]"
        if ([string]::IsNullOrWhiteSpace($inputServerIdentifier)) { $inputServerIdentifier = $ServerIdentifier }
        
        # SQL Server
        $inputSqlServer = Read-Host "SQL Server instance [$SqlServer]"
        if ([string]::IsNullOrWhiteSpace($inputSqlServer)) { $inputSqlServer = $SqlServer }
        
        # Test SQL connection
        Write-Status "Testing SQL Server connection..." "Info"
        if (Test-SqlConnection -ServerInstance $inputSqlServer) {
            Write-Status "SQL Server connection successful" "Success"
        }
        else {
            Write-Status "Could not connect to SQL Server: $inputSqlServer" "Warning"
            $continue = Read-Host "Continue anyway? (y/N)"
            if ($continue -ne 'y') { exit 1 }
        }
        
        # Databases
        $inputDatabases = Read-Host "Database names (comma-separated)"
        if ([string]::IsNullOrWhiteSpace($inputDatabases)) {
            Write-Status "At least one database name is required" "Error"
            exit 1
        }
        
        # S3 configuration
        $inputS3Bucket = Read-Host "S3 bucket name"
        if ([string]::IsNullOrWhiteSpace($inputS3Bucket)) {
            Write-Status "S3 bucket name is required" "Error"
            exit 1
        }
        
        $inputS3Region = Read-Host "S3 region [$S3Region]"
        if ([string]::IsNullOrWhiteSpace($inputS3Region)) { $inputS3Region = $S3Region }
        
        $inputS3Prefix = Read-Host "S3 prefix/folder [$S3Prefix]"
        if ([string]::IsNullOrWhiteSpace($inputS3Prefix)) { $inputS3Prefix = $S3Prefix }
        
        # AWS credentials
        $inputAwsAccessKey = Read-Host "AWS Access Key ID"
        if ([string]::IsNullOrWhiteSpace($inputAwsAccessKey)) {
            Write-Status "AWS Access Key ID is required" "Error"
            exit 1
        }
        
        $inputAwsSecretKey = Read-SecureInput "AWS Secret Access Key: "
        if ([string]::IsNullOrWhiteSpace($inputAwsSecretKey)) {
            Write-Status "AWS Secret Access Key is required" "Error"
            exit 1
        }
        
        # Backup time
        $inputBackupTime = Read-Host "Daily backup time (HH:mm) [$BackupTime]"
        if ([string]::IsNullOrWhiteSpace($inputBackupTime)) { $inputBackupTime = $BackupTime }
        
        # Install path
        $inputInstallPath = Read-Host "Installation directory [$InstallPath]"
        if ([string]::IsNullOrWhiteSpace($inputInstallPath)) { $inputInstallPath = $InstallPath }
        
        $config = @{
            server_identifier = $inputServerIdentifier
            sql_server = $inputSqlServer
            databases = $inputDatabases -split ',' | ForEach-Object { $_.Trim() }
            s3_bucket = $inputS3Bucket
            s3_region = $inputS3Region
            s3_prefix = $inputS3Prefix
            aws_access_key = $inputAwsAccessKey
            aws_secret_key = $inputAwsSecretKey
            temp_directory = Join-Path $inputInstallPath "temp"
            log_directory = Join-Path $inputInstallPath "logs"
            log_retention_days = 30
            backup_time = $inputBackupTime
        }
        
        $InstallPath = $inputInstallPath
    }
    
    # Test S3 connectivity BEFORE installation
    Write-Host ""
    Write-Host "--- Testing S3 Connectivity ---" -ForegroundColor Yellow
    Write-Host ""
    
    $s3TestResult = Test-S3Connectivity `
        -BucketName $config.s3_bucket `
        -AccessKey $config.aws_access_key `
        -SecretKey $config.aws_secret_key `
        -Region $config.s3_region `
        -S3Prefix $config.s3_prefix
    
    if (-not $s3TestResult) {
        Write-Status "S3 connectivity test failed" "Error"
        Write-Status "Cannot proceed with installation without S3 access" "Error"
        
        if ($Silent) {
            Write-Status "Silent mode: Exiting due to S3 connectivity failure" "Error"
            exit 1
        }
        else {
            $continue = Read-Host "Continue with installation anyway? (y/N)"
            if ($continue -ne 'y') {
                Write-Status "Installation cancelled by user" "Warning"
                exit 1
            }
            Write-Status "Proceeding with installation despite S3 test failure" "Warning"
        }
    }
    
    Write-Host ""
    Write-Host "--- Installing ---" -ForegroundColor Yellow
    Write-Host ""
    
    # Create installation directory
    Write-Status "Creating installation directory: $InstallPath" "Info"
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }
    New-Item -ItemType Directory -Path $config.temp_directory -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path $config.log_directory -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Status "Directories created" "Success"
    
    # Copy scripts
    Write-Status "Copying backup script..." "Info"
    $sourceScript = Join-Path $PSScriptRoot "backup-to-s3.ps1"
    $destScript = Join-Path $InstallPath "backup-to-s3.ps1"
    
    if (Test-Path $sourceScript) {
        Copy-Item $sourceScript $destScript -Force
    }
    else {
        Write-Status "Source script not found: $sourceScript" "Error"
        Write-Status "Please ensure backup-to-s3.ps1 is in the same directory as install.ps1" "Error"
        exit 1
    }
    Write-Status "Backup script copied" "Success"
    
    # Copy uninstall script
    $sourceUninstall = Join-Path $PSScriptRoot "uninstall.ps1"
    $destUninstall = Join-Path $InstallPath "uninstall.ps1"
    if (Test-Path $sourceUninstall) {
        Copy-Item $sourceUninstall $destUninstall -Force
        Write-Status "Uninstall script copied" "Success"
    }
    
    # Save configuration
    Write-Status "Saving configuration..." "Info"
    $configPath = Join-Path $InstallPath "config.json"
    
    # Remove help comments before saving
    $cleanConfig = @{
        server_identifier = $config.server_identifier
        sql_server = $config.sql_server
        databases = $config.databases
        s3_bucket = $config.s3_bucket
        s3_region = $config.s3_region
        s3_prefix = $config.s3_prefix
        aws_access_key = $config.aws_access_key
        aws_secret_key = $config.aws_secret_key
        temp_directory = $config.temp_directory
        log_directory = $config.log_directory
        log_retention_days = $config.log_retention_days
        backup_time = $config.backup_time
    }
    
    $cleanConfig | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8
    Write-Status "Configuration saved to: $configPath" "Success"
    
    # Secure the config file (restrict to Administrators)
    Write-Status "Securing configuration file..." "Info"
    try {
        $acl = Get-Acl $configPath
        $acl.SetAccessRuleProtection($true, $false)
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators", "FullControl", "Allow")
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "Allow")
        $acl.SetAccessRule($adminRule)
        $acl.SetAccessRule($systemRule)
        Set-Acl $configPath $acl
        Write-Status "Configuration file secured" "Success"
    }
    catch {
        Write-Status "Could not restrict config file permissions: $_" "Warning"
    }
    
    # Create scheduled task
    Write-Host ""
    Write-Host "--- Creating Scheduled Task ---" -ForegroundColor Yellow
    Write-Host ""
    
    $taskName = "SarovarBackup-DailyS3Sync"
    $taskDescription = "Daily MSSQL database backup to S3"
    
    # Parse backup time
    $timeParts = $config.backup_time -split ':'
    $taskHour = [int]$timeParts[0]
    $taskMinute = [int]$timeParts[1]
    
    # Remove existing task if present
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Status "Removing existing scheduled task..." "Info"
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    
    # Create the scheduled task
    Write-Status "Creating scheduled task: $taskName" "Info"
    
    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$destScript`" -ConfigPath `"$configPath`"" `
        -WorkingDirectory $InstallPath
    
    $trigger = New-ScheduledTaskTrigger -Daily -At "$($taskHour.ToString('00')):$($taskMinute.ToString('00'))"
    
    $principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable `
        -MultipleInstances IgnoreNew
    
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description $taskDescription | Out-Null
    
    Write-Status "Scheduled task created successfully" "Success"
    Write-Status "Backup will run daily at $($config.backup_time)" "Info"
    
    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Installation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Installation directory: $InstallPath" -ForegroundColor White
    Write-Host "Configuration file: $configPath" -ForegroundColor White
    Write-Host "Log directory: $($config.log_directory)" -ForegroundColor White
    Write-Host "Scheduled task: $taskName" -ForegroundColor White
    Write-Host "Daily backup time: $($config.backup_time)" -ForegroundColor White
    Write-Host ""
    Write-Host "To run a backup manually:" -ForegroundColor Yellow
    Write-Host "  & `"$destScript`" -ConfigPath `"$configPath`"" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To test connection only:" -ForegroundColor Yellow
    Write-Host "  & `"$destScript`" -ConfigPath `"$configPath`" -TestOnly" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To uninstall:" -ForegroundColor Yellow
    Write-Host "  & `"$destUninstall`"" -ForegroundColor Gray
    Write-Host ""
}

# Run main function
Main
