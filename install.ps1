<#
.SYNOPSIS
    Installer for SQL Server BAK File to S3 Backup Solution
.DESCRIPTION
    Sets up automated upload of SQL Server .bak files to S3.
    The SQL Agent creates .bak files, and this solution uploads the latest one to S3.
.PARAMETER Silent
    Run in silent mode without prompts (requires all parameters)
.PARAMETER S3Bucket
    S3 bucket name
.PARAMETER S3Region
    AWS region (default: us-east-1)
.PARAMETER AwsAccessKey
    AWS Access Key ID
.PARAMETER AwsSecretKey
    AWS Secret Access Key
.PARAMETER BakFilePath
    Path to directory where SQL Agent creates .bak files
.PARAMETER BackupTime
    Time for daily backup in HH:mm format (default: 02:00)
.PARAMETER InstallPath
    Installation directory (default: C:\SarovarBackup)
.PARAMETER ServerIdentifier
    Unique server identifier (default: hostname)
.PARAMETER S3Prefix
    S3 prefix/folder for uploads (default: backups)
.PARAMETER CompressionEnabled
    Enable RAR compression before upload (default: false for silent mode)
.PARAMETER RarPath
    Path to WinRAR rar.exe executable
.PARAMETER CompressionLevel
    RAR compression level 0-5 (default: 5 for best compression)
.PARAMETER TempDirectory
    Directory for temporary compressed files (default: InstallPath\temp)
.EXAMPLE
    # Interactive installation
    .\install.ps1
.EXAMPLE
    # Silent installation with parameters
    .\install.ps1 -Silent -S3Bucket "my-bucket" -BakFilePath "D:\Backups" -AwsAccessKey "AKIA..." -AwsSecretKey "xxx"
.EXAMPLE
    # Silent installation with compression
    .\install.ps1 -Silent -S3Bucket "my-bucket" -BakFilePath "D:\Backups" -AwsAccessKey "AKIA..." -AwsSecretKey "xxx" -CompressionEnabled -RarPath "C:\Program Files\WinRAR\rar.exe"
#>

param(
    [switch]$Silent,
    [string]$S3Bucket,
    [string]$S3Region = "us-east-1",
    [string]$AwsAccessKey,
    [string]$AwsSecretKey,
    [string]$BakFilePath,
    [string]$BackupTime = "02:00",
    [string]$InstallPath = "C:\SarovarBackup",
    [string]$ServerIdentifier = $env:COMPUTERNAME,
    [string]$S3Prefix = "backups",
    [switch]$CompressionEnabled,
    [string]$RarPath,
    [int]$CompressionLevel = 5,
    [string]$TempDirectory
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

function Find-WinRarPath {
    # Check common WinRAR installation paths
    $commonPaths = @(
        "C:\Program Files\WinRAR\rar.exe",
        "C:\Program Files (x86)\WinRAR\rar.exe"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            return $path
        }
    }
    
    # Try to find via registry
    try {
        $regPath = Get-ItemProperty "HKLM:\SOFTWARE\WinRAR" -ErrorAction SilentlyContinue
        if ($regPath -and $regPath.exe64) {
            $rarPath = Join-Path (Split-Path $regPath.exe64) "rar.exe"
            if (Test-Path $rarPath) {
                return $rarPath
            }
        }
    }
    catch {
        # Registry lookup failed, continue
    }
    
    return $null
}

function Test-RarExecutable {
    param([string]$RarPath)
    
    if ([string]::IsNullOrEmpty($RarPath)) {
        return $false
    }
    
    if (-not (Test-Path $RarPath)) {
        return $false
    }
    
    try {
        $output = & $RarPath 2>&1 | Select-Object -First 1
        return $output -match "RAR"
    }
    catch {
        return $false
    }
}

#endregion

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

#region ==================== S3 CONNECTIVITY TEST ====================

function Test-S3Connectivity {
    param(
        [string]$BucketName,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region,
        [string]$S3Prefix = "backups"
    )
    
    try {
        Write-Status "Testing S3 connectivity (firewall and credentials check)..." "Info"
        
        # Create test file
        $testKey = "$S3Prefix/_connectivity_test_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
        $testContent = "Connectivity test from $env:COMPUTERNAME - $(Get-Date -Format 'o')"
        $testFile = Join-Path $env:TEMP "_s3_connectivity_test.txt"
        
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
        
        Write-Status "S3 connectivity test PASSED - bucket is accessible and writable" "Success"
        Write-Status "Firewall is not blocking S3 access" "Success"
        return $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode.value__
            $errorMessage = "HTTP $statusCode : $errorMessage"
        }
        
        Write-Status "S3 connectivity test FAILED: $errorMessage" "Error"
        
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
        elseif ($errorMessage -like "*timeout*" -or $errorMessage -like "*network*" -or $errorMessage -like "*Unable to connect*") {
            Write-Status "Network/Firewall error - S3 access may be blocked by firewall" "Error"
            Write-Status "Please ensure outbound HTTPS (port 443) to s3.$Region.amazonaws.com is allowed" "Error"
        }
        
        return $false
    }
}

#endregion

#region ==================== MAIN INSTALLATION ====================

function Main {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  SQL BAK File to S3 - Installer" -ForegroundColor Cyan
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
    
    # Configuration
    $config = $null
    
    if ($Silent) {
        # Build config from parameters
        if ([string]::IsNullOrEmpty($S3Bucket) -or 
            [string]::IsNullOrEmpty($BakFilePath) -or 
            [string]::IsNullOrEmpty($AwsAccessKey) -or 
            [string]::IsNullOrEmpty($AwsSecretKey)) {
            Write-Status "Silent mode requires: S3Bucket, BakFilePath, AwsAccessKey, AwsSecretKey" "Error"
            exit 1
        }
        
        # Determine temp directory for silent mode
        $silentTempDir = if ([string]::IsNullOrEmpty($TempDirectory)) { 
            Join-Path $InstallPath "temp" 
        } else { 
            $TempDirectory 
        }
        
        # Validate RAR path if compression is enabled in silent mode
        if ($CompressionEnabled) {
            if ([string]::IsNullOrEmpty($RarPath)) {
                # Try auto-detect
                $RarPath = Find-WinRarPath
                if ([string]::IsNullOrEmpty($RarPath)) {
                    Write-Status "Compression enabled but RarPath not specified and WinRAR not found" "Error"
                    exit 1
                }
                Write-Status "Auto-detected WinRAR at: $RarPath" "Info"
            }
            
            if (-not (Test-RarExecutable -RarPath $RarPath)) {
                Write-Status "Invalid or non-functional RAR executable: $RarPath" "Error"
                exit 1
            }
        }
        
        $config = @{
            server_identifier = $ServerIdentifier
            bak_file_path = $BakFilePath
            s3_bucket = $S3Bucket
            s3_region = $S3Region
            s3_prefix = $S3Prefix
            aws_access_key = $AwsAccessKey
            aws_secret_key = $AwsSecretKey
            log_directory = Join-Path $InstallPath "logs"
            log_retention_days = 30
            backup_time = $BackupTime
            compression_enabled = [bool]$CompressionEnabled
            rar_executable_path = $RarPath
            compression_level = $CompressionLevel
            temp_directory = $silentTempDir
        }
    }
    else {
        # Interactive mode
        Write-Host ""
        Write-Host "--- Step 1: S3 Credentials ---" -ForegroundColor Yellow
        Write-Host ""
        
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
        
        # Test S3 connectivity BEFORE proceeding
        Write-Host ""
        Write-Host "--- Step 2: Testing S3 Connectivity ---" -ForegroundColor Yellow
        Write-Host ""
        
        $s3TestResult = Test-S3Connectivity `
            -BucketName $inputS3Bucket `
            -AccessKey $inputAwsAccessKey `
            -SecretKey $inputAwsSecretKey `
            -Region $inputS3Region `
            -S3Prefix $inputS3Prefix
        
        if (-not $s3TestResult) {
            Write-Status "S3 connectivity test failed" "Error"
            Write-Status "Cannot proceed with installation without S3 access" "Error"
            Write-Status "Please check your credentials and firewall settings" "Error"
            exit 1
        }
        
        Write-Host ""
        Write-Host "--- Step 3: BAK File Location ---" -ForegroundColor Yellow
        Write-Host ""
        
        # BAK file path
        $inputBakFilePath = Read-Host "Path where SQL Agent creates .bak files (e.g., D:\SQLBackups)"
        if ([string]::IsNullOrWhiteSpace($inputBakFilePath)) {
            Write-Status "BAK file path is required" "Error"
            exit 1
        }
        
        # Validate the path exists
        if (-not (Test-Path $inputBakFilePath)) {
            Write-Status "Path does not exist: $inputBakFilePath" "Warning"
            $createPath = Read-Host "Continue anyway? (y/N)"
            if ($createPath -ne 'y') {
                exit 1
            }
        }
        else {
            # Check if there are any .bak files in the path
            $bakFiles = Get-ChildItem -Path $inputBakFilePath -Filter "*.bak" -ErrorAction SilentlyContinue
            if ($bakFiles) {
                Write-Status "Found $($bakFiles.Count) .bak file(s) in the specified path" "Success"
            }
            else {
                Write-Status "No .bak files found in the specified path (this is OK if backups haven't run yet)" "Warning"
            }
        }
        
        Write-Host ""
        Write-Host "--- Step 4: Schedule Configuration ---" -ForegroundColor Yellow
        Write-Host ""
        
        # Server identifier
        $inputServerIdentifier = Read-Host "Server identifier [$ServerIdentifier]"
        if ([string]::IsNullOrWhiteSpace($inputServerIdentifier)) { $inputServerIdentifier = $ServerIdentifier }
        
        # Backup time
        $inputBackupTime = Read-Host "Daily upload time (HH:mm) [$BackupTime]"
        if ([string]::IsNullOrWhiteSpace($inputBackupTime)) { $inputBackupTime = $BackupTime }
        
        # Validate time format
        if ($inputBackupTime -notmatch '^\d{1,2}:\d{2}$') {
            Write-Status "Invalid time format. Please use HH:mm format (e.g., 02:00)" "Error"
            exit 1
        }
        
        # Install path
        $inputInstallPath = Read-Host "Installation directory [$InstallPath]"
        if ([string]::IsNullOrWhiteSpace($inputInstallPath)) { $inputInstallPath = $InstallPath }
        
        Write-Host ""
        Write-Host "--- Step 5: Compression Configuration ---" -ForegroundColor Yellow
        Write-Host ""
        
        # Auto-detect WinRAR
        $detectedRarPath = Find-WinRarPath
        $inputCompressionEnabled = $false
        $inputRarPath = ""
        $inputCompressionLevel = 5
        $inputTempDirectory = Join-Path $inputInstallPath "temp"
        
        if ($detectedRarPath) {
            Write-Status "WinRAR detected at: $detectedRarPath" "Success"
            $enableCompression = Read-Host "Enable RAR compression before upload? (Y/n)"
            if ($enableCompression -ne 'n' -and $enableCompression -ne 'N') {
                $inputCompressionEnabled = $true
                
                # Ask if they want to use detected path or custom
                $useDetectedPath = Read-Host "Use detected path? (Y/n)"
                if ($useDetectedPath -eq 'n' -or $useDetectedPath -eq 'N') {
                    $inputRarPath = Read-Host "Enter path to rar.exe"
                }
                else {
                    $inputRarPath = $detectedRarPath
                }
            }
        }
        else {
            Write-Status "WinRAR not detected in common locations" "Warning"
            $enableCompression = Read-Host "Enable RAR compression? (y/N)"
            if ($enableCompression -eq 'y' -or $enableCompression -eq 'Y') {
                $inputCompressionEnabled = $true
                $inputRarPath = Read-Host "Enter path to rar.exe (e.g., C:\Program Files\WinRAR\rar.exe)"
                if ([string]::IsNullOrWhiteSpace($inputRarPath)) {
                    Write-Status "RAR path is required when compression is enabled" "Error"
                    exit 1
                }
            }
        }
        
        # If compression enabled, get additional settings and validate
        if ($inputCompressionEnabled) {
            # Validate RAR executable
            if (-not (Test-RarExecutable -RarPath $inputRarPath)) {
                Write-Status "Invalid or non-functional RAR executable: $inputRarPath" "Error"
                exit 1
            }
            Write-Status "RAR executable validated successfully" "Success"
            
            # Compression level
            $levelInput = Read-Host "Compression level 0-5 (0=store, 5=best) [$inputCompressionLevel]"
            if (-not [string]::IsNullOrWhiteSpace($levelInput)) {
                $inputCompressionLevel = [int]$levelInput
                if ($inputCompressionLevel -lt 0 -or $inputCompressionLevel -gt 5) {
                    Write-Status "Invalid compression level. Using default: 5" "Warning"
                    $inputCompressionLevel = 5
                }
            }
            
            # Temp directory
            $tempInput = Read-Host "Temp directory for compressed files [$inputTempDirectory]"
            if (-not [string]::IsNullOrWhiteSpace($tempInput)) {
                $inputTempDirectory = $tempInput
            }
            
            Write-Status "Compression enabled with level $inputCompressionLevel" "Success"
        }
        else {
            Write-Status "Compression disabled - will upload raw .bak files" "Info"
        }
        
        $config = @{
            server_identifier = $inputServerIdentifier
            bak_file_path = $inputBakFilePath
            s3_bucket = $inputS3Bucket
            s3_region = $inputS3Region
            s3_prefix = $inputS3Prefix
            aws_access_key = $inputAwsAccessKey
            aws_secret_key = $inputAwsSecretKey
            log_directory = Join-Path $inputInstallPath "logs"
            log_retention_days = 30
            backup_time = $inputBackupTime
            compression_enabled = $inputCompressionEnabled
            rar_executable_path = $inputRarPath
            compression_level = $inputCompressionLevel
            temp_directory = $inputTempDirectory
        }
        
        $InstallPath = $inputInstallPath
    }
    
    # For silent mode, test S3 connectivity
    if ($Silent) {
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
            Write-Status "Silent mode: Exiting due to S3 connectivity failure" "Error"
            exit 1
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
    
    $config | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8
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
    
    $taskName = "SarovarBackup-BakToS3"
    $taskDescription = "Daily SQL Server BAK file upload to S3"
    
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
    Write-Status "BAK file upload will run daily at $($config.backup_time)" "Info"
    
    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Installation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Installation directory: $InstallPath" -ForegroundColor White
    Write-Host "Configuration file: $configPath" -ForegroundColor White
    Write-Host "Log directory: $($config.log_directory)" -ForegroundColor White
    Write-Host "BAK file source: $($config.bak_file_path)" -ForegroundColor White
    Write-Host "Scheduled task: $taskName" -ForegroundColor White
    Write-Host "Daily upload time: $($config.backup_time)" -ForegroundColor White
    Write-Host ""
    Write-Host "To run a backup manually:" -ForegroundColor Yellow
    Write-Host "  & `"$destScript`" -ConfigPath `"$configPath`"" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To uninstall:" -ForegroundColor Yellow
    Write-Host "  & `"$destUninstall`"" -ForegroundColor Gray
    Write-Host ""
}

# Run main function
Main
