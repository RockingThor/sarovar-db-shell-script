<#
.SYNOPSIS
    SQL Server BAK File Upload to S3 - Pure PowerShell Implementation
.DESCRIPTION
    Finds the latest .bak file from the configured directory and uploads it to S3
    using native PowerShell REST API calls (no AWS CLI required).
.NOTES
    Version: 2.0.0
    Requires: PowerShell 5.1+
#>

param(
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    [switch]$TestOnly
)

$ErrorActionPreference = "Stop"
$script:LogFile = $null

#region ==================== LOGGING ====================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        "WARN"    { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage -ForegroundColor Cyan }
    }
    
    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $logMessage
    }
}

function Initialize-Logging {
    param([string]$LogDirectory)
    
    if (-not (Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    
    $date = Get-Date -Format "yyyy-MM-dd"
    $script:LogFile = Join-Path $LogDirectory "backup-$date.log"
    
    Write-Log "=== Backup Session Started ===" "INFO"
}

function Remove-OldLogs {
    param(
        [string]$LogDirectory,
        [int]$RetentionDays
    )
    
    $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
    Get-ChildItem -Path $LogDirectory -Filter "backup-*.log" | 
        Where-Object { $_.LastWriteTime -lt $cutoffDate } | 
        ForEach-Object {
            Write-Log "Removing old log: $($_.Name)" "INFO"
            Remove-Item $_.FullName -Force
        }
}

#endregion

#region ==================== AWS SIGNATURE V4 ====================

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

#region ==================== S3 OPERATIONS ====================

function Send-FileToS3 {
    param(
        [string]$BucketName,
        [string]$Key,
        [string]$FilePath,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region,
        [int]$MaxRetries = 3
    )
    
    $fileInfo = Get-Item $FilePath
    $contentType = "application/octet-stream"
    
    Write-Log "Calculating file hash for: $($fileInfo.Name) ($([math]::Round($fileInfo.Length / 1MB, 2)) MB)" "INFO"
    
    # Calculate payload hash from file
    $payloadHash = Get-SHA256HashFromFile -FilePath $FilePath
    
    # Build endpoint URL (path-style for compatibility)
    $endpoint = "https://s3.$Region.amazonaws.com/$BucketName/$Key"
    
    $headers = @{
        "Host" = "s3.$Region.amazonaws.com"
        "Content-Type" = $contentType
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
        "Content-Type" = $contentType
        "Host" = "s3.$Region.amazonaws.com"
    }
    
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $MaxRetries) {
        try {
            Write-Log "Uploading to S3: $Key (Attempt $($retryCount + 1)/$MaxRetries)" "INFO"
            
            $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
            
            $response = Invoke-RestMethod `
                -Uri $endpoint `
                -Method PUT `
                -Headers $requestHeaders `
                -Body $fileBytes `
                -ContentType $contentType
            
            $success = $true
            Write-Log "Upload successful: $Key ($([math]::Round($fileInfo.Length / 1MB, 2)) MB)" "SUCCESS"
        }
        catch {
            $retryCount++
            if ($retryCount -lt $MaxRetries) {
                $waitTime = [math]::Pow(2, $retryCount)
                Write-Log "Upload failed, retrying in $waitTime seconds... (Attempt $retryCount/$MaxRetries): $_" "WARN"
                Start-Sleep -Seconds $waitTime
                
                # Recalculate signature for retry (time changes)
                $authResult = Get-AWSSignatureV4 `
                    -Method "PUT" `
                    -Uri $endpoint `
                    -Region $Region `
                    -Service "s3" `
                    -AccessKey $AccessKey `
                    -SecretKey $SecretKey `
                    -Headers $headers `
                    -PayloadHash $payloadHash
                
                $requestHeaders["Authorization"] = $authResult.Authorization
                $requestHeaders["x-amz-date"] = $authResult.AmzDate
            }
            else {
                throw "Failed to upload $Key after $MaxRetries attempts: $_"
            }
        }
    }
    
    return $success
}

function Test-S3Connection {
    param(
        [string]$BucketName,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region,
        [string]$S3Prefix
    )
    
    try {
        $testKey = "$S3Prefix/_connection_test_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
        $testContent = "Connection test - $(Get-Date)"
        $testFile = Join-Path $env:TEMP "_s3_test_$((Get-Date -Format 'yyyyMMddHHmmss')).txt"
        
        Set-Content -Path $testFile -Value $testContent -Encoding UTF8
        
        Send-FileToS3 `
            -BucketName $BucketName `
            -Key $testKey `
            -FilePath $testFile `
            -AccessKey $AccessKey `
            -SecretKey $SecretKey `
            -Region $Region
        
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        
        Write-Log "S3 connection test successful" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "S3 connection test failed: $_" "ERROR"
        return $false
    }
}

#endregion

#region ==================== MAIN BACKUP LOGIC ====================

function Get-LatestBakFile {
    param(
        [string]$BakDirectory
    )
    
    Write-Log "Searching for .bak files in: $BakDirectory" "INFO"
    
    if (-not (Test-Path $BakDirectory)) {
        throw "BAK file directory does not exist: $BakDirectory"
    }
    
    # Get the latest .bak file by LastWriteTime
    $latestBak = Get-ChildItem -Path $BakDirectory -Filter "*.bak" -File | 
                 Sort-Object LastWriteTime -Descending | 
                 Select-Object -First 1
    
    if (-not $latestBak) {
        throw "No .bak files found in directory: $BakDirectory"
    }
    
    Write-Log "Found latest BAK file: $($latestBak.Name)" "INFO"
    Write-Log "File size: $([math]::Round($latestBak.Length / 1MB, 2)) MB" "INFO"
    Write-Log "Last modified: $($latestBak.LastWriteTime)" "INFO"
    
    return $latestBak
}

function Start-BakFileUpload {
    param(
        [object]$Config
    )
    
    $date = Get-Date -Format "yyyy-MM-dd"
    $serverIdentifier = $Config.server_identifier
    if ([string]::IsNullOrEmpty($serverIdentifier)) {
        $serverIdentifier = $env:COMPUTERNAME
    }
    
    # Get the latest .bak file
    $bakFile = Get-LatestBakFile -BakDirectory $Config.bak_file_path
    
    # Build S3 key with server identifier and date
    $s3Key = "$($Config.s3_prefix)/$serverIdentifier/$date/$($bakFile.Name)"
    
    Write-Log "Starting upload to S3..." "INFO"
    Write-Log "S3 Bucket: $($Config.s3_bucket)" "INFO"
    Write-Log "S3 Key: $s3Key" "INFO"
    
    # Upload to S3
    $uploadResult = Send-FileToS3 `
        -BucketName $Config.s3_bucket `
        -Key $s3Key `
        -FilePath $bakFile.FullName `
        -AccessKey $Config.aws_access_key `
        -SecretKey $Config.aws_secret_key `
        -Region $Config.s3_region
    
    if ($uploadResult) {
        Write-Log "BAK file uploaded successfully to S3" "SUCCESS"
        return @{
            success = $true
            file_name = $bakFile.Name
            file_size_mb = [math]::Round($bakFile.Length / 1MB, 2)
            s3_key = $s3Key
            timestamp = (Get-Date).ToString("o")
        }
    }
    else {
        throw "Failed to upload BAK file to S3"
    }
}

#endregion

#region ==================== MAIN ENTRY POINT ====================

function Main {
    try {
        # Load configuration
        if (-not (Test-Path $ConfigPath)) {
            throw "Configuration file not found: $ConfigPath"
        }
        
        $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        
        # Initialize logging
        Initialize-Logging -LogDirectory $config.log_directory
        
        Write-Log "Configuration loaded from: $ConfigPath" "INFO"
        Write-Log "Server: $($config.server_identifier)" "INFO"
        Write-Log "BAK File Path: $($config.bak_file_path)" "INFO"
        Write-Log "S3 Bucket: $($config.s3_bucket)" "INFO"
        
        # Clean old logs
        if ($config.log_retention_days -gt 0) {
            Remove-OldLogs -LogDirectory $config.log_directory -RetentionDays $config.log_retention_days
        }
        
        # Test S3 connection first
        Write-Log "Testing S3 connection..." "INFO"
        $s3Test = Test-S3Connection `
            -BucketName $config.s3_bucket `
            -AccessKey $config.aws_access_key `
            -SecretKey $config.aws_secret_key `
            -Region $config.s3_region `
            -S3Prefix $config.s3_prefix
        
        if (-not $s3Test) {
            throw "S3 connection test failed. Please verify your AWS credentials and bucket access."
        }
        
        if ($TestOnly) {
            Write-Log "Test mode - exiting after connection tests" "SUCCESS"
            exit 0
        }
        
        # Start backup
        $result = Start-BakFileUpload -Config $config
        
        # Print summary
        Write-Log "=== Backup Complete ===" "SUCCESS"
        Write-Log "File: $($result.file_name)" "INFO"
        Write-Log "Size: $($result.file_size_mb) MB" "INFO"
        Write-Log "S3 Location: s3://$($config.s3_bucket)/$($result.s3_key)" "INFO"
        
        exit 0
    }
    catch {
        Write-Log "FATAL ERROR: $_" "ERROR"
        Write-Log $_.ScriptStackTrace "ERROR"
        exit 1
    }
}

# Run main function
Main

#endregion
