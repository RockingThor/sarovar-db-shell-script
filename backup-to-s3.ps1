<#
.SYNOPSIS
    SQL Server BAK File Upload to S3 - Pure PowerShell Implementation
.DESCRIPTION
    Finds the latest .bak file from the configured directory and uploads it to S3
    using S3 Multipart Upload API for large file support (no AWS CLI required).
.NOTES
    Version: 3.0.0
    Requires: PowerShell 5.1+
    Supports files up to 1TB using multipart upload
#>

param(
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    [switch]$TestOnly
)

$ErrorActionPreference = "Stop"
$script:LogFile = $null

# Multipart upload configuration
$script:PartSizeMB = 100  # 100MB per part
$script:PartSizeBytes = $script:PartSizeMB * 1MB
$script:MaxRetries = 3

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

#region ==================== S3 MULTIPART UPLOAD ====================

function Start-S3MultipartUpload {
    param(
        [string]$BucketName,
        [string]$Key,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region
    )
    
    Write-Log "Initiating multipart upload for: $Key" "INFO"
    
    $endpoint = "https://s3.$Region.amazonaws.com/$BucketName/$Key"
    $queryString = "uploads="
    
    $payloadHash = Get-SHA256Hash -Data ([byte[]]@())
    
    $headers = @{
        "Host" = "s3.$Region.amazonaws.com"
        "Content-Type" = "application/octet-stream"
    }
    
    $authResult = Get-AWSSignatureV4 `
        -Method "POST" `
        -Uri $endpoint `
        -Region $Region `
        -Service "s3" `
        -AccessKey $AccessKey `
        -SecretKey $SecretKey `
        -Headers $headers `
        -PayloadHash $payloadHash `
        -QueryString $queryString
    
    $requestHeaders = @{
        "Authorization" = $authResult.Authorization
        "x-amz-date" = $authResult.AmzDate
        "x-amz-content-sha256" = $authResult.AmzContentSha256
        "Content-Type" = "application/octet-stream"
        "Host" = "s3.$Region.amazonaws.com"
    }
    
    $response = Invoke-RestMethod `
        -Uri "$endpoint`?uploads" `
        -Method POST `
        -Headers $requestHeaders
    
    $uploadId = $response.InitiateMultipartUploadResult.UploadId
    Write-Log "Multipart upload initiated. UploadId: $uploadId" "INFO"
    
    return $uploadId
}

function Send-S3Part {
    param(
        [string]$BucketName,
        [string]$Key,
        [string]$UploadId,
        [int]$PartNumber,
        [byte[]]$Data,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region,
        [int]$MaxRetries = 3
    )
    
    $endpoint = "https://s3.$Region.amazonaws.com/$BucketName/$Key"
    $queryString = "partNumber=$PartNumber&uploadId=$UploadId"
    
    # Use UNSIGNED-PAYLOAD to skip expensive SHA256 hash computation
    # This is safe and used by AWS CLI/SDKs - S3 still validates integrity
    $payloadHash = "UNSIGNED-PAYLOAD"
    
    $headers = @{
        "Host" = "s3.$Region.amazonaws.com"
        "Content-Type" = "application/octet-stream"
    }
    
    $retryCount = 0
    $etag = $null
    
    while (-not $etag -and $retryCount -lt $MaxRetries) {
        try {
            $authResult = Get-AWSSignatureV4 `
                -Method "PUT" `
                -Uri $endpoint `
                -Region $Region `
                -Service "s3" `
                -AccessKey $AccessKey `
                -SecretKey $SecretKey `
                -Headers $headers `
                -PayloadHash $payloadHash `
                -QueryString $queryString
            
            $requestHeaders = @{
                "Authorization" = $authResult.Authorization
                "x-amz-date" = $authResult.AmzDate
                "x-amz-content-sha256" = $authResult.AmzContentSha256
                "Content-Type" = "application/octet-stream"
                "Host" = "s3.$Region.amazonaws.com"
            }
            
            $response = Invoke-WebRequest `
                -Uri "$endpoint`?partNumber=$PartNumber&uploadId=$UploadId" `
                -Method PUT `
                -Headers $requestHeaders `
                -Body $Data `
                -ContentType "application/octet-stream" `
                -UseBasicParsing
            
            # Extract ETag from response headers
            $etag = $response.Headers["ETag"]
            if ($etag) {
                $etag = $etag.Trim('"')
            }
        }
        catch {
            $retryCount++
            if ($retryCount -lt $MaxRetries) {
                $waitTime = [math]::Pow(2, $retryCount)
                Write-Log "Part $PartNumber upload failed, retrying in $waitTime seconds... (Attempt $retryCount/$MaxRetries)" "WARN"
                Start-Sleep -Seconds $waitTime
            }
            else {
                throw "Failed to upload part $PartNumber after $MaxRetries attempts: $_"
            }
        }
    }
    
    return $etag
}

function Complete-S3MultipartUpload {
    param(
        [string]$BucketName,
        [string]$Key,
        [string]$UploadId,
        [array]$Parts,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region
    )
    
    Write-Log "Completing multipart upload with $($Parts.Count) parts..." "INFO"
    
    $endpoint = "https://s3.$Region.amazonaws.com/$BucketName/$Key"
    $queryString = "uploadId=$UploadId"
    
    # Build the completion XML
    $xmlParts = $Parts | ForEach-Object {
        "<Part><PartNumber>$($_.PartNumber)</PartNumber><ETag>`"$($_.ETag)`"</ETag></Part>"
    }
    $completionXml = "<CompleteMultipartUpload>$($xmlParts -join '')</CompleteMultipartUpload>"
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($completionXml)
    
    $payloadHash = Get-SHA256Hash -Data $bodyBytes
    
    $headers = @{
        "Host" = "s3.$Region.amazonaws.com"
        "Content-Type" = "application/xml"
    }
    
    $authResult = Get-AWSSignatureV4 `
        -Method "POST" `
        -Uri $endpoint `
        -Region $Region `
        -Service "s3" `
        -AccessKey $AccessKey `
        -SecretKey $SecretKey `
        -Headers $headers `
        -PayloadHash $payloadHash `
        -QueryString $queryString
    
    $requestHeaders = @{
        "Authorization" = $authResult.Authorization
        "x-amz-date" = $authResult.AmzDate
        "x-amz-content-sha256" = $authResult.AmzContentSha256
        "Content-Type" = "application/xml"
        "Host" = "s3.$Region.amazonaws.com"
    }
    
    $response = Invoke-RestMethod `
        -Uri "$endpoint`?uploadId=$UploadId" `
        -Method POST `
        -Headers $requestHeaders `
        -Body $completionXml `
        -ContentType "application/xml"
    
    Write-Log "Multipart upload completed successfully" "SUCCESS"
    return $response
}

function Stop-S3MultipartUpload {
    param(
        [string]$BucketName,
        [string]$Key,
        [string]$UploadId,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region
    )
    
    Write-Log "Aborting multipart upload: $UploadId" "WARN"
    
    $endpoint = "https://s3.$Region.amazonaws.com/$BucketName/$Key"
    $queryString = "uploadId=$UploadId"
    
    $payloadHash = Get-SHA256Hash -Data ([byte[]]@())
    
    $headers = @{
        "Host" = "s3.$Region.amazonaws.com"
    }
    
    $authResult = Get-AWSSignatureV4 `
        -Method "DELETE" `
        -Uri $endpoint `
        -Region $Region `
        -Service "s3" `
        -AccessKey $AccessKey `
        -SecretKey $SecretKey `
        -Headers $headers `
        -PayloadHash $payloadHash `
        -QueryString $queryString
    
    $requestHeaders = @{
        "Authorization" = $authResult.Authorization
        "x-amz-date" = $authResult.AmzDate
        "x-amz-content-sha256" = $authResult.AmzContentSha256
        "Host" = "s3.$Region.amazonaws.com"
    }
    
    try {
        Invoke-RestMethod `
            -Uri "$endpoint`?uploadId=$UploadId" `
            -Method DELETE `
            -Headers $requestHeaders | Out-Null
        
        Write-Log "Multipart upload aborted successfully" "INFO"
    }
    catch {
        Write-Log "Failed to abort multipart upload: $_" "WARN"
    }
}

#endregion

#region ==================== S3 FILE UPLOAD ====================

function Send-S3SinglePut {
    param(
        [string]$BucketName,
        [string]$Key,
        [string]$FilePath,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region
    )
    
    $fileInfo = Get-Item $FilePath
    $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
    
    Write-Log "Using single PUT upload for file: $($fileInfo.Name) ($fileSizeMB MB)" "INFO"
    
    $endpoint = "https://s3.$Region.amazonaws.com/$BucketName/$Key"
    
    # Use UNSIGNED-PAYLOAD for speed (skip SHA256 hashing)
    $payloadHash = "UNSIGNED-PAYLOAD"
    
    $headers = @{
        "Host" = "s3.$Region.amazonaws.com"
        "Content-Type" = "application/octet-stream"
    }
    
    $startTime = Get-Date
    
    try {
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
            "Content-Type" = "application/octet-stream"
            "Host" = "s3.$Region.amazonaws.com"
        }
        
        # Read file and upload in single request
        Write-Log "Uploading file..." "INFO"
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        Invoke-RestMethod `
            -Uri $endpoint `
            -Method PUT `
            -Headers $requestHeaders `
            -Body $fileBytes `
            -ContentType "application/octet-stream"
        
        # Calculate upload time and speed
        $totalTime = (Get-Date) - $startTime
        $totalTimeStr = if ($totalTime.TotalMinutes -ge 1) {
            "{0:0}m {1:0}s" -f $totalTime.TotalMinutes, $totalTime.Seconds
        } else {
            "{0:0}s" -f $totalTime.TotalSeconds
        }
        
        $avgSpeedMBps = if ($totalTime.TotalSeconds -gt 0) {
            [math]::Round($fileSizeMB / $totalTime.TotalSeconds, 2)
        } else { 0 }
        
        Write-Log "Single PUT upload complete: $fileSizeMB MB in $totalTimeStr (avg: $avgSpeedMBps MB/s)" "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Single PUT upload failed: $_" "ERROR"
        throw "Single PUT upload failed: $_"
    }
}

function Send-FileToS3 {
    param(
        [string]$BucketName,
        [string]$Key,
        [string]$FilePath,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region
    )
    
    $fileInfo = Get-Item $FilePath
    $fileSizeBytes = $fileInfo.Length
    $fileSizeMB = [math]::Round($fileSizeBytes / 1MB, 2)
    $fileSizeGB = [math]::Round($fileSizeBytes / 1GB, 2)
    
    Write-Log "Starting upload: $($fileInfo.Name)" "INFO"
    Write-Log "File size: $fileSizeMB MB ($fileSizeGB GB)" "INFO"
    
    # Threshold: 3GB - use single PUT for smaller files (faster, less overhead)
    # S3 allows up to 5GB for single PUT, using 3GB as safe limit
    $singlePutThresholdBytes = 3 * 1GB
    
    if ($fileSizeBytes -lt $singlePutThresholdBytes) {
        Write-Log "File under 3GB - using single PUT (faster than multipart)" "INFO"
        return Send-S3SinglePut `
            -BucketName $BucketName `
            -Key $Key `
            -FilePath $FilePath `
            -AccessKey $AccessKey `
            -SecretKey $SecretKey `
            -Region $Region
    }
    
    # File is 3GB+ - use multipart upload
    Write-Log "File over 3GB - using multipart upload" "INFO"
    
    # Calculate total parts
    $totalParts = [math]::Ceiling($fileSizeBytes / $script:PartSizeBytes)
    Write-Log "Upload will be split into $totalParts parts ($script:PartSizeMB MB each)" "INFO"
    
    $uploadId = $null
    $startTime = Get-Date
    
    try {
        # Step 1: Initiate multipart upload
        $uploadId = Start-S3MultipartUpload `
            -BucketName $BucketName `
            -Key $Key `
            -AccessKey $AccessKey `
            -SecretKey $SecretKey `
            -Region $Region
        
        # Step 2: Upload parts
        $parts = @()
        $partNumber = 1
        $bytesUploaded = 0
        
        $stream = [System.IO.File]::OpenRead($FilePath)
        $buffer = New-Object byte[] $script:PartSizeBytes
        
        try {
            while (($bytesRead = $stream.Read($buffer, 0, $script:PartSizeBytes)) -gt 0) {
                # Get the actual chunk data
                $chunk = if ($bytesRead -eq $script:PartSizeBytes) {
                    $buffer
                } else {
                    $buffer[0..($bytesRead - 1)]
                }
                
                # Calculate progress
                $percentComplete = [math]::Round(($partNumber / $totalParts) * 100, 1)
                $bytesUploaded += $bytesRead
                
                # Calculate estimated time remaining
                $elapsed = (Get-Date) - $startTime
                $bytesPerSecond = if ($elapsed.TotalSeconds -gt 0) { $bytesUploaded / $elapsed.TotalSeconds } else { 0 }
                $bytesRemaining = $fileSizeBytes - $bytesUploaded
                $secondsRemaining = if ($bytesPerSecond -gt 0) { $bytesRemaining / $bytesPerSecond } else { 0 }
                $timeRemaining = [TimeSpan]::FromSeconds($secondsRemaining)
                
                # Format time remaining
                $timeRemainingStr = if ($timeRemaining.TotalHours -ge 1) {
                    "{0:0}h {1:0}m" -f $timeRemaining.TotalHours, $timeRemaining.Minutes
                } elseif ($timeRemaining.TotalMinutes -ge 1) {
                    "{0:0}m {1:0}s" -f $timeRemaining.TotalMinutes, $timeRemaining.Seconds
                } else {
                    "{0:0}s" -f $timeRemaining.TotalSeconds
                }
                
                Write-Log "Uploading part $partNumber of $totalParts ($percentComplete%) - ETA: $timeRemainingStr" "INFO"
                
                # Upload the part
                $etag = Send-S3Part `
                    -BucketName $BucketName `
                    -Key $Key `
                    -UploadId $uploadId `
                    -PartNumber $partNumber `
                    -Data $chunk `
                    -AccessKey $AccessKey `
                    -SecretKey $SecretKey `
                    -Region $Region `
                    -MaxRetries $script:MaxRetries
                
                $parts += @{
                    PartNumber = $partNumber
                    ETag = $etag
                }
                
                $partNumber++
            }
        }
        finally {
            $stream.Close()
        }
        
        # Step 3: Complete multipart upload
        Complete-S3MultipartUpload `
            -BucketName $BucketName `
            -Key $Key `
            -UploadId $uploadId `
            -Parts $parts `
            -AccessKey $AccessKey `
            -SecretKey $SecretKey `
            -Region $Region
        
        # Calculate total time
        $totalTime = (Get-Date) - $startTime
        $totalTimeStr = if ($totalTime.TotalHours -ge 1) {
            "{0:0}h {1:0}m {2:0}s" -f $totalTime.TotalHours, $totalTime.Minutes, $totalTime.Seconds
        } elseif ($totalTime.TotalMinutes -ge 1) {
            "{0:0}m {1:0}s" -f $totalTime.TotalMinutes, $totalTime.Seconds
        } else {
            "{0:0}s" -f $totalTime.TotalSeconds
        }
        
        $avgSpeedMBps = [math]::Round($fileSizeMB / $totalTime.TotalSeconds, 2)
        
        Write-Log "Upload complete: $fileSizeGB GB in $totalTimeStr (avg: $avgSpeedMBps MB/s)" "SUCCESS"
        
        return $true
    }
    catch {
        # Abort the multipart upload on failure
        if ($uploadId) {
            Stop-S3MultipartUpload `
                -BucketName $BucketName `
                -Key $Key `
                -UploadId $uploadId `
                -AccessKey $AccessKey `
                -SecretKey $SecretKey `
                -Region $Region
        }
        
        throw "Upload failed and was aborted: $_"
    }
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
        Write-Log "Testing S3 connection..." "INFO"
        
        $testKey = "$S3Prefix/_connection_test_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
        $testContent = "Connection test - $(Get-Date)"
        $testBytes = [System.Text.Encoding]::UTF8.GetBytes($testContent)
        
        # Simple PUT for small test file
        $endpoint = "https://s3.$Region.amazonaws.com/$BucketName/$testKey"
        $payloadHash = Get-SHA256Hash -Data $testBytes
        
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
        
        Invoke-RestMethod `
            -Uri $endpoint `
            -Method PUT `
            -Headers $requestHeaders `
            -Body $testBytes `
            -ContentType "text/plain" | Out-Null
        
        Write-Log "S3 connection test successful" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "S3 connection test failed: $_" "ERROR"
        return $false
    }
}

#endregion

#region ==================== RAR COMPRESSION ====================

function Test-RarExecutable {
    param(
        [string]$RarPath
    )
    
    Write-Log "Validating RAR executable: $RarPath" "INFO"
    
    if ([string]::IsNullOrEmpty($RarPath)) {
        throw "RAR executable path is not configured. Set 'rar_executable_path' in config.json"
    }
    
    if (-not (Test-Path $RarPath)) {
        throw "RAR executable not found at: $RarPath. Please install WinRAR or update the path in config.json"
    }
    
    # Test if it's actually executable - check multiple lines of output (not just first line)
    try {
        $versionOutput = & $RarPath 2>&1 | Select-Object -First 10
        $outputText = $versionOutput -join "`n"
        if ($outputText -match "RAR") {
            Write-Log "RAR executable validated successfully" "SUCCESS"
            return $true
        }
        else {
            throw "File at $RarPath does not appear to be a valid RAR executable"
        }
    }
    catch {
        throw "Failed to execute RAR at $RarPath : $_"
    }
}

function Compress-BakFile {
    param(
        [string]$BakFilePath,
        [string]$TempDirectory,
        [string]$RarPath,
        [int]$CompressionLevel = 5
    )
    
    $bakFileInfo = Get-Item $BakFilePath
    $bakSizeMB = [math]::Round($bakFileInfo.Length / 1MB, 2)
    $bakSizeGB = [math]::Round($bakFileInfo.Length / 1GB, 2)
    
    Write-Log "Starting RAR compression..." "INFO"
    Write-Log "Source file: $($bakFileInfo.Name) ($bakSizeGB GB)" "INFO"
    Write-Log "Compression level: $CompressionLevel (0=store, 5=best)" "INFO"
    
    # Create temp directory if it doesn't exist
    if (-not (Test-Path $TempDirectory)) {
        Write-Log "Creating temp directory: $TempDirectory" "INFO"
        New-Item -ItemType Directory -Path $TempDirectory -Force | Out-Null
    }
    
    # Build output path - same name but .rar extension
    $rarFileName = [System.IO.Path]::GetFileNameWithoutExtension($bakFileInfo.Name) + ".rar"
    $rarFilePath = Join-Path $TempDirectory $rarFileName
    
    # Remove existing RAR file if present (from previous failed attempt)
    if (Test-Path $rarFilePath) {
        Write-Log "Removing existing RAR file from previous attempt: $rarFilePath" "WARN"
        Remove-Item $rarFilePath -Force
    }
    
    Write-Log "Output file: $rarFilePath" "INFO"
    
    $startTime = Get-Date
    
    try {
        # Build RAR command arguments
        # a = add to archive
        # -m<n> = compression level (0-5)
        # -ep1 = exclude base directory from names
        # -y = assume yes on all queries
        # -idq = quiet mode (disable messages)
        $arguments = @(
            "a",
            "-m$CompressionLevel",
            "-ep1",
            "-y",
            "-idq",
            "`"$rarFilePath`"",
            "`"$BakFilePath`""
        )
        
        Write-Log "Executing: $RarPath $($arguments -join ' ')" "INFO"
        
        # Run RAR compression
        $process = Start-Process -FilePath $RarPath `
            -ArgumentList $arguments `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput "$TempDirectory\rar_stdout.txt" `
            -RedirectStandardError "$TempDirectory\rar_stderr.txt"
        
        # Check exit code
        if ($process.ExitCode -ne 0) {
            $stderr = ""
            if (Test-Path "$TempDirectory\rar_stderr.txt") {
                $stderr = Get-Content "$TempDirectory\rar_stderr.txt" -Raw
            }
            throw "RAR compression failed with exit code $($process.ExitCode). Error: $stderr"
        }
        
        # Verify the RAR file was created
        if (-not (Test-Path $rarFilePath)) {
            throw "RAR compression completed but output file not found: $rarFilePath"
        }
        
        $rarFileInfo = Get-Item $rarFilePath
        $rarSizeMB = [math]::Round($rarFileInfo.Length / 1MB, 2)
        $rarSizeGB = [math]::Round($rarFileInfo.Length / 1GB, 2)
        
        $compressionTime = (Get-Date) - $startTime
        $compressionTimeStr = if ($compressionTime.TotalHours -ge 1) {
            "{0:0}h {1:0}m {2:0}s" -f $compressionTime.TotalHours, $compressionTime.Minutes, $compressionTime.Seconds
        } elseif ($compressionTime.TotalMinutes -ge 1) {
            "{0:0}m {1:0}s" -f $compressionTime.TotalMinutes, $compressionTime.Seconds
        } else {
            "{0:0}s" -f $compressionTime.TotalSeconds
        }
        
        $compressionRatio = [math]::Round(($rarFileInfo.Length / $bakFileInfo.Length) * 100, 1)
        $spaceSaved = [math]::Round(($bakFileInfo.Length - $rarFileInfo.Length) / 1GB, 2)
        
        Write-Log "Compression complete in $compressionTimeStr" "SUCCESS"
        Write-Log "Original size: $bakSizeGB GB -> Compressed size: $rarSizeGB GB ($compressionRatio% of original)" "INFO"
        Write-Log "Space saved: $spaceSaved GB" "INFO"
        
        # Clean up temp log files
        Remove-Item "$TempDirectory\rar_stdout.txt" -Force -ErrorAction SilentlyContinue
        Remove-Item "$TempDirectory\rar_stderr.txt" -Force -ErrorAction SilentlyContinue
        
        return $rarFileInfo
    }
    catch {
        # Clean up partial RAR file on failure
        if (Test-Path $rarFilePath) {
            Write-Log "Cleaning up partial RAR file after failure" "WARN"
            Remove-Item $rarFilePath -Force -ErrorAction SilentlyContinue
        }
        
        # Clean up temp log files
        Remove-Item "$TempDirectory\rar_stdout.txt" -Force -ErrorAction SilentlyContinue
        Remove-Item "$TempDirectory\rar_stderr.txt" -Force -ErrorAction SilentlyContinue
        
        throw "Compression failed: $_"
    }
}

function Remove-CompressedFile {
    param(
        [string]$FilePath
    )
    
    if (Test-Path $FilePath) {
        Write-Log "Cleaning up compressed file: $FilePath" "INFO"
        try {
            Remove-Item $FilePath -Force
            Write-Log "Compressed file removed successfully" "SUCCESS"
            return $true
        }
        catch {
            Write-Log "Failed to remove compressed file: $_" "WARN"
            return $false
        }
    }
    else {
        Write-Log "Compressed file not found for cleanup: $FilePath" "WARN"
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
    Write-Log "File size: $([math]::Round($latestBak.Length / 1MB, 2)) MB ($([math]::Round($latestBak.Length / 1GB, 2)) GB)" "INFO"
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
    
    # Determine if compression is enabled
    $compressionEnabled = $Config.compression_enabled -eq $true
    
    # Variables to track file to upload and cleanup
    $fileToUpload = $bakFile
    $compressedFilePath = $null
    
    # Compress if enabled
    if ($compressionEnabled) {
        Write-Log "Compression is ENABLED - compressing before upload" "INFO"
        
        $compressionLevel = if ($null -ne $Config.compression_level) { $Config.compression_level } else { 5 }
        
        $compressedFile = Compress-BakFile `
            -BakFilePath $bakFile.FullName `
            -TempDirectory $Config.temp_directory `
            -RarPath $Config.rar_executable_path `
            -CompressionLevel $compressionLevel
        
        $fileToUpload = $compressedFile
        $compressedFilePath = $compressedFile.FullName
    }
    else {
        Write-Log "Compression is DISABLED - uploading raw .bak file" "INFO"
    }
    
    # Build S3 key with server identifier and date
    $s3Key = "$($Config.s3_prefix)/$serverIdentifier/$date/$($fileToUpload.Name)"
    
    Write-Log "Starting upload to S3..." "INFO"
    Write-Log "S3 Bucket: $($Config.s3_bucket)" "INFO"
    Write-Log "S3 Key: $s3Key" "INFO"
    
    try {
        # Upload to S3 using multipart upload
        $uploadResult = Send-FileToS3 `
            -BucketName $Config.s3_bucket `
            -Key $s3Key `
            -FilePath $fileToUpload.FullName `
            -AccessKey $Config.aws_access_key `
            -SecretKey $Config.aws_secret_key `
            -Region $Config.s3_region
        
        if ($uploadResult) {
            Write-Log "File uploaded successfully to S3" "SUCCESS"
            
            # Clean up compressed file after successful upload
            if ($compressedFilePath) {
                Remove-CompressedFile -FilePath $compressedFilePath
            }
            
            return @{
                success = $true
                original_file_name = $bakFile.Name
                uploaded_file_name = $fileToUpload.Name
                original_size_mb = [math]::Round($bakFile.Length / 1MB, 2)
                original_size_gb = [math]::Round($bakFile.Length / 1GB, 2)
                uploaded_size_mb = [math]::Round($fileToUpload.Length / 1MB, 2)
                uploaded_size_gb = [math]::Round($fileToUpload.Length / 1GB, 2)
                compression_enabled = $compressionEnabled
                s3_key = $s3Key
                timestamp = (Get-Date).ToString("o")
            }
        }
        else {
            throw "Failed to upload file to S3"
        }
    }
    catch {
        # On upload failure, keep the compressed file for potential retry
        if ($compressedFilePath -and (Test-Path $compressedFilePath)) {
            Write-Log "Upload failed - keeping compressed file for retry: $compressedFilePath" "WARN"
        }
        throw $_
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
        Write-Log "Part Size: $script:PartSizeMB MB" "INFO"
        
        # Log and validate compression settings
        $compressionEnabled = $config.compression_enabled -eq $true
        Write-Log "Compression: $(if ($compressionEnabled) { 'ENABLED' } else { 'DISABLED' })" "INFO"
        
        if ($compressionEnabled) {
            Write-Log "RAR Path: $($config.rar_executable_path)" "INFO"
            Write-Log "Compression Level: $($config.compression_level)" "INFO"
            Write-Log "Temp Directory: $($config.temp_directory)" "INFO"
            
            # Validate RAR executable exists and is functional
            Test-RarExecutable -RarPath $config.rar_executable_path
        }
        
        # Clean old logs
        if ($config.log_retention_days -gt 0) {
            Remove-OldLogs -LogDirectory $config.log_directory -RetentionDays $config.log_retention_days
        }
        
        # Test S3 connection first
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
        Write-Log "Original File: $($result.original_file_name)" "INFO"
        Write-Log "Uploaded File: $($result.uploaded_file_name)" "INFO"
        if ($result.compression_enabled) {
            Write-Log "Original Size: $($result.original_size_gb) GB -> Uploaded Size: $($result.uploaded_size_gb) GB" "INFO"
            $compressionRatio = [math]::Round(($result.uploaded_size_mb / $result.original_size_mb) * 100, 1)
            Write-Log "Compression Ratio: $compressionRatio% of original" "INFO"
        }
        else {
            Write-Log "Size: $($result.uploaded_size_mb) MB ($($result.uploaded_size_gb) GB)" "INFO"
        }
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
