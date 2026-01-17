<#
.SYNOPSIS
    MSSQL Database Backup to S3 - Pure PowerShell Implementation
.DESCRIPTION
    Exports all tables from specified MSSQL databases to CSV and uploads to S3
    using native PowerShell REST API calls (no AWS CLI required).
.NOTES
    Version: 1.0.0
    Requires: PowerShell 5.1+, SqlServer module
#>

param(
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    [switch]$TestOnly,
    [switch]$Verbose
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

function Send-S3Object {
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
    $contentType = "text/csv"
    
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
            $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
            
            $response = Invoke-RestMethod `
                -Uri $endpoint `
                -Method PUT `
                -Headers $requestHeaders `
                -Body $fileBytes `
                -ContentType $contentType
            
            $success = $true
            Write-Log "Uploaded: $Key ($([math]::Round($fileInfo.Length / 1KB, 2)) KB)" "SUCCESS"
        }
        catch {
            $retryCount++
            if ($retryCount -lt $MaxRetries) {
                $waitTime = [math]::Pow(2, $retryCount)
                Write-Log "Upload failed, retrying in $waitTime seconds... (Attempt $retryCount/$MaxRetries)" "WARN"
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

function Get-S3Object {
    param(
        [string]$BucketName,
        [string]$Key,
        [string]$OutputPath,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region
    )
    
    $endpoint = "https://s3.$Region.amazonaws.com/$BucketName/$Key"
    $payloadHash = Get-SHA256Hash -Data ([byte[]]@())
    
    $headers = @{
        "Host" = "s3.$Region.amazonaws.com"
    }
    
    $authResult = Get-AWSSignatureV4 `
        -Method "GET" `
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
        "Host" = "s3.$Region.amazonaws.com"
    }
    
    Invoke-RestMethod -Uri $endpoint -Method GET -Headers $requestHeaders -OutFile $OutputPath
    Write-Log "Downloaded: $Key" "SUCCESS"
}

function Test-S3Connection {
    param(
        [string]$BucketName,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region
    )
    
    try {
        $testKey = "_connection_test_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
        $testContent = "Connection test - $(Get-Date)"
        $testFile = Join-Path $env:TEMP $testKey
        
        Set-Content -Path $testFile -Value $testContent
        
        Send-S3Object `
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

#region ==================== DATABASE OPERATIONS ====================

function Test-SqlConnection {
    param(
        [string]$ServerInstance,
        [string]$Database
    )
    
    try {
        $query = "SELECT 1 AS ConnectionTest"
        Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $query -ConnectionTimeout 10 | Out-Null
        return $true
    }
    catch {
        Write-Log "SQL connection failed to $ServerInstance/$Database : $_" "ERROR"
        return $false
    }
}

function Get-DatabaseTables {
    param(
        [string]$ServerInstance,
        [string]$Database
    )
    
    $query = @"
        SELECT 
            TABLE_SCHEMA,
            TABLE_NAME
        FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_TYPE = 'BASE TABLE'
        ORDER BY TABLE_SCHEMA, TABLE_NAME
"@
    
    $tables = Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $query
    return $tables
}

function Get-TableRowCount {
    param(
        [string]$ServerInstance,
        [string]$Database,
        [string]$Schema,
        [string]$TableName
    )
    
    $query = "SELECT COUNT(*) AS [RowCount] FROM [$Schema].[$TableName]"
    $result = Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $query
    return $result.RowCount
}

function Export-TableToCsv {
    param(
        [string]$ServerInstance,
        [string]$Database,
        [string]$Schema,
        [string]$TableName,
        [string]$OutputPath
    )
    
    $query = "SELECT * FROM [$Schema].[$TableName]"
    
    try {
        $data = Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $query -MaxCharLength 65535
        
        if ($data) {
            $data | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            return $true
        }
        else {
            # Empty table - create empty CSV with headers
            $headerQuery = @"
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = '$Schema' AND TABLE_NAME = '$TableName'
                ORDER BY ORDINAL_POSITION
"@
            $columns = Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $headerQuery
            $headers = ($columns | ForEach-Object { "`"$($_.COLUMN_NAME)`"" }) -join ","
            Set-Content -Path $OutputPath -Value $headers -Encoding UTF8
            return $true
        }
    }
    catch {
        Write-Log "Failed to export $Schema.$TableName : $_" "ERROR"
        return $false
    }
}

function Get-TableSchema {
    param(
        [string]$ServerInstance,
        [string]$Database,
        [string]$Schema,
        [string]$TableName
    )
    
    $query = @"
        SELECT 
            COLUMN_NAME,
            DATA_TYPE,
            CHARACTER_MAXIMUM_LENGTH,
            IS_NULLABLE,
            COLUMN_DEFAULT
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = '$Schema' AND TABLE_NAME = '$TableName'
        ORDER BY ORDINAL_POSITION
"@
    
    $columns = Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $query
    
    return $columns | ForEach-Object {
        @{
            name = $_.COLUMN_NAME
            type = $_.DATA_TYPE
            max_length = $_.CHARACTER_MAXIMUM_LENGTH
            nullable = $_.IS_NULLABLE
            default = $_.COLUMN_DEFAULT
        }
    }
}

#endregion

#region ==================== MAIN BACKUP LOGIC ====================

function Start-DatabaseBackup {
    param(
        [object]$Config
    )
    
    $date = Get-Date -Format "yyyy-MM-dd"
    $serverIdentifier = $Config.server_identifier
    if ([string]::IsNullOrEmpty($serverIdentifier)) {
        $serverIdentifier = $env:COMPUTERNAME
    }
    
    $backupSummary = @{
        server = $serverIdentifier
        timestamp = (Get-Date).ToString("o")
        databases = @()
        total_tables = 0
        successful_uploads = 0
        failed_uploads = 0
    }
    
    foreach ($database in $Config.databases) {
        Write-Log "Processing database: $database" "INFO"
        
        $dbSummary = @{
            name = $database
            tables = @()
            status = "success"
        }
        
        # Test connection
        if (-not (Test-SqlConnection -ServerInstance $Config.sql_server -Database $database)) {
            Write-Log "Skipping database $database - connection failed" "ERROR"
            $dbSummary.status = "connection_failed"
            $backupSummary.databases += $dbSummary
            continue
        }
        
        # Get all tables
        $tables = Get-DatabaseTables -ServerInstance $Config.sql_server -Database $database
        Write-Log "Found $($tables.Count) tables in $database" "INFO"
        
        # Create temp directory for this database
        $dbTempDir = Join-Path $Config.temp_directory "$serverIdentifier\$database\$date"
        if (-not (Test-Path $dbTempDir)) {
            New-Item -ItemType Directory -Path $dbTempDir -Force | Out-Null
        }
        
        foreach ($table in $tables) {
            $schema = $table.TABLE_SCHEMA
            $tableName = $table.TABLE_NAME
            $fullTableName = "$schema.$tableName"
            $csvFileName = "$schema`_$tableName.csv"
            $csvPath = Join-Path $dbTempDir $csvFileName
            
            $backupSummary.total_tables++
            
            Write-Log "Exporting: $fullTableName" "INFO"
            
            $tableSummary = @{
                schema = $schema
                name = $tableName
                rows = 0
                status = "success"
            }
            
            try {
                # Get row count
                $rowCount = Get-TableRowCount -ServerInstance $Config.sql_server -Database $database -Schema $schema -TableName $tableName
                $tableSummary.rows = $rowCount
                
                # Export to CSV
                $exportSuccess = Export-TableToCsv `
                    -ServerInstance $Config.sql_server `
                    -Database $database `
                    -Schema $schema `
                    -TableName $tableName `
                    -OutputPath $csvPath
                
                if ($exportSuccess) {
                    # Upload to S3
                    $s3Key = "$($Config.s3_prefix)/$serverIdentifier/$database/$date/$csvFileName"
                    
                    Send-S3Object `
                        -BucketName $Config.s3_bucket `
                        -Key $s3Key `
                        -FilePath $csvPath `
                        -AccessKey $Config.aws_access_key `
                        -SecretKey $Config.aws_secret_key `
                        -Region $Config.s3_region
                    
                    $backupSummary.successful_uploads++
                    
                    # Get schema info for manifest
                    $tableSummary.schema_info = Get-TableSchema `
                        -ServerInstance $Config.sql_server `
                        -Database $database `
                        -Schema $schema `
                        -TableName $tableName
                }
                else {
                    $tableSummary.status = "export_failed"
                    $backupSummary.failed_uploads++
                }
            }
            catch {
                Write-Log "Failed to backup $fullTableName : $_" "ERROR"
                $tableSummary.status = "failed"
                $tableSummary.error = $_.ToString()
                $backupSummary.failed_uploads++
            }
            
            $dbSummary.tables += $tableSummary
        }
        
        $backupSummary.databases += $dbSummary
    }
    
    # Upload manifest
    try {
        $manifestPath = Join-Path $Config.temp_directory "_manifest.json"
        $backupSummary | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -Encoding UTF8
        
        $manifestKey = "$($Config.s3_prefix)/$serverIdentifier/_manifest_$date.json"
        Send-S3Object `
            -BucketName $Config.s3_bucket `
            -Key $manifestKey `
            -FilePath $manifestPath `
            -AccessKey $Config.aws_access_key `
            -SecretKey $Config.aws_secret_key `
            -Region $Config.s3_region
        
        Remove-Item $manifestPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Failed to upload manifest: $_" "WARN"
    }
    
    # Cleanup temp files
    Write-Log "Cleaning up temporary files..." "INFO"
    $tempServerDir = Join-Path $Config.temp_directory $serverIdentifier
    if (Test-Path $tempServerDir) {
        Remove-Item $tempServerDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    return $backupSummary
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
        Write-Log "Databases: $($config.databases -join ', ')" "INFO"
        Write-Log "S3 Bucket: $($config.s3_bucket)" "INFO"
        
        # Clean old logs
        if ($config.log_retention_days -gt 0) {
            Remove-OldLogs -LogDirectory $config.log_directory -RetentionDays $config.log_retention_days
        }
        
        # Create temp directory if needed
        if (-not (Test-Path $config.temp_directory)) {
            New-Item -ItemType Directory -Path $config.temp_directory -Force | Out-Null
        }
        
        # Test S3 connection first
        Write-Log "Testing S3 connection..." "INFO"
        $s3Test = Test-S3Connection `
            -BucketName $config.s3_bucket `
            -AccessKey $config.aws_access_key `
            -SecretKey $config.aws_secret_key `
            -Region $config.s3_region
        
        if (-not $s3Test) {
            throw "S3 connection test failed. Please verify your AWS credentials and bucket access."
        }
        
        if ($TestOnly) {
            Write-Log "Test mode - exiting after connection tests" "SUCCESS"
            return
        }
        
        # Start backup
        $summary = Start-DatabaseBackup -Config $config
        
        # Print summary
        Write-Log "=== Backup Complete ===" "INFO"
        Write-Log "Total tables: $($summary.total_tables)" "INFO"
        Write-Log "Successful uploads: $($summary.successful_uploads)" "SUCCESS"
        
        if ($summary.failed_uploads -gt 0) {
            Write-Log "Failed uploads: $($summary.failed_uploads)" "ERROR"
            exit 1
        }
        
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
