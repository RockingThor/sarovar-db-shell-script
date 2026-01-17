<#
.SYNOPSIS
    Restore MSSQL Database Tables from S3 Backup
.DESCRIPTION
    Downloads CSV backups from S3 and restores them to MSSQL using BULK INSERT.
    Can restore to a different server or database than the original.
.PARAMETER ConfigPath
    Path to config.json file
.PARAMETER Date
    Backup date to restore (format: yyyy-MM-dd)
.PARAMETER SourceServer
    Source server identifier in S3 (default: from config)
.PARAMETER Database
    Database name to restore
.PARAMETER TargetServer
    Target SQL Server instance (default: from config)
.PARAMETER TargetDatabase
    Target database name (default: same as source)
.PARAMETER Tables
    Comma-separated list of specific tables to restore (default: all)
.PARAMETER TruncateBeforeImport
    Truncate target tables before importing data
.PARAMETER CreateTables
    Create tables if they don't exist (uses schema from manifest)
.PARAMETER ListOnly
    Only list available backups, don't restore
.EXAMPLE
    # List available backups
    .\restore-from-s3.ps1 -ListOnly
.EXAMPLE
    # Restore all tables from a specific date
    .\restore-from-s3.ps1 -Date "2026-01-15" -Database "SalesDB"
.EXAMPLE
    # Restore specific tables to a different server
    .\restore-from-s3.ps1 -Date "2026-01-15" -Database "SalesDB" -Tables "Customers,Orders" -TargetServer "NewServer" -TruncateBeforeImport
#>

param(
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    [string]$Date,
    [string]$SourceServer,
    [string]$Database,
    [string]$TargetServer,
    [string]$TargetDatabase,
    [string]$Tables,
    [switch]$TruncateBeforeImport,
    [switch]$CreateTables,
    [switch]$ListOnly
)

$ErrorActionPreference = "Stop"

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
    
    $uriObj = [System.Uri]$Uri
    $canonicalUri = $uriObj.AbsolutePath
    if ([string]::IsNullOrEmpty($canonicalUri)) { $canonicalUri = "/" }
    
    $canonicalQueryString = $QueryString
    
    $Headers["x-amz-date"] = $amzDate
    $Headers["x-amz-content-sha256"] = $PayloadHash
    
    $sortedHeaders = $Headers.GetEnumerator() | Sort-Object Name
    $canonicalHeaders = ($sortedHeaders | ForEach-Object { "$($_.Name.ToLower()):$($_.Value.Trim())" }) -join "`n"
    $canonicalHeaders += "`n"
    
    $signedHeaders = ($sortedHeaders | ForEach-Object { $_.Name.ToLower() }) -join ";"
    
    $canonicalRequest = @(
        $Method,
        $canonicalUri,
        $canonicalQueryString,
        $canonicalHeaders,
        $signedHeaders,
        $PayloadHash
    ) -join "`n"
    
    $algorithm = "AWS4-HMAC-SHA256"
    $credentialScope = "$dateStamp/$Region/$Service/aws4_request"
    $canonicalRequestHash = Get-SHA256Hash -Data ([System.Text.Encoding]::UTF8.GetBytes($canonicalRequest))
    
    $stringToSign = @(
        $algorithm,
        $amzDate,
        $credentialScope,
        $canonicalRequestHash
    ) -join "`n"
    
    $signingKey = Get-SignatureKey -SecretKey $SecretKey -DateStamp $dateStamp -Region $Region -Service $Service
    $signatureBytes = Get-HMACSHA256 -Key $signingKey -Message $stringToSign
    $signature = [BitConverter]::ToString($signatureBytes).Replace("-", "").ToLower()
    
    $authorization = "$algorithm Credential=$AccessKey/$credentialScope, SignedHeaders=$signedHeaders, Signature=$signature"
    
    return @{
        Authorization = $authorization
        AmzDate = $amzDate
        AmzContentSha256 = $PayloadHash
    }
}

#endregion

#region ==================== S3 OPERATIONS ====================

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
}

function Get-S3ObjectContent {
    param(
        [string]$BucketName,
        [string]$Key,
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
    
    return Invoke-RestMethod -Uri $endpoint -Method GET -Headers $requestHeaders
}

function Get-S3ObjectList {
    param(
        [string]$BucketName,
        [string]$Prefix,
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$Region
    )
    
    $endpoint = "https://s3.$Region.amazonaws.com/$BucketName"
    $queryString = "list-type=2&prefix=$([System.Uri]::EscapeDataString($Prefix))"
    $payloadHash = Get-SHA256Hash -Data ([byte[]]@())
    
    $headers = @{
        "Host" = "s3.$Region.amazonaws.com"
    }
    
    $authResult = Get-AWSSignatureV4 `
        -Method "GET" `
        -Uri "$endpoint/?$queryString" `
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
    
    $response = Invoke-RestMethod -Uri "$endpoint/?$queryString" -Method GET -Headers $requestHeaders
    return $response
}

#endregion

#region ==================== DATABASE OPERATIONS ====================

function Test-TableExists {
    param(
        [string]$ServerInstance,
        [string]$Database,
        [string]$Schema,
        [string]$TableName
    )
    
    $query = @"
        SELECT COUNT(*) AS TableExists 
        FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_SCHEMA = '$Schema' AND TABLE_NAME = '$TableName'
"@
    
    $result = Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $query
    return $result.TableExists -gt 0
}

function New-TableFromSchema {
    param(
        [string]$ServerInstance,
        [string]$Database,
        [string]$Schema,
        [string]$TableName,
        [array]$SchemaInfo
    )
    
    $columns = @()
    foreach ($col in $SchemaInfo) {
        $colDef = "[$($col.name)] $($col.type)"
        
        if ($col.max_length -and $col.max_length -ne [DBNull]::Value) {
            if ($col.type -in @('varchar', 'nvarchar', 'char', 'nchar')) {
                $length = if ($col.max_length -eq -1) { "MAX" } else { $col.max_length }
                $colDef += "($length)"
            }
        }
        
        if ($col.nullable -eq "NO") {
            $colDef += " NOT NULL"
        }
        else {
            $colDef += " NULL"
        }
        
        $columns += $colDef
    }
    
    $createQuery = @"
        IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = '$Schema')
            EXEC('CREATE SCHEMA [$Schema]')
        
        CREATE TABLE [$Schema].[$TableName] (
            $($columns -join ",`n            ")
        )
"@
    
    Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $createQuery
    Write-Log "Created table: $Schema.$TableName" "SUCCESS"
}

function Import-CsvToTable {
    param(
        [string]$ServerInstance,
        [string]$Database,
        [string]$Schema,
        [string]$TableName,
        [string]$CsvPath,
        [switch]$TruncateFirst
    )
    
    if ($TruncateFirst) {
        Write-Log "Truncating table: $Schema.$TableName" "INFO"
        $truncateQuery = "TRUNCATE TABLE [$Schema].[$TableName]"
        Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $truncateQuery
    }
    
    # Read CSV and insert data
    $csvData = Import-Csv -Path $CsvPath -Encoding UTF8
    
    if ($csvData.Count -eq 0) {
        Write-Log "No data to import for $Schema.$TableName (empty CSV)" "WARN"
        return 0
    }
    
    # Get column names from CSV
    $columns = $csvData[0].PSObject.Properties.Name
    $columnList = ($columns | ForEach-Object { "[$_]" }) -join ", "
    
    $rowCount = 0
    $batchSize = 1000
    $batch = @()
    
    foreach ($row in $csvData) {
        $values = @()
        foreach ($col in $columns) {
            $value = $row.$col
            if ($null -eq $value -or $value -eq '') {
                $values += "NULL"
            }
            else {
                # Escape single quotes
                $escapedValue = $value -replace "'", "''"
                $values += "'$escapedValue'"
            }
        }
        $batch += "($($values -join ', '))"
        $rowCount++
        
        if ($batch.Count -ge $batchSize) {
            $insertQuery = "INSERT INTO [$Schema].[$TableName] ($columnList) VALUES $($batch -join ', ')"
            Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $insertQuery -QueryTimeout 300
            $batch = @()
            Write-Log "Imported $rowCount rows..." "INFO"
        }
    }
    
    # Insert remaining batch
    if ($batch.Count -gt 0) {
        $insertQuery = "INSERT INTO [$Schema].[$TableName] ($columnList) VALUES $($batch -join ', ')"
        Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Query $insertQuery -QueryTimeout 300
    }
    
    return $rowCount
}

#endregion

#region ==================== MAIN RESTORE LOGIC ====================

function Get-AvailableBackups {
    param(
        [object]$Config
    )
    
    Write-Log "Fetching available backups from S3..." "INFO"
    
    $manifests = @()
    
    try {
        $listResult = Get-S3ObjectList `
            -BucketName $Config.s3_bucket `
            -Prefix "$($Config.s3_prefix)/" `
            -AccessKey $Config.aws_access_key `
            -SecretKey $Config.aws_secret_key `
            -Region $Config.s3_region
        
        # Parse XML response
        $keys = @()
        if ($listResult.ListBucketResult.Contents) {
            foreach ($item in $listResult.ListBucketResult.Contents) {
                $key = $item.Key
                if ($key -match "_manifest_.*\.json$") {
                    $keys += $key
                }
            }
        }
        
        foreach ($key in $keys) {
            try {
                $manifestContent = Get-S3ObjectContent `
                    -BucketName $Config.s3_bucket `
                    -Key $key `
                    -AccessKey $Config.aws_access_key `
                    -SecretKey $Config.aws_secret_key `
                    -Region $Config.s3_region
                
                $manifests += $manifestContent
            }
            catch {
                Write-Log "Could not read manifest: $key" "WARN"
            }
        }
    }
    catch {
        Write-Log "Error listing S3 objects: $_" "ERROR"
    }
    
    return $manifests
}

function Start-Restore {
    param(
        [object]$Config,
        [string]$Date,
        [string]$SourceServer,
        [string]$Database,
        [string]$TargetServer,
        [string]$TargetDatabase,
        [array]$TableList,
        [switch]$TruncateBeforeImport,
        [switch]$CreateTables
    )
    
    Write-Log "Starting restore for $Database from $Date" "INFO"
    
    # Set defaults
    if ([string]::IsNullOrEmpty($SourceServer)) {
        $SourceServer = $Config.server_identifier
        if ([string]::IsNullOrEmpty($SourceServer)) {
            $SourceServer = $env:COMPUTERNAME
        }
    }
    
    if ([string]::IsNullOrEmpty($TargetServer)) {
        $TargetServer = $Config.sql_server
    }
    
    if ([string]::IsNullOrEmpty($TargetDatabase)) {
        $TargetDatabase = $Database
    }
    
    # Download manifest
    $manifestKey = "$($Config.s3_prefix)/$SourceServer/_manifest_$Date.json"
    $tempDir = Join-Path $Config.temp_directory "restore_$Date"
    
    if (-not (Test-Path $tempDir)) {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    }
    
    $manifestPath = Join-Path $tempDir "_manifest.json"
    
    Write-Log "Downloading manifest: $manifestKey" "INFO"
    
    try {
        Get-S3Object `
            -BucketName $Config.s3_bucket `
            -Key $manifestKey `
            -OutputPath $manifestPath `
            -AccessKey $Config.aws_access_key `
            -SecretKey $Config.aws_secret_key `
            -Region $Config.s3_region
    }
    catch {
        Write-Log "Could not download manifest. Backup may not exist for this date." "ERROR"
        throw $_
    }
    
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
    
    # Find database in manifest
    $dbInfo = $manifest.databases | Where-Object { $_.name -eq $Database }
    if (-not $dbInfo) {
        throw "Database '$Database' not found in backup manifest"
    }
    
    Write-Log "Found $($dbInfo.tables.Count) tables in backup" "INFO"
    
    $restoreSummary = @{
        database = $Database
        target_server = $TargetServer
        target_database = $TargetDatabase
        tables_restored = 0
        tables_failed = 0
        total_rows = 0
    }
    
    foreach ($table in $dbInfo.tables) {
        $schema = $table.schema
        $tableName = $table.name
        $fullTableName = "$schema.$tableName"
        
        # Filter tables if specified
        if ($TableList.Count -gt 0 -and $tableName -notin $TableList -and $fullTableName -notin $TableList) {
            continue
        }
        
        Write-Log "Restoring: $fullTableName" "INFO"
        
        try {
            # Download CSV
            $csvFileName = "$schema`_$tableName.csv"
            $s3Key = "$($Config.s3_prefix)/$SourceServer/$Database/$Date/$csvFileName"
            $csvPath = Join-Path $tempDir $csvFileName
            
            Get-S3Object `
                -BucketName $Config.s3_bucket `
                -Key $s3Key `
                -OutputPath $csvPath `
                -AccessKey $Config.aws_access_key `
                -SecretKey $Config.aws_secret_key `
                -Region $Config.s3_region
            
            # Check if table exists
            $tableExists = Test-TableExists `
                -ServerInstance $TargetServer `
                -Database $TargetDatabase `
                -Schema $schema `
                -TableName $tableName
            
            if (-not $tableExists) {
                if ($CreateTables -and $table.schema_info) {
                    New-TableFromSchema `
                        -ServerInstance $TargetServer `
                        -Database $TargetDatabase `
                        -Schema $schema `
                        -TableName $tableName `
                        -SchemaInfo $table.schema_info
                }
                else {
                    Write-Log "Table $fullTableName does not exist and -CreateTables not specified. Skipping." "WARN"
                    $restoreSummary.tables_failed++
                    continue
                }
            }
            
            # Import data
            $rowsImported = Import-CsvToTable `
                -ServerInstance $TargetServer `
                -Database $TargetDatabase `
                -Schema $schema `
                -TableName $tableName `
                -CsvPath $csvPath `
                -TruncateFirst:$TruncateBeforeImport
            
            Write-Log "Restored $rowsImported rows to $fullTableName" "SUCCESS"
            $restoreSummary.tables_restored++
            $restoreSummary.total_rows += $rowsImported
        }
        catch {
            Write-Log "Failed to restore $fullTableName : $_" "ERROR"
            $restoreSummary.tables_failed++
        }
    }
    
    # Cleanup temp files
    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    
    return $restoreSummary
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
        
        # Create temp directory if needed
        if (-not (Test-Path $config.temp_directory)) {
            New-Item -ItemType Directory -Path $config.temp_directory -Force | Out-Null
        }
        
        # Import SQL module
        try {
            Import-Module SqlServer -ErrorAction SilentlyContinue
        }
        catch {
            Import-Module SQLPS -DisableNameChecking -ErrorAction SilentlyContinue
        }
        
        if ($ListOnly) {
            # List available backups
            $backups = Get-AvailableBackups -Config $config
            
            Write-Host ""
            Write-Host "Available Backups:" -ForegroundColor Cyan
            Write-Host "==================" -ForegroundColor Cyan
            
            if ($backups.Count -eq 0) {
                Write-Host "No backups found in S3 bucket: $($config.s3_bucket)" -ForegroundColor Yellow
            }
            else {
                foreach ($backup in $backups) {
                    Write-Host ""
                    Write-Host "Server: $($backup.server)" -ForegroundColor White
                    Write-Host "Timestamp: $($backup.timestamp)" -ForegroundColor Gray
                    
                    foreach ($db in $backup.databases) {
                        Write-Host "  Database: $($db.name)" -ForegroundColor Yellow
                        Write-Host "    Tables: $($db.tables.Count)" -ForegroundColor Gray
                        $totalRows = ($db.tables | Measure-Object -Property rows -Sum).Sum
                        Write-Host "    Total Rows: $totalRows" -ForegroundColor Gray
                    }
                }
            }
            
            Write-Host ""
            return
        }
        
        # Validate required parameters
        if ([string]::IsNullOrEmpty($Date)) {
            throw "Date parameter is required. Use -Date 'yyyy-MM-dd'"
        }
        
        if ([string]::IsNullOrEmpty($Database)) {
            throw "Database parameter is required. Use -Database 'DatabaseName'"
        }
        
        # Parse table list
        $tableList = @()
        if (-not [string]::IsNullOrEmpty($Tables)) {
            $tableList = $Tables -split ',' | ForEach-Object { $_.Trim() }
        }
        
        # Start restore
        $summary = Start-Restore `
            -Config $config `
            -Date $Date `
            -SourceServer $SourceServer `
            -Database $Database `
            -TargetServer $TargetServer `
            -TargetDatabase $TargetDatabase `
            -TableList $tableList `
            -TruncateBeforeImport:$TruncateBeforeImport `
            -CreateTables:$CreateTables
        
        # Print summary
        Write-Host ""
        Write-Host "=== Restore Complete ===" -ForegroundColor Cyan
        Write-Host "Target: $($summary.target_server)/$($summary.target_database)" -ForegroundColor White
        Write-Host "Tables restored: $($summary.tables_restored)" -ForegroundColor Green
        Write-Host "Total rows: $($summary.total_rows)" -ForegroundColor Green
        
        if ($summary.tables_failed -gt 0) {
            Write-Host "Tables failed: $($summary.tables_failed)" -ForegroundColor Red
            exit 1
        }
        
        exit 0
    }
    catch {
        Write-Log "FATAL ERROR: $_" "ERROR"
        exit 1
    }
}

# Run main function
Main

#endregion
