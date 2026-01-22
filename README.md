# MSSQL to S3 Backup Solution

Automated daily backup of MSSQL database tables to Amazon S3 using pure PowerShell - **no AWS CLI or external dependencies required**.

## Features

- **Zero External Dependencies**: Uses native PowerShell with direct S3 REST API calls (AWS Signature V4)
- **Simple Installation**: One-command installer with automatic Task Scheduler setup
- **Production-Ready Validation**: Validates S3 connectivity and permissions before installation
- **Mass Deployment Ready**: Silent mode for deploying to 140+ servers
- **Full Table Export**: Exports all tables from specified databases to CSV format
- **Restoration Support**: Restore data to any MSSQL server from S3 backups
- **Secure**: Windows Authentication for SQL, restricted config file permissions

## Quick Start

### Single Server Installation

1. Download the scripts to your Windows server
2. Open PowerShell as Administrator
3. Run the installer:

```powershell
.\install.ps1
```

4. Follow the prompts to configure:
   - SQL Server instance
   - Database names to backup
   - S3 bucket and AWS credentials
   - Backup schedule time

5. The installer will automatically:
   - Test SQL Server connectivity
   - **Validate S3 connectivity and write permissions** (before installation)
   - Create installation directories
   - Set up scheduled task

### Silent Installation (for Mass Deployment)

```powershell
.\install.ps1 -Silent `
    -S3Bucket "your-bucket-name" `
    -S3Region "us-east-1" `
    -Databases "DB1,DB2,DB3" `
    -AwsAccessKey "AKIAXXXXXXXX" `
    -AwsSecretKey "your-secret-key" `
    -BackupTime "02:00"
```

**Note**: In silent mode, the installer will **fail immediately** if S3 connectivity test fails, preventing incomplete installations in production environments.

## File Structure

```
C:\SarovarBackup\           # Default installation directory
├── backup-to-s3.ps1        # Main backup script
├── restore-from-s3.ps1     # Restore script
├── uninstall.ps1           # Uninstaller
├── config.json             # Configuration (secured)
├── temp\                   # Temporary CSV files (auto-cleaned)
└── logs\                   # Backup logs
```

## S3 Data Structure

```
s3://bucket-name/backups/
└── SERVER-001/
    ├── _manifest_2026-01-16.json    # Backup metadata
    └── DatabaseName/
        └── 2026-01-16/
            ├── dbo_Customers.csv
            ├── dbo_Orders.csv
            └── dbo_Products.csv
```

## Configuration

Configuration is stored in `config.json`:

```json
{
    "server_identifier": "SERVER-001",
    "sql_server": "localhost",
    "databases": ["Database1", "Database2"],
    "s3_bucket": "your-bucket-name",
    "s3_region": "us-east-1",
    "s3_prefix": "backups",
    "aws_access_key": "AKIAXXXXXXXX",
    "aws_secret_key": "your-secret-key",
    "temp_directory": "C:\\SarovarBackup\\temp",
    "log_directory": "C:\\SarovarBackup\\logs",
    "log_retention_days": 30,
    "backup_time": "02:00"
}
```

## Manual Operations

### Run Backup Manually

```powershell
& "C:\SarovarBackup\backup-to-s3.ps1" -ConfigPath "C:\SarovarBackup\config.json"
```

### Test Connection Only

```powershell
& "C:\SarovarBackup\backup-to-s3.ps1" -ConfigPath "C:\SarovarBackup\config.json" -TestOnly
```

**Note**: The installer also performs this connectivity test automatically during installation, before any files are copied or configured.

### List Available Backups

```powershell
& "C:\SarovarBackup\restore-from-s3.ps1" -ListOnly
```

### Restore Data

```powershell
# Restore all tables from a specific date
& "C:\SarovarBackup\restore-from-s3.ps1" -Date "2026-01-15" -Database "SalesDB"

# Restore specific tables
& "C:\SarovarBackup\restore-from-s3.ps1" -Date "2026-01-15" -Database "SalesDB" -Tables "Customers,Orders"

# Restore to a different server
& "C:\SarovarBackup\restore-from-s3.ps1" -Date "2026-01-15" -Database "SalesDB" -TargetServer "NewServer\SQLEXPRESS" -TargetDatabase "SalesDB_Restored"

# Truncate and restore (clean import)
& "C:\SarovarBackup\restore-from-s3.ps1" -Date "2026-01-15" -Database "SalesDB" -TruncateBeforeImport
```

## Mass Deployment (140+ Servers)

### Option 1: Network Share with Per-Server Configs

1. Create config files for each server on a network share:
   ```
   \\fileserver\backup-configs\
   ├── SERVER-001.json
   ├── SERVER-002.json
   └── ...
   ```

2. Deploy using remote PowerShell:
   ```powershell
   $servers = Get-Content "servers.txt"
   
   foreach ($server in $servers) {
       Invoke-Command -ComputerName $server -ScriptBlock {
           # Copy installer from network share
           Copy-Item "\\fileserver\scripts\*" "C:\temp\backup-install\" -Recurse
           
           # Run silent installation
           & "C:\temp\backup-install\install.ps1" -Silent `
               -ConfigFile "\\fileserver\backup-configs\$env:COMPUTERNAME.json"
       }
   }
   ```

### Option 2: Parameterized Mass Deploy

```powershell
$servers = Get-Content "servers.txt"
$commonParams = @{
    S3Bucket = "company-backups"
    S3Region = "us-east-1"
    AwsAccessKey = "AKIAXXXXXXXX"
    AwsSecretKey = "your-secret-key"
    BackupTime = "02:00"
}

foreach ($server in $servers) {
    # Get databases for this server (customize as needed)
    $databases = Get-ServerDatabases $server
    
    Invoke-Command -ComputerName $server -ScriptBlock {
        param($params, $dbs)
        
        & "C:\temp\install.ps1" -Silent `
            -S3Bucket $params.S3Bucket `
            -S3Region $params.S3Region `
            -Databases ($dbs -join ",") `
            -AwsAccessKey $params.AwsAccessKey `
            -AwsSecretKey $params.AwsSecretKey `
            -BackupTime $params.BackupTime `
            -ServerIdentifier $env:COMPUTERNAME
            
    } -ArgumentList $commonParams, $databases
}
```

### Option 3: Group Policy / SCCM

1. Create a startup script that runs the installer
2. Deploy via GPO or SCCM
3. Use environment variables or config file for customization

## AWS S3 Setup

### Required IAM Permissions

Create an IAM user/role with this policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::your-bucket-name",
                "arn:aws:s3:::your-bucket-name/*"
            ]
        }
    ]
}
```

### Recommended S3 Bucket Settings

- Enable versioning (optional, for backup history)
- Enable server-side encryption (SSE-S3 or SSE-KMS)
- Set lifecycle rules to archive old backups to Glacier
- Enable access logging for audit trail

## Prerequisites

- **Windows Server 2016+** (PowerShell 5.1 included)
- **SQL Server** with Windows Authentication configured
- **SqlServer PowerShell Module** (installer will attempt to install if missing)
- **Network access** to `s3.{region}.amazonaws.com` on port 443
- **Valid AWS credentials** with S3 write permissions (tested during installation)

## Uninstallation

```powershell
# Full uninstall
& "C:\SarovarBackup\uninstall.ps1"

# Keep logs and config
& "C:\SarovarBackup\uninstall.ps1" -KeepLogs -KeepConfig

# Silent uninstall
& "C:\SarovarBackup\uninstall.ps1" -Silent
```

## Troubleshooting

### Installation Fails with S3 Connectivity Error

The installer validates S3 connectivity **before** installation. If this fails:

- **403 Forbidden / Access Denied**: 
  - Verify AWS credentials are correct
  - Check IAM user has `s3:PutObject` permission
  - Verify bucket policy allows the IAM user
- **404 Not Found**: 
  - Verify bucket name is correct
  - Ensure bucket exists in the specified region
- **401 Unauthorized**: 
  - Check AWS Access Key and Secret Key are valid
  - Verify credentials haven't been rotated
- **Network/Timeout Errors**: 
  - Check firewall allows outbound HTTPS (port 443) to `s3.{region}.amazonaws.com`
  - Verify internet connectivity
  - Check proxy settings if behind corporate firewall

**In Silent Mode**: Installation will exit immediately if S3 test fails. Fix connectivity issues before retrying.

**In Interactive Mode**: You can choose to continue installation despite S3 test failure, but backups will not work until connectivity is fixed.

### Backup Fails with "Access Denied"

- Verify AWS credentials in config.json
- Check S3 bucket policy allows the IAM user
- Ensure the bucket exists in the specified region

### SQL Connection Errors

- Verify SQL Server is running
- Check Windows Authentication is enabled
- Ensure the SYSTEM account has access to the databases

### Scheduled Task Not Running

- Open Task Scheduler and check task status
- Verify the task is running as SYSTEM
- Check logs in `C:\SarovarBackup\logs\`

### Large Tables Timeout

For tables with millions of rows, consider:
- Increasing `-QueryTimeout` in the script
- Backing up during low-usage periods
- Using SQL Server's native backup for very large databases

## Logs

Logs are stored in `C:\SarovarBackup\logs\`:
- `backup-2026-01-16.log` - Daily backup logs
- Automatic cleanup based on `log_retention_days`

## Security Notes

1. **Config file is ACL-protected** - Only Administrators and SYSTEM can read
2. **AWS credentials are stored locally** - Consider using AWS IAM roles if running on EC2
3. **Windows Authentication** - No SQL passwords stored in config
4. **HTTPS only** - All S3 communication uses TLS

## License

MIT License - Use freely in your organization.
