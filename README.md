# SQL Server BAK File to S3 Backup Solution

Automated daily upload of SQL Server .bak backup files to Amazon S3 using pure PowerShell - **no AWS CLI or external dependencies required**.

## Features

- **Zero External Dependencies**: Uses native PowerShell with direct S3 REST API calls (AWS Signature V4)
- **Large File Support**: S3 Multipart Upload handles files up to 1TB (uploads in 100MB chunks)
- **Memory Efficient**: Streams file chunks instead of loading entire file into RAM
- **Progress Tracking**: Real-time upload progress with percentage and estimated time remaining
- **Simple Installation**: One-command installer with automatic Task Scheduler setup
- **Firewall Validation**: Tests S3 connectivity before installation to ensure network access
- **Mass Deployment Ready**: Silent mode for deploying to multiple servers
- **Automatic Latest File Detection**: Finds and uploads the latest .bak file from your backup directory
- **Secure**: Restricted config file permissions, HTTPS-only S3 communication

## How It Works

1. SQL Server Agent creates .bak files in a designated directory (your existing backup process)
2. This solution runs on a schedule and uploads the **latest** .bak file to S3
3. Files are organized in S3 by server name and date

## Quick Start

### Single Server Installation

1. Download the scripts to your Windows server
2. Open PowerShell as Administrator
3. Run the installer:

```powershell
.\install.ps1
```

4. Follow the prompts to configure:
   - **Step 1**: S3 bucket name, region, and AWS credentials
   - **Step 2**: Automatic S3 connectivity/firewall test
   - **Step 3**: Path where SQL Agent creates .bak files
   - **Step 4**: Schedule time for daily uploads

5. The installer will automatically:
   - **Validate S3 connectivity and firewall access** (before installation)
   - Create installation directories
   - Set up scheduled task

### Silent Installation (for Mass Deployment)

```powershell
.\install.ps1 -Silent `
    -S3Bucket "your-bucket-name" `
    -S3Region "us-east-1" `
    -BakFilePath "D:\SQLBackups" `
    -AwsAccessKey "AKIAXXXXXXXX" `
    -AwsSecretKey "your-secret-key" `
    -BackupTime "02:00"
```

**Note**: In silent mode, the installer will **fail immediately** if S3 connectivity test fails, preventing incomplete installations.

## File Structure

```
C:\SarovarBackup\           # Default installation directory
├── backup-to-s3.ps1        # Main backup script
├── uninstall.ps1           # Uninstaller
├── config.json             # Configuration (secured)
└── logs\                   # Backup logs
```

## S3 Data Structure

```
s3://bucket-name/backups/
└── SERVER-001/
    └── 2026-01-29/
        └── DatabaseName_Full_20260129.bak
```

## Configuration

Configuration is stored in `config.json`:

```json
{
    "server_identifier": "SERVER-001",
    "bak_file_path": "D:\\SQLBackups",
    "s3_bucket": "your-bucket-name",
    "s3_region": "us-east-1",
    "s3_prefix": "backups",
    "aws_access_key": "AKIAXXXXXXXX",
    "aws_secret_key": "your-secret-key",
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

## Mass Deployment

### Option 1: Parameterized Mass Deploy

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
    Invoke-Command -ComputerName $server -ScriptBlock {
        param($params)
        
        & "C:\temp\install.ps1" -Silent `
            -S3Bucket $params.S3Bucket `
            -S3Region $params.S3Region `
            -BakFilePath "D:\SQLBackups" `
            -AwsAccessKey $params.AwsAccessKey `
            -AwsSecretKey $params.AwsSecretKey `
            -BackupTime $params.BackupTime `
            -ServerIdentifier $env:COMPUTERNAME
            
    } -ArgumentList $commonParams
}
```

### Option 2: Group Policy / SCCM

1. Create a startup script that runs the installer
2. Deploy via GPO or SCCM
3. Use parameters for customization

## AWS S3 Setup

### Required IAM Permissions

Create an IAM user/role with this policy (includes multipart upload permissions):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:AbortMultipartUpload"
            ],
            "Resource": [
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
- **SQL Server Agent** creating .bak files (your existing backup process)
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

### No .bak Files Found

- Verify the `bak_file_path` in config.json is correct
- Ensure SQL Agent backup job is running and creating .bak files
- Check that the path is accessible to the SYSTEM account

### Scheduled Task Not Running

- Open Task Scheduler and check task status
- Verify the task is running as SYSTEM
- Check logs in `C:\SarovarBackup\logs\`

### Large Files (20GB+)

The script uses S3 Multipart Upload for efficient handling of large files:
- Files are uploaded in 100MB chunks (memory efficient)
- Progress is shown for each chunk with estimated time remaining
- Each chunk retries up to 3 times on failure with exponential backoff
- If upload fails, incomplete parts are automatically cleaned up from S3
- Supports files up to 1TB

Example log output for a 20GB file:
```
[INFO] Starting upload: database_full.bak
[INFO] File size: 20480.00 MB (20.0 GB)
[INFO] Upload will be split into 205 parts (100 MB each)
[INFO] Uploading part 1 of 205 (0.5%) - ETA: 45m 30s
[INFO] Uploading part 50 of 205 (24.4%) - ETA: 34m 15s
...
[SUCCESS] Upload complete: 20.0 GB in 42m 15s (avg: 8.09 MB/s)
```

## Logs

Logs are stored in `C:\SarovarBackup\logs\`:
- `backup-2026-01-29.log` - Daily backup logs
- Automatic cleanup based on `log_retention_days`

## Security Notes

1. **Config file is ACL-protected** - Only Administrators and SYSTEM can read
2. **AWS credentials are stored locally** - Consider using AWS IAM roles if running on EC2
3. **HTTPS only** - All S3 communication uses TLS

## License

MIT License - Use freely in your organization.
