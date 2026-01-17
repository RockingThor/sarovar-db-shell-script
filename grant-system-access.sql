/*
    Grant NT AUTHORITY\SYSTEM Access to SQL Server
    ================================================
    
    This script grants the Windows SYSTEM account access to SQL Server
    so that scheduled tasks running under SYSTEM can connect to databases.
    
    Run this script in SQL Server Management Studio (SSMS) or via sqlcmd:
        sqlcmd -S localhost -i grant-system-access.sql
    
    You must be a SQL Server administrator (sysadmin) to execute this script.
*/

-- ============================================
-- Step 1: Create SQL Server login for SYSTEM
-- ============================================
USE [master];
GO

-- Check if login already exists, create if not
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'NT AUTHORITY\SYSTEM')
BEGIN
    CREATE LOGIN [NT AUTHORITY\SYSTEM] FROM WINDOWS WITH DEFAULT_DATABASE=[master];
    PRINT 'Created login: NT AUTHORITY\SYSTEM';
END
ELSE
BEGIN
    PRINT 'Login already exists: NT AUTHORITY\SYSTEM';
END
GO

-- ============================================
-- Step 2: Grant access to NEXT70 database
-- ============================================
USE [NEXT70];
GO

-- Check if user already exists, create if not
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'NT AUTHORITY\SYSTEM')
BEGIN
    CREATE USER [NT AUTHORITY\SYSTEM] FOR LOGIN [NT AUTHORITY\SYSTEM];
    PRINT 'Created database user: NT AUTHORITY\SYSTEM in NEXT70';
END
ELSE
BEGIN
    PRINT 'Database user already exists: NT AUTHORITY\SYSTEM in NEXT70';
END
GO

-- Grant db_datareader role for read access to all tables
ALTER ROLE [db_datareader] ADD MEMBER [NT AUTHORITY\SYSTEM];
PRINT 'Granted db_datareader role to NT AUTHORITY\SYSTEM in NEXT70';
GO

-- ============================================
-- Verification: Test the permissions
-- ============================================
PRINT '';
PRINT '=== Verification ===';
PRINT 'Login and permissions have been configured.';
PRINT 'To verify, run the backup script manually:';
PRINT '  & "C:\SarovarBackup\backup-to-s3.ps1" -ConfigPath "C:\SarovarBackup\config.json"';
PRINT '';
GO
