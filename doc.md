# Database Migration Pipeline – Design Document

## 1. Overview

This document describes the architecture and working of an **event-driven database migration pipeline** built on AWS.

### Goal
- Accept **Microsoft SQL Server full backups (.BAK)** uploaded to Amazon S3
- Automatically restore them into a **self-hosted MSSQL Server on EC2**
- Migrate the restored database into **PostgreSQL hosted on another EC2**
- Fully automated, scalable, and fault-tolerant

---

## 2. High-Level Architecture

```
Client / Hotel Systems
        |
        | Upload (.rar containing .bak)
        v
Amazon S3 (Backup Buckets)
        |
        | Event Notification
        v
Amazon SQS (Standard Queue)
        |
        | Polling
        v
Migration Worker EC2
        |
        * Download
        * Extract
        * Restore MSSQL
        * Migrate to PostgreSQL
        |
        v
PostgreSQL EC2 (Final Target)
```

---

## 3. Components

### 3.1 Amazon S3

**Purpose**
- Stores compressed SQL Server backups (`.rar`)
- Each hotel uploads to a dedicated folder

**Structure**

```
s3://database-test-rn-2/
└── hotel123/
    └── NEXT70_20260202103002.rar
```

**Notes**
- Multipart uploads supported
- Upload completion triggers S3 event

---

### 3.2 Amazon SQS (Standard Queue)

**Purpose**
- Decouples S3 uploads from processing
- Provides retry and durability
- Enables multiple workers in the future

**Why Standard Queue**
- No strict ordering required
- Simpler configuration
- Higher throughput

**Message Payload**

SQS receives raw S3 event JSON:

```json
{
  "Records": [
    {
      "s3": {
        "bucket": { "name": "database-test-rn-2" },
        "object": { "key": "hotel123/NEXT70_20260202103002.rar" }
      }
    }
  ]
}
```

---

### 3.3 Migration Worker EC2

**OS**
- Ubuntu 22.04 LTS

**Installed Tools**
- awscli
- jq
- unrar
- Microsoft SQL Server 2022
- mssql-tools (sqlcmd)
- pgloader
- PostgreSQL client

**IAM Role Permissions**

```json
sqs:ReceiveMessage
sqs:DeleteMessage
sqs:GetQueueAttributes
s3:GetObject
```

No access keys stored locally.

---

## 4. End-to-End Flow

### Step 1: Upload Backup
- Hotel uploads `.rar` file to S3
- Path contains hotel identifier

### Step 2: S3 Sends Event to SQS
- Triggered on `ObjectCreated`
- Sends bucket name and object key

### Step 3: Worker Polls SQS
- Long polling (20 seconds)
- Processes one message at a time

### Step 4: Download Backup

```bash
aws s3 cp s3://bucket/key local_path
```

### Step 5: Extract RAR

```bash
unrar x backup.rar /work/extracted/hotel123/
```

### Step 6: Locate BAK
- Searches extracted directory
- Stops safely if `.BAK` is missing

---

## 5. MSSQL Restore Design

### 5.1 SQL Server Backup Location

SQL Server on Linux only allows restore from:

```
/var/opt/mssql/backup/
```

Ownership:

```
mssql:mssql
```

### 5.2 Logical File Discovery

Before restore:

```sql
RESTORE FILELISTONLY FROM DISK = '/var/opt/mssql/backup/file.bak';
```

Extracts:
- Logical data file name
- Logical log file name

### 5.3 Restore Strategy

```sql
RESTORE DATABASE hotel123_db
FROM DISK = '/var/opt/mssql/backup/file.bak'
WITH
  MOVE 'LogicalDataName' TO '/var/opt/mssql/data/hotel123_db.mdf',
  MOVE 'LogicalLogName'  TO '/var/opt/mssql/data/hotel123_db_log.ldf',
  REPLACE;
```

**Why MOVE is required**
- Backup paths are Windows-based (D:...)
- Linux requires valid Linux paths

---

## 6. PostgreSQL Server Design

### 6.1 PostgreSQL EC2

**OS**
- Ubuntu 22.04

**Version**
- PostgreSQL 14

**Listening Configuration**

```conf
listen_addresses = '*'
```

**Access Control**

```conf
host all all 0.0.0.0/0 scram-sha-256
```

**Port**
- 5432 open in Security Group

---

## 7. PostgreSQL Migration (pgloader)

### 7.1 Database Lifecycle

For each hotel:
1. Drop PostgreSQL DB if it exists
2. Create fresh DB
3. Load schema and data from MSSQL

### 7.2 pgloader Execution

```bash
pgloader \
  mssql://sa:PASSWORD@MSSQL_EC2/hotel123_db \
  postgresql://pguser:PASSWORD@PG_EC2/hotel123_db
```

### 7.3 Behavior
- Auto-creates schema
- Migrates tables, indexes, and data
- Converts data types
- Idempotent per hotel

---

## 8. Failure Handling

| Failure Point       | Behavior            |
| ------------------- | ------------------- |
| S3 download fails   | Message retried     |
| RAR extraction fail | Message deleted     |
| BAK missing         | Message deleted     |
| MSSQL restore fail  | Message NOT deleted |
| pgloader fail       | Message NOT deleted |

---

## 9. Security Considerations

- IAM roles instead of credentials
- No secrets committed in scripts
- Databases in private subnet
- Controlled security group access
- Minimal permissions

---

## 10. Scalability

- Add more worker EC2s
- Standard SQS supports parallel consumers
- One database per hotel
- Stateless workers

---

## 11. Current Status

- S3 → SQS integration complete
- Worker polling SQS
- RAR extraction working
- MSSQL restore successful
- PostgreSQL reachable
- pgloader integration in progress

---

## 12. Future Improvements

- CloudWatch logging
- Dead-letter queue
- Retry backoff
- Schema validation
- Migration metrics

---

## 13. Summary

This system provides a **robust, automated pipeline** to migrate SQL Server backups into PostgreSQL using AWS-managed primitives and self-hosted databases, ensuring scalability, reliability, and minimal manual effort.
