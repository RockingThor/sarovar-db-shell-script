#!/usr/bin/env python3
"""
S3 CSV to PostgreSQL Restore Script
Restores MSSQL CSV backups from S3 to PostgreSQL
"""

import os
import sys
import json
import boto3
import psycopg2
import logging
import argparse
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import tempfile
import csv

# ==================== CONFIGURATION ====================

CONFIG = {
    # AWS Settings
    "aws_access_key": "YOUR_AWS_ACCESS_KEY",
    "aws_secret_key": "YOUR_AWS_SECRET_KEY",
    "s3_bucket": "YOUR_BUCKET_NAME",
    "s3_region": "ap-south-1",
    "s3_prefix": "backups",  # Your backup prefix
    "server_identifier": "YOUR_SERVER_IDENTIFIER",  # From backup config
    
    # PostgreSQL Settings
    "pg_host": "localhost",
    "pg_port": 5432,
    "pg_user": "sarovar_admin",
    "pg_password": "YOUR_PG_PASSWORD",
    
    # Restore Settings
    "temp_directory": "/opt/sarovar-restore/temp",
    "log_directory": "/opt/sarovar-restore/logs",
    "parallel_workers": 8,  # Adjust based on CPU cores
    "batch_size": 50,  # Tables per batch commit
}

# MSSQL to PostgreSQL type mapping
TYPE_MAPPING = {
    "int": "INTEGER",
    "bigint": "BIGINT",
    "smallint": "SMALLINT",
    "tinyint": "SMALLINT",
    "bit": "BOOLEAN",
    "decimal": "NUMERIC",
    "numeric": "NUMERIC",
    "money": "NUMERIC(19,4)",
    "smallmoney": "NUMERIC(10,4)",
    "float": "DOUBLE PRECISION",
    "real": "REAL",
    "datetime": "TIMESTAMP",
    "datetime2": "TIMESTAMP",
    "smalldatetime": "TIMESTAMP",
    "date": "DATE",
    "time": "TIME",
    "datetimeoffset": "TIMESTAMPTZ",
    "char": "CHAR",
    "varchar": "VARCHAR",
    "text": "TEXT",
    "nchar": "CHAR",
    "nvarchar": "VARCHAR",
    "ntext": "TEXT",
    "binary": "BYTEA",
    "varbinary": "BYTEA",
    "image": "BYTEA",
    "uniqueidentifier": "UUID",
    "xml": "XML",
    "sql_variant": "TEXT",
}

# ==================== LOGGING ====================

def setup_logging():
    log_file = os.path.join(
        CONFIG["log_directory"],
        f"restore-{datetime.now().strftime('%Y-%m-%d')}.log"
    )
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

logger = None

# ==================== S3 OPERATIONS ====================

def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=CONFIG["aws_access_key"],
        aws_secret_access_key=CONFIG["aws_secret_key"],
        region_name=CONFIG["s3_region"]
    )

def download_manifest(s3_client, date_str):
    """Download manifest file for given date"""
    manifest_key = f"{CONFIG['s3_prefix']}/{CONFIG['server_identifier']}/_manifest_{date_str}.json"
    
    logger.info(f"Downloading manifest: {manifest_key}")
    
    try:
        response = s3_client.get_object(Bucket=CONFIG["s3_bucket"], Key=manifest_key)
        manifest = json.loads(response['Body'].read().decode('utf-8'))
        return manifest
    except Exception as e:
        logger.error(f"Failed to download manifest: {e}")
        raise

def download_csv(s3_client, s3_key, local_path):
    """Download a CSV file from S3"""
    try:
        s3_client.download_file(CONFIG["s3_bucket"], s3_key, local_path)
        return True
    except Exception as e:
        logger.error(f"Failed to download {s3_key}: {e}")
        return False

# ==================== POSTGRESQL OPERATIONS ====================

def get_pg_connection(database="postgres"):
    """Get PostgreSQL connection"""
    return psycopg2.connect(
        host=CONFIG["pg_host"],
        port=CONFIG["pg_port"],
        user=CONFIG["pg_user"],
        password=CONFIG["pg_password"],
        database=database
    )

def create_database_if_not_exists(db_name):
    """Create database if it doesn't exist"""
    # Sanitize database name (PostgreSQL naming rules)
    safe_db_name = db_name.lower().replace("-", "_").replace(" ", "_")
    
    conn = get_pg_connection()
    conn.autocommit = True
    cur = conn.cursor()
    
    try:
        cur.execute(f"SELECT 1 FROM pg_database WHERE datname = %s", (safe_db_name,))
        if not cur.fetchone():
            cur.execute(f'CREATE DATABASE "{safe_db_name}"')
            logger.info(f"Created database: {safe_db_name}")
        else:
            logger.info(f"Database exists: {safe_db_name}")
    finally:
        cur.close()
        conn.close()
    
    return safe_db_name

def map_mssql_type_to_pg(mssql_type, max_length=None):
    """Convert MSSQL type to PostgreSQL type"""
    mssql_type = mssql_type.lower()
    pg_type = TYPE_MAPPING.get(mssql_type, "TEXT")
    
    # Handle varchar/char with length
    if mssql_type in ("varchar", "nvarchar", "char", "nchar"):
        if max_length and max_length > 0 and max_length < 10485760:
            pg_type = f"{pg_type}({max_length})"
        else:
            pg_type = "TEXT"
    
    # Handle decimal/numeric with precision
    if mssql_type in ("decimal", "numeric"):
        pg_type = "NUMERIC"
    
    return pg_type

def create_table_from_schema(conn, schema_name, table_name, schema_info):
    """Create table from manifest schema info"""
    cur = conn.cursor()
    
    # Create schema if not exists
    cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"')
    
    # Build column definitions
    columns = []
    for col in schema_info:
        col_name = col['name']
        pg_type = map_mssql_type_to_pg(col['type'], col.get('max_length'))
        nullable = "NULL" if col.get('nullable') == "YES" else "NOT NULL"
        # Skip NOT NULL for simplicity during restore
        columns.append(f'"{col_name}" {pg_type}')
    
    columns_sql = ",\n    ".join(columns)
    
    # Drop and recreate table
    full_table_name = f'"{schema_name}"."{table_name}"'
    cur.execute(f'DROP TABLE IF EXISTS {full_table_name} CASCADE')
    
    create_sql = f"""
    CREATE TABLE {full_table_name} (
        {columns_sql}
    )
    """
    
    cur.execute(create_sql)
    conn.commit()
    cur.close()
    
    return full_table_name

def load_csv_to_table(conn, full_table_name, csv_path):
    """Load CSV data into table using COPY"""
    cur = conn.cursor()
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            # Skip header and use COPY
            cur.copy_expert(
                f"COPY {full_table_name} FROM STDIN WITH (FORMAT csv, HEADER true, NULL '')",
                f
            )
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to load {full_table_name}: {e}")
        return False
    finally:
        cur.close()

# ==================== RESTORE LOGIC ====================

def restore_table(args):
    """Restore a single table (for parallel execution)"""
    s3_client, db_name, date_str, table_info = args
    
    schema = table_info.get('schema', 'dbo')
    table_name = table_info['name']
    schema_info = table_info.get('schema_info', [])
    
    if table_info.get('status') != 'success':
        logger.warning(f"Skipping {schema}.{table_name} - backup status: {table_info.get('status')}")
        return False
    
    if not schema_info:
        logger.warning(f"Skipping {schema}.{table_name} - no schema info")
        return False
    
    csv_filename = f"{schema}_{table_name}.csv"
    s3_key = f"{CONFIG['s3_prefix']}/{CONFIG['server_identifier']}/{db_name}/{date_str}/{csv_filename}"
    local_csv = os.path.join(CONFIG['temp_directory'], f"{db_name}_{csv_filename}")
    
    try:
        # Download CSV
        if not download_csv(s3_client, s3_key, local_csv):
            return False
        
        # Get connection to the database
        safe_db_name = db_name.lower().replace("-", "_").replace(" ", "_")
        conn = get_pg_connection(safe_db_name)
        
        try:
            # Create table
            full_table_name = create_table_from_schema(conn, schema, table_name, schema_info)
            
            # Load data
            success = load_csv_to_table(conn, full_table_name, local_csv)
            
            if success:
                logger.info(f"✓ Restored: {db_name}.{schema}.{table_name}")
            
            return success
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Failed to restore {db_name}.{schema}.{table_name}: {e}")
        return False
    finally:
        # Cleanup temp file
        if os.path.exists(local_csv):
            os.remove(local_csv)

def restore_database(s3_client, db_info, date_str):
    """Restore all tables for a single database"""
    db_name = db_info['name']
    tables = db_info.get('tables', [])
    
    if db_info.get('status') != 'success':
        logger.warning(f"Skipping database {db_name} - status: {db_info.get('status')}")
        return 0, len(tables)
    
    logger.info(f"Restoring database: {db_name} ({len(tables)} tables)")
    
    # Create database
    safe_db_name = create_database_if_not_exists(db_name)
    
    # Prepare restore tasks
    tasks = [(s3_client, db_name, date_str, table) for table in tables]
    
    success_count = 0
    fail_count = 0
    
    # Use thread pool for parallel restore
    with ThreadPoolExecutor(max_workers=CONFIG['parallel_workers']) as executor:
        futures = {executor.submit(restore_table, task): task for task in tasks}
        
        for future in as_completed(futures):
            if future.result():
                success_count += 1
            else:
                fail_count += 1
    
    logger.info(f"Database {db_name}: {success_count} succeeded, {fail_count} failed")
    return success_count, fail_count

def run_restore(date_str=None):
    """Main restore function"""
    global logger
    logger = setup_logging()
    
    if date_str is None:
        date_str = datetime.now().strftime("%Y-%m-%d")
    
    logger.info("=" * 60)
    logger.info(f"Starting restore for date: {date_str}")
    logger.info("=" * 60)
    
    # Ensure temp directory exists
    os.makedirs(CONFIG['temp_directory'], exist_ok=True)
    
    # Get S3 client
    s3_client = get_s3_client()
    
    # Download manifest
    try:
        manifest = download_manifest(s3_client, date_str)
    except Exception as e:
        logger.error(f"Cannot proceed without manifest: {e}")
        return False
    
    total_success = 0
    total_fail = 0
    
    # Restore each database
    for db_info in manifest.get('databases', []):
        success, fail = restore_database(s3_client, db_info, date_str)
        total_success += success
        total_fail += fail
    
    # Summary
    logger.info("=" * 60)
    logger.info("RESTORE COMPLETE")
    logger.info(f"Total tables restored: {total_success}")
    logger.info(f"Total failures: {total_fail}")
    logger.info("=" * 60)
    
    # Cleanup temp directory
    for f in Path(CONFIG['temp_directory']).glob("*.csv"):
        f.unlink()
    
    return total_fail == 0

# ==================== MAIN ====================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Restore S3 CSV backups to PostgreSQL")
    parser.add_argument(
        "--date",
        help="Date to restore (YYYY-MM-DD). Defaults to today.",
        default=None
    )
    parser.add_argument(
        "--config",
        help="Path to config file (JSON)",
        default=None
    )
    
    args = parser.parse_args()
    
    # Load config from file if provided
    if args.config and os.path.exists(args.config):
        with open(args.config) as f:
            file_config = json.load(f)
            CONFIG.update(file_config)
    
    success = run_restore(args.date)
    sys.exit(0 if success else 1)