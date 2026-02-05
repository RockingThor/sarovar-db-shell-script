#!/usr/bin/env python3
"""
MSSQL to PostgreSQL Migration Script

Migrates 3 specific tables (FMTRNVEW, PSHP4VEW, FMR01VEW) from MSSQL to PostgreSQL.
Called by migration-worker.sh for each hotel database.

Usage:
    python3 mssql_to_postgres.py \
        <mssql_host> <mssql_db> <mssql_user> <mssql_password> \
        <pg_host> <pg_port> <pg_db> <pg_user> <pg_password>
"""

import io
import sys
import urllib.parse
from datetime import datetime

import pandas as pd
import psycopg2
from sqlalchemy import create_engine


# Tables to migrate
TABLES_REQUIRED = ["FMTRNVEW", "PSHP4VEW", "FMR01VEW"]

# MSSQL to PostgreSQL type mapping
TYPE_MAP = {
    "int": "INTEGER",
    "bigint": "BIGINT",
    "smallint": "SMALLINT",
    "tinyint": "SMALLINT",
    "bit": "BOOLEAN",
    "decimal": "NUMERIC",
    "numeric": "NUMERIC",
    "float": "DOUBLE PRECISION",
    "real": "REAL",
    "money": "NUMERIC(19,4)",
    "datetime": "TIMESTAMP",
    "datetime2": "TIMESTAMP",
    "smalldatetime": "TIMESTAMP",
    "date": "DATE",
    "time": "TIME",
    "char": "CHAR",
    "nchar": "CHAR",
    "varchar": "VARCHAR",
    "nvarchar": "VARCHAR",
    "text": "TEXT",
    "ntext": "TEXT",
    "uniqueidentifier": "UUID",
}

# Chunk size for data transfer
CHUNK_SIZE = 100000


def log(message: str) -> None:
    """Print timestamped log message."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} | {message}")


def create_mssql_engine(host: str, database: str, user: str, password: str):
    """Create SQLAlchemy engine for MSSQL."""
    params = urllib.parse.quote_plus(
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={host};"
        f"DATABASE={database};"
        f"UID={user};"
        f"PWD={password}"
    )
    return create_engine(
        f"mssql+pyodbc:///?odbc_connect={params}",
        fast_executemany=True
    )


def create_pg_connection(host: str, port: str, database: str, user: str, password: str):
    """Create psycopg2 connection for PostgreSQL."""
    conn = psycopg2.connect(
        host=host,
        database=database,
        user=user,
        password=password,
        port=int(port),
    )
    conn.autocommit = False
    return conn


def get_schema_info(mssql_engine, tables: list) -> pd.DataFrame:
    """Fetch schema information for specified tables from MSSQL."""
    schema_df = pd.read_sql(
        """
        SELECT
            TABLE_SCHEMA,
            TABLE_NAME,
            COLUMN_NAME,
            DATA_TYPE,
            CHARACTER_MAXIMUM_LENGTH
        FROM INFORMATION_SCHEMA.COLUMNS
        ORDER BY TABLE_NAME, ORDINAL_POSITION
        """,
        mssql_engine,
    )

    # Filter to required tables only
    schema_df = schema_df[schema_df["TABLE_NAME"].isin(tables)]
    schema_df.reset_index(inplace=True, drop=True)

    return schema_df


def create_tables(pg_conn, schema_df: pd.DataFrame) -> None:
    """Create tables in PostgreSQL based on MSSQL schema."""
    pg_cur = pg_conn.cursor()

    for table in schema_df["TABLE_NAME"].unique():
        try:
            group = schema_df[schema_df["TABLE_NAME"] == table]

            cols = []
            for _, row in group.iterrows():
                pg_type = TYPE_MAP.get(row["DATA_TYPE"].lower(), "TEXT")
                col = f'"{row["COLUMN_NAME"]}" {pg_type}'
                cols.append(col)

            create_sql = f'''
            CREATE TABLE IF NOT EXISTS "{table}" (
                {", ".join(cols)}
            );
            '''

            pg_cur.execute(create_sql)
            log(f"Created table: {table}")

        except Exception as e:
            log(f"Error creating table {table}: {e}")
            raise

    pg_conn.commit()


def migrate_table(mssql_engine, pg_conn, table: str) -> tuple:
    """Migrate a single table from MSSQL to PostgreSQL using COPY."""
    log(f"Migrating {table}...")

    pg_cur = pg_conn.cursor()

    # Truncate target table before inserting
    pg_cur.execute(f'TRUNCATE TABLE "{table}"')
    pg_conn.commit()

    # Read and transfer data in chunks using COPY
    rows_transferred = 0
    query = f'SELECT * FROM PMS."{table}"'

    for chunk in pd.read_sql(query, mssql_engine, chunksize=CHUNK_SIZE):
        buffer = io.StringIO()
        chunk.to_csv(buffer, index=False, header=False)
        buffer.seek(0)

        pg_cur.copy_expert(
            f'COPY "{table}" FROM STDIN WITH CSV',
            buffer
        )

        pg_conn.commit()
        rows_transferred += len(chunk)
        log(f"  Transferred {rows_transferred} rows...")

    log(f"{table} migration complete ({rows_transferred} rows)")
    return table, rows_transferred


def verify_migration(mssql_engine, pg_conn, tables: list) -> bool:
    """Verify row counts match between MSSQL and PostgreSQL."""
    log("Verifying migration...")
    all_match = True

    pg_cur = pg_conn.cursor()

    for table in tables:
        mssql_count = pd.read_sql(
            f'SELECT COUNT(*) c FROM PMS."{table}"', mssql_engine
        )["c"][0]

        pg_cur.execute(f'SELECT COUNT(*) FROM "{table}"')
        pg_count = pg_cur.fetchone()[0]

        status = "OK" if mssql_count == pg_count else "MISMATCH"
        log(f"  {table}: MSSQL={mssql_count}, POSTGRES={pg_count} [{status}]")

        if mssql_count != pg_count:
            all_match = False

    return all_match


def main():
    """Main migration entry point."""
    if len(sys.argv) != 10:
        print(
            "Usage: python3 mssql_to_postgres.py "
            "<mssql_host> <mssql_db> <mssql_user> <mssql_password> "
            "<pg_host> <pg_port> <pg_db> <pg_user> <pg_password>"
        )
        sys.exit(1)

    # Parse arguments
    mssql_host = sys.argv[1]
    mssql_db = sys.argv[2]
    mssql_user = sys.argv[3]
    mssql_password = sys.argv[4]
    pg_host = sys.argv[5]
    pg_port = sys.argv[6]
    pg_db = sys.argv[7]
    pg_user = sys.argv[8]
    pg_password = sys.argv[9]

    log(f"Starting migration: {mssql_db} -> {pg_db}")
    log(f"Tables to migrate: {', '.join(TABLES_REQUIRED)}")

    pg_conn = None
    try:
        # Create database connections
        log("Connecting to MSSQL...")
        mssql_engine = create_mssql_engine(
            mssql_host, mssql_db, mssql_user, mssql_password
        )

        log("Connecting to PostgreSQL...")
        pg_conn = create_pg_connection(pg_host, pg_port, pg_db, pg_user, pg_password)

        # Get schema information
        log("Fetching schema information...")
        schema_df = get_schema_info(mssql_engine, TABLES_REQUIRED)

        if schema_df.empty:
            log("ERROR: No tables found matching required tables")
            sys.exit(1)

        # Create tables in PostgreSQL
        log("Creating tables in PostgreSQL...")
        create_tables(pg_conn, schema_df)

        # Migrate each table
        tables = schema_df["TABLE_NAME"].unique()
        for table in tables:
            migrate_table(mssql_engine, pg_conn, table)

        # Verify migration
        if verify_migration(mssql_engine, pg_conn, tables):
            log("Migration completed successfully!")
        else:
            log("WARNING: Row count mismatch detected!")
            sys.exit(1)

    except Exception as e:
        log(f"ERROR: Migration failed - {e}")
        sys.exit(1)

    finally:
        if pg_conn:
            pg_conn.close()


if __name__ == "__main__":
    main()
