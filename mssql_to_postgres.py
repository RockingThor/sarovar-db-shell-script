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

import sys
import urllib.parse
from datetime import datetime

import pandas as pd
from sqlalchemy import create_engine, text


# Tables to migrate
TABLES_REQUIRED = ["FMTRNVEW", "PSHP4VEW", "FMR01VEW"]

# MSSQL to PostgreSQL type mapping
TYPE_MAP = {
    "int": "integer",
    "bigint": "bigint",
    "smallint": "smallint",
    "tinyint": "smallint",
    "bit": "boolean",
    "decimal": "numeric",
    "numeric": "numeric",
    "money": "numeric(18,2)",
    "float": "double precision",
    "real": "real",
    "datetime": "timestamp",
    "datetime2": "timestamp",
    "smalldatetime": "timestamp",
    "date": "date",
    "nvarchar": "varchar",
    "varchar": "varchar",
    "char": "char",
    "nchar": "char",
    "text": "text",
    "uniqueidentifier": "uuid",
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
    return create_engine(f"mssql+pyodbc:///?odbc_connect={params}")


def create_pg_engine(host: str, port: str, database: str, user: str, password: str):
    """Create SQLAlchemy engine for PostgreSQL."""
    return create_engine(
        f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}", executemany_mode="values",
    executemany_values_page_size=10000,
    executemany_batch_page_size=500
    )


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


def create_tables(pg_engine, schema_df: pd.DataFrame) -> None:
    """Create tables in PostgreSQL based on MSSQL schema."""
    with pg_engine.connect() as conn:
        for table in schema_df["TABLE_NAME"].unique():
            try:
                cols = schema_df[schema_df["TABLE_NAME"] == table]

                col_defs = []
                for _, row in cols.iterrows():
                    pg_type = TYPE_MAP.get(row["DATA_TYPE"], "text")

                    # Add length for char types
                    if row["CHARACTER_MAXIMUM_LENGTH"] and "char" in pg_type:
                        pg_type += f"({int(row['CHARACTER_MAXIMUM_LENGTH'])})"

                    col_defs.append(f'"{row["COLUMN_NAME"]}" {pg_type}')

                create_sql = f"""
                CREATE TABLE IF NOT EXISTS "{table}" (
                    {", ".join(col_defs)}
                );
                """

                conn.execute(text(create_sql))
                conn.commit()
                log(f"Created table: {table}")

            except Exception as e:
                log(f"Error creating table {table}: {e}")
                raise


def migrate_table(mssql_engine, pg_engine, table: str) -> tuple:
    """Migrate a single table from MSSQL to PostgreSQL."""
    log(f"Migrating {table}...")

    # Truncate target table before inserting
    with pg_engine.begin() as conn:
        conn.execute(text(f'TRUNCATE TABLE "{table}"'))

    # Read and transfer data in chunks
    rows_transferred = 0
    for chunk in pd.read_sql(
        f'SELECT * FROM PMS."{table}"', mssql_engine, chunksize=CHUNK_SIZE
    ):
        chunk.to_sql(
            table,
            pg_engine,
            if_exists="append",
            index=False,
            method="multi",
        )
        rows_transferred += len(chunk)
        log(f"  Transferred {rows_transferred} rows...")

    log(f"{table} migration complete ({rows_transferred} rows)")
    return table, rows_transferred


def verify_migration(mssql_engine, pg_engine, tables: list) -> bool:
    """Verify row counts match between MSSQL and PostgreSQL."""
    log("Verifying migration...")
    all_match = True

    for table in tables:
        mssql_count = pd.read_sql(
            f'SELECT COUNT(*) c FROM PMS."{table}"', mssql_engine
        )["c"][0]
        pg_count = pd.read_sql(f'SELECT COUNT(*) c FROM "{table}"', pg_engine)["c"][0]

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

    try:
        # Create database engines
        log("Connecting to MSSQL...")
        mssql_engine = create_mssql_engine(
            mssql_host, mssql_db, mssql_user, mssql_password
        )

        log("Connecting to PostgreSQL...")
        pg_engine = create_pg_engine(pg_host, pg_port, pg_db, pg_user, pg_password)

        # Get schema information
        log("Fetching schema information...")
        schema_df = get_schema_info(mssql_engine, TABLES_REQUIRED)

        if schema_df.empty:
            log("ERROR: No tables found matching required tables")
            sys.exit(1)

        # Create tables in PostgreSQL
        log("Creating tables in PostgreSQL...")
        create_tables(pg_engine, schema_df)

        # Migrate each table
        tables = schema_df["TABLE_NAME"].unique()
        for table in tables:
            migrate_table(mssql_engine, pg_engine, table)

        # Verify migration
        if verify_migration(mssql_engine, pg_engine, tables):
            log("Migration completed successfully!")
        else:
            log("WARNING: Row count mismatch detected!")
            sys.exit(1)

    except Exception as e:
        log(f"ERROR: Migration failed - {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
