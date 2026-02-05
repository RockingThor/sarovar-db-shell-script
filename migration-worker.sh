#!/bin/bash
set -euo pipefail

# =============================
# Migration Worker Script
# =============================

export PATH="$PATH:/opt/mssql-tools/bin"

# ---- AWS ----
AWS_REGION="ap-southeast-1"
SQS_URL="https://sqs.ap-southeast-1.amazonaws.com/396608801241/database-rn"

# ---- Work dirs ----
WORK_DIR="$HOME/work"
RAR_DIR="$WORK_DIR/rar"
EXTRACT_DIR="$WORK_DIR/extracted"

# ---- MSSQL ----
MSSQL_HOST="localhost"
MSSQL_USER="sa"
MSSQL_PASSWORD="Password#3132343"
MSSQL_DATA_DIR="/var/opt/mssql/data"

# ---- PostgreSQL ----
PG_HOST="172.31.33.158"
PG_PORT="5432"
PG_USER="postgres"
PG_PASSWORD="POSTGRES_PASSWORD_HERE"

# ---- Python migrator ----
PY_MIGRATOR="/home/ubuntu/mssql_to_postgres.py"

mkdir -p "$RAR_DIR" "$EXTRACT_DIR"
sudo mkdir -p /var/opt/mssql/backup
sudo chown -R mssql:mssql /var/opt/mssql
sudo chmod 700 /var/opt/mssql/data /var/opt/mssql/backup

echo "$(date '+%Y-%m-%d %H:%M:%S') | 🚀 Worker started"

while true; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') | Polling SQS..."

    RESPONSE=$(aws sqs receive-message \
        --queue-url "$SQS_URL" \
        --max-number-of-messages 1 \
        --wait-time-seconds 20 \
        --region "$AWS_REGION")

    [[ -z "$RESPONSE" || "$RESPONSE" == "{}" ]] && sleep 5 && continue

    MESSAGE=$(echo "$RESPONSE" | jq -r '.Messages[0]')
    [[ "$MESSAGE" == "null" ]] && sleep 5 && continue

    RECEIPT_HANDLE=$(echo "$MESSAGE" | jq -r '.ReceiptHandle')
    BODY=$(echo "$MESSAGE" | jq -r '.Body')

    RECORD=$(echo "$BODY" | jq -r '.Records[0]')
    BUCKET=$(echo "$RECORD" | jq -r '.s3.bucket.name')
    OBJECT_KEY=$(echo "$RECORD" | jq -r '.s3.object.key')
    HOTEL_ID=$(echo "$OBJECT_KEY" | cut -d'/' -f1)

    echo "$(date '+%Y-%m-%d %H:%M:%S') | Hotel: $HOTEL_ID"

    # ---- Download ----
    LOCAL_RAR="$RAR_DIR/$(basename "$OBJECT_KEY")"
    aws s3 cp "s3://$BUCKET/$OBJECT_KEY" "$LOCAL_RAR" --region "$AWS_REGION"

    # ---- Extract ----
    HOTEL_EXTRACT_DIR="$EXTRACT_DIR/$HOTEL_ID"
    mkdir -p "$HOTEL_EXTRACT_DIR"
    unrar x -o+ "$LOCAL_RAR" "$HOTEL_EXTRACT_DIR/"

    # ---- Find BAK ----
    BAK_FILE_NAME=$(find "$HOTEL_EXTRACT_DIR" -iname "*.BAK" | head -n 1)
    [[ -z "$BAK_FILE_NAME" ]] && aws sqs delete-message \
        --queue-url "$SQS_URL" \
        --receipt-handle "$RECEIPT_HANDLE" \
        --region "$AWS_REGION" && continue

    BAK_FILE="/var/opt/mssql/backup/$(basename "$BAK_FILE_NAME")"
    sudo mv "$BAK_FILE_NAME" "$BAK_FILE"
    sudo chown mssql:mssql "$BAK_FILE"

    DB_NAME="${HOTEL_ID}_db"

    # ---- Restore MSSQL ----
    LOGICAL_FILES=$(sqlcmd -S "$MSSQL_HOST" -U "$MSSQL_USER" -P "$MSSQL_PASSWORD" \
        -Q "RESTORE FILELISTONLY FROM DISK=N'$BAK_FILE'" -s "," -W)

    DATA_FILE=$(echo "$LOGICAL_FILES" | awk -F, 'NR==3 {print $1}' | tr -d '\r')
    LOG_FILE=$(echo "$LOGICAL_FILES" | awk -F, 'NR==4 {print $1}' | tr -d '\r')
    sqlcmd -S "$MSSQL_HOST" -U "$MSSQL_USER" -P "$MSSQL_PASSWORD" \
        -Q "RESTORE DATABASE [$DB_NAME]
            FROM DISK=N'$BAK_FILE'
            WITH
              MOVE '$DATA_FILE' TO '$MSSQL_DATA_DIR/$DB_NAME.mdf',
              MOVE '$LOG_FILE'  TO '$MSSQL_DATA_DIR/${DB_NAME}_log.ldf',
              REPLACE"

    echo "$(date '+%Y-%m-%d %H:%M:%S') | MSSQL restored"

    # ---- Recreate PostgreSQL DB ----
    PGPASSWORD="$PG_PASSWORD" psql -h "$PG_HOST" -U "$PG_USER" -p "$PG_PORT" -d postgres <<EOF
DROP DATABASE IF EXISTS "$DB_NAME";
CREATE DATABASE "$DB_NAME";
EOF

    # ---- Run Python migration ----
    python3 "$PY_MIGRATOR" \
        "$MSSQL_HOST" "$DB_NAME" "$MSSQL_USER" "$MSSQL_PASSWORD" \
        "$PG_HOST" "$PG_PORT" "$DB_NAME" "$PG_USER" "$PG_PASSWORD"

    echo "$(date '+%Y-%m-%d %H:%M:%S') | ✅ Migration completed"

    aws sqs delete-message \
        --queue-url "$SQS_URL" \
        --receipt-handle "$RECEIPT_HANDLE" \
        --region "$AWS_REGION"

    sleep 2
done

