    #!/bin/bash

# =============================
# Migration Worker Script
# =============================

#!/bin/bash
set -euo pipefail

# Add sqlcmd to PATH
export PATH="$PATH:/opt/mssql-tools/bin"


# ---- Configuration ----
AWS_REGION="ap-southeast-1"
SQS_URL="https://sqs.ap-southeast-1.amazonaws.com/396608801241/database-rn"
WORK_DIR="$HOME/work"
RAR_DIR="$WORK_DIR/rar"
EXTRACT_DIR="$WORK_DIR/extracted"

MSSQL_HOST="localhost"
MSSQL_USER="sa"
MSSQL_PASSWORD="Password#3132343"
MSSQL_DATA_DIR="/var/opt/mssql/data"

# Ensure directories exist
mkdir -p "$RAR_DIR" "$EXTRACT_DIR"
sudo mkdir -p /var/opt/mssql/backup
sudo chown -R mssql:mssql /var/opt/mssql
sudo chmod 700 /var/opt/mssql/data /var/opt/mssql/backup

echo "$(date '+%Y-%m-%d %H:%M:%S') | 🚀 Migration worker started"

while true; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') | Polling SQS..."
    
    # Receive messages from SQS (FIFO queue)
    RESPONSE=$(aws sqs receive-message \
        --queue-url "$SQS_URL" \
        --max-number-of-messages 1 \
        --wait-time-seconds 20 \
        --region "$AWS_REGION")
    
    if [[ -z "$RESPONSE" || "$RESPONSE" == "{}" ]]; then
        sleep 5
        continue
    fi

    MESSAGE=$(echo "$RESPONSE" | jq -r '.Messages[0]')
    if [[ "$MESSAGE" == "null" ]]; then
        sleep 5
        continue
    fi

    RECEIPT_HANDLE=$(echo "$MESSAGE" | jq -r '.ReceiptHandle')
    BODY=$(echo "$MESSAGE" | jq -r '.Body')
    
    # Extract S3 info and hotel ID
    RECORD=$(echo "$BODY" | jq -r '.Records[0]')
    BUCKET=$(echo "$RECORD" | jq -r '.s3.bucket.name')
    OBJECT_KEY=$(echo "$RECORD" | jq -r '.s3.object.key')
    HOTEL_ID=$(echo "$OBJECT_KEY" | cut -d'/' -f1)

    echo "$(date '+%Y-%m-%d %H:%M:%S') | 📩 Message received"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | Hotel ID  : $HOTEL_ID"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | Bucket    : $BUCKET"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | ObjectKey : $OBJECT_KEY"

    # ---- Download from S3 ----
    LOCAL_RAR="$RAR_DIR/$(basename "$OBJECT_KEY")"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | ⬇️ Downloading file"
    aws s3 cp "s3://$BUCKET/$OBJECT_KEY" "$LOCAL_RAR" --region "$AWS_REGION"

    # ---- Extract RAR ----
    echo "$(date '+%Y-%m-%d %H:%M:%S') | 📦 Extracting RAR"
    HOTEL_EXTRACT_DIR="$EXTRACT_DIR/$HOTEL_ID"
    mkdir -p "$HOTEL_EXTRACT_DIR"
    unrar x -o+ "$LOCAL_RAR" "$HOTEL_EXTRACT_DIR/"

    # ---- Find BAK file ----
    BAK_FILE_NAME=$(find "$HOTEL_EXTRACT_DIR" -type f -iname "*.BAK" | head -n 1)
    if [[ -z "$BAK_FILE_NAME" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') | ❌ No BAK file found"
        aws sqs delete-message --queue-url "$SQS_URL" --receipt-handle "$RECEIPT_HANDLE" --region "$AWS_REGION"
        continue
    fi

    # ---- Move BAK to SQL Server backup folder ----
    BAK_FILE="/var/opt/mssql/backup/$(basename "$BAK_FILE_NAME")"
    sudo mv "$BAK_FILE_NAME" "$BAK_FILE"
    sudo chown mssql:mssql "$BAK_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | ✅ BAK file ready: $BAK_FILE"

    # ---- Restore MSSQL Database ----
    DB_NAME="${HOTEL_ID}_db"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | 🗄️ Restoring database: $DB_NAME"

    # Get logical file names
    LOGICAL_FILES=$(sqlcmd -S "$MSSQL_HOST" -U "$MSSQL_USER" -P "$MSSQL_PASSWORD" \
        -Q "RESTORE FILELISTONLY FROM DISK=N'$BAK_FILE'" -s "," -W)

    DATA_FILE=$(echo "$LOGICAL_FILES" | awk -F, 'NR==3 {print $1}' | tr -d '\r')
    LOG_FILE=$(echo "$LOGICAL_FILES" | awk -F, 'NR==4 {print $1}' | tr -d '\r')

    # Restore with MOVE
    sqlcmd -S "$MSSQL_HOST" -U "$MSSQL_USER" -P "$MSSQL_PASSWORD" \
        -Q "RESTORE DATABASE [$DB_NAME] FROM DISK=N'$BAK_FILE' WITH MOVE '$DATA_FILE' TO '$MSSQL_DATA_DIR/$DB_NAME.mdf', MOVE '$LOG_FILE' TO '$MSSQL_DATA_DIR/${DB_NAME}_log.ldf', REPLAC>

    echo "$(date '+%Y-%m-%d %H:%M:%S') | ✅ MSSQL restore completed for $DB_NAME"

    # ---- Delete SQS message ----
    aws sqs delete-message --queue-url "$SQS_URL" --receipt-handle "$RECEIPT_HANDLE" --region "$AWS_REGION"

    # Optional: PostgreSQL migration using pgloader can be added here

    sleep 2
done
