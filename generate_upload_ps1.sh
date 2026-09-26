#!/bin/bash

# ==========================================
# Configuration
# ==========================================
# IMPORTANT: Make sure this matches the SA_FILE / state file name 
# used in create_uploader_sa.sh (e.g., .last_uploader_sa, .last_uploader_sa_nw)
SA_FILE=".last_uploader_sa"
if [ ! -f "$SA_FILE" ]; then
    echo "Error: $SA_FILE not found. Please run the creation script first."
    exit 1
fi
SA=$(cat "$SA_FILE")

REGION="us-central1"
BUCKET="gs://your-project-nw/log/aws"
PS1_FILE="upload_evidence.ps1"

# Duration of signed URL (Max 12h for impersonation)
# For >12h: authenticate gcloud as SA and remove --impersonate-service-account
DURATION="12h"

FILES=(
    "FG01-202601010000-202601011200.csv.gz"
    "FG01-202601011200-202601020000.csv.gz"
    "FG01-202601020000-202601021200.csv.gz"
)

# ==========================================
# Generate PowerShell Script
# ==========================================
echo "Generating $PS1_FILE using SA: $SA (Duration: $DURATION)..."

cat << EOF > "$PS1_FILE"
# ==========================================
# GCS Forensic File Upload Script
# ==========================================
Write-Host "Starting file upload to GCS..." -ForegroundColor Cyan
\$success = 0
EOF

i=1
for file in "${FILES[@]}"; do
    echo "Signing URL for $file..."
    
    # Generate signed URL (impersonating the service account)
    SIGNED_URL=$(gcloud storage sign-url "$BUCKET/$file" \
        --regione="$REGION" \
        --duration="$DURATION" \
        --http-verb=PUT \
        --impersonate-service-account="$SA" \
        --format="value(signed_url)")

    cat << EOF >> "$PS1_FILE"
Write-Host "[$i/${#FILES[@]}] Uploading: $file ..." -ForegroundColor Yellow
curl.exe -X PUT -T "$file" "$SIGNED_URL"
if (\$?) { 
    Write-Host "-> Success: $file" -ForegroundColor Green 
    \$success++
} else { 
    Write-Host "-> Failed: $file" -ForegroundColor Red 
}
EOF
    i=$((i + 1))
done

cat << 'EOF' >> "$PS1_FILE"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "All upload tasks completed." -ForegroundColor Cyan
Read-Host -Prompt "Press Enter to exit"
EOF

echo "Done! Generated $PS1_FILE successfully."