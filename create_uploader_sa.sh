#!/bin/bash

# ==========================================
# Configuration
# ==========================================
PROJECT_ID="your-project"
SA_NAME="evidence-uploader-$(date +%s)"
SA="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
BUCKET="gs://your-project-nw/log/aws"
CURRENT_USER=$(gcloud config get-value account)
# Modify file name if multiple uploads are planned e.g. .last_uploader_sa_nw
SA_FILE=".last_uploader_sa"

# ==========================================
# Execution
# ==========================================
echo "=== [1/2] Creating dedicated Service Account: $SA_NAME ==="
gcloud iam service-accounts create "$SA_NAME" \
    --description="Temporary evidence upload service account" \
    --display-name="Evidence Uploader ($SA_NAME)"

echo "=== [2/2] Granting necessary permissions ==="
# Grant storage object admin role on the target bucket
gcloud storage buckets add-iam-policy-binding "$BUCKET" \
    --member="serviceAccount:$SA" \
    --role="roles/storage.objectAdmin"

# Grant token creator role to the current user for impersonation
gcloud iam service-accounts add-iam-policy-binding "$SA" \
    --member="user:$CURRENT_USER" \
    --role="roles/iam.serviceAccountTokenCreator"

# Save SA email for subsequent scripts
echo "$SA" > $SA_FILE

echo ""
echo "Successfully created SA: $SA"
echo "Saved to $SA_FILE"