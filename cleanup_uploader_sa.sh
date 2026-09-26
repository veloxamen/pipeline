#!/bin/bash

# IMPORTANT: Make sure this matches the SA_FILE / state file name 
# used in create_uploader_sa.sh (e.g., .last_uploader_sa, .last_uploader_sa_nw)
SA_FILE=".last_uploader_sa"

if [ ! -f "$SA_FILE" ]; then
    echo "Error: $SA_FILE not found."
    exit 1
fi

SA=$(cat "$SA_FILE")

echo "Target Service Account to delete: $SA"
read -p "Are you sure you want to delete this Service Account and revoke all access? (y/N) " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Deleting service account..."
    gcloud iam service-accounts delete "$SA" --quiet
    rm -f "$SA_FILE"
    echo "Cleanup completed successfully!"
else
    echo "Aborted."
fi