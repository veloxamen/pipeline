#!/usr/bin/env bash

# =========================================================================
#  Veloxamen: Cloud-Native DFIR Pipeline Deployment Script
# =========================================================================

# Exit immediately if a command exits with a non-zero status
set -euo pipefail

# Under `set -e`, bash itself prints nothing when it stops the script — only
# the failing command's own stderr (if any) is visible. That output is easy
# to miss in a long log, which can make a real failure look like a clean,
# silent completion. This trap makes that moment impossible to miss: it
# always prints the exact line number and command before the script exits.
trap 'echo "[FATAL] line ${LINENO}: command failed (exit ${?}): ${BASH_COMMAND}" >&2' ERR

# retry_iam: wraps IAM-binding commands that reference a service account
# created earlier in this same script run. A freshly created SA can take a
# few seconds up to ~1 minute to propagate before it's usable as an IAM
# policy member elsewhere; without a retry, whichever binding happens to run
# first after propagation is still in progress will fail — which section
# that turns out to be is timing-dependent, not fixed at "3-3".
retry_iam() {
  local max_attempts=6
  local delay=5
  local attempt=1
  until "$@" >/dev/null; do
    if (( attempt >= max_attempts )); then
      echo "[ERROR] IAM binding still failing after ${attempt} attempts, giving up: $*" >&2
      return 1
    fi
    echo "[!] IAM binding not propagated yet, retrying in ${delay}s (attempt ${attempt}/${max_attempts}): $*" >&2
    sleep "${delay}"
    attempt=$((attempt + 1))
    delay=$((delay + 5))
  done
}

# ---- 1. Project & Region Configuration ----
# One GCP project per case, to avoid commingling evidence across cases.
# PROJECT is also a globally-unique GCP project ID (6-30 chars, lowercase
# alphanumeric + hyphens), so give it an org-specific prefix rather than a
# bare case number to avoid clashing with someone else's project someday.
export PROJECT_ID="poc001"                          # Specify your Google Cloud Project ID (per-case, AlphaNumeric recommended)
export PROJECT="vxmn-${PROJECT_ID}"                 # Specify your Project Name prefix
export REGION="us-central1"                         # Recommended region to leverage free tier (depends on the budgetting)
export BILLING_ACCOUNT_ID="0123456-7890AB-123456"   # Specify your Billing Account ID

# ---- 2. Cloud Storage (GCS) Buckets ----
# NOTE: GCS bucket names are globally unique across ALL of GCP (not just
# this project), unlike every other resource type in this script (KMS
# keys, Pub/Sub topics, BQ datasets, service accounts are all scoped to
# PROJECT already and don't need this treatment). Deriving these from
# PROJECT — which is itself already globally unique — is the one change
# that's actually required to run this script again for a second case
# without colliding with the first case's buckets.
export BUCKET_UPLOAD="${PROJECT}-in"     # Encrypted forensic artifacts collection bucket
export BUCKET_RAW="${PROJECT}-raw"      # Decrypted artifacts or tool exported artifacts processing staging bucket
export BUCKET_OUTPUT="${PROJECT}-out"    # Plaso/log2timeline output storage bucket
export BUCKET_NW="${PROJECT}-nw"        # NW log ingestion bucket (subfolder-per-log-type: fortigate/, generic_csv/, ...)

# ---- 3. Cloud KMS Configuration ----
# KMS keyrings/keys are scoped to PROJECT already, so this naming isn't
# strictly required for isolation the way the bucket names above are — but
# keeping it consistent with PROJECT makes it obvious at a glance which
# case a given key belongs to when looking at shared org-level audit logs.
export KMS_RING="${PROJECT}-ring"
export KMS_KEY="${PROJECT}-key"
export KMS_KEY_NAME="projects/${PROJECT}/locations/${REGION}/keyRings/${KMS_RING}/cryptoKeys/${KMS_KEY}/cryptoKeyVersions/1"

# ---- 4. Pub/Sub Configuration ----
export PUBSUB_TOPIC_IN="vxmn-notify-in"     # BUCKET_UPLOAD    -> decrypt-trigger
export PUBSUB_SUB_IN="vxmn-sub-in"
export PUBSUB_TOPIC_RAW="vxmn-notify-raw"  # BUCKET_RAW      -> plaso-trigger
export PUBSUB_SUB_RAW="vxmn-sub-raw"
export PUBSUB_TOPIC_OUT="vxmn-notify-out"   # BUCKET_OUTPUT    -> bqload-trigger
export PUBSUB_SUB_OUT="vxmn-sub-out"
export PUBSUB_TOPIC_NW="vxmn-notify-nw"    # BUCKET_NW       -> network-trigger
export PUBSUB_SUB_NW="vxmn-sub-nw"
export PUBSUB_DLQ="vxmn-notify-dlq"         # shared dead-letter topic for all subscriptions

# ---- 5. IAM Service Accounts ----
export SA_DECRYPT_TRIGGER="decrypt-trigger-sa@${PROJECT}.iam.gserviceaccount.com"
export SA_DECRYPT="decrypt-job-sa@${PROJECT}.iam.gserviceaccount.com"
export SA_PLASO="plaso-job-sa@${PROJECT}.iam.gserviceaccount.com"
export SA_PLASO_TRIGGER="plaso-trigger-sa@${PROJECT}.iam.gserviceaccount.com"
export SA_BQLOAD_TRIGGER="bqload-trigger-sa@${PROJECT}.iam.gserviceaccount.com"
export SA_NETWORK_TRIGGER="network-trigger-sa@${PROJECT}.iam.gserviceaccount.com"
export SA_NETWORK="network-job-sa@${PROJECT}.iam.gserviceaccount.com"

# ---- 6. Artifact Registry & Container Management ----
export REPO="${REGION}-docker.pkg.dev/${PROJECT}/vxmn-repo"
export IMAGE_DECRYPT_TRIGGER="${REPO}/decrypt-trigger:latest"
export IMAGE_DECRYPT="${REPO}/decrypt-job:latest"
export IMAGE_PLASO="${REPO}/plaso-job:latest"
export IMAGE_PLASO_TRIGGER="${REPO}/plaso-trigger:latest"
export IMAGE_BQLOAD_TRIGGER="${REPO}/bqload-trigger:latest"
export IMAGE_NETWORK_TRIGGER="${REPO}/network-trigger:latest"
export IMAGE_NETWORK="${REPO}/network-job:latest"

# ---- 6b. Google Batch (plaso-job execution) ----
# plaso-job no longer runs as a Cloud Run Job — Cloud Run Jobs caps out at
# 32Gi memory and stages its working directory on tmpfs (RAM-backed /tmp),
# which is what caused the Cloud Run OOM incident this pipeline hit in
# production. Google Batch runs the same container on a Compute Engine VM
# with a real, disk-backed scratch volume and no fixed memory ceiling.
# plaso-trigger builds and submits the full Batch Job spec per execution
# (see plaso-trigger/internal/jobs/jobs.go) using these settings.
export PLASO_MACHINE_TYPE="n2-highmem-16"     # 16 vCPU / 128GiB RAM; size to case evidence volume
export PLASO_CPU_MILLI="16000"                # matches machine type's 16 vCPU
export PLASO_MEMORY_MIB="124000"              # leave a little headroom under the machine's 128GiB
export PLASO_DISK_GB="200"                    # scratch disk for evidence + Plaso intermediates
export PLASO_PROVISIONING_MODEL="STANDARD"    # Use STANDARD for production to avoid preemption; use SPOT for cost-sensitive PoCs.
export PLASO_MAX_RETRY_COUNT="2"              # Batch retries non-zero exits (incl. SPOT preemption) on a fresh VM
export PLASO_MAX_RUN_DURATION="12h"

# ---- 7. BigQuery Configuration ----
# BigQuery dataset IDs only allow letters, numbers, and underscores (no
# hyphens), unlike PROJECT itself — hence the substitution below rather
# than a plain ${PROJECT}-ds.
export BQ_DATASET="${PROJECT//-/_}_ds"
export BQ_TABLE="timeline_events"
export SCHEMA_FILE="timeline_events.json"
export BQ_TABLE_NETWORK="network_events"
export SCHEMA_FILE_NETWORK="network_events.json"
export SUPPORTED_LOG_TYPES="fortigate,generic_csv"   # network-trigger subfolder allowlist; keep in sync with network-job's parser registry

echo "[+] Target Project: ${PROJECT}"
echo "[+] Target Region : ${REGION}"
echo "[+] Environment variables initialized successfully."

# =========================================================================
#  Phase 1: Google Cloud Initialization & API Enablement
# =========================================================================
echo "==> Phase 1-1: Creating the project..."
if ! gcloud projects describe "${PROJECT}" &>/dev/null; then
    echo "[+] Project does not exist. Creating..."
    gcloud projects create "${PROJECT}" --name="${PROJECT}"
else
    echo "[-] Project already exists. Skipping creation."
fi

echo "==> Phase 1-2: Linking Billing Account..."
BILLING_ENABLED=$(gcloud billing projects describe "${PROJECT}" --format="value(billingEnabled)" 2>/dev/null || echo "False")
if [[ "${BILLING_ENABLED}" != "True" ]]; then
    echo "[+] Linking billing account..."
    gcloud billing projects link "${PROJECT}" --billing-account="${BILLING_ACCOUNT_ID}"
else
    echo "[-] Billing account is already linked. Skipping."
fi

echo "==> Phase 1-3: Enabling required Google Cloud APIs..."
gcloud config set project ${PROJECT}

gcloud services enable \
  cloudkms.googleapis.com \
  storage.googleapis.com \
  run.googleapis.com \
  pubsub.googleapis.com \
  artifactregistry.googleapis.com \
  bigquery.googleapis.com \
  batch.googleapis.com \
  compute.googleapis.com

# =========================================================================
#  Phase 2: Infrastructure Resource Generation
# =========================================================================
echo "==> Phase 2: Creating infrastructure resources..."

# 2-1. Artifact Registry (Container Repository)
if ! gcloud artifacts repositories describe vxmn-repo --location=${REGION} &>/dev/null; then
  echo "[+] Creating Artifact Registry repository..."
  gcloud artifacts repositories create vxmn-repo \
    --repository-format=docker \
    --location=${REGION} \
    --description="veloxamen pipeline container images"
else
  echo "[-] Artifact Registry repository already exists. Skipping."
fi

# Configure Docker authentication for WSL/local environment
gcloud auth configure-docker ${REGION}-docker.pkg.dev --quiet

# 2-2. Cloud Storage Buckets Creation
create_bucket_if_not_exists() {
  local bucket_name=$1
  if ! gcloud storage buckets describe gs://${bucket_name} &>/dev/null; then
    echo "[+] Creating GCS bucket: gs://${bucket_name}"
    gcloud storage buckets create gs://${bucket_name} \
      --location=${REGION} \
      --default-storage-class=STANDARD \
      --uniform-bucket-level-access \
      --public-access-prevention
  else
    echo "[-] GCS bucket gs://${bucket_name} already exists. Skipping."
  fi
}

create_bucket_if_not_exists "${BUCKET_UPLOAD}"
create_bucket_if_not_exists "${BUCKET_RAW}"
create_bucket_if_not_exists "${BUCKET_OUTPUT}"
create_bucket_if_not_exists "${BUCKET_NW}"

# 2-2b. Force-provision the GCS service agent (service-PROJECT_NUMBER@
# gs-project-accounts.iam.gserviceaccount.com) now. It is otherwise
# created lazily on first use of certain features (e.g. bucket
# notifications, CMEK), which races with a freshly created project and
# causes "Service account ... does not exist" in Phase 6.
echo "[+] Ensuring GCS service agent is provisioned..."
gcloud storage service-agent --project=${PROJECT} >/dev/null

# 2-3. Cloud KMS KeyRing & Asymmetric CryptoKey
if ! gcloud kms keyrings describe ${KMS_RING} --location=${REGION} &>/dev/null; then
  echo "[+] Creating KMS KeyRing..."
  gcloud kms keyrings create ${KMS_RING} --location=${REGION}
else
  echo "[-] KMS KeyRing already exists. Skipping."
fi

if ! gcloud kms keys describe ${KMS_KEY} --keyring=${KMS_RING} --location=${REGION} &>/dev/null; then
  echo "[+] Creating Asymmetric Decryption Key..."
  gcloud kms keys create ${KMS_KEY} \
    --keyring=${KMS_RING} \
    --location=${REGION} \
    --purpose=asymmetric-encryption \
    --default-algorithm=rsa-decrypt-oaep-2048-sha256
else
  echo "[-] KMS Key already exists. Skipping."
fi

# 2-4. Export Public Key for veloxamen
echo "[+] Exporting Cloud KMS public key for local tool embedding..."
gcloud kms keys versions get-public-key 1 \
  --key=${KMS_KEY} \
  --keyring=${KMS_RING} \
  --location=${REGION} \
  --output-file=${PROJECT_ID}.pub

echo "[+] Storage and KMS infrastructure provisioning completed."

# 2-5. BigQuery dataset/table for Plaso output
echo "[+] Provisioning BigQuery dataset and table..."

if ! bq show --dataset "${PROJECT}:${BQ_DATASET}" &>/dev/null; then
  echo "[+] Creating BigQuery dataset: ${BQ_DATASET}"
  bq mk --dataset --location=${REGION} "${PROJECT}:${BQ_DATASET}"
else
  echo "[-] BigQuery dataset already exists. Skipping."
fi

# NOTE: Define an explicit schema file instead of
# relying on --autodetect, since Plaso's JSONL field set can vary slightly
# between plugins/parsers.
if ! bq show "${PROJECT}:${BQ_DATASET}.${BQ_TABLE}" &>/dev/null; then
  echo "[+] Creating BigQuery table: ${BQ_TABLE}"
  bq mk --table "${PROJECT}:${BQ_DATASET}.${BQ_TABLE}" ${SCHEMA_FILE}
else
  echo "[-] BigQuery table already exists. Skipping."
fi

# Daily partition on event_timestamp, clustered on src_ip/dst_ip.
if ! bq show "${PROJECT}:${BQ_DATASET}.${BQ_TABLE_NETWORK}" &>/dev/null; then
  echo "[+] Creating BigQuery table: ${BQ_TABLE_NETWORK}"
  bq mk --table \
    --time_partitioning_field=event_timestamp \
    --time_partitioning_type=DAY \
    --clustering_fields=src_ip,dst_ip \
    "${PROJECT}:${BQ_DATASET}.${BQ_TABLE_NETWORK}" ${SCHEMA_FILE_NETWORK}
else
  echo "[-] BigQuery table already exists. Skipping."
fi

# =========================================================================
#  Phase 3: IAM & Service Account Configuration
# =========================================================================
echo "==> Phase 3: Configuring Identity and Access Management (IAM)..."

create_sa_if_not_exists() {
  local sa_name=$1
  local display_name=$2
  if ! gcloud iam service-accounts describe "${sa_name}@${PROJECT}.iam.gserviceaccount.com" &>/dev/null; then
    echo "[+] Creating Service Account: ${sa_name}"
    retry_iam gcloud iam service-accounts create "${sa_name}" --display-name="${display_name}"
  else
    echo "[-] Service Account ${sa_name} already exists. Skipping."
  fi
}

create_sa_if_not_exists "decrypt-trigger-sa" "vxmn Decrypt Trigger SA"
create_sa_if_not_exists "decrypt-job-sa" "vxmn Decrypt Job SA"
create_sa_if_not_exists "plaso-job-sa" "vxmn Plaso Job SA"
create_sa_if_not_exists "plaso-trigger-sa" "vxmn Plaso Job Trigger SA"
create_sa_if_not_exists "bqload-trigger-sa" "vxmn BigQuery Load Trigger SA"
create_sa_if_not_exists "network-trigger-sa" "vxmn Network Log Trigger SA"
create_sa_if_not_exists "network-job-sa" "vxmn Network Log Job SA"

# roles/run.invoker lacks run.jobs.runWithOverrides, needed to pass
# per-execution env vars (CASE_ID, SRC_OBJECT, etc.) when running a job.
# Custom role keeps this minimal instead of using run.developer/run.admin.
create_custom_role_if_not_exists() {
  local role_id=$1
  local title=$2
  local permissions=$3
  if ! gcloud iam roles describe "${role_id}" --project=${PROJECT} &>/dev/null; then
    echo "[+] Creating custom IAM role: ${role_id}"
    gcloud iam roles create "${role_id}" \
      --project=${PROJECT} \
      --title="${title}" \
      --description="Minimal permissions to execute a Cloud Run Job with per-execution environment variable overrides" \
      --permissions="${permissions}" \
      --stage=GA
  else
    echo "[-] Custom IAM role ${role_id} already exists. Skipping."
  fi
}

create_custom_role_if_not_exists \
  "runJobRunnerWithOverrides" \
  "Run Job Runner (with overrides)" \
  "run.jobs.get,run.jobs.run,run.jobs.runWithOverrides"

# 3-1. Permissions for decrypt-trigger-sa
echo "[+] Binding IAM roles for decrypt-trigger-sa..."
retry_iam gcloud projects add-iam-policy-binding ${PROJECT} \
  --member="serviceAccount:${SA_DECRYPT_TRIGGER}" \
  --role=roles/iam.serviceAccountTokenCreator --quiet

# 3-2. Permissions for decrypt-job-sa
echo "[+] Binding IAM roles for decrypt-job-sa..."
retry_iam gcloud storage buckets add-iam-policy-binding gs://${BUCKET_UPLOAD} \
  --member="serviceAccount:${SA_DECRYPT}" \
  --role=roles/storage.objectViewer --quiet

# objectUser (not objectCreator): retries after a partial write need to
# overwrite the existing object, which requires delete + create.
retry_iam gcloud storage buckets add-iam-policy-binding gs://${BUCKET_RAW} \
  --member="serviceAccount:${SA_DECRYPT}" \
  --role=roles/storage.objectUser --quiet

retry_iam gcloud kms keys add-iam-policy-binding ${KMS_KEY} \
  --keyring=${KMS_RING} \
  --location=${REGION} \
  --member="serviceAccount:${SA_DECRYPT}" \
  --role=roles/cloudkms.cryptoKeyDecrypter --quiet

# 3-3. Permissions for plaso-job-sa
# plaso-job now runs as the *VM runtime* service account of a Google Batch
# job rather than a Cloud Run Job's runtime SA. Cloud Run Jobs get logging/
# monitoring write access implicitly; a Batch VM's user-managed SA needs it
# granted explicitly, or plaso-job's logs never make it to Cloud Logging.
echo "[+] Binding IAM roles for plaso-job-sa..."
retry_iam gcloud storage buckets add-iam-policy-binding gs://${BUCKET_RAW} \
  --member="serviceAccount:${SA_PLASO}" \
  --role=roles/storage.objectViewer --quiet

# Same reason as decrypt-job-sa: objectUser to allow overwrite on retry.
retry_iam gcloud storage buckets add-iam-policy-binding gs://${BUCKET_OUTPUT} \
  --member="serviceAccount:${SA_PLASO}" \
  --role=roles/storage.objectUser --quiet

retry_iam gcloud projects add-iam-policy-binding ${PROJECT} \
  --member="serviceAccount:${SA_PLASO}" \
  --role=roles/logging.logWriter --quiet

retry_iam gcloud projects add-iam-policy-binding ${PROJECT} \
  --member="serviceAccount:${SA_PLASO}" \
  --role=roles/monitoring.metricWriter --quiet

# roles/batch.agentReporter is required on the *VM's* service account (not
# plaso-trigger-sa, which submits the job) — it's what lets the Batch
# agent running on the VM report task state back to the Batch control
# plane. Missing this doesn't fail CreateJob (the trigger's Execute call
# succeeds and logs "plaso-job execution submitted" either way); it
# manifests downstream as a job that never progresses past
# SCHEDULED/RUNNING because the VM can never confirm it's alive. See
# https://cloud.google.com/batch/docs/troubleshooting
retry_iam gcloud projects add-iam-policy-binding ${PROJECT} \
  --member="serviceAccount:${SA_PLASO}" \
  --role=roles/batch.agentReporter --quiet

# Cloud Run Jobs pulled plaso-job's image through Cloud Run's own managed
# pull path, which didn't need the job's runtime SA to hold any Artifact
# Registry permission. A Batch VM pulls the image itself (via
# docker-credential-gcr, in the startup runnables the Batch agent injects
# before plaso-job's own runnable ever starts) using its own runtime SA,
# so that SA needs read access to the repository or the pull step fails
# with exit 1 before plaso-job's container ever runs.
retry_iam gcloud artifacts repositories add-iam-policy-binding vxmn-repo \
  --location=${REGION} \
  --member="serviceAccount:${SA_PLASO}" \
  --role=roles/artifactregistry.reader --quiet

# 3-4. Permissions for plaso-trigger-sa / bqload-trigger-sa
echo "[+] Binding IAM roles for relay trigger service accounts..."

# Self-bind tokenCreator so each relay SA can mint its own ID token for the
# push subscription auth header. Scoping to "self" avoids the broad
# project-level grant used for decrypt-trigger-sa (see 3-1; that broader grant
# is a known follow-up item, not addressed in this pass).
retry_iam gcloud iam service-accounts add-iam-policy-binding ${SA_PLASO_TRIGGER} \
  --member="serviceAccount:${SA_PLASO_TRIGGER}" \
  --role=roles/iam.serviceAccountTokenCreator --quiet

retry_iam gcloud iam service-accounts add-iam-policy-binding ${SA_BQLOAD_TRIGGER} \
  --member="serviceAccount:${SA_BQLOAD_TRIGGER}" \
  --role=roles/iam.serviceAccountTokenCreator --quiet

# BigQuery LOAD jobs read the source GCS file as the job's principal
# (bqload-trigger-sa — see the load job's user_email in `bq show -j`), not
# as some BigQuery-managed service agent. Without read access here, the
# load job is created successfully (LoaderFrom().Run() returns no error,
# so bqload-trigger logs "bigquery load job submitted") and only fails
# later, asynchronously, with accessDenied — invisible unless someone goes
# looking at `bq show -j <job-id>`.
retry_iam gcloud storage buckets add-iam-policy-binding gs://${BUCKET_OUTPUT} \
  --member="serviceAccount:${SA_BQLOAD_TRIGGER}" \
  --role=roles/storage.objectViewer --quiet

# plaso-trigger-sa submits Google Batch jobs (batch.jobsEditor covers
# jobs.create) and must be allowed to attach plaso-job-sa to the Batch VM
# as its runtime identity (serviceAccountUser *on* plaso-job-sa itself,
# not on plaso-trigger-sa — Batch checks this the same way Compute Engine
# does for "run as" service accounts).
retry_iam gcloud projects add-iam-policy-binding ${PROJECT} \
  --member="serviceAccount:${SA_PLASO_TRIGGER}" \
  --role=roles/batch.jobsEditor --quiet

retry_iam gcloud iam service-accounts add-iam-policy-binding ${SA_PLASO} \
  --member="serviceAccount:${SA_PLASO_TRIGGER}" \
  --role=roles/iam.serviceAccountUser --quiet

# bqload-trigger-sa needs to submit a BigQuery load job and write to the
# target dataset. It does NOT need GCS read access directly — BigQuery's
# own service agent reads the source object via the gs:// URI. The
# BQ_DATASET referenced here was already created in Phase 2-5.
#
# NOTE: dataset-level access is NOT supported by `bq add-iam-policy-binding`
# (that command only works on tables/views). Dataset grants use the GRANT
# DCL statement via `bq query` instead. Re-running GRANT for a member that
# already has the role is a safe no-op, so this is fine to leave inside the
# retry wrapper and to re-run on subsequent script runs.
retry_iam bq query --use_legacy_sql=false --project_id="${PROJECT}" \
  "GRANT \`roles/bigquery.dataEditor\` ON SCHEMA \`${PROJECT}\`.${BQ_DATASET} TO \"serviceAccount:${SA_BQLOAD_TRIGGER}\""

retry_iam gcloud projects add-iam-policy-binding ${PROJECT} \
  --member="serviceAccount:${SA_BQLOAD_TRIGGER}" \
  --role=roles/bigquery.jobUser --quiet

echo "[+] Binding IAM roles for network-trigger-sa / network-job-sa..."

# Self-bind, same as plaso-trigger-sa/bqload-trigger-sa (3-4 above).
retry_iam gcloud iam service-accounts add-iam-policy-binding ${SA_NETWORK_TRIGGER} \
  --member="serviceAccount:${SA_NETWORK_TRIGGER}" \
  --role=roles/iam.serviceAccountTokenCreator --quiet

# network-job is a plain Cloud Run Job (not Batch), so logging/monitoring
# write access is implicit, same as decrypt-job — no explicit binding needed.

retry_iam gcloud storage buckets add-iam-policy-binding gs://${BUCKET_NW} \
  --member="serviceAccount:${SA_NETWORK}" \
  --role=roles/storage.objectViewer --quiet

# Dataset-level grant, same pattern as bqload-trigger-sa (3-4 above).
retry_iam bq query --use_legacy_sql=false --project_id="${PROJECT}" \
  "GRANT \`roles/bigquery.dataEditor\` ON SCHEMA \`${PROJECT}\`.${BQ_DATASET} TO \"serviceAccount:${SA_NETWORK}\""

retry_iam gcloud projects add-iam-policy-binding ${PROJECT} \
  --member="serviceAccount:${SA_NETWORK}" \
  --role=roles/bigquery.jobUser --quiet

echo "[+] Service Accounts and IAM policies applied successfully."

# =========================================================================
#  Phase 4: Container Build & Push (Pre-heating Registry)
# =========================================================================
echo "==> Phase 4: Building and pushing all container images first..."

# 4-1. Build & Push: decrypt-trigger
if [ -d "decrypt-trigger" ]; then
  echo "[+] Building and pushing 'decrypt-trigger' image..."
  cd decrypt-trigger
  docker build --no-cache -t ${IMAGE_DECRYPT_TRIGGER} .
  docker push ${IMAGE_DECRYPT_TRIGGER}
  cd ..
else
  echo "[!] Directory 'decrypt-trigger' not found!"
fi

# 4-2. Build & Push: decrypt-job
if [ -d "decrypt-job" ]; then
  echo "[+] Building and pushing 'decrypt-job' image..."
  cd decrypt-job
  docker build --no-cache -t ${IMAGE_DECRYPT} .
  docker push ${IMAGE_DECRYPT}
  cd ..
else
  echo "[!] Directory 'decrypt-job' not found!"
fi

# 4-3. Build & Push: plaso-job
if [ -d "plaso-job" ]; then
  echo "[+] Building and pushing 'plaso-job' image..."
  cd plaso-job
  docker build --no-cache -t ${IMAGE_PLASO} .
  docker push ${IMAGE_PLASO}
  cd ..
else
  echo "[!] Directory 'plaso-job' not found!"
fi

# 4-4. Build & Push: plaso-trigger
if [ -d "plaso-trigger" ]; then
  echo "[+] Building and pushing 'plaso-trigger' image..."
  cd plaso-trigger
  docker build --no-cache -t ${IMAGE_PLASO_TRIGGER} .
  docker push ${IMAGE_PLASO_TRIGGER}
  cd ..
else
  echo "[!] Directory 'plaso-trigger' not found!"
fi

# 4-5. Build & Push: bqload-trigger
if [ -d "bqload-trigger" ]; then
  echo "[+] Building and pushing 'bqload-trigger' image..."
  cd bqload-trigger
  docker build --no-cache -t ${IMAGE_BQLOAD_TRIGGER} .
  docker push ${IMAGE_BQLOAD_TRIGGER}
  cd ..
else
  echo "[!] Directory 'bqload-trigger' not found!"
fi

# 4-6. Build & Push: network-trigger
if [ -d "network-trigger" ]; then
  echo "[+] Building and pushing 'network-trigger' image..."
  cd network-trigger
  docker build --no-cache -t ${IMAGE_NETWORK_TRIGGER} .
  docker push ${IMAGE_NETWORK_TRIGGER}
  cd ..
else
  echo "[!] Directory 'network-trigger' not found!"
fi

# 4-7. Build & Push: network-job
if [ -d "network-job" ]; then
  echo "[+] Building and pushing 'network-job' image..."
  cd network-job
  docker build --no-cache -t ${IMAGE_NETWORK} .
  docker push ${IMAGE_NETWORK}
  cd ..
else
  echo "[!] Directory 'network-job' not found!"
fi

# =========================================================================
#  Phase 5: Cloud Run Pipeline Workloads Deployment
# =========================================================================
echo "==> Phase 5: Deploying Cloud Run Service and Jobs..."

# 5-1. Deploy Cloud Run Job: decrypt-job
echo "[+] Instantiating Cloud Run Job: decrypt-job..."
if gcloud run jobs describe decrypt-job --region=${REGION} &>/dev/null; then
  gcloud run jobs update decrypt-job \
    --image=${IMAGE_DECRYPT} \
    --service-account=${SA_DECRYPT} \
    --memory=4Gi \
    --cpu=2 \
    --task-timeout=2h \
    --max-retries=1 \
    --set-env-vars=DST_BUCKET=${BUCKET_RAW},KMS_KEY_NAME=${KMS_KEY_NAME}
else
  gcloud run jobs create decrypt-job \
    --image=${IMAGE_DECRYPT} \
    --region=${REGION} \
    --service-account=${SA_DECRYPT} \
    --memory=4Gi \
    --cpu=2 \
    --task-timeout=2h \
    --max-retries=1 \
    --set-env-vars=DST_BUCKET=${BUCKET_RAW},KMS_KEY_NAME=${KMS_KEY_NAME}
fi

# 5-2. plaso-job: no persistent deployment step.
# Unlike Cloud Run Jobs, a Google Batch job is a one-shot resource with no
# standing "definition" to create/update here — plaso-trigger assembles
# the full Batch Job spec (image, machine type, disk, env vars) and
# submits it fresh on every execution. See plaso-trigger/internal/jobs/jobs.go
# and the PLASO_* exports in section 6b above for what would otherwise be
# configured here.

# 5-3. Deploy Cloud Run Service: decrypt-trigger
echo "[+] Deploying Cloud Run Service: decrypt-trigger..."
gcloud run deploy decrypt-trigger \
  --image=${IMAGE_DECRYPT_TRIGGER} \
  --region=${REGION} \
  --service-account=${SA_DECRYPT_TRIGGER} \
  --no-allow-unauthenticated \
  --set-env-vars=\
GOOGLE_CLOUD_PROJECT=${PROJECT},\
GCP_REGION=${REGION},\
DECRYPT_JOB_NAME=decrypt-job,\
DST_BUCKET=${BUCKET_RAW},\
KMS_KEY_NAME=${KMS_KEY_NAME},\
ALLOWED_SRC_BUCKET=${BUCKET_UPLOAD},\
CASE_ID=${PROJECT_ID}

# Fetch assigned Service URL
export SERVICE_URL=$(gcloud run services describe decrypt-trigger \
  --region=${REGION} \
  --format="value(status.url)")

# Grant run.invoker on decrypt-trigger to its own push-auth SA. Without
# this, Pub/Sub push gets a 403 at the Cloud Run ingress and never
# reaches the handler (serviceAccountTokenCreator in 3-1 only lets it
# mint an ID token — it doesn't grant call access).
retry_iam gcloud run services add-iam-policy-binding decrypt-trigger \
  --region=${REGION} \
  --member="serviceAccount:${SA_DECRYPT_TRIGGER}" \
  --role=roles/run.invoker --quiet

# 5-4. Bind dynamic job-runner access to decrypt-job
# runJobRunnerWithOverrides (not roles/run.invoker) — decrypt-trigger calls
# RunJob with SRC_OBJECT/CASE_ID/DST_PREFIX overrides per execution, which
# needs run.jobs.runWithOverrides specifically (see Phase 3 custom role).
retry_iam gcloud run jobs add-iam-policy-binding decrypt-job \
  --region=${REGION} \
  --member="serviceAccount:${SA_DECRYPT_TRIGGER}" \
  --role="projects/${PROJECT}/roles/runJobRunnerWithOverrides" --quiet

# 5-5. Deploy Cloud Run Service: plaso-trigger
# Receives WORK bucket finalize events and submits a Google Batch job
# running plaso-job for the case (see internal/jobs/jobs.go). Batch has no
# persistent job "definition" the way Cloud Run Jobs does, so everything
# needed to build that job's spec — image, runtime SA, machine type,
# disk, retry policy — is passed here rather than baked into a one-time
# `gcloud run jobs create` like the old plaso-job deployment was.
echo "[+] Deploying Cloud Run Service: plaso-trigger..."
gcloud run deploy plaso-trigger \
  --image=${IMAGE_PLASO_TRIGGER} \
  --region=${REGION} \
  --service-account=${SA_PLASO_TRIGGER} \
  --no-allow-unauthenticated \
  --set-env-vars=\
GOOGLE_CLOUD_PROJECT=${PROJECT},\
GCP_REGION=${REGION},\
PLASO_JOB_IMAGE=${IMAGE_PLASO},\
PLASO_JOB_SA=${SA_PLASO},\
SRC_BUCKET=${BUCKET_RAW},\
DST_BUCKET=${BUCKET_OUTPUT},\
PLASO_MACHINE_TYPE=${PLASO_MACHINE_TYPE},\
PLASO_CPU_MILLI=${PLASO_CPU_MILLI},\
PLASO_MEMORY_MIB=${PLASO_MEMORY_MIB},\
PLASO_DISK_GB=${PLASO_DISK_GB},\
PLASO_PROVISIONING_MODEL=${PLASO_PROVISIONING_MODEL},\
PLASO_MAX_RETRY_COUNT=${PLASO_MAX_RETRY_COUNT},\
PLASO_MAX_RUN_DURATION=${PLASO_MAX_RUN_DURATION},\
ALLOWED_SRC_BUCKET=${BUCKET_RAW},\
CASE_ID=${PROJECT_ID}

export PLASO_TRIGGER_URL=$(gcloud run services describe plaso-trigger \
  --region=${REGION} \
  --format="value(status.url)")

# Same reason as decrypt-trigger: grant run.invoker to plaso-trigger's
# own push-auth SA.
retry_iam gcloud run services add-iam-policy-binding plaso-trigger \
  --region=${REGION} \
  --member="serviceAccount:${SA_PLASO_TRIGGER}" \
  --role=roles/run.invoker --quiet

# 5-6. Deploy Cloud Run Service: bqload-trigger
# Receives OUTPUT bucket finalize events, submits a BigQuery load job
# directly (no separate Cloud Run Job needed for this lightweight,
# short-lived operation).
echo "[+] Deploying Cloud Run Service: bqload-trigger..."
gcloud run deploy bqload-trigger \
  --image=${IMAGE_BQLOAD_TRIGGER} \
  --region=${REGION} \
  --service-account=${SA_BQLOAD_TRIGGER} \
  --no-allow-unauthenticated \
  --set-env-vars=\
GOOGLE_CLOUD_PROJECT=${PROJECT},\
BQ_DATASET=${BQ_DATASET},\
BQ_TABLE=${BQ_TABLE},\
ALLOWED_SRC_BUCKET=${BUCKET_OUTPUT}

export BQLOAD_TRIGGER_URL=$(gcloud run services describe bqload-trigger \
  --region=${REGION} \
  --format="value(status.url)")

# Same reason as decrypt-trigger/plaso-trigger: grant run.invoker to
# bqload-trigger's own push-auth SA.
retry_iam gcloud run services add-iam-policy-binding bqload-trigger \
  --region=${REGION} \
  --member="serviceAccount:${SA_BQLOAD_TRIGGER}" \
  --role=roles/run.invoker --quiet

# 5-7. Deploy Cloud Run Job: network-job
# Plain Cloud Run Job (same shape as decrypt-job in 5-1) — network-job
# streams its input, so it doesn't need Batch's scratch disk like plaso-job.
echo "[+] Instantiating Cloud Run Job: network-job..."
if gcloud run jobs describe network-job --region=${REGION} &>/dev/null; then
  gcloud run jobs update network-job \
    --image=${IMAGE_NETWORK} \
    --service-account=${SA_NETWORK} \
    --memory=512Mi \
    --cpu=1 \
    --task-timeout=30m \
    --max-retries=1 \
    --set-env-vars=GOOGLE_CLOUD_PROJECT=${PROJECT},SRC_BUCKET=${BUCKET_NW},BQ_DATASET=${BQ_DATASET},BQ_TABLE=${BQ_TABLE_NETWORK}
else
  gcloud run jobs create network-job \
    --image=${IMAGE_NETWORK} \
    --region=${REGION} \
    --service-account=${SA_NETWORK} \
    --memory=512Mi \
    --cpu=1 \
    --task-timeout=30m \
    --max-retries=1 \
    --set-env-vars=GOOGLE_CLOUD_PROJECT=${PROJECT},SRC_BUCKET=${BUCKET_NW},BQ_DATASET=${BQ_DATASET},BQ_TABLE=${BQ_TABLE_NETWORK}
fi

# 5-8. Deploy Cloud Run Service: network-trigger
# Submits a network-job execution per object; SRC_OBJECT/LOG_TYPE are
# passed as per-execution overrides (see internal/jobs/jobs.go), not set here.
echo "[+] Deploying Cloud Run Service: network-trigger..."
gcloud run deploy network-trigger \
  --image=${IMAGE_NETWORK_TRIGGER} \
  --region=${REGION} \
  --service-account=${SA_NETWORK_TRIGGER} \
  --no-allow-unauthenticated \
  --set-env-vars="^;^\
GOOGLE_CLOUD_PROJECT=${PROJECT};\
GCP_REGION=${REGION};\
NETWORK_JOB_NAME=network-job;\
ALLOWED_SRC_BUCKET=${BUCKET_NW};\
SUPPORTED_LOG_TYPES=${SUPPORTED_LOG_TYPES}"

export NETWORK_TRIGGER_URL=$(gcloud run services describe network-trigger \
  --region=${REGION} \
  --format="value(status.url)")

# Same reason as the other triggers: grant run.invoker to
# network-trigger's own push-auth SA.
retry_iam gcloud run services add-iam-policy-binding network-trigger \
  --region=${REGION} \
  --member="serviceAccount:${SA_NETWORK_TRIGGER}" \
  --role=roles/run.invoker --quiet

# 5-9. Bind dynamic job-runner access to network-job
# Same reasoning as decrypt-trigger's 5-4 binding.
retry_iam gcloud run jobs add-iam-policy-binding network-job \
  --region=${REGION} \
  --member="serviceAccount:${SA_NETWORK_TRIGGER}" \
  --role="projects/${PROJECT}/roles/runJobRunnerWithOverrides" --quiet

# =========================================================================
#  Phase 6: Pub/Sub & GCS Event-Driven Notification Wiring
# =========================================================================
echo "==> Phase 6: Configuring Pub/Sub messaging and GCS event notifications..."

# Shared dead-letter topic used by the WORK and OUTPUT subscriptions below.
if ! gcloud pubsub topics describe ${PUBSUB_DLQ} &>/dev/null; then
  echo "[+] Creating DLQ topic: ${PUBSUB_DLQ}"
  gcloud pubsub topics create ${PUBSUB_DLQ}
else
  echo "[-] DLQ topic already exists. Skipping."
fi

# --- 6-1. UPLOAD bucket -> decrypt-trigger ---
if ! gcloud pubsub topics describe ${PUBSUB_TOPIC_IN} &>/dev/null; then
  echo "[+] Creating Pub/Sub Topic: ${PUBSUB_TOPIC_IN}"
  gcloud pubsub topics create ${PUBSUB_TOPIC_IN}
else
  echo "[-] Pub/Sub Topic already exists. Skipping."
fi

if ! gcloud storage buckets notifications list gs://${BUCKET_UPLOAD} 2>/dev/null | grep -q "${PUBSUB_TOPIC_IN}"; then
  echo "[+] Creating GCS bucket event notification link..."
  gcloud storage buckets notifications create gs://${BUCKET_UPLOAD} \
    --topic=${PUBSUB_TOPIC_IN} \
    --event-types=OBJECT_FINALIZE \
    --payload-format=json
else
  echo "[-] GCS bucket event notification configuration already bound. Skipping."
fi

echo "[+] Granting Token Creation role to GCP Pub/Sub Service Agent..."
PROJECT_NUMBER=$(gcloud projects describe ${PROJECT} --format='value(projectNumber)')
retry_iam gcloud projects add-iam-policy-binding ${PROJECT} \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-pubsub.iam.gserviceaccount.com" \
  --role=roles/iam.serviceAccountTokenCreator --quiet

if ! gcloud pubsub subscriptions describe ${PUBSUB_SUB_IN} &>/dev/null; then
  echo "[+] Creating Pub/Sub Push Subscription linked to Cloud Run Service..."
  gcloud pubsub subscriptions create ${PUBSUB_SUB_IN} \
    --topic=${PUBSUB_TOPIC_IN} \
    --push-endpoint=${SERVICE_URL}/ \
    --push-auth-service-account=${SA_DECRYPT_TRIGGER} \
    --ack-deadline=60 \
    --min-retry-delay=10s \
    --max-retry-delay=300s
else
  echo "[-] Pub/Sub Subscription already exists. Skipping."
fi

# --- 6-2. WORK bucket -> plaso-trigger ---
if ! gcloud pubsub topics describe ${PUBSUB_TOPIC_RAW} &>/dev/null; then
  echo "[+] Creating Pub/Sub Topic: ${PUBSUB_TOPIC_RAW}"
  gcloud pubsub topics create ${PUBSUB_TOPIC_RAW}
else
  echo "[-] Pub/Sub Topic already exists. Skipping."
fi

if ! gcloud storage buckets notifications list gs://${BUCKET_RAW} 2>/dev/null | grep -q "${PUBSUB_TOPIC_RAW}"; then
  echo "[+] Creating GCS bucket event notification link..."
  gcloud storage buckets notifications create gs://${BUCKET_RAW} \
    --topic=${PUBSUB_TOPIC_RAW} \
    --event-types=OBJECT_FINALIZE \
    --payload-format=json
else
  echo "[-] GCS bucket event notification configuration already bound. Skipping."
fi

if ! gcloud pubsub subscriptions describe ${PUBSUB_SUB_RAW} &>/dev/null; then
  echo "[+] Creating Pub/Sub Push Subscription linked to plaso-trigger..."
  gcloud pubsub subscriptions create ${PUBSUB_SUB_RAW} \
    --topic=${PUBSUB_TOPIC_RAW} \
    --push-endpoint=${PLASO_TRIGGER_URL}/ \
    --push-auth-service-account=${SA_PLASO_TRIGGER} \
    --ack-deadline=60 \
    --min-retry-delay=10s \
    --max-retry-delay=300s \
    --dead-letter-topic=${PUBSUB_DLQ} \
    --max-delivery-attempts=5
else
  echo "[-] Pub/Sub Subscription already exists. Skipping."
fi

# --- 6-3. OUTPUT bucket -> bqload-trigger ---
if ! gcloud pubsub topics describe ${PUBSUB_TOPIC_OUT} &>/dev/null; then
  echo "[+] Creating Pub/Sub Topic: ${PUBSUB_TOPIC_OUT}"
  gcloud pubsub topics create ${PUBSUB_TOPIC_OUT}
else
  echo "[-] Pub/Sub Topic already exists. Skipping."
fi

if ! gcloud storage buckets notifications list gs://${BUCKET_OUTPUT} 2>/dev/null | grep -q "${PUBSUB_TOPIC_OUT}"; then
  echo "[+] Creating GCS bucket event notification link..."
  gcloud storage buckets notifications create gs://${BUCKET_OUTPUT} \
    --topic=${PUBSUB_TOPIC_OUT} \
    --event-types=OBJECT_FINALIZE \
    --payload-format=json
else
  echo "[-] GCS bucket event notification configuration already bound. Skipping."
fi

if ! gcloud pubsub subscriptions describe ${PUBSUB_SUB_OUT} &>/dev/null; then
  echo "[+] Creating Pub/Sub Push Subscription linked to bqload-trigger..."
  gcloud pubsub subscriptions create ${PUBSUB_SUB_OUT} \
    --topic=${PUBSUB_TOPIC_OUT} \
    --push-endpoint=${BQLOAD_TRIGGER_URL}/ \
    --push-auth-service-account=${SA_BQLOAD_TRIGGER} \
    --ack-deadline=60 \
    --min-retry-delay=10s \
    --max-retry-delay=300s \
    --dead-letter-topic=${PUBSUB_DLQ} \
    --max-delivery-attempts=5
else
  echo "[-] Pub/Sub Subscription already exists. Skipping."
fi

# --- 6-4. RAW bucket -> network-trigger ---
if ! gcloud pubsub topics describe ${PUBSUB_TOPIC_NW} &>/dev/null; then
  echo "[+] Creating Pub/Sub Topic: ${PUBSUB_TOPIC_NW}"
  gcloud pubsub topics create ${PUBSUB_TOPIC_NW}
else
  echo "[-] Pub/Sub Topic already exists. Skipping."
fi

if ! gcloud storage buckets notifications list gs://${BUCKET_NW} 2>/dev/null | grep -q "${PUBSUB_TOPIC_NW}"; then
  echo "[+] Creating GCS bucket event notification link..."
  gcloud storage buckets notifications create gs://${BUCKET_NW} \
    --topic=${PUBSUB_TOPIC_NW} \
    --event-types=OBJECT_FINALIZE \
    --payload-format=json
else
  echo "[-] GCS bucket event notification configuration already bound. Skipping."
fi

if ! gcloud pubsub subscriptions describe ${PUBSUB_SUB_NW} &>/dev/null; then
  echo "[+] Creating Pub/Sub Push Subscription linked to network-trigger..."
  gcloud pubsub subscriptions create ${PUBSUB_SUB_NW} \
    --topic=${PUBSUB_TOPIC_NW} \
    --push-endpoint=${NETWORK_TRIGGER_URL}/ \
    --push-auth-service-account=${SA_NETWORK_TRIGGER} \
    --ack-deadline=60 \
    --min-retry-delay=10s \
    --max-retry-delay=300s \
    --dead-letter-topic=${PUBSUB_DLQ} \
    --max-delivery-attempts=5
else
  echo "[-] Pub/Sub Subscription already exists. Skipping."
fi

## =========================================================================
##  Phase 7: Optional settings
## =========================================================================
# echo "==> Phase 7: Enabling optional settings..."
## Pre-create a network log config folder if required and log type is identified.
## Uncomment and/or copy the lines below then rename fortigate to others.
# echo "[+] Generating log top-level config/ and log/ prefixes exist under gs://${BUCKET_NW}..."
# gcloud storage cp nw-config-templates/fortigate.json "gs://${BUCKET_NW}/config/fortigate.json"
## NOTE: modify fortigate.json and/or other configs to fit the actual log format.
## "logs" folder will be created when log(s) are uploaded to the bucket using signed URLs.

echo "======================================================================="
echo " Deployment Complete: Veloxamen Cloud-Native DFIR Pipeline is active!"
echo "======================================================================="