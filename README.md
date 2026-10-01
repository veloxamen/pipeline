# 🛤️ pipeline

**Automated Processing Pipeline for Cloud-Native DFIR**

`pipeline` is a set of processing pipelines mainly written in **Go**, designed to process various artifacts and network logs for cloud-native incident response.

---

## ✨ Key Concepts

* **Automation** Automatically triggers processing and loads data into BigQuery schemas once evidence or logs are uploaded to the appropriate GCS bucket.
* **Security** Integrated with Cloud KMS and RSA encryption for secure artifact handling, minimizing compliance risks.
* **Flexibility**: Easily adaptable to various situations and investigation styles through custom views and flexible network configurations.

---
## 📂 File Structure
```txt
`pipeline/`
├─ `bqload-trigger/` : Triggers and loads Plaso JSONL into BigQuery (`timeline_events`).
├─ `bqload-job/` : Handles the BigQuery loading process for timeline events.
├─ `decrypt-trigger/` : Triggers the decryption process for uploaded forensic artifacts.
├─ `decrypt-job/` : Decrypts encrypted forensic artifacts using Cloud KMS.
├─ `network-trigger/` : Triggers network log processing upon new uploads.
├─ `network-job/` : Parses multi-vendor network logs and loads them into BigQuery (`network_events`).
├─ `nw-config-templates/` : Base JSON configuration templates for network log parsing.
├─ `plaso-trigger/` : Triggers log2timeline/plaso processing for raw evidence.
├─ `plaso-job/` : Runs Plaso processing via Google Batch to generate timeline JSONL.
├─ `deploy.sh` : Automated deployment script for the entire pipeline on GCP.
├─ `timeline_events.json` : Schema design for the `timeline_events` table.
├─ `network_events.json` : Schema design for the `network_events` table.
├─ `timeline_events_aggregated.sql` : Sample view query for timeline data, to have local timestamp.
├─ `timeline_nexus.sql` : Sample query to generate correlated-analysis schema via Scheduled Query.
├─ `create_uploader_sa.sh` : Helper script to create dedicated Service Account for GCS file uploading.
├─ `generate_upload_ps1.sh` : Helper script to generate a PowerShell scripts consists of curl coomands with signed URLs.
└─ `cleanup_uploader_sa.sh` : Helper script to delete dedicated Service Account for GCS file uploading.
```
---

## ⚙️ Configuration

Minimal configuration is required. Edit the environment variables at the top of `deploy.sh`:

1. **Project ID (`PROJECT_ID`):** Specify your case-specific name (e.g., `jdoe202601`). The script automatically prefixes it to ensure uniqueness.
2. **Billing Account ID (`BILLING_ACCOUNT_ID`):** Specify your GCP Billing Account ID.

> [!IMPORTANT]
> GCS bucket names must be globally unique. If a naming collision occurs, adjust the prefix in `deploy.sh`. Do not alter the underlying directory structure, as dependencies rely on it.

---

## 💻 Usage & Deployment

### 1. Deployment

Run `deploy.sh` from a `gcloud`-authenticated console:

```bash
./deploy.sh
```

### 2. Ingestions & Secure Upload Workflow

For handling forensic evidence uploads from client environments securely, a dedicated temporary Service Account (SA) workflow is provided. This prevents over-privileged access and ensures clean teardown after uploads complete.

#### Workflow Steps:
1. **Create Uploader SA:**
   Run the setup script to generate an ephemeral Service Account, grant necessary bucket permissions (`objectAdmin`), and assign impersonation rights:
   ```bash
   ./create_uploader_sa.sh

```

*(This automatically saves the SA state to $SA_FILE)*

2. **Configure & Generate Upload Script:**
Edit the target bucket and file list in `generate_upload_ps1.sh`, then run it to generate the PowerShell upload script (`upload_evidence.ps1`) using signed URLs:
```bash
./generate_upload_ps1.sh
```
> [!NOTE]
> Even though your `gcloud`-authenticated user has high-level permissions such as `Owner` or `Editor`, the `Service Account Token Creator` role is explicitly required on the Service Account.
> If your upload requires more than 12 hours (e.g., artifacts include memory dump, UsnJrnl and/or slow networks), authenticate `gcloud` directly using the SA's JSON key and adjust the `DURATION` variable accordingly.

3. **Client Execution:**
Send `upload_evidence.ps1` (along with your evidence files) to the client/target environment to execute the upload.
4. **Cleanup:**
Once uploads are verified, run the cleanup script to safely delete the temporary Service Account and revoke all associated permissions:
```bash
./cleanup_uploader_sa.sh
```

#### Network ingestion supplemental info

Network logs are processed via config-driven parsers without hardcoding vendor logic.

* **Bucket Structure (`BUCKET_NW`):**
  * `config/`: Contains vendor-specific mapping JSON files (e.g., `fortigate.json`, `aws.json`, derived from `nw-config-templates/`).
  * `log/`: Raw log files uploaded via signed URLs, categorized by log type (e.g., `log/fortigate/...`).

##### Supported Vendors & Templates

Templates are available in `nw-config-templates/` for the following formats:

* **JSON:** `google.json` (VPC Firewall), `aws.json` (Network Firewall / Suricata), `azure.json` (Azure Firewall)
* **Key-Value (KV):** `fortigate.json`, `checkpoint.json`
* **CSV:** `generic_csv.json`, `paloalto.json`
* **Regex:** `cisco_asa.json`

> [!NOTE]
> Templates were generated from sample log files available online, so there is no guarantee they will parse your specific logs as expected. It will be tuned through practical engagements.
> To onboard a new vendor, simply copy the closest matching template into `gs://<BUCKET-NW>/config/<log_type>.json`, upload the logs to `gs://<BUCKET-NW>/log/<log_type>/` using upload script by generate_upload_ps1.sh, rclone or other tools.
