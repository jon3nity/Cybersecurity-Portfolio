# Sybersek Master IR Workflow — n8n SOAR Framework

Open-source incident response automation framework built on [n8n](https://n8n.io), published as part of an MSc Cybersecurity dissertation at Atlantic Technological University Letterkenny, 2026.

**Research title:** Design and Evaluation of an Open-Source Incident Response Automation Framework for Under-Resourced SOC Teams  
**Author:** Chinedu John Onyekachi — [github.com/jon3nity](https://github.com/jon3nity)

---

## What it does

A single webhook endpoint (`/webhook/master-ir`) receives security alerts from any source and automatically:

1. Assigns a persistent, incrementing ticket number (TKT-0001, TKT-0002 …) stored in Google Sheets
2. Routes the alert through one of five MITRE ATT&CK-aligned branches
3. Enriches it via VirusTotal and AbuseIPDB APIs
4. Assigns a verdict and actionable recommendation
5. Logs a structured 26-column record to Google Sheets
6. Fires a real-time Slack notification

**Three alert sources feed the same pipeline:**

```
PowerShell synthetic scenarios ──────────────────────┐
Microsoft Defender for Business (via Power Automate) ─├──► ngrok ──► /webhook/master-ir ──► n8n pipeline
Microsoft Graph Sign-in Monitor (n8n scheduler) ─────┘
```

---

## Workflow branches

| Branch | MITRE Technique | Trigger `incident_type` | Enrichment |
|--------|----------------|--------------------------|------------|
| W1 — Phishing Triage | T1566 | `Phishing Attempt` | VT URL scan (async, 15s wait) + KnowBe4/Cofense whitelist check |
| W2 — Brute Force | T1110 | `Brute Force Attempt` | VT IP lookup + AbuseIPDB confidence score (sequential) |
| W3 — IP Reputation | T1071 | `Suspicious Outbound Traffic` | VT IP lookup + AbuseIPDB confidence score (sequential) |
| W4 — Malware Hash | T1204 | `Malware Detected` / `Execution` | VT file hash report |
| W5 — Ticket Creation | — | All other alert types | None — structured ticket logged for analyst review |
| Graph Monitor | T1110 | Schedule (every 2 min) | Self-posts to Master IR as `Brute Force Attempt` |

---

## Tech stack

| Tool | Version | Role |
|------|---------|------|
| n8n | 2.1.4 (Docker) | Workflow orchestration engine |
| VirusTotal API | v3 (free, 500/day) | URL, IP, and file hash enrichment |
| AbuseIPDB API | v2 (free, 1000/day) | IP abuse confidence scoring |
| Google Sheets | Cloud | 26-column IR log + Sheet2!A1 persistent counter |
| Slack | Free (incoming webhook) | Real-time analyst notification |
| Microsoft Graph API | v1.0 | Entra ID sign-in log polling |
| Microsoft Defender for Business | Cloud | Live endpoint alert source |
| Power Automate | Premium trial | Relay Defender alerts to n8n via ngrok |
| ngrok | Free tier | Expose local n8n to internet |
| Docker | 4.x | Reproducible n8n deployment |

---

## Full setup guide

### Step 1 — Deploy n8n via Docker

```bash
docker run -it --rm \
  -p 5678:5678 \
  -v ~/.n8n:/home/node/.n8n \
  n8nio/n8n
```

n8n is now running at `http://localhost:5678`. Open it in your browser and create an admin account.

---

### Step 2 — Configure credentials in n8n

In n8n go to **Settings → Credentials → Add Credential** and create:

**Google Sheets OAuth2**
- Type: Google Sheets OAuth2 API
- Sign in with your Google account
- This credential is used by the Log to Google Sheets node and the Read Counter / Write Counter HTTP Request nodes

VirusTotal and AbuseIPDB keys are entered directly in the HTTP Request node header fields — no separate credential needed in n8n.

---

### Step 3 — Set up Google Sheets

Create a new Google Sheet and note the Sheet ID from the URL (`https://docs.google.com/spreadsheets/d/YOUR_SHEET_ID/edit`).

**Sheet1** — the IR log. Add these 26 column headers in row 1 exactly:

```
ticket_number | alert_id | incident_type | severity | source_ip | hostname | user | description | timestamp | status | vt_malicious_score | vt_total_engines | aipdb_confidence | aipdb_country | verdict | file_hash | file_name | file_type | failed_login_count | recommendation | sender_domain | extracted_url | url_verdict | sender_email | email_subject | workflow_branch
```

**Sheet2** — the persistent ticket counter.
- Click `+` at the bottom to add Sheet2
- In cell A1 type `0` — this is the counter starting value. Reset to 0 before any evaluation run.

---

### Step 4 — Set up ngrok

```bash
# Download from https://ngrok.com/download and authenticate with your account token
ngrok config add-authtoken YOUR_NGROK_TOKEN

# Start a tunnel to your local n8n
ngrok http 5678
```

Copy the forwarding URL (e.g. `https://your-subdomain.ngrok-free.app`). Use this as the base URL everywhere you need to reach n8n from outside. For a stable URL that survives restarts, claim a free static domain in your ngrok dashboard and start with `ngrok http --domain=your-domain.ngrok-free.app 5678`.

---

### Step 5 — Import the workflow

1. In n8n go to **Workflows → Import from File** and select `master-ir-workflow.json`
2. Open each node containing a `YOUR_*` placeholder and replace with your real values:

| Placeholder | Node | What to enter |
|-------------|------|---------------|
| `YOUR_VIRUSTOTAL_API_KEY` | All VT HTTP Request nodes → `x-apikey` header | Your VirusTotal API key |
| `YOUR_ABUSEIPDB_API_KEY` | AbuseIPDB Lookup node → `Key` header | Your AbuseIPDB API key |
| `YOUR_SLACK_WEBHOOK_URL` | Slack Notification node → URL field | Your Slack incoming webhook URL |
| `YOUR_GOOGLE_SHEET_ID` | Log to Google Sheets, Read Counter, Write Counter | Your Sheet ID |
| `YOUR_NGROK_DOMAIN.ngrok-free.app` | Send to Master IR node (Graph Monitor section) | Your ngrok domain |
| `YOUR_ENTRA_TENANT_ID` | Get Graph Token node → URL | Your Azure Entra tenant ID |
| `YOUR_AZURE_APP_CLIENT_ID` | Get Graph Token node → `client_id` body param | Your app registration client ID |
| `YOUR_AZURE_CLIENT_SECRET` | Get Graph Token node → `client_secret` body param | Your app registration secret value |

3. In the **Read Counter** and **Write Counter** HTTP Request nodes, set Authentication to `Predefined Credential Type → Google Sheets OAuth2 API` and select your credential
4. In the **Log to Google Sheets** node, set the credential, confirm Document ID is your Sheet ID, and Sheet Name is `Sheet1`
5. Save the workflow

---

### Step 6 — Activate

Toggle the workflow to **Active**. The webhook is now live at:
```
https://YOUR_NGROK_DOMAIN.ngrok-free.app/webhook/master-ir
```

---

### Step 7 — Test with PowerShell synthetic scenarios (W1, W2, W3, W5)

Run from any Windows machine. Add `Start-Sleep -Seconds 20` between scenarios so each completes before the next fires.

**W1 — Phishing Attempt**
```powershell
Invoke-WebRequest -Uri "https://YOUR_NGROK_DOMAIN.ngrok-free.app/webhook/master-ir" `
  -Method POST -ContentType "application/json" `
  -Body '{
    "alert_id": "W1-S1",
    "incident_type": "Phishing Attempt",
    "severity": "High",
    "source_ip": "N/A",
    "hostname": "workstation-01",
    "user": "user@yourdomain.com",
    "description": "Suspicious email with malicious link",
    "file_hash": "N/A",
    "failed_login_count": 0,
    "sender_email": "attacker@malicious-domain.com",
    "email_body": "Click here http://malware.wicar.org/data/java_jre17_exec.html to verify",
    "email_subject": "Urgent: Verify your account"
  }'
```

**W1 — Phishing Simulation (KnowBe4 whitelist test)**
```powershell
Invoke-WebRequest -Uri "https://YOUR_NGROK_DOMAIN.ngrok-free.app/webhook/master-ir" `
  -Method POST -ContentType "application/json" `
  -Body '{
    "alert_id": "W1-S2",
    "incident_type": "Phishing Attempt",
    "severity": "Informational",
    "source_ip": "N/A",
    "hostname": "workstation-01",
    "user": "user@yourdomain.com",
    "description": "Phishing simulation email detected",
    "file_hash": "N/A",
    "failed_login_count": 0,
    "sender_email": "test@knowbe4.com",
    "email_body": "Click here http://phishingtest.example.com to verify",
    "email_subject": "Security awareness test"
  }'
```

**W2 — Brute Force Attempt**
```powershell
Invoke-WebRequest -Uri "https://YOUR_NGROK_DOMAIN.ngrok-free.app/webhook/master-ir" `
  -Method POST -ContentType "application/json" `
  -Body '{
    "alert_id": "W2-S1",
    "incident_type": "Brute Force Attempt",
    "severity": "Critical",
    "source_ip": "185.220.101.45",
    "hostname": "dc-01",
    "user": "admin@yourdomain.com",
    "description": "Multiple failed login attempts from Tor exit node",
    "file_hash": "N/A",
    "failed_login_count": 25,
    "sender_email": "",
    "email_body": "",
    "email_subject": "N/A"
  }'
```

**W3 — Suspicious Outbound Traffic**
```powershell
Invoke-WebRequest -Uri "https://YOUR_NGROK_DOMAIN.ngrok-free.app/webhook/master-ir" `
  -Method POST -ContentType "application/json" `
  -Body '{
    "alert_id": "W3-S1",
    "incident_type": "Suspicious Outbound Traffic",
    "severity": "High",
    "source_ip": "185.220.101.45",
    "hostname": "workstation-01",
    "user": "user@yourdomain.com",
    "description": "Outbound connection to known Tor exit node",
    "file_hash": "N/A",
    "failed_login_count": 0,
    "sender_email": "",
    "email_body": "",
    "email_subject": "N/A"
  }'
```

**W5 — General ticket (unclassified alert)**
```powershell
Invoke-WebRequest -Uri "https://YOUR_NGROK_DOMAIN.ngrok-free.app/webhook/master-ir" `
  -Method POST -ContentType "application/json" `
  -Body '{
    "alert_id": "W5-S1",
    "incident_type": "Generic Alert",
    "severity": "Low",
    "source_ip": "N/A",
    "hostname": "workstation-01",
    "user": "user@yourdomain.com",
    "description": "Unclassified security event detected",
    "file_hash": "N/A",
    "failed_login_count": 0,
    "sender_email": "",
    "email_body": "",
    "email_subject": "N/A"
  }'
```

After each run check Google Sheets for a new TKT-XXXX row and your Slack channel for the notification.

---

### Step 8 — Connect Microsoft Defender for Business (W4 live malware alerts)

This sends real Defender detections through the pipeline. Requires Microsoft 365 Business Premium with Defender for Business enabled and a Power Automate Premium licence or trial.

**8a — Register an Azure App**

1. Go to [portal.azure.com](https://portal.azure.com) → **Azure Active Directory → App registrations → New registration**
2. Name it anything (e.g. `n8n-IR-Connector`), leave defaults, click **Register**
3. Note the **Application (client) ID** and **Directory (tenant) ID** from the Overview page
4. Go to **Certificates & secrets → New client secret** — set an expiry and click Add. Copy the **Value** immediately (it disappears after you navigate away)
5. Go to **API permissions → Add a permission → Microsoft Graph → Application permissions** and add:
   - `SecurityAlert.Read.All`
   - `AuditLog.Read.All`
   - `Directory.Read.All`
6. Click **Grant admin consent for [your tenant]**

**8b — Create the Power Automate flow**

1. Go to [make.powerautomate.com](https://make.powerautomate.com)
2. Click **Create → Automated cloud flow**
3. Search for trigger: **Microsoft Defender for Endpoint — When a new alert is created (WDATP)**
4. Add a new step: **HTTP**
   - Method: `POST`
   - URI: `https://YOUR_NGROK_DOMAIN.ngrok-free.app/webhook/master-ir`
   - Headers: `Content-Type` = `application/json`
   - Body — click in the body field and use **Expression** / dynamic content to build:
   ```json
   {
     "alert_id": "@{triggerBody()?['id']}",
     "incident_type": "Malware Detected",
     "severity": "@{triggerBody()?['severity']}",
     "source_ip": "N/A",
     "hostname": "@{triggerBody()?['computerDnsName']}",
     "user": "@{triggerBody()?['relatedUser']?['userName']}",
     "description": "@{triggerBody()?['title']}",
     "file_hash": "@{triggerBody()?['evidence']?[0]?['sha256']}",
     "failed_login_count": 0,
     "sender_email": "",
     "email_body": "",
     "email_subject": "N/A"
   }
   ```
5. **Save** and turn the flow **On**

**8c — Trigger a live W4 test using the EICAR test file**

The EICAR test file is an industry-standard, non-malicious string that all antivirus vendors recognise as a safe test substitute for real malware.

```powershell
# Download the EICAR test file to your enrolled Defender endpoint
# This is NOT real malware — it safely triggers a genuine Defender detection
Invoke-WebRequest -Uri "https://www.eicar.org/download/eicar_com.zip" `
  -OutFile "$env:TEMP\eicar_test.zip"
```

Defender for Business detects it within approximately one minute. Power Automate fires automatically, the alert arrives at your n8n webhook, and a TKT row with `workflow_branch: W4-MalwareHash` appears in Google Sheets with the VT file hash verdict.

---

### Step 9 — Enable the Graph Sign-in Monitor (live W2 brute-force detection)

The Graph Monitor is a second workflow embedded in the same JSON file. It runs on a 2-minute schedule, polls Microsoft Graph for failed sign-in patterns, and self-posts `Brute Force Attempt` alerts to the Master IR webhook whenever it finds an IP with two or more failures in the last 10 minutes.

**9a — Verify Azure App permissions**

Your app from Step 8a needs `AuditLog.Read.All` and `Directory.Read.All` as Application permissions with admin consent granted. If you added them in 8a you are already set.

**9b — Configure the Graph Monitor nodes**

Open the `Get Graph Token2` node and set:
- URL: `https://login.microsoftonline.com/YOUR_ENTRA_TENANT_ID/oauth2/v2.0/token`
- Body params: `client_id` = your client ID, `client_secret` = your secret value, `grant_type` = `client_credentials`, `scope` = `https://graph.microsoft.com/.default`

Open the `Send to Master IR2` node and set:
- URL: `https://YOUR_NGROK_DOMAIN.ngrok-free.app/webhook/master-ir`

**9c — Activate the Graph Monitor workflow**

In n8n, open the Graph Monitor workflow (it is a separate workflow in the same import) and toggle it **Active**. It will poll immediately and then every 2 minutes.

**9d — Test with a simulated brute-force**

From a browser or separate device, attempt several failed logins to your Microsoft 365 tenant sign-in page with an incorrect password. Within 2–4 minutes the Graph Monitor detects the pattern and a `Brute Force Attempt` ticket appears in Google Sheets with the source IP, failure count, and AbuseIPDB/VT enrichment.

---

## Alert payload schema

Full schema accepted by `/webhook/master-ir`:

```json
{
  "alert_id": "string — unique alert identifier",
  "incident_type": "Phishing Attempt | Brute Force Attempt | Suspicious Outbound Traffic | Malware Detected | Execution | (any other value routes to W5)",
  "severity": "Critical | High | Medium | Low | Informational",
  "source_ip": "string — IPv4 address or N/A",
  "hostname": "string — affected machine name",
  "user": "string — affected user UPN or username",
  "description": "string — human-readable alert description",
  "file_hash": "string — SHA256 hash or N/A",
  "failed_login_count": "integer — number of failed logins (W2 brute-force threshold logic)",
  "sender_email": "string — full sender address for phishing alerts, or empty string",
  "email_body": "string — email body text, URL extracted automatically, or empty string",
  "email_subject": "string — email subject line or N/A"
}
```

---

## Google Sheets — Sheet1 column reference

| Column | Description |
|--------|-------------|
| `ticket_number` | Auto-incrementing TKT-XXXX, sourced from Sheet2!A1 counter |
| `alert_id` | Source alert identifier |
| `incident_type` | Alert classification |
| `severity` | Critical / High / Medium / Low / Informational |
| `source_ip` | Source IP address |
| `hostname` | Affected endpoint hostname |
| `user` | Affected user |
| `description` | Alert description |
| `timestamp` | Dublin timezone timestamp |
| `status` | Open / Closed |
| `vt_malicious_score` | Number of VT engines flagging as malicious |
| `vt_total_engines` | Total VT engines in the scan |
| `aipdb_confidence` | AbuseIPDB confidence score 0–100 |
| `aipdb_country` | Country code from AbuseIPDB |
| `verdict` | Malicious / Suspicious / Low Risk / Clean / Phishing Confirmed / Simulation - False Positive / Ticket Created |
| `file_hash` | SHA256 hash (W4 only) |
| `file_name` | File name from VT response (W4 only) |
| `file_type` | File type from VT response (W4 only) |
| `failed_login_count` | Failed login count (W2 only) |
| `recommendation` | e.g. Block IP immediately / Quarantine file / Delete email |
| `sender_domain` | Sender email domain (W1 only) |
| `extracted_url` | URL extracted from email body (W1 only) |
| `url_verdict` | VT URL verdict (W1 only) |
| `sender_email` | Full sender email address (W1 only) |
| `email_subject` | Email subject line (W1 only) |
| `workflow_branch` | W1-Phishing / W2-BruteForce / W3-IPReputation / W4-MalwareHash / W5-TicketCreation |

---

## Known implementation constraints

- **AbuseIPDB must be called sequentially after VirusTotal** — parallel execution causes a Merge node failure in n8n v2.1.4 where the second branch registers as not executed
- **Switch node not used** — n8n v2.1.4 Switch node v3 has an expression evaluation bug causing incorrect branch routing; cascading IF nodes are the reliable alternative
- **Counter uses HTTP Request nodes, not Code nodes** — n8n v2.1.4 task runner mode blocks `$helpers` and `$http` inside Code nodes; authenticated HTTP calls require dedicated HTTP Request nodes with the predefined Google Sheets OAuth2 credential
- **ngrok is for local development only** — production deployments should use a cloud-hosted n8n instance or a static public domain instead of a tunnel

---

## Licence

MIT — free to use, adapt, and republish with attribution.
