# POV Hunt Toolkit

> Scenario-based inbound threat intelligence hunts for Sublime Security POVs — run in a live customer session and walk out with confirmed detections.

Most email security tools tell you what they blocked. Sublime lets you ask questions. The POV Hunt Toolkit is a library of pre-built hunt scenarios organised by threat category — service abuse, social engineering, graymail, and vendor/trust chain attacks. Each hunt is a structured MQL query you can run against any customer environment in under five minutes.

This toolkit is designed for use during the hands-on phase of a POV. The hunts find things that exist in the inbox right now, name them precisely, and give you a natural transition to "here is the rule that catches this going forward."

---

## Quick Start

Three commands to get results:

```bash
# 1. Clone / enter the toolkit
cd se-scripts/pov-hunt-toolkit

# 2. Run the standard profile (graymail + vendor-and-trust, 30-day lookback)
python3 run_pov_hunts.py \
  --api-key YOUR_API_KEY \
  --base-url https://platform.sublime.security \
  --label "Acme Corp" \
  --output acme_pov_hunts.md

# 3. Open the report
open acme_pov_hunts.md
```

To run all categories (deep sweep):

```bash
python3 run_pov_hunts.py \
  --api-key YOUR_API_KEY \
  --base-url https://platform.sublime.security \
  --profile deep \
  --lookback 60 \
  --label "HSBC" \
  --output hsbc_deep_hunt.md
```

To run a specific category only:

```bash
python3 run_pov_hunts.py \
  --api-key YOUR_API_KEY \
  --base-url https://platform.sublime.security \
  --category social-engineering \
  --label "ITV" \
  --output itv_social_eng.md
```

---

## Hunt Categories

### `graymail/`

Unsolicited bulk mail that users did not explicitly request — B2B cold outreach, marketing automation, webinar invites, LinkedIn noise. High volume in nearly every environment. Used in the quick profile because it always produces results and demonstrates detection capability immediately.

**What to expect:** Hundreds to tens of thousands of messages in 30 days. Use to show the scale of unwanted mail the existing gateway is passing through.

### `vendor-and-trust/`

Abuse of trusted relationships and vendor impersonation — DocuSign lures, invoice fraud, brand impersonation using legitimate infrastructure (SendGrid, Mailchimp), lookalike domains from known vendors. These find real threats that bypass reputation-based controls.

**What to expect:** 5–100 results in 30 days. Even a small number of vendor impersonation hits is a strong POV conversation starter.

### `social-engineering/`

Targeted manipulation techniques — urgent CEO/CFO impersonation, gift card request chains, vishing bait (call me back), thread hijacking, malicious OAuth consent flows, fake invoice approvals. These are the threats that land in executives' inboxes.

**What to expect:** Lower volume, higher severity. 2–20 results per hunt is normal and significant.

### `service-abuse/`

Legitimate service abuse — adversarial use of file sharing (Dropbox, Google Drive, OneDrive), notification abuse (Calendly, Docusign, Zoom invite), free email-to-SMS gateways used to bypass reputation, QR code payloads, and multi-stage redirect chains. These all look clean to a gateway because the sending infrastructure is legitimate.

**What to expect:** Medium volume. Results here are usually high signal — this infrastructure is not in blocklists.

---

## Profiles

| Profile | Categories | Typical Runtime | When to use |
|---------|------------|----------------|-------------|
| `quick` | graymail only | 2–3 min | Day 1 of HIP, need a fast win |
| `standard` | graymail + vendor-and-trust | 5–8 min | Default for all standard POVs |
| `deep` | all four categories | 10–20 min | Scheduled run, not live demo |
| `all` | all four categories | 10–20 min | Alias for deep |

Run `--profile quick` in a live session. Run `--profile deep` overnight or before a debrief.

---

## Private vs Public Hunts

**Private (default):** Hunt jobs are visible only to your API key / session. Use this for all customer work. The platform shows results in the hunt UI, but the hunt does not appear in community feeds or the shared hunt library.

**Public:** Hunt is visible to all org admins and may be indexed in the platform's community hunt library. Never run public without customer consent.

```bash
# Default: private
python3 run_pov_hunts.py --api-key KEY --base-url URL

# Explicit private
python3 run_pov_hunts.py --api-key KEY --base-url URL --private

# Public (with customer permission)
python3 run_pov_hunts.py --api-key KEY --base-url URL --public
```

---

## Interpreting Results

The report shows, per hunt:

| Field | What it means |
|-------|--------------|
| **Messages** | Total messages matching the hunt in the lookback window |
| **Groups** | Distinct sender/campaign clusters. High group count = breadth; low group count + high messages = volume from a single campaign. |
| **Hunt ID** | Direct link to review matched messages in the platform UI |
| **Suggested next steps** | Context-specific action — review messages, enable a rule, or both |

**Quick interpretation guide:**

- **0 results** — Hunt found nothing. Either the environment is genuinely clean for this scenario, or the lookback window is too short. Try extending to 60 days before concluding the threat isn't present.
- **1–10 results** — Worth reviewing manually. Open each message in the platform UI. These are your best candidates for a live demo — specific, easy to explain, hard to dismiss.
- **11–100 results** — Healthy signal. Sample 5–10 manually before presenting counts to the customer.
- **100+ results** — High volume. Understand the composition first. In graymail this is expected and fine. In social-engineering categories, 100+ results warrants immediate investigation before presenting.

See [docs/HUNT_GUIDE.md](docs/HUNT_GUIDE.md) for the full interpretation guide.

---

## Adding Custom Hunts

Hunt files are YAML. Drop a new file into the appropriate category directory and it will be picked up automatically on the next run.

**Minimum required fields:**

```yaml
name: "Descriptive hunt name"
description: |
  What this hunt looks for and why it matters.
  Include at least one real-world example if you have one.
category: graymail         # graymail | vendor-and-trust | social-engineering | service-abuse
profile: standard          # quick | standard | deep — minimum profile to include in
fp_risk: low               # low | medium | high
expected_volume: low       # low | medium | high
source: |
  type.inbound
  and <your MQL here>
suggested_next_steps: |
  What to do if this hunt returns results.
```

**Validation:**

```bash
python3 run_pov_hunts.py --api-key KEY --base-url URL --dry-run
```

Dry-run validates all hunt YAML and MQL syntax without submitting any jobs. Run this before a customer session.

---

## Directory Structure

```
pov-hunt-toolkit/
├── README.md                         # This file
├── run_pov_hunts.py                  # Main runner (CLI entry point)
├── config.example.yaml               # Config template
│
├── hunts/
│   ├── graymail/                     # Unsolicited bulk / cold outreach
│   ├── vendor-and-trust/             # Vendor impersonation, invoice fraud
│   ├── social-engineering/           # CEO fraud, gift cards, vishing bait
│   └── service-abuse/                # Legitimate service abuse (Dropbox, GDrive, QR)
│
└── docs/
    ├── HUNT_GUIDE.md                 # Full interpretation + iteration guide
    └── PLAYBOOK.md                   # Which hunts at which POV stage
```

---

## CLI Reference

```
python3 run_pov_hunts.py [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--api-key KEY` | required | Sublime Security API key |
| `--base-url URL` | required | Tenant base URL (e.g. `https://platform.sublime.security`) |
| `--profile NAME` | `standard` | Hunt profile: quick \| standard \| deep \| all |
| `--category NAME` | (all in profile) | Run one category only |
| `--lookback N` | `30` | Lookback window in days |
| `--private` | default | Run hunts as private |
| `--public` | off | Run hunts as public (use with caution) |
| `--label "Org Name"` | (none) | Label for the report header |
| `--output FILE` | stdout | Write markdown report to FILE |
| `--dry-run` | off | Validate MQL syntax only, do not submit jobs |
| `--quiet` | off | Suppress progress output |

---

## Further Reading

- [docs/HUNT_GUIDE.md](docs/HUNT_GUIDE.md) — how to run, interpret, and iterate on hunt results
- [docs/PLAYBOOK.md](docs/PLAYBOOK.md) — which hunts to run at each stage of a POV, with expected ranges and conversation starters

---

*Built for Sublime Security SE team field use. For questions, contact William Mireles.*
