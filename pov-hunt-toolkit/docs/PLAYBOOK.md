# POV Hunt Playbook

> Which hunts to run at which stage of a POV, what to expect, and how to turn results into conversation.

---

## Overview

The POV Hunt Toolkit runs in three phases across a typical 2–4 week POV:

| Phase | When | Profile | Goal |
|-------|------|---------|------|
| **Day 1** | First hands-on session | `quick` | Immediate win — show something live |
| **Week 1** | After initial ingestion period | `standard` | Structured findings for the debrief |
| **Ongoing** | Weekly until POV close | `deep` | Depth findings, rule-to-result mapping |

---

## Day 1: The Fast Win

**Goal:** Leave the first session with at least one confirmed finding the customer did not know about.

**Profile:** `quick` (graymail only, 2–3 min)

**Command:**

```bash
python3 run_pov_hunts.py \
  --api-key KEY \
  --base-url URL \
  --profile quick \
  --lookback 30 \
  --label "Customer Name" \
  --output day1_quick.md
```

**What to do with the results:**

Graymail always returns results. The story is not "here are threats" — it's "here is everything your gateway passed through that your users did not ask for."

Walk the customer through two or three examples from the platform hunt view. Pick the most recognisable brands (LinkedIn, Salesforce, HubSpot partners). Ask: "Were your users expecting this?" The answer is almost always no.

**Conversation starter:**

> "This is 30 days of inbound mail that made it through your existing controls. Every one of these matched a pattern for unsolicited bulk outreach. The gateway passed them because the sending infrastructure is legitimate — the issue is the content and context, not the IP reputation. This is what behavioural detection catches."

**Expected ranges:**

| Result | Response |
|--------|----------|
| < 200 messages | Normal for a clean, smaller environment. Extend to 60 days. |
| 200–5,000 | Standard finding. Show a cross-section of sender types. |
| > 5,000 | Strong. Lead with the scale. "In 30 days, 5,000+ messages arrived that your gateway had no opinion on." |

---

## Week 1: The Structured Debrief

**Goal:** A full findings report ready for the first formal debrief call.

**Profile:** `standard` (graymail + vendor-and-trust, 5–8 min)

**Command:**

```bash
python3 run_pov_hunts.py \
  --api-key KEY \
  --base-url URL \
  --profile standard \
  --lookback 30 \
  --label "Customer Name" \
  --output week1_standard.md
```

**Run this the night before the debrief.** Review the output before the call. For every vendor-and-trust result:

1. Open the hunt URL in the platform
2. Read 3–5 message bodies
3. Classify as: genuine threat, borderline, or FP
4. Note which senders/domains are the most convincing impersonators

**What to highlight in the debrief:**

Vendor impersonation results land best. Pick the one or two examples where the sender looks most like a legitimate vendor — DocuSign lures, invoice notifications from lookalike domains, branded phishing using Mailchimp infrastructure. These are the findings that make security teams say "we would have trusted that."

**Conversation starters by category:**

**Graymail:**
> "Across 30 days we found [N] messages matching unsolicited outreach patterns. That's a productivity and noise story — your team is processing mail they didn't ask for. The interesting number is the group count: [N] distinct sender campaigns. Each one of those is a different organisation that acquired your employees' contact details."

**Vendor & Trust:**
> "These [N] messages all used legitimate sending infrastructure — SendGrid, Mailchimp, or direct sends from domains that look like your vendors. Reputation-based controls scored these as clean. Sublime caught them because of the structural signals: lookalike domain patterns, missing SPF/DKIM alignment, or content patterns that match known impersonation campaigns."

**Expected ranges — vendor-and-trust:**

| Result | Interpretation | Response |
|--------|---------------|----------|
| 0 | Clean, or short lookback | Try 60 days; discuss live detection rules |
| 1–15 | Standard — solid demo material | Walk through each one manually |
| 16–50 | Strong | Sample 10, identify top 3 for the debrief |
| > 50 | High | Categorise by sender type before presenting — likely a mix of genuine threats and borderline |

---

## Ongoing: Weekly Depth Hunts

**Goal:** Continuous coverage across all categories to build the full picture for the final POV share-out.

**Profile:** `deep` (all four categories, 10–20 min)

**Command:**

```bash
python3 run_pov_hunts.py \
  --api-key KEY \
  --base-url URL \
  --profile deep \
  --lookback 60 \
  --label "Customer Name" \
  --output week2_deep_$(date +%Y%m%d).md
```

Run this **before each weekly check-in**, not during it. Review the results in advance and select the 2–3 most compelling findings for the call.

**What changes over time:**

As Sublime ingests more mail, hunt results stabilise. The first 72 hours of ingestion can be noisy or sparse depending on mail volume. By week 2, you have a representative sample.

Look for **new patterns** in each weekly run that weren't present the week before. New campaigns, new sender infrastructure, new impersonation targets. These are your "look what we found this week" moments.

**Managing social-engineering and service-abuse results:**

These categories require more triage than graymail or vendor-and-trust. Before presenting:

- Open every result with > 0 messages
- Confirm at least 2 genuine TPs per hunt before citing the count
- Never present a service-abuse count without being able to explain the specific technique (e.g. "these are Google Drive share notifications with malicious payload links — the notification itself is authentic, the linked document isn't")

**Conversation starters by category:**

**Social Engineering:**
> "These [N] messages matched social engineering patterns — urgency signals, impersonation of internal roles like CFO or IT, or reward/gift request structures. Your gateway passed them because the content looks like normal email. The detection is entirely behavioural."

**Service Abuse:**
> "Every message in this group came from a trusted sending domain — Google, Dropbox, Calendly. They'd pass any reputation check. The payload — the malicious content or link — is one hop removed. This is the technique that makes legacy gateways blind: attack the target through infrastructure the gateway trusts."

---

## Hunt-to-Rule Pipeline

For each category, the natural POV progression is:

1. **Hunt** — find the signal in historical mail
2. **Show** — walk through examples in the platform UI
3. **Enable** — deploy the matching detection rule (detection-only first)
4. **Confirm** — check rule results after 1 week, validate TP rate
5. **Enforce** — enable quarantine or label actions if TP rate is acceptable

| Category | Typical rule deployment |
|----------|------------------------|
| Graymail | Standard graymail rules — enable on day 1 or 2 |
| Vendor & Trust | Impersonation rules from community feed — enable after hunt confirms presence |
| Social Engineering | Role impersonation + urgency rules — enable after manual TP validation |
| Service Abuse | Service-specific rules (Drive, Dropbox, Calendly) — enable per finding |

---

## Do Not Say

Things to avoid based on common missteps:

- **"We found X threats"** — Hunt results are candidates, not confirmed threats. Say "matched patterns" or "flagged for review."
- **Presenting Tier 2 / high-FP hunt counts without reading the messages first** — This undermines trust immediately.
- **Running `deep` profile live in a customer session** — It takes too long and the social-engineering category needs pre-triage.
- **Sharing the raw markdown report as a deliverable** — The report is a working document. Convert findings into a proper customer-facing summary (use the canvas report format).

---

## Quick Reference: Conversation Hooks by Stage

| Stage | Best opening line |
|-------|------------------|
| Day 1 — graymail results | "Here's what arrived in your inbox in the last 30 days that your gateway had no opinion on." |
| Week 1 — vendor impersonation | "These emails came from legitimate infrastructure. They passed every reputation check. Here's why Sublime flagged them anyway." |
| Week 2 — social engineering | "This is one message. Read the subject line. Would you have clicked it?" |
| Week 2 — service abuse | "Every one of these notifications came from a Google or Dropbox IP. The attack is in the payload, one click away." |
| Final debrief | "In [N] weeks, we found [N] hunt categories with results, [N] confirmed threat patterns, and [N] rules now live in detection mode. Here's what that means for ongoing coverage." |
