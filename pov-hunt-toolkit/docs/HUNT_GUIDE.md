# Hunt Guide

> How to run, interpret, and iterate on POV hunt results.

---

## Running a Hunt Session

### Before the session

1. **Confirm your API key and base URL.** Test with `--dry-run` before the customer session.

   ```bash
   python3 run_pov_hunts.py \
     --api-key YOUR_KEY \
     --base-url https://platform.sublime.security \
     --dry-run
   ```

   If all hunts pass validation, you're ready. If any fail, check the YAML syntax and MQL source in the flagged file.

2. **Choose the right profile.** In a live session, use `quick` or `standard`. Never run `deep` live — it takes too long and the extra categories need triage before presenting.

3. **Set the lookback window.** 30 days is standard. If the customer asks "have we seen anything historically?", re-run with `--lookback 60` after the session.

### During the session

Run the standard profile and share your screen:

```bash
python3 run_pov_hunts.py \
  --api-key YOUR_KEY \
  --base-url URL \
  --profile standard \
  --label "Customer Name" \
  --output customer_name_$(date +%Y%m%d).md
```

The progress bar gives the customer something to watch. Point out that each line is a different threat scenario being checked in real time.

### After the session

Open the saved report and review all hits before sharing it with the customer. Annotate or trim entries you want to discuss further.

---

## Interpreting Results

### The two numbers that matter

Each hunt returns two counts:

- **Messages** — total emails matching the hunt scenario in the lookback window
- **Groups** — distinct sender clusters or campaign groupings

**High messages, low groups** = a single campaign or sender hitting the environment repeatedly. This is volume from one source.

**High messages, high groups** = broad exposure across many senders. This is a category-level problem, not an isolated incident.

**Low messages, low groups** = targeted or sporadic. Low numbers in social-engineering categories are still significant — a single vishing bait email to the CFO is meaningful.

### What counts as interesting

#### Graymail

| Messages (30 days) | Interpretation |
|-------------------|----------------|
| < 500 | Low. Either the environment has good existing filtering, or the hunts don't cover the specific patterns present. |
| 500–5,000 | Normal. Expected for most mid-size organisations. Demonstrates coverage. |
| 5,000–50,000 | High volume. Good POV material — show the scale and contrast with what the gateway blocked. |
| > 50,000 | Very high. Lead with this as a noise/productivity story. |

#### Vendor & Trust Chain

| Messages (30 days) | Interpretation |
|-------------------|----------------|
| 0 | Either clean, or the lookback is too short. Try 60 days. |
| 1–20 | Solid findings. Review each one manually. These are your demo examples. |
| 21–100 | Strong signal. Sample 10+ before presenting. |
| > 100 | Investigate composition before presenting — could be a single campaign or genuine breadth. |

#### Social Engineering

| Messages (30 days) | Interpretation |
|-------------------|----------------|
| 0 | Possibly clean, but also possibly the hardest category to hunt retroactively. Discuss live detection (rules) instead. |
| 1–10 | High value. Each hit warrants individual review. |
| > 10 | Unusual. Validate that these are genuine before presenting counts. |

#### Service Abuse

| Messages (30 days) | Interpretation |
|-------------------|----------------|
| 0–5 | Low but potentially significant — service abuse is targeted. |
| 6–50 | Normal. Show examples, explain the infrastructure abuse angle. |
| > 50 | Good breadth story. Emphasise that these come from trusted IPs and would bypass reputation controls. |

### The most important thing you can do with hunt results

**Read message bodies, not metadata.** The count tells you where to look. The actual content tells you if it's real.

Before presenting any result to a customer:
1. Click through to the hunt link in the platform
2. Open the 3 most recent results
3. Read the subject, sender, and body
4. Decide: is this clearly malicious/unwanted, ambiguous, or a clear FP?

Only present results you've read. A count you haven't verified is a liability.

---

## Iterating on Hunt Results

### Hunt came back empty

1. Extend the lookback window: `--lookback 60` or `--lookback 90`
2. Check if the hunt YAML source is scoped correctly (private vs public, inbound vs any)
3. Open the hunt URL directly in the platform and try adjusting the date range manually
4. Consider whether this category is genuinely absent from the environment — that's also worth noting to the customer

### Hunt returned too many results to triage

1. Sample the first 10–20 results manually
2. Identify the dominant pattern (one sender, one campaign, one domain structure)
3. Present the pattern, not the count — "we found a recurring pattern of X" lands better than "we found 847 matches"
4. For graymail, high counts are the story — don't try to triage them all

### Hunt found something genuinely alarming

1. Do not immediately escalate in front of the customer
2. Note the hunt ID and message count
3. After the session: open the messages, assess whether it's an active threat or historical
4. Loop in the relevant contact (SOC lead, CISO) separately before the next call
5. The platform link in the report is the artifact to share internally

---

## From Hunt Results to a Recommended Rule

Every hunt that returns results should end with a suggested rule. The workflow:

1. **Identify the pattern** — what is the structural signal that makes these messages stand out? (domain mismatch, specific header, NLU topic, attachment type)

2. **Find the closest existing rule** in the Sublime community feed or rule library that matches the pattern. This is almost always the faster path.

3. **If no existing rule exists**, write one using the hunt MQL as a starting point. Hunt MQL is already structured as a detection — it usually needs:
   - Adding `type.inbound` if not already scoped
   - Adding `not profile.by_sender().solicited` if appropriate
   - Tightening the signal to reduce FP risk before enabling actions

4. **Deploy as detection-only first.** Share results in the next weekly report, validate TP rate, then enable enforcement actions after 2 weeks.

5. **Name the rule** to match the hunt name — this makes it easy to track back to the original discovery session.

### Example: graymail hunt → rule

Hunt finds 4,200 messages matching cold B2B outreach patterns over 30 days.

- Find the two standard graymail rules (Baseline Graymail Protection + Advanced Graymail Detection) in the workspace rules context
- Enable both as detection-only
- Show the customer the rule in the UI and the projected detection volume
- Revisit after one week to confirm the TP rate and discuss enabling suppression actions

---

## Adding New Hunts

See [README.md](../README.md#adding-custom-hunts) for the minimum YAML schema.

When writing a new hunt:
- Start with the broadest version and test it on a real environment
- Count the results and estimate the FP rate from a manual sample
- Tighten the MQL until the FP rate is acceptable for the `fp_risk` field you plan to set
- Add a `suggested_next_steps` field that tells the operator what to do if this hunt returns results
- Set `profile: quick` only if the hunt is reliable enough to run live without pre-validation
