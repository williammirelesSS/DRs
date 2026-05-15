#!/usr/bin/env python3
"""
run_pov_hunts.py
─────────────────────────────────────────────────────────────────────────────
POV Hunt Toolkit — Hunt Runner
Executes scenario-based inbound threat intelligence hunts for Sublime Security POVs.

Usage:
    python3 run_pov_hunts.py --api-key KEY --base-url https://platform.sublime.security
    python3 run_pov_hunts.py --api-key KEY --base-url URL --profile deep --lookback 60
    python3 run_pov_hunts.py --api-key KEY --base-url URL --category social-engineering
    python3 run_pov_hunts.py --api-key KEY --base-url URL --label "Acme Corp" --output report.md
    python3 run_pov_hunts.py --api-key KEY --base-url URL --dry-run

Profiles:
    quick     — graymail only (2–3 min, safe for live demos)
    standard  — graymail + vendor-and-trust (default, 5–8 min)
    deep/all  — all four categories (10–20 min)
"""

import sys
import os
import subprocess


def _bootstrap():
    venv = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv")
    py   = os.path.join(venv, "bin", "python3")
    if not os.path.exists(py):
        print("Setting up virtual environment...")
        subprocess.check_call(
            [sys.executable, "-m", "venv", venv],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    in_venv = (
        hasattr(sys, "real_prefix")
        or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
        or bool(os.environ.get("VIRTUAL_ENV"))
    )
    if not in_venv:
        os.execv(py, [py] + sys.argv)


_bootstrap()

for _pkg in ("requests", "pyyaml"):
    try:
        __import__(_pkg.replace("-", "_").split(".")[0])
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", _pkg, "-q"])

import requests
import yaml
import time
import argparse
import json
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path


# ─────────────────────────────── ANSI Colors ─────────────────────────────────

RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def red(s):    return f"{RED}{s}{RESET}"
def green(s):  return f"{GREEN}{s}{RESET}"
def yellow(s): return f"{YELLOW}{s}{RESET}"
def cyan(s):   return f"{CYAN}{s}{RESET}"
def bold(s):   return f"{BOLD}{s}{RESET}"
def dim(s):    return f"{DIM}{s}{RESET}"


# ──────────────────────────────── Profile Map ─────────────────────────────────

# Maps profile name → list of categories to include
PROFILE_CATEGORIES = {
    "quick":    ["graymail"],
    "standard": ["graymail", "vendor-and-trust"],
    "deep":     ["graymail", "vendor-and-trust", "social-engineering", "service-abuse"],
    "all":      ["graymail", "vendor-and-trust", "social-engineering", "service-abuse"],
}

ALL_CATEGORIES = ["graymail", "vendor-and-trust", "social-engineering", "service-abuse"]

CATEGORY_LABEL = {
    "graymail":            "Graymail",
    "vendor-and-trust":    "Vendor & Trust Chain",
    "social-engineering":  "Social Engineering",
    "service-abuse":       "Service Abuse",
}

# Hunt fields that suggest which minimum profile a hunt belongs to
PROFILE_ORDER = ["quick", "standard", "deep", "all"]


# ─────────────────────────────── Progress Bar ────────────────────────────────

class ProgressBar:
    """
    Simple terminal progress bar.

    Usage:
        bar = ProgressBar(total=10, label="Running hunts")
        bar.start()
        for _ in range(10):
            bar.advance()
        bar.done()
    """

    def __init__(self, total: int, label: str = "", width: int = 40, quiet: bool = False):
        self.total   = max(total, 1)
        self.current = 0
        self.label   = label
        self.width   = width
        self.quiet   = quiet

    def _render(self):
        pct   = self.current / self.total
        filled = int(self.width * pct)
        bar   = "█" * filled + "░" * (self.width - filled)
        pct_s = f"{int(pct * 100):3d}%"
        return f"\r  {self.label}  [{bar}]  {pct_s}  {self.current}/{self.total}"

    def start(self):
        if not self.quiet:
            print(self._render(), end="", flush=True)

    def advance(self, label: str = ""):
        self.current += 1
        if label:
            self.label = label
        if not self.quiet:
            print(self._render(), end="", flush=True)

    def done(self):
        if not self.quiet:
            print()  # newline after bar


# ─────────────────────────────── Spinner ─────────────────────────────────────

class Spinner:
    """Dot-based progress indicator that runs on a background thread."""

    def __init__(self, msg: str, quiet: bool = False):
        self.msg    = msg
        self.quiet  = quiet
        self._stop  = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        if self.quiet:
            return
        print(f"\n{self.msg}", end="", flush=True)
        while not self._stop.wait(timeout=1.5):
            print(".", end="", flush=True)

    def start(self):
        self._thread.start()

    def stop(self, suffix=" done."):
        self._stop.set()
        self._thread.join()
        if not self.quiet:
            print(suffix)


# ──────────────────────────────── Hunt Runner ────────────────────────────────

class POVHuntRunner:
    """
    Loads hunt YAML files, submits jobs to the Sublime hunt API,
    polls for results, and writes a markdown report.
    """

    POLL_INTERVAL_S   = 3     # seconds between status polls
    MAX_POLL_ATTEMPTS = 120   # give up after ~6 minutes per job
    SUBMIT_CONCURRENCY = 5    # how many jobs to submit before starting to poll

    def __init__(self, api_key: str, base_url: str, private: bool = True, quiet: bool = False):
        self.base    = base_url.rstrip("/")
        self.private = private
        self.quiet   = quiet
        self.s       = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        })

    # ── Hunt loading ──────────────────────────────────────────────────────────

    def load_hunts(
        self,
        toolkit_dir: Path,
        profile: str = "standard",
        category_override: str = None,
    ) -> list:
        """
        Load hunt YAMLs from hunts/<category>/*.yml.

        If category_override is set, load only that category.
        Otherwise load all categories defined by the profile.
        """
        if category_override:
            categories = [category_override]
        else:
            categories = PROFILE_CATEGORIES.get(profile, PROFILE_CATEGORIES["standard"])

        hunts_dir = toolkit_dir / "hunts"
        hunts     = []

        for cat in categories:
            cat_dir = hunts_dir / cat
            if not cat_dir.exists():
                if not self.quiet:
                    print(yellow(f"  ⚠  Category directory not found: {cat_dir}"))
                continue

            cat_files = sorted(cat_dir.glob("*.yml"))
            if not cat_files:
                if not self.quiet:
                    print(dim(f"  ·  No hunt files in {cat}/ (add .yml files to populate)"))
                continue

            for f in cat_files:
                try:
                    hunt = yaml.safe_load(f.read_text())
                    if not hunt:
                        continue
                    missing = [k for k in ("name", "source") if k not in hunt]
                    if missing:
                        print(yellow(f"  ⚠  Skipping {f.name}: missing fields {missing}"))
                        continue
                    hunt["_file"]     = f.name
                    hunt["_path"]     = str(f)
                    hunt["_category"] = cat
                    hunts.append(hunt)
                except yaml.YAMLError as e:
                    print(red(f"  ✗  YAML parse error in {f.name}: {e}"))

        return hunts

    # ── Dry-run: MQL validation ───────────────────────────────────────────────

    def validate_mql(self, hunt: dict) -> tuple:
        """Call POST /v1/rules/format to syntax-check hunt source. Returns (ok, error_msg)."""
        try:
            r = self.s.post(
                f"{self.base}/v1/rules/format",
                json={"source": hunt["source"].strip()},
                timeout=15,
            )
            if r.status_code == 200:
                return True, ""
            data = r.json()
            err  = data.get("error", {})
            msg  = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            return False, msg
        except Exception as e:
            return False, str(e)

    def run_dry(
        self,
        toolkit_dir: Path,
        profile: str = "standard",
        category_override: str = None,
    ):
        """Validate all hunt MQL syntax without submitting any jobs."""
        hunts = self.load_hunts(toolkit_dir, profile, category_override)
        if not hunts:
            print(yellow("  No hunts matched your filters. Check the hunts/ directory."))
            return

        print(f"\n{bold('DRY RUN — MQL Syntax Validation')}")
        print(f"{'─' * 70}")
        print(f"  Platform   : {cyan(self.base)}")
        print(f"  Profile    : {profile}")
        print(f"  Validating : {len(hunts)} hunt(s)\n")

        ok_count = err_count = 0
        for hunt in hunts:
            ok, err = self.validate_mql(hunt)
            cat     = hunt.get("_category", "?")
            label   = f"[{CATEGORY_LABEL.get(cat, cat)}] {hunt['name']}"
            if ok:
                ok_count += 1
                print(f"  {green('✓')}  {label}")
            else:
                err_count += 1
                print(f"  {red('✗')}  {label}")
                print(f"       {red(err)}")
            time.sleep(0.1)

        print(f"\n{'─' * 70}")
        if err_count == 0:
            print(f"  {green(f'All {ok_count} hunt(s) passed validation.')}")
        else:
            print(f"  {green(f'{ok_count} passed')}, {red(f'{err_count} failed')}")
        print()

    # ── Hunt submission ───────────────────────────────────────────────────────

    def submit_hunt(self, hunt: dict, start: str, end: str) -> str:
        """
        Submit a hunt job via POST /v1/hunt-jobs.
        Returns:
          - hunt_job_id (str)         on success
          - 'MQL_ERROR:<msg>'         on 400 / 422
          - 'CONFLICT'                on 409 with no recoverable job_id
        """
        try:
            r = self.s.post(
                f"{self.base}/v1/hunt-jobs",
                json={
                    "source":           hunt["source"].strip(),
                    "range_start_time": start,
                    "range_end_time":   end,
                    "private":          self.private,
                    "name":             hunt["name"],
                },
                timeout=30,
            )
            if r.status_code in (400, 422):
                err_obj = r.json().get("error", {})
                msg = (
                    err_obj.get("message", str(err_obj))
                    if isinstance(err_obj, dict)
                    else str(err_obj)
                )
                return f"MQL_ERROR:{msg[:180]}"
            if r.status_code == 409:
                try:
                    existing = r.json().get("hunt_job_id", "")
                    if existing:
                        return existing
                except Exception:
                    pass
                return "CONFLICT"
            r.raise_for_status()
            return r.json().get("hunt_job_id", "")
        except requests.RequestException as e:
            return f"MQL_ERROR:HTTP error — {e}"

    # ── Polling ───────────────────────────────────────────────────────────────

    def poll_once(self, job_id: str) -> str:
        """Single poll. Returns 'COMPLETED', 'PENDING', or a terminal error state."""
        try:
            r = self.s.get(f"{self.base}/v1/hunt-jobs/{job_id}", timeout=15)
            r.raise_for_status()
            stat = r.json().get("status", "").upper()
            if stat == "COMPLETED":
                return "COMPLETED"
            if stat in ("FAILED", "ERROR", "CANCELLED"):
                return stat
            return "PENDING"
        except requests.RequestException as e:
            return f"HTTP_ERROR:{e}"

    # ── Results fetching ──────────────────────────────────────────────────────

    def get_results(self, job_id: str) -> dict:
        """
        Fetch completed hunt job results.
        Returns dict with keys: groups, messages, raw.
        """
        try:
            r = self.s.get(f"{self.base}/v1/hunt-jobs/{job_id}", timeout=30)
            r.raise_for_status()
            data = r.json()
            return {
                "groups":   data.get("group_count", data.get("groups", 0)),
                "messages": data.get("message_count", data.get("messages", 0)),
                "raw":      data,
            }
        except Exception as e:
            return {"groups": 0, "messages": 0, "raw": {}, "error": str(e)}

    # ── Main run ──────────────────────────────────────────────────────────────

    def run_all(
        self,
        days: int = 30,
        profile: str = "standard",
        category_override: str = None,
        label: str = "",
        output_file: str = None,
    ) -> list:
        """
        Full hunt run: load → submit → poll → report.
        Returns list of job result dicts.
        """
        toolkit_dir = Path(__file__).parent
        hunts       = self.load_hunts(toolkit_dir, profile, category_override)

        if not hunts:
            print(yellow(
                "  No hunts found. The hunts/ directory may be empty.\n"
                "  Add .yml hunt files or check the --profile / --category flags."
            ))
            return []

        end   = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso   = end.strftime("%Y-%m-%dT%H:%M:%SZ")

        # ── Header ──
        org_label = f" — {label}" if label else ""
        print()
        print(f"{bold('═' * 70)}")
        print(f"  {bold('POV Hunt Toolkit')}{org_label}")
        print(f"{'═' * 70}")
        print(f"  Platform  : {cyan(self.base)}")
        print(f"  Profile   : {bold(profile)}")
        print(f"  Lookback  : {days} days  ({start.date()} → {end.date()})")
        print(f"  Visibility: {'private' if self.private else bold(yellow('PUBLIC'))}")
        print(f"  Hunts     : {len(hunts)}")
        print(f"{'─' * 70}\n")

        # ── Submit all jobs ──
        jobs = []
        bar  = ProgressBar(
            total = len(hunts),
            label = "Submitting",
            quiet = self.quiet,
        )
        bar.start()

        for hunt in hunts:
            job_id = self.submit_hunt(hunt, start_iso, end_iso)
            jobs.append({
                "hunt":   hunt,
                "job_id": job_id if not job_id.startswith("MQL_ERROR") and job_id != "CONFLICT" else None,
                "status": "error" if job_id.startswith("MQL_ERROR") else (
                    "conflict" if job_id == "CONFLICT" else "pending"
                ),
                "error":    job_id if job_id.startswith("MQL_ERROR") else "",
                "groups":   0,
                "messages": 0,
            })
            bar.advance(label=f"Submitting ({hunt['name'][:35]})")

        bar.done()

        # ── Poll for completion ──
        pending = [j for j in jobs if j["status"] == "pending"]
        if pending:
            bar2 = ProgressBar(
                total = len(pending),
                label = "Polling  ",
                quiet = self.quiet,
            )
            bar2.start()

            completed_count = 0
            attempts        = 0
            while pending and attempts < self.MAX_POLL_ATTEMPTS:
                still_pending = []
                for j in pending:
                    result = self.poll_once(j["job_id"])
                    if result == "COMPLETED":
                        data       = self.get_results(j["job_id"])
                        j["status"]   = "completed"
                        j["groups"]   = data.get("groups", 0)
                        j["messages"] = data.get("messages", 0)
                        completed_count += 1
                        bar2.advance(label=f"Polling   ({hunt['name'][:35]})")
                    elif result in ("FAILED", "ERROR", "CANCELLED") or result.startswith("HTTP_ERROR"):
                        j["status"] = "error"
                        j["error"]  = result
                        completed_count += 1
                        bar2.advance()
                    else:
                        still_pending.append(j)
                pending   = still_pending
                attempts += 1
                if pending:
                    time.sleep(self.POLL_INTERVAL_S)

            if pending:
                for j in pending:
                    j["status"] = "timeout"
                    j["error"]  = "Timed out waiting for completion"

            bar2.done()

        # ── Print results ──
        self._print_results(jobs)

        # ── Save report ──
        if output_file:
            self._save_report(jobs, output_file, days, start, end, label, profile)

        return jobs

    # ── Results printer ──────────────────────────────────────────────────────

    def _print_results(self, jobs: list):
        print(f"\n{bold('═' * 70)}")
        print(f"  {bold('RESULTS')}")
        print(f"{'═' * 70}\n")

        # Group by category, hits first
        categories_seen = []
        jobs_by_cat: dict = {}
        for j in jobs:
            cat = j["hunt"].get("_category", "unknown")
            if cat not in jobs_by_cat:
                jobs_by_cat[cat] = []
                categories_seen.append(cat)
            jobs_by_cat[cat].append(j)

        for cat in categories_seen:
            cat_jobs = jobs_by_cat[cat]
            hits     = [j for j in cat_jobs if j["messages"] > 0 and j["status"] == "completed"]
            clean    = [j for j in cat_jobs if j["messages"] == 0 and j["status"] == "completed"]
            errs     = [j for j in cat_jobs if j["status"] in ("error", "timeout", "conflict")]

            print(f"  {bold(CATEGORY_LABEL.get(cat, cat))}")
            print(f"  {'─' * 60}")

            for j in sorted(hits, key=lambda x: x["messages"], reverse=True):
                name = j["hunt"]["name"]
                msgs = j["messages"]
                grps = j["groups"]
                link = f"{self.base}/messages/hunt?huntId={j['job_id']}" if j["job_id"] else ""
                print(f"    {green('✅')}  {green(f'{msgs:5,} msg')}  {dim(f'{grps} group(s)')}  {name}")
                if link:
                    print(f"         {dim(link)}")
                steps = j["hunt"].get("suggested_next_steps", "").strip()
                if steps and msgs > 0:
                    first = steps.splitlines()[0]
                    print(f"         {cyan('→')} {dim(first)}")

            for j in clean:
                print(f"    {dim('◻')}   {dim('    0 msg')}   {dim(j['hunt']['name'])}")

            for j in errs:
                name = j["hunt"]["name"]
                err  = j.get("error", j["status"])
                if err.startswith("MQL_ERROR:"):
                    err = err[len("MQL_ERROR:"):]
                print(f"    {yellow('⚠')}   {yellow('  err')}       {name}")
                print(f"         {red(err[:100])}")

            print()

        # ── Summary ──
        total_msgs = sum(j["messages"] for j in jobs)
        hits_count = len([j for j in jobs if j["messages"] > 0])
        err_count  = len([j for j in jobs if j["status"] in ("error", "timeout")])

        print(f"{'─' * 70}")
        print(f"  {green(str(hits_count))}/{len(jobs)} hunts with results")
        if err_count:
            print(f"  {yellow(str(err_count))} hunt(s) had errors")
        print(f"  Total messages found : {bold(f'{total_msgs:,}')}")
        print(f"{'═' * 70}\n")

    # ── Markdown report ───────────────────────────────────────────────────────

    def _save_report(
        self,
        jobs: list,
        output_file: str,
        days: int,
        start: datetime,
        end: datetime,
        label: str,
        profile: str,
    ):
        org_label    = label or "POV Tenant"
        total_msgs   = sum(j["messages"] for j in jobs)
        hits_count   = len([j for j in jobs if j["messages"] > 0])
        err_count    = len([j for j in jobs if j["status"] in ("error", "timeout")])
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines = [
            f"# POV Hunt Report — {org_label}",
            "",
            f"**Platform:** {self.base}  ",
            f"**Profile:** {profile}  ",
            f"**Lookback:** {days} days ({start.date()} to {end.date()})  ",
            f"**Generated:** {generated_at}  ",
            "",
            "---",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Hunts run | {len(jobs)} |",
            f"| Hunts with results | {hits_count} |",
            f"| Total messages found | {total_msgs:,} |",
            f"| Errors | {err_count} |",
            "",
            "---",
            "",
        ]

        # Group by category
        jobs_by_cat: dict = {}
        for j in jobs:
            cat = j["hunt"].get("_category", "unknown")
            if cat not in jobs_by_cat:
                jobs_by_cat[cat] = []
            jobs_by_cat[cat].append(j)

        for cat, cat_jobs in jobs_by_cat.items():
            cat_label  = CATEGORY_LABEL.get(cat, cat)
            cat_msgs   = sum(j["messages"] for j in cat_jobs)
            cat_groups = sum(j["groups"] for j in cat_jobs)

            lines.append(f"## {cat_label}")
            lines.append("")
            lines.append(
                f"**{len(cat_jobs)} hunt(s) in this category — "
                f"{cat_msgs:,} messages across {cat_groups} group(s)**"
            )
            lines.append("")

            sorted_jobs = sorted(cat_jobs, key=lambda x: x["messages"], reverse=True)
            for j in sorted_jobs:
                hunt   = j["hunt"]
                name   = hunt["name"]
                msgs   = j["messages"]
                grps   = j["groups"]
                status = j["status"]

                if status == "completed" and msgs > 0:
                    icon = "✅"
                elif status == "completed":
                    icon = "◻️"
                elif status in ("error", "timeout"):
                    icon = "⚠️"
                else:
                    icon = "?"

                lines.append(f"### {icon} {name}")
                lines.append("")

                if j["job_id"]:
                    hunt_url = f"{self.base}/messages/hunt?huntId={j['job_id']}"
                    lines.append(
                        f"- **Messages:** [{msgs:,}]({hunt_url}) "
                        f"| **Groups:** {grps} "
                        f"| **Hunt ID:** `{j['job_id']}`"
                    )
                elif status in ("error", "timeout"):
                    err = j.get("error", "Unknown error")
                    if err.startswith("MQL_ERROR:"):
                        err = err[len("MQL_ERROR:"):]
                    lines.append(f"- **Error:** `{err}`")

                desc = hunt.get("description", "").strip()
                if desc:
                    first_line = desc.splitlines()[0]
                    lines.append("")
                    lines.append(f"> {first_line}")

                steps = hunt.get("suggested_next_steps", "").strip()
                if steps and msgs > 0:
                    lines.append("")
                    lines.append("**Suggested next steps:**")
                    lines.append("")
                    for step_line in steps.splitlines():
                        stripped = step_line.strip()
                        if stripped:
                            lines.append(f"- {stripped}")

                fp_risk = hunt.get("fp_risk", "")
                if fp_risk:
                    lines.append("")
                    lines.append(f"*FP risk: {fp_risk}*")

                lines.append("")

        # ── Appendix: full hunt list ──
        lines += [
            "---",
            "",
            "## Appendix: All Hunts Run",
            "",
            "| Hunt | Category | Messages | Groups | Hunt ID |",
            "|------|----------|----------|--------|---------|",
        ]
        for j in jobs:
            hunt    = j["hunt"]
            cat     = CATEGORY_LABEL.get(j["hunt"].get("_category", ""), "?")
            msgs    = j["messages"]
            grps    = j["groups"]
            job_id  = j["job_id"] or ""
            id_cell = f"`{job_id[:12]}...`" if len(job_id) > 12 else f"`{job_id}`" if job_id else "-"
            lines.append(
                f"| {hunt['name']} | {cat} | {msgs:,} | {grps} | {id_cell} |"
            )

        lines.append("")

        out = Path(output_file)
        out.write_text("\n".join(lines), encoding="utf-8")
        print(f"  Report saved: {dim(str(out.resolve()))}")


# ──────────────────────────────────── CLI ────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="POV Hunt Toolkit — scenario-based inbound threat hunts for Sublime Security POVs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Profiles:
  quick     — graymail only (2-3 min, safe for live demos)
  standard  — graymail + vendor-and-trust (default)
  deep/all  — all four categories

Examples:
  python3 run_pov_hunts.py --api-key KEY --base-url https://platform.sublime.security
  python3 run_pov_hunts.py --api-key KEY --base-url URL --profile deep --lookback 60
  python3 run_pov_hunts.py --api-key KEY --base-url URL --category social-engineering
  python3 run_pov_hunts.py --api-key KEY --base-url URL --label "Acme Corp" --output report.md
  python3 run_pov_hunts.py --api-key KEY --base-url URL --dry-run
        """,
    )
    ap.add_argument(
        "--api-key",
        default=os.environ.get("SUBLIME_API_KEY", ""),
        help="Sublime Security API key (or set SUBLIME_API_KEY env var)",
    )
    ap.add_argument(
        "--base-url",
        default=os.environ.get("SUBLIME_BASE_URL", ""),
        help="Tenant base URL, e.g. https://platform.sublime.security",
    )
    ap.add_argument(
        "--profile",
        default="standard",
        choices=["quick", "standard", "deep", "all"],
        help="Hunt profile: quick | standard (default) | deep | all",
    )
    ap.add_argument(
        "--category",
        default=None,
        choices=ALL_CATEGORIES,
        metavar="CATEGORY",
        help=(
            "Run a single category only: "
            "graymail | vendor-and-trust | social-engineering | service-abuse"
        ),
    )
    ap.add_argument(
        "--lookback",
        type=int,
        default=30,
        metavar="N",
        help="Lookback window in days (default: 30)",
    )
    ap.add_argument(
        "--label",
        default="",
        metavar="NAME",
        help='Organisation label for the report header, e.g. "Acme Corp"',
    )
    ap.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Write markdown report to FILE (default: print summary only)",
    )
    ap.add_argument(
        "--private",
        action="store_true",
        default=True,
        help="Run hunts as private (default — recommended for all customer work)",
    )
    ap.add_argument(
        "--public",
        action="store_true",
        default=False,
        help="Run hunts as public (visible to all org admins — use only with customer consent)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate all hunt MQL syntax via /v1/rules/format without submitting jobs",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output",
    )

    args = ap.parse_args()

    if not args.api_key:
        ap.error(
            "API key required. Pass --api-key or set SUBLIME_API_KEY environment variable."
        )
    if not args.base_url:
        ap.error(
            "Base URL required. Pass --base-url, e.g. --base-url https://platform.sublime.security"
        )

    private = not args.public  # --public overrides --private default

    runner = POVHuntRunner(
        api_key  = args.api_key,
        base_url = args.base_url,
        private  = private,
        quiet    = args.quiet,
    )

    if args.dry_run:
        runner.run_dry(
            toolkit_dir       = Path(__file__).parent,
            profile           = args.profile,
            category_override = args.category,
        )
    else:
        runner.run_all(
            days              = args.lookback,
            profile           = args.profile,
            category_override = args.category,
            label             = args.label,
            output_file       = args.output,
        )


if __name__ == "__main__":
    main()
