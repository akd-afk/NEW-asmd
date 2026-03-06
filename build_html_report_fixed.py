#!/usr/bin/env python3
# =============================================================================
# build_html_report.py  v3.0 -- ASMDU Capacity & Growth Report
# Python 3.6+  |  No external dependencies
#
# v3.0 — Adversarially hardened. All 31 DBA-identified issues fixed.
# =============================================================================

import os, sys, re, glob, json, html, datetime, argparse, csv, math
from collections import defaultdict

# Python 3.6 compatibility helper for ISO dates
def parse_iso_date(s):
    return datetime.datetime.strptime(s, "%Y-%m-%d").date()


# =============================================================================
# THRESHOLDS  (all overridable per-host via meta.json)
# =============================================================================
DEFAULT_WARN_PCT   = 75.0
DEFAULT_CRIT_PCT   = 85.0
RECO_WARN_PCT      = 65.0   # FRA/archivelog DGs: tighter (ORA-19809 risk)
RECO_CRIT_PCT      = 75.0
SMALL_DG_TB        = 2.0    # below this: absolute free TB triggers alert
SMALL_DG_FREE_WARN = 0.5    # TB
SMALL_DG_FREE_CRIT = 0.2    # TB
MIN_FREE_TB_ABS    = 1.0    # universal hard floor regardless of %
WARN_DAYS          = 90
CRIT_DAYS          = 30
TOP_N              = 3
STALE_HOURS        = 25
MIN_CONF_PTS       = 7      # < 7 data points = LOW confidence
MED_CONF_PTS       = 14     # < 14 = MED, >= 14 = HIGH
ANOMALY_MULT       = 2.5    # recent rate > N x baseline = anomaly
ANOMALY_MIN_ABS    = 0.1    # AND absolute recent rate > 0.1 TB/day
MONTHEND_DAYS      = 5      # flag if <= N days before month-end
MIN_GB_DISPLAY     = 0.001  # DGs below 0.001 TB shown in GB

# =============================================================================
# DG TYPE CLASSIFICATION
# =============================================================================

def classify_dg(name):
    n = name.upper()
    if re.search(r'RECO|FRA|FLASH|ARCH|RECOVER|BACKUP', n): return "RECO"
    if re.search(r'OCR|VOTE|GRID|MGMT|CRS',              n): return "OCR"
    if re.search(r'SPARSE',                               n): return "SPARSE"
    return "DATA"

DG_LABELS = {
    "DATA":   ("DB Files",    "#00d4ff"),
    "RECO":   ("Arch/Backup", "#f39c12"),
    "OCR":    ("Grid/OCR",    "#8e9aaf"),
    "SPARSE": ("Sparse",      "#9b59b6"),
}

# =============================================================================
# FILE HELPERS
# =============================================================================

def read_file(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return ""

def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}

def file_age_hours(path):
    try:
        return (datetime.datetime.now().timestamp() - os.path.getmtime(path)) / 3600
    except Exception:
        return 9999

def data_age_hours(meta, fallback_path):
    """
    FIX #14: Use timestamp from meta.json for freshness check.
    Fall back to file mtime. NFS remounts can preserve stale mtimes.
    """
    ts = meta.get("timestamp", "")
    if ts:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M"):
            try:
                dt = datetime.datetime.strptime(ts[:19], fmt)
                return (datetime.datetime.now() - dt).total_seconds() / 3600
            except Exception:
                continue
    return file_age_hours(fallback_path)

# =============================================================================
# PARSER  (FIX #9, #10, #11)
# =============================================================================

def parse_dg_summary(text, warn_stream=None):
    """
    Parse asmdu dg_summary.txt output.
    FIX #9:  Regex now explicitly anchors to line start with optional whitespace
             and optional '+', capturing DG name starting at [A-Z].
    FIX #10: pct > 100.5 instead of > 100 (allows legitimately full DGs).
    FIX #11: Duplicate DG names emit a warning to warn_stream.
    Returns (rows, pct_was_recomputed_flags).
    """
    results, seen = [], set()
    warnings = []
    pat = re.compile(
        r'^\s*\+?([A-Z][A-Z0-9_\-]*)'   # FIX #9: explicit \s*, capture without +
        r'\s+([\d]+\.[\d]+)'
        r'\s+([\d]+\.[\d]+)'
        r'\s+([\d]+\.[\d]+)'
        r'(?:\s+([\d]+\.[\d]+))?'
        r'\s+([\d]+\.[\d]+)',
        re.MULTILINE | re.IGNORECASE
    )
    for m in pat.finditer(text):
        name = m.group(1).upper()
        if name in seen:
            # FIX #11: warn on duplicate
            warnings.append(f"WARN: duplicate DG name '{name}' in output — "
                             f"only first occurrence used.")
            continue
        c2, c3, c4 = float(m.group(2)), float(m.group(3)), float(m.group(4))
        c5  = float(m.group(5)) if m.group(5) else None
        orig_pct = float(m.group(6))
        if c2 == 0 and c3 == 0:
            continue
        if orig_pct > 100.5:  # FIX #10: allow genuine 100% full DGs
            continue
        total, free, used = c2, c3, c4
        pct_recomputed = False
        if total > 0 and abs((used + free) - total) > total * 0.1:
            used, free = free, used
            pct_recomputed = True
        # FIX #6: only recompute pct if we did a column swap, else keep original
        if total > 0 and pct_recomputed:
            pct = round((used / total) * 100.0, 2)
        else:
            pct = orig_pct
        seen.add(name)
        results.append({
            "dg":            name,
            "type":          classify_dg(name),
            "total_tb":      round(total, 3),
            "used_tb":       round(used,  3),
            "free_tb":       round(free,  3),
            "usable_tb":     round(c5, 3) if c5 is not None else None,
            "pct_used":      pct,
            "pct_recomputed": pct_recomputed,  # FIX #6
        })
    if warn_stream is not None:
        for w in warnings:
            warn_stream.append(w)
    return results

# =============================================================================
# REDUNDANCY INFERENCE  (FIX #7 — label as estimate, not authoritative)
# =============================================================================

def infer_redundancy(free_tb, usable_tb):
    """
    FIX #7: Infer ASM redundancy level from USABLE/FREE ratio.
    This is an ESTIMATE. On Exadata, smart scan extents and partner disk
    pre-allocation can shift the ratio. Always verify with:
      SELECT name, redundancy FROM v$asm_diskgroup;
    """
    if usable_tb is None or free_tb is None or free_tb == 0:
        return "UNKNOWN", "var(--muted)"
    ratio = usable_tb / free_tb
    if ratio > 0.85: return "EXT (est.)",    "#9b59b6"
    if ratio > 0.40: return "NORMAL (est.)", "#00d4ff"
    return "HIGH (est.)",   "#e74c3c"

# =============================================================================
# SEVERITY
# =============================================================================

def sev_for_dg(dg_dict, host_thresholds=None):
    """
    Multi-layer severity: pct-based, absolute free-TB floor, small DG.
    FIX #19: compute_changes now calls this function too, so severity
    is always computed consistently (no hardcoded threshold duplication).
    """
    pct     = dg_dict["pct_used"]
    free    = dg_dict["free_tb"]
    total   = dg_dict["total_tb"]
    dg_type = dg_dict["type"]

    if host_thresholds:
        warn_pct = float(host_thresholds.get("warn_pct", DEFAULT_WARN_PCT))
        crit_pct = float(host_thresholds.get("crit_pct", DEFAULT_CRIT_PCT))
    elif dg_type == "RECO":
        warn_pct, crit_pct = RECO_WARN_PCT, RECO_CRIT_PCT
    else:
        warn_pct, crit_pct = DEFAULT_WARN_PCT, DEFAULT_CRIT_PCT

    # Absolute free TB floors (catches small DGs where % is misleading)
    if free < SMALL_DG_FREE_CRIT:                         return "crit"
    if free < MIN_FREE_TB_ABS and total < SMALL_DG_TB:    return "crit"
    if free < SMALL_DG_FREE_WARN and total < SMALL_DG_TB: return "warn"

    if pct >= crit_pct: return "crit"
    if pct >= warn_pct: return "warn"
    return "ok"

def dsev(days):
    if days is None:    return "ok"
    if days <= 0:       return "crit"   # FIX #25: 0 or negative = full now
    if days <= CRIT_DAYS: return "crit"
    if days <= WARN_DAYS: return "warn"
    return "ok"

def worst(*args):
    order = {"crit": 2, "warn": 1, "ok": 0, "unknown": -1}
    return max(args, key=lambda x: order.get(x, -1))

SEV_COLOR   = {"ok": "#2ecc71", "warn": "#f39c12", "crit": "#e74c3c",
               "unknown": "#5a7a99"}
SEV_ICON    = {"ok": "&#x2714;", "warn": "&#x26A0;", "crit": "&#x2716;",
               "unknown": "?"}

def confidence(pts, date_range_days):
    """
    FIX #13: Show N/M days (data points / lookback days), not just point count.
    Sparsity matters: 7 points over 7 days >> 7 points over 30 days.
    """
    if pts < MIN_CONF_PTS:  return "LOW",  "#e74c3c"
    if pts < MED_CONF_PTS:  return "MED",  "#f39c12"
    return "HIGH", "#2ecc71"

# =============================================================================
# NUMERICALLY STABLE LINEAR REGRESSION  (FIX #1)
# =============================================================================

def linreg(xs, ys):
    """
    FIX #1: Center xs around their mean before regression to avoid
    catastrophic cancellation when sum(x^2) ≈ (sum(x)/n)^2 * n
    with large absolute ordinal values.
    Returns slope (TB per unit of xs).
    """
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    cx = [x - mx for x in xs]   # centered xs
    sxy = sum(cx[i] * ys[i] for i in range(n))
    sxx = sum(cx[i] * cx[i] for i in range(n))
    return sxy / sxx if sxx != 0 else 0.0

# =============================================================================
# HISTORY LOADING
# =============================================================================

def load_history(nas_root, host, run_date, lookback):
    today = parse_iso_date(run_date)
    hist  = []
    parse_warnings = []
    for d in range(lookback, 0, -1):   # excludes 0 = today (today is current snapshot)
        dt   = (today - datetime.timedelta(days=d)).isoformat()
        path = os.path.join(nas_root, dt, host, "dg_summary.txt")
        if not os.path.isfile(path):
            continue
        for row in parse_dg_summary(read_file(path), warn_stream=parse_warnings):
            hist.append(dict(row, date=dt))
    return hist, parse_warnings

# =============================================================================
# DELTA HELPER  (FIX #3 — annotate actual day count)
# =============================================================================

def delta_days(rows, target_days, field):
    """
    FIX #3: Returns (delta_value, actual_days_used) so the caller can show
    'WoW (9d actual)' if the collection missed a day.
    """
    if len(rows) < 2:
        return None, None
    latest      = parse_iso_date(rows[-1]["date"])
    target_date = latest - datetime.timedelta(days=target_days)
    past = [r for r in rows
            if parse_iso_date(r["date"]) <= target_date]
    if not past:
        return None, None
    actual_days = (latest - parse_iso_date(past[-1]["date"])).days
    delta       = round(rows[-1][field] - past[-1][field], 3)
    return delta, actual_days

# =============================================================================
# GROWTH ANALYSIS  (FIX #2, #4, #5, #21, #22)
# =============================================================================

def compute_growth(history, today_dg_map):
    """
    today_dg_map: dict of dg_name -> dg_dict from today's snapshot.
    FIX #5: Use today's free_tb for projection, not yesterday's.
    FIX #2: Show both 30d (conservative) and 14d (aggressive) projections.
    FIX #4: Anomaly uses actual delta between day-3 and day-0, not linreg.
            Requires both rate multiple AND absolute floor.
    FIX #21: Stable DGs (slope=0) show 'Stable' not HIGH confidence + infinity.
    FIX #22: Negative slope (shrinking) flagged explicitly.
    """
    by_dg = defaultdict(list)
    for r in history:
        by_dg[r["dg"]].append(r)

    out = {}
    for dg, rows in by_dg.items():
        rows = sorted(rows, key=lambda r: r["date"])
        if len(rows) < 2:
            out[dg] = _eg()
            continue

        xs    = [parse_iso_date(r["date"]).toordinal() for r in rows]
        used  = [r["used_tb"] for r in rows]
        slope = linreg(xs, used)   # TB per calendar day, numerically stable

        # FIX #5: use today's snapshot free_tb if available
        if dg in today_dg_map:
            current_free = today_dg_map[dg]["free_tb"]
            current_used = today_dg_map[dg]["used_tb"]
        else:
            current_free = rows[-1]["free_tb"]
            current_used = rows[-1]["used_tb"]

        # FIX #2: 14d aggressive projection
        slope_14d = None
        days_full_14d = None
        proj_date_14d = None
        if len(rows) >= 4:
            xs14 = xs[-14:] if len(xs) >= 14 else xs
            ys14 = used[-14:] if len(used) >= 14 else used
            slope_14d = linreg(xs14, ys14)
            if slope_14d > 0:
                days_full_14d = round(current_free / slope_14d)
                try:
                    proj_date_14d = datetime.date.fromordinal(
                        parse_iso_date(rows[-1]["date"]).toordinal() + days_full_14d
                    ).isoformat()
                except Exception:
                    proj_date_14d = "far future"

        # 30d conservative projection
        days_full = None
        proj_date = None
        if slope > 0:
            days_full = round(current_free / slope)
            try:
                proj_date = datetime.date.fromordinal(
                    parse_iso_date(rows[-1]["date"]).toordinal() + days_full
                ).isoformat()
            except Exception:
                proj_date = "far future"

        # FIX #25: already-full DG
        if days_full is not None and days_full <= 0:
            days_full = 0   # will render as "FULL NOW"

        # FIX #22: Shrinking DG
        shrinking = slope < -0.001   # more than 1GB/day shrink

        # FIX #4: anomaly = recent 3d delta > ANOMALY_MULT * baseline AND > absolute min
        anomaly, anomaly_msg = False, ""
        if len(rows) >= 4 and slope > 0:
            recent_delta = used[-1] - used[-4]          # actual delta over last 3 days
            recent_rate  = recent_delta / 3.0           # TB/day simple average
            if recent_rate > slope * ANOMALY_MULT and recent_rate > ANOMALY_MIN_ABS:
                anomaly = True
                anomaly_msg = (f"Recent 3d rate {recent_rate:.4f} TB/day is "
                               f"{recent_rate/slope:.1f}x the {slope:.4f} TB/day "
                               f"30d baseline (min threshold: {ANOMALY_MIN_ABS} TB/day)")

        # Date range for confidence context
        date_range_days = (parse_iso_date(rows[-1]["date"]) -
                           parse_iso_date(rows[0]["date"])).days + 1

        # FIX #3: actual day deltas
        wow_val, wow_days = delta_days(rows, 7,  "used_tb")
        mom_val, mom_days = delta_days(rows, 30, "used_tb")

        conf_lbl, conf_clr = confidence(len(rows), date_range_days)

        # FIX #21: override for stable or shrinking
        growth_state = "growing"
        if slope <= 0 and not shrinking:
            growth_state = "stable"
        elif shrinking:
            growth_state = "shrinking"

        out[dg] = {
            "slope_day":    round(slope, 4),
            "slope_week":   round(slope * 7, 3),
            "slope_month":  round(slope * 30, 2),
            "slope_14d":    round(slope_14d, 4) if slope_14d is not None else None,
            "days_full":    days_full,
            "days_full_14d": days_full_14d,
            "proj_date":    proj_date,
            "proj_date_14d": proj_date_14d,
            "wow":          wow_val,
            "wow_days":     wow_days,    # FIX #3
            "mom":          mom_val,
            "mom_days":     mom_days,    # FIX #3
            "pts":          len(rows),
            "date_range_days": date_range_days,
            "conf":         conf_lbl,
            "conf_color":   conf_clr,
            "anomaly":      anomaly,
            "anomaly_msg":  anomaly_msg,
            "shrinking":    shrinking,
            "growth_state": growth_state,
            "history":      rows,
        }
    return out

def _eg():
    return {
        "slope_day": None, "slope_week": None, "slope_month": None,
        "slope_14d": None, "days_full": None, "days_full_14d": None,
        "proj_date": None, "proj_date_14d": None,
        "wow": None, "wow_days": None, "mom": None, "mom_days": None,
        "pts": 0, "date_range_days": 0,
        "conf": "LOW", "conf_color": "#e74c3c",
        "anomaly": False, "anomaly_msg": "",
        "shrinking": False, "growth_state": "unknown",
        "history": [],
    }

# =============================================================================
# THRESHOLD AUDIT TRAIL  (FIX #15)
# =============================================================================

def audit_trail(history_rows, warn_pct, crit_pct):
    """
    FIX #15: If the DG was already in WARN/CRIT at the start of our lookback
    window, we can't claim to know the true first crossing. We prefix the date
    with '≤' to show it's the earliest data we have, not the absolute first.
    """
    first_warn = first_crit = None
    in_warn_at_start = in_crit_at_start = False
    sorted_rows = sorted(history_rows, key=lambda x: x["date"])
    for i, r in enumerate(sorted_rows):
        if first_warn is None and r["pct_used"] >= warn_pct:
            first_warn = r["date"]
            if i == 0:
                in_warn_at_start = True
        if first_crit is None and r["pct_used"] >= crit_pct:
            first_crit = r["date"]
            if i == 0:
                in_crit_at_start = True
    # Prefix with '≤' if already in threshold at start of window
    if first_warn and in_warn_at_start:
        first_warn = "\u2264" + first_warn   # ≤ prefix
    if first_crit and in_crit_at_start:
        first_crit = "\u2264" + first_crit
    return {"first_warn": first_warn, "first_crit": first_crit}

# =============================================================================
# WEEK-OVER-WEEK CHANGES  (FIX #19)
# =============================================================================

def compute_changes(nas_root, run_date, host, today_dgs_with_sv, host_thresh):
    """
    FIX #19: Use sev_for_dg() consistently for both old and new severity.
    No more hardcoded DEFAULT_CRIT_PCT/WARN_PCT for old state calculation.
    """
    changes  = []
    week_ago = (parse_iso_date(run_date)
                - datetime.timedelta(days=7)).isoformat()
    old_path = os.path.join(nas_root, week_ago, host, "dg_summary.txt")
    if not os.path.isfile(old_path):
        return changes
    old_dgs = {d["dg"]: d for d in parse_dg_summary(read_file(old_path))}

    for d in today_dgs_with_sv:
        name = d["dg"]
        if name not in old_dgs:
            continue
        old     = old_dgs[name]
        new_sv  = d["sv"]
        # FIX #19: same severity function as everywhere else
        old_sv  = sev_for_dg(old, host_thresh)
        if new_sv != old_sv:
            changes.append({
                "dg":        name,
                "old_pct":   old["pct_used"],
                "new_pct":   d["pct_used"],
                "old_sv":    old_sv,
                "new_sv":    new_sv,
                "delta_used": round(d["used_tb"] - old["used_tb"], 3),
            })
    return changes

# =============================================================================
# RECOMMENDATION ENGINE  (FIX #16, #17, #18, #20)
# =============================================================================

def recommend(dg_name, dg_type, pct, free_tb, total_tb, days_full,
              days_full_14d, growth_month, anomaly, redundancy, shrinking):
    recs = []

    # FIX #22: Shrinking is worth noting
    if shrinking and growth_month is not None:
        recs.append(
            f"DG is currently SHRINKING ({abs(growth_month):.2f} TB/month). "
            f"This may indicate a recent purge, RMAN delete, or data archival. "
            f"Verify this is intentional."
        )
        return recs

    if dg_type == "OCR" and growth_month and growth_month > 0.01:
        recs.append(
            "OCR/VOTE DG should not grow. Investigate: check $GRID_HOME/log/diag "
            "and alert log. Growth here is abnormal and warrants immediate review."
        )
        return recs

    if dg_type == "RECO":
        if pct >= RECO_CRIT_PCT:
            recs.append(
                "URGENT: Increase db_recovery_file_dest_size or reduce RMAN retention "
                "to prevent ORA-19809 (archiver stuck). Query: "
                "SELECT * FROM v$recovery_file_dest;"
            )
        if anomaly:
            recs.append(
                "Archivelog accumulation spike detected. Check: "
                "SELECT * FROM v$rman_backup_job_details ORDER BY start_time DESC; "
                "and verify no backup jobs are failing."
            )
        if growth_month and growth_month > 0.5:
            recs.append(
                f"RECO growing {growth_month:.2f} TB/month — review RMAN retention policy "
                f"and ensure backup jobs complete successfully. "
                f"Note: On standby DBs, RECO fills via redo apply, not RMAN."  # FIX #20
            )
        # FIX #18: FRA size caveat
        recs.append(
            "Note: db_recovery_file_dest_size may be set lower than the physical DG size. "
            "Verify: SELECT space_limit/1024/1024/1024 limit_gb, "
            "space_used/1024/1024/1024 used_gb FROM v$recovery_file_dest;"
        )
        return recs

    # DATA DG
    if anomaly:
        recs.append(
            "Abnormal growth spike detected. Check: "
            "SELECT sql_id, rows_processed FROM v$sql ORDER BY rows_processed DESC; "
            "and v$session for active bulk loads or table reorgs."
        )

    # FIX #16: deduct existing free space from capacity needed
    if days_full is not None and days_full <= CRIT_DAYS:
        needed_180 = max(0.0, round((growth_month or 0) * 6 - free_tb, 1))
        recs.append(
            f"Critical: Add {needed_180:.1f} TB to achieve 180-day runway "
            f"(calculation: 6 months growth {(growth_month or 0)*6:.1f} TB "
            f"minus existing free {free_tb:.1f} TB). "
            f"Current projection: full in {days_full}d (30d trend), "
            + (f"{days_full_14d}d (14d aggressive trend)." if days_full_14d else "")
        )
    elif days_full is not None and days_full <= WARN_DAYS:
        needed_90 = max(0.0, round((growth_month or 0) * 3 - free_tb, 1))
        recs.append(
            f"Plan capacity addition of {needed_90:.1f} TB within {max(0,days_full-30)} days "
            f"to maintain 90-day runway."
        )

    if redundancy.startswith("HIGH") and pct > 60:
        recs.append(
            "DG appears to use HIGH redundancy (3-way mirror, estimated from USABLE/FREE ratio). "
            "Raw disk usage is approximately 3x the USED value shown. "
            "Verify: SELECT redundancy FROM v$asm_diskgroup WHERE name='" +
            dg_name + "';"
        )

    if pct >= DEFAULT_CRIT_PCT and free_tb < 2.0:
        recs.append(
            f"Only {free_tb:.3f} TB physically free. Immediate action required: "
            f"add disks to diskgroup or relocate/purge data."
        )

    # FIX #17: USABLE explanation
    recs.append(
        "USABLE = allocatable space after mirror overhead. "
        "Alert thresholds are based on USED/TOTAL (physical utilisation), not USABLE."
    )

    if not recs:
        recs.append("No capacity concerns. Continue monitoring.")
    return recs

# =============================================================================
# CORRELATION DETECTION
# =============================================================================

def detect_correlation(enriched_dgs):
    anomalous = [d for d in enriched_dgs if d["g"]["anomaly"]]
    if len(anomalous) >= 2:
        names = " + ".join(f"+{d['dg']}" for d in anomalous)
        return (f"CORRELATED GROWTH: {names} are both/all spiking simultaneously. "
                f"Likely cause: active bulk load, batch job, or unplanned workload.")
    return None

# =============================================================================
# FLEET TIME SERIES  (FIX #8, #28)
# =============================================================================

def fleet_time_series(nas_root, run_date, hosts, lookback, today_all_dgs):
    """
    FIX #8:  Only include hosts present in BOTH today's data AND the historical
             date. New hosts mid-period inflate the fleet total artificially.
    FIX #28: range(lookback, 0, -1) excludes 0 for consistency with load_history.
             Today's total computed from already-parsed today_all_dgs (avoids double parse).
    Returns (series_dict, host_count_changed_flag)
    """
    today    = parse_iso_date(run_date)
    # Compute today's total from already-parsed data
    today_total = round(sum(d["used_tb"] for d in today_all_dgs), 2)

    series         = {}
    host_counts    = {}   # date -> number of hosts with data
    today_host_set = set(hosts)

    for d in range(lookback, 0, -1):
        dt    = (today - datetime.timedelta(days=d)).isoformat()
        total = 0.0
        hist_hosts_today = set()
        for host in hosts:
            path = os.path.join(nas_root, dt, host, "dg_summary.txt")
            if not os.path.isfile(path):
                continue
            hist_hosts_today.add(host)
            for row in parse_dg_summary(read_file(path)):
                total += row["used_tb"]
        if hist_hosts_today:
            # FIX #8: only record if same host set as today
            if hist_hosts_today == today_host_set:
                series[dt] = round(total, 2)
            else:
                series[dt] = None   # mark as incomparable
            host_counts[dt] = len(hist_hosts_today)

    # Add today
    series[run_date] = today_total
    host_counts[run_date] = len(today_host_set)

    host_count_changed = len(set(host_counts.values())) > 1
    # Return only comparable points for sparkline
    comparable = {k: v for k, v in series.items() if v is not None}
    return comparable, host_count_changed

# =============================================================================
# SEASONALITY
# =============================================================================

def monthend_flag(run_date):
    d = parse_iso_date(run_date)
    if d.month == 12:
        last = datetime.date(d.year + 1, 1, 1) - datetime.timedelta(days=1)
    else:
        last = datetime.date(d.year, d.month + 1, 1) - datetime.timedelta(days=1)
    days_to_end = (last - d).days
    return days_to_end <= MONTHEND_DAYS, days_to_end, last.isoformat()

# =============================================================================
# SPARKLINE
# =============================================================================

def spark(vals, w=80, h=18, color="#00d4ff"):
    if len(vals) < 2:
        return ""
    mn, mx = min(vals), max(vals)
    rng    = mx - mn if mx != mn else 1.0
    pts    = []
    for i, v in enumerate(vals):
        x = round((i / (len(vals) - 1)) * w, 1)
        y = round(h - ((v - mn) / rng) * (h - 2) - 1, 1)
        pts.append(f"{x},{y}")
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'style="vertical-align:middle;display:inline-block">'
            f'<polyline points="{" ".join(pts)}" fill="none" '
            f'stroke="{color}" stroke-width="1.5" stroke-linejoin="round"/>'
            f'</svg>')

# =============================================================================
# FORMAT HELPERS  (FIX #27 — GB display for tiny DGs)
# =============================================================================

def ftb(v):
    if v is None:
        return "—"
    if abs(v) < MIN_GB_DISPLAY:
        return f"{v*1024:.1f}&nbsp;GB"   # FIX #27: show in GB if < 0.001 TB
    return f"{v:,.3f}&nbsp;TB"

def fpct(v):
    return f"{v:.2f}%"   # 2dp everywhere for precision

def fdelta(v, days_actual=None):
    if v is None:
        return "—"
    s = (f"+{v:,.3f}" if v >= 0 else f"{v:,.3f}") + "&nbsp;TB"
    if days_actual is not None:
        s += f'<span style="font-size:9px;color:var(--muted)"> ({days_actual}d)</span>'
    return s

def fdays(v):
    if v is None:     return "&#x221e;"
    if v <= 0:        return '<span style="color:#e74c3c;font-weight:700">FULL NOW</span>'  # FIX #25
    return f"{v:,}d"

def fdays_both(v30, v14):
    """Show both 30d conservative and 14d aggressive projections."""
    parts = []
    if v30 is not None:
        parts.append(f"{v30:,}d <span style='font-size:9px;color:var(--muted)'>(30d)</span>")
    if v14 is not None and v14 != v30:
        clr = "#e74c3c" if v14 <= CRIT_DAYS else "#f39c12" if v14 <= WARN_DAYS else "#2ecc71"
        parts.append(f'<span style="color:{clr}">{v14:,}d</span>'
                     f' <span style="font-size:9px;color:var(--muted)">(14d)</span>')
    return " / ".join(parts) if parts else "&#x221e;"

# =============================================================================
# CSV
# =============================================================================

def write_csv(path, rows):
    if not rows:
        return
    fields = [
        "date", "host", "platform", "dg", "dg_type", "redundancy_est",
        "total_tb", "used_tb", "free_tb", "usable_tb", "pct_used",
        "pct_recomputed", "growth_tb_day", "growth_tb_week", "growth_tb_month",
        "growth_tb_day_14d", "wow_tb", "wow_days_actual", "mom_tb", "mom_days_actual",
        "days_to_full_30d", "days_to_full_14d",
        "proj_full_date_30d", "proj_full_date_14d",
        "growth_state", "trend_confidence", "conf_pts", "conf_date_range_days",
        "anomaly", "anomaly_msg", "first_warn_since", "first_crit_since",
        "recommendation",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

# =============================================================================
# DISCOVERY
# =============================================================================

def discover(nas_root, run_date):
    base = os.path.join(nas_root, run_date)
    if not os.path.isdir(base):
        raise SystemExit(f"[ERROR] Run folder not found: {base}")
    hosts = sorted(d for d in os.listdir(base)
                   if os.path.isdir(os.path.join(base, d)))
    return base, hosts

# =============================================================================
# MAIN REPORT BUILDER
# =============================================================================

def build_report(nas_root, run_date, lookback):
    base, hosts   = discover(nas_root, run_date)
    now_str       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title         = f"ASM Capacity — {run_date}"
    is_monthend, days_to_end, monthend_date = monthend_flag(run_date)

    # ── First pass: parse all today's DGs (needed for fleet TS + growth) ──
    host_raw      = {}
    for host in hosts:
        hdir     = os.path.join(base, host)
        meta     = load_json(os.path.join(hdir, "meta.json"))
        raw_sum  = read_file(os.path.join(hdir, "dg_summary.txt"))
        parse_w  = []
        dgs      = parse_dg_summary(raw_sum, warn_stream=parse_w)
        host_raw[host] = {"meta": meta, "raw_sum": raw_sum, "dgs": dgs,
                          "parse_warnings": parse_w}

    all_today_dgs = [d for h in host_raw.values() for d in h["dgs"]]

    # Fleet time series (FIX #8, #28)
    fleet_ts, host_count_changed = fleet_time_series(
        nas_root, run_date, hosts, lookback, all_today_dgs)

    # ── Second pass: full enrichment per host ──
    host_data     = []
    csv_rows      = []
    all_alerts    = []
    all_anomalies = []
    all_changes   = []
    runway_list   = []
    reco_critical = []

    for host in hosts:
        hdir     = os.path.join(base, host)
        meta     = host_raw[host]["meta"]
        raw_sum  = host_raw[host]["raw_sum"]
        raw_err  = read_file(os.path.join(hdir, "dg_summary.err"))
        ts_str   = meta.get("timestamp", "")
        age_h    = data_age_hours(meta, os.path.join(hdir, "dg_summary.txt"))  # FIX #14
        stale    = age_h > STALE_HOURS
        subdirs  = [(os.path.basename(p), read_file(p))
                    for p in sorted(glob.glob(os.path.join(hdir, "*_root_subdirs.txt")))]
        parse_w  = host_raw[host]["parse_warnings"]
        platform = meta.get("platform", "unknown")

        host_thresh = {k: meta[k] for k in ("warn_pct", "crit_pct") if k in meta} or None
        dgs         = host_raw[host]["dgs"]
        history, hist_w = load_history(nas_root, host, run_date, lookback)
        parse_w.extend(hist_w)

        # Build today's DG map for growth projection (FIX #5)
        today_dg_map = {d["dg"]: d for d in dgs}
        growth       = compute_growth(history, today_dg_map)

        # Compute severity for all today's DGs (used consistently everywhere)
        dgs_with_sv = []
        for dg in dgs:
            sv = sev_for_dg(dg, host_thresh)
            dgs_with_sv.append(dict(dg, sv=sv))

        changes = compute_changes(nas_root, run_date, host, dgs_with_sv, host_thresh)  # FIX #19
        for ch in changes:
            all_changes.append((host, ch))

        enriched = []
        for dg in dgs_with_sv:
            g        = growth.get(dg["dg"], _eg())
            dg_type  = dg["type"]
            sv_      = dg["sv"]
            dv_      = dsev(g["days_full"])
            ws       = worst(sv_, dv_)
            redund, rclr = infer_redundancy(dg["free_tb"], dg["usable_tb"])

            # Audit trail (FIX #15)
            wp = (host_thresh or {}).get("warn_pct",
                  RECO_WARN_PCT if dg_type == "RECO" else DEFAULT_WARN_PCT)
            cp = (host_thresh or {}).get("crit_pct",
                  RECO_CRIT_PCT if dg_type == "RECO" else DEFAULT_CRIT_PCT)
            audit = audit_trail(g["history"], wp, cp)

            # Recommendations (FIX #16-20)
            recs = recommend(
                dg["dg"], dg_type, dg["pct_used"], dg["free_tb"], dg["total_tb"],
                g["days_full"], g["days_full_14d"], g["slope_month"],
                g["anomaly"], redund, g["shrinking"]
            )

            if ws in ("crit", "warn"):
                rank = 2 if ws == "crit" else 1
                all_alerts.append((rank, host, dg["dg"], dg_type,
                    f"{ws.upper()} +{dg['dg']} on {host}: "
                    f"{dg['pct_used']:.2f}% used, {dg['free_tb']:.3f}TB free"
                    + (f" — full in {g['days_full']}d ({g['proj_date']})"
                       if g["days_full"] else "")))

            if dg_type == "RECO" and sv_ == "crit":
                reco_critical.append((host, dg["dg"], dg["pct_used"], dg["free_tb"]))

            if g["anomaly"]:
                all_anomalies.append((host, dg["dg"], g["anomaly_msg"]))

            if g["days_full"] and g["days_full"] > 0:
                runway_list.append((g["days_full"], host, dg["dg"],
                                    dg["pct_used"], g["proj_date"],
                                    dg_type, dg["free_tb"],
                                    g["days_full_14d"], g["proj_date_14d"]))

            enriched.append({**dg, "g": g, "sv": sv_, "dv": dv_, "ws": ws,
                              "redund": redund, "redund_color": rclr,
                              "audit": audit, "recs": recs})

            csv_rows.append({
                "date": run_date, "host": host, "platform": platform,
                "dg": dg["dg"], "dg_type": dg_type, "redundancy_est": redund,
                "total_tb": dg["total_tb"], "used_tb": dg["used_tb"],
                "free_tb": dg["free_tb"], "usable_tb": dg.get("usable_tb"),
                "pct_used": dg["pct_used"],
                "pct_recomputed": dg.get("pct_recomputed", False),  # FIX #6
                "growth_tb_day":   g["slope_day"],
                "growth_tb_week":  g["slope_week"],
                "growth_tb_month": g["slope_month"],
                "growth_tb_day_14d": g["slope_14d"],
                "wow_tb": g["wow"], "wow_days_actual": g["wow_days"],
                "mom_tb": g["mom"], "mom_days_actual": g["mom_days"],
                "days_to_full_30d": g["days_full"],
                "days_to_full_14d": g["days_full_14d"],
                "proj_full_date_30d": g["proj_date"],
                "proj_full_date_14d": g["proj_date_14d"],
                "growth_state": g["growth_state"],
                "trend_confidence": g["conf"],
                "conf_pts": g["pts"],
                "conf_date_range_days": g["date_range_days"],
                "anomaly": g["anomaly"], "anomaly_msg": g["anomaly_msg"],
                "first_warn_since": audit["first_warn"],
                "first_crit_since": audit["first_crit"],
                "recommendation": "; ".join(recs),
            })

        corr_msg = detect_correlation(enriched)

        # FIX #23: hosts with no DGs = UNKNOWN, not OK
        if not enriched:
            host_sv_overall = "unknown"
        else:
            host_sv_overall = worst(*[d["ws"] for d in enriched])

        host_data.append({
            "host": host, "platform": platform, "meta": meta,
            "dgs": enriched, "raw_sum": raw_sum, "raw_err": raw_err,
            "subdirs": subdirs, "stale": stale, "age_h": age_h,
            "ts_str": ts_str, "changes": changes, "corr_msg": corr_msg,
            "host_sv": host_sv_overall, "parse_warnings": parse_w,
        })

    # Sort hosts: CRIT first, then WARN, then OK, then UNKNOWN; within group by max pct desc
    sv_order = {"crit": 0, "warn": 1, "ok": 2, "unknown": 3}
    def host_sort_key(h):
        mx = max((d["pct_used"] for d in h["dgs"]), default=0)
        return (sv_order.get(h["host_sv"], 9), -mx)
    host_data.sort(key=host_sort_key)

    all_alerts.sort(key=lambda a: (-a[0], a[4]))
    runway_list.sort(key=lambda r: r[0])

    # Fleet totals
    all_dgs  = [d for h in host_data for d in h["dgs"]]
    fl_total = sum(d["total_tb"] for d in all_dgs)
    fl_used  = sum(d["used_tb"]  for d in all_dgs)
    fl_free  = fl_total - fl_used
    fl_pct   = round((fl_used / fl_total) * 100, 2) if fl_total else 0
    fl_sv    = sev_for_dg({"pct_used": fl_pct, "free_tb": fl_free,
                            "total_tb": fl_total, "type": "DATA"})

    # Platform rollup
    platforms = defaultdict(lambda: {"total": 0, "used": 0, "hosts": set()})
    for h in host_data:
        for d in h["dgs"]:
            platforms[h["platform"]]["total"] += d["total_tb"]
            platforms[h["platform"]]["used"]  += d["used_tb"]
            platforms[h["platform"]]["hosts"].add(h["host"])

    # Top N by used
    top_dgs = sorted(all_dgs, key=lambda d: d["used_tb"], reverse=True)[:TOP_N]
    dg_to_host = {}
    for h in host_data:
        for d in h["dgs"]:
            dg_to_host[(h["host"], d["dg"])] = h["host"]

    crit_count = sum(1 for a in all_alerts if a[0] == 2)
    warn_count = sum(1 for a in all_alerts if a[0] == 1)
    soon_30    = [r for r in runway_list if r[0] <= 30]
    soon_90    = [r for r in runway_list if r[0] <= 90]

    exec_status = ("CRITICAL ACTION REQUIRED" if crit_count or reco_critical
                   else "ATTENTION NEEDED"     if warn_count or soon_90
                   else "HEALTHY")
    exec_color  = ("#e74c3c" if "CRITICAL" in exec_status
                   else "#f39c12" if "ATTENTION" in exec_status else "#2ecc71")

    exec_lines = [f"Fleet: {fl_pct:.2f}% used &mdash; {ftb(fl_used)} of {ftb(fl_total)}."]
    if reco_critical:
        names = ", ".join(f"+{r[1]}@{r[0]}" for r in reco_critical)
        exec_lines.append(f"&#x1F6A8; RECO DG CRITICAL: {names} &mdash; risk of ORA-19809 (archiver hung).")
    if crit_count:
        exec_lines.append(f"{crit_count} diskgroup(s) at CRITICAL capacity. Immediate action required.")
    if soon_30:
        names = ", ".join(f"+{r[2]}@{r[1]}" for r in soon_30[:3])
        exec_lines.append(f"{len(soon_30)} DG(s) projected full within 30 days: {names}.")
    elif soon_90:
        exec_lines.append(f"{len(soon_90)} DG(s) projected full within 90 days — plan capacity additions.")
    if all_anomalies:
        exec_lines.append(f"&#x26A1; {len(all_anomalies)} growth anomaly/anomalies — possible runaway job or unplanned workload.")
    if all_changes:
        exec_lines.append(f"{len(all_changes)} DG(s) crossed a severity threshold since last week.")
    if is_monthend:
        exec_lines.append(f"&#x1F4C5; Month-end in {days_to_end} day(s) ({monthend_date}) &mdash; elevated archivelog/batch growth expected.")
    if host_count_changed:
        exec_lines.append("&#x26A0; Fleet host count changed during lookback period — fleet trend sparkline shows comparable hosts only.")
    if exec_status == "HEALTHY":
        exec_lines.append("No immediate capacity concerns.")

    all_dg_names = sorted(set(d["dg"] for d in all_dgs))

    # ======================================================================
    # HTML
    # ======================================================================
    H = []
    def w(s): H.append(s)

    w(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Barlow:wght@400;600;700;900&display=swap');
:root{{
  --bg:#0a1628;--bg2:#0f1f3d;--bg3:#162847;--border:#1e3a5f;
  --amber:#f5a623;--teal:#00d4ff;
  --ok:#2ecc71;--warn:#f39c12;--crit:#e74c3c;--unk:#5a7a99;
  --text:#cdd9e5;--muted:#5a7a99;
  --mono:'JetBrains Mono','Courier New',monospace;
  --ui:'Barlow',Arial,sans-serif;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:var(--bg);color:var(--text);font-family:var(--ui);font-size:13px;line-height:1.55;display:flex;flex-direction:column;min-height:100vh;}}
a{{color:var(--teal);text-decoration:none;}}a:hover{{text-decoration:underline;}}
.layout{{display:flex;flex:1;}}
/* SIDEBAR */
.sidebar{{width:200px;min-width:200px;background:var(--bg2);border-right:1px solid var(--border);position:sticky;top:0;height:100vh;overflow-y:auto;flex-shrink:0;}}
.sb-title{{padding:10px 12px;font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--amber);font-weight:700;border-bottom:1px solid var(--border);}}
.sb-search{{padding:6px 8px;border-bottom:1px solid var(--border);}}
.sb-search input{{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);font-family:var(--mono);font-size:11px;padding:3px 6px;border-radius:3px;}}
.sb-item{{display:flex;align-items:center;gap:5px;padding:5px 12px;font-family:var(--mono);font-size:11px;cursor:pointer;border-left:3px solid transparent;transition:all .12s;white-space:nowrap;overflow:hidden;}}
.sb-item:hover{{background:var(--bg3);}}
.sb-item.crit{{border-left-color:var(--crit);}}.sb-item.warn{{border-left-color:var(--warn);}}.sb-item.ok{{border-left-color:var(--ok);}}.sb-item.unknown{{border-left-color:var(--unk);}}
.sb-dot{{width:6px;height:6px;border-radius:50%;flex-shrink:0;}}
.sb-dot.crit{{background:var(--crit);}}.sb-dot.warn{{background:var(--warn);}}.sb-dot.ok{{background:var(--ok);}}.sb-dot.unknown{{background:var(--unk);}}
.sb-pct{{margin-left:auto;color:var(--muted);font-size:10px;padding-left:4px;}}
/* MAIN */
.main{{flex:1;overflow:hidden;}}
/* TOPBAR */
.topbar{{background:var(--bg2);border-bottom:3px solid var(--amber);padding:11px 18px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;}}
.topbar h1{{font-size:16px;font-weight:900;color:var(--amber);text-transform:uppercase;letter-spacing:.06em;}}
.topbar .sub{{color:var(--teal);font-family:var(--mono);font-size:11px;}}
.topbar .meta{{margin-left:auto;font-size:10px;color:var(--muted);font-family:var(--mono);text-align:right;}}
/* BANNERS */
.banner{{padding:8px 18px;font-family:var(--mono);font-size:11px;border-bottom:1px solid;}}
.banner.reco{{background:#1a0000;border-color:var(--crit);color:var(--crit);font-weight:700;}}
.banner.monthend{{background:#1a1000;border-color:var(--warn);color:var(--warn);}}
.banner.anomaly{{background:#0a0015;border-color:#9b59b6;color:#c39bd3;}}
.banner.changes{{background:#001510;border-color:var(--ok);color:var(--ok);}}
.banner.fleet-warn{{background:#0d0d00;border-color:var(--warn);color:var(--warn);}}
/* EXEC */
.exec{{background:var(--bg2);border-left:4px solid {exec_color};padding:11px 18px;}}
.exec .status{{font-size:10px;font-weight:700;letter-spacing:.1em;color:{exec_color};text-transform:uppercase;margin-bottom:4px;}}
.exec p{{font-size:12px;line-height:1.8;}}
/* ALERTS */
.alerts{{padding:6px 18px;background:#0d0000;border-bottom:1px solid var(--crit);}}
.alert-row{{font-family:var(--mono);font-size:11px;padding:1px 0;}}
.alert-row.crit{{color:var(--crit);}}.alert-row.warn{{color:var(--warn);}}
/* PLATFORMS */
.platforms{{display:flex;gap:8px;padding:10px 18px;background:var(--bg3);border-bottom:1px solid var(--border);flex-wrap:wrap;}}
.plat-card{{background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:9px 12px;min-width:140px;flex:1;}}
.plat-name{{font-size:9px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:2px;}}
.plat-pct{{font-family:var(--mono);font-size:18px;font-weight:700;}}
.plat-sub{{font-size:10px;color:var(--muted);font-family:var(--mono);margin-top:2px;}}
.bar-outer{{height:4px;background:var(--bg);border:1px solid var(--border);border-radius:2px;overflow:hidden;margin:3px 0 2px;}}
.bar-fill{{height:100%;border-radius:1px;}}
.bar-fill.ok{{background:var(--ok);}}.bar-fill.warn{{background:var(--warn);}}.bar-fill.crit{{background:var(--crit);}}.bar-fill.unknown{{background:var(--unk);}}
/* FLEET TS */
.fleet-ts{{padding:10px 18px;background:var(--bg2);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:18px;flex-wrap:wrap;}}
.fkpi{{display:flex;flex-direction:column;gap:1px;}}
.fkpi .lbl{{font-size:9px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);}}
.fkpi .val{{font-family:var(--mono);font-size:15px;font-weight:700;}}
.fkpi .val.ok{{color:var(--ok);}}.fkpi .val.warn{{color:var(--warn);}}.fkpi .val.crit{{color:var(--crit);}}
/* FILTER */
.filterbar{{padding:6px 18px;background:var(--bg3);border-bottom:1px solid var(--border);display:flex;gap:6px;flex-wrap:wrap;align-items:center;}}
.fbtn{{background:var(--bg);border:1px solid var(--border);color:var(--muted);font-size:10px;padding:2px 8px;border-radius:3px;cursor:pointer;font-family:var(--mono);transition:all .12s;}}
.fbtn:hover,.fbtn.active{{background:var(--border);color:var(--text);}}
.fbtn.fcrit.active{{border-color:var(--crit);color:var(--crit);}}.fbtn.fwarn.active{{border-color:var(--warn);color:var(--warn);}}
/* TOP3 */
.top3{{display:flex;gap:8px;padding:10px 18px;background:var(--bg3);border-bottom:1px solid var(--border);flex-wrap:wrap;}}
.t3card{{flex:1;min-width:180px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:10px;}}
.t3rank{{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:2px;}}
.t3dg{{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--teal);}}
.t3host{{font-size:10px;color:var(--muted);margin-bottom:4px;}}
.t3used{{font-family:var(--mono);font-size:17px;font-weight:700;margin-bottom:2px;}}
.t3info{{font-size:10px;color:var(--muted);font-family:var(--mono);line-height:1.6;}}
/* HEATMAP */
.heatmap{{padding:10px 18px;border-bottom:1px solid var(--border);}}
.heatmap h2{{font-size:11px;font-weight:700;color:var(--amber);text-transform:uppercase;letter-spacing:.06em;margin-bottom:7px;}}
.hm-wrap{{overflow-x:auto;}}
.hm-table{{border-collapse:collapse;font-family:var(--mono);font-size:11px;}}
.hm-table th{{padding:2px 7px;font-size:9px;text-transform:uppercase;color:var(--muted);text-align:center;border-bottom:1px solid var(--border);white-space:nowrap;}}
.hm-table th.host-th{{text-align:left;min-width:120px;}}
.hm-table td{{padding:2px 5px;text-align:center;}}
.hm-table td.host-td{{text-align:left;color:var(--text);padding-right:10px;white-space:nowrap;font-size:11px;}}
.hm-cell{{border-radius:2px;padding:2px 6px;font-weight:700;font-size:11px;min-width:52px;display:inline-block;text-align:center;}}
.hm-ok{{background:#1a4a2e;color:#2ecc71;}}.hm-warn{{background:#4a3000;color:#f39c12;}}.hm-crit{{background:#4a0000;color:#e74c3c;}}.hm-unknown{{background:var(--bg3);color:var(--muted);}}.hm-na{{background:var(--bg3);color:var(--muted);}}
/* RUNWAY / CHANGES */
.runway,.changes{{padding:10px 18px;border-bottom:1px solid var(--border);}}
.runway h2,.changes h2{{font-size:11px;font-weight:700;color:var(--amber);text-transform:uppercase;letter-spacing:.06em;margin-bottom:7px;}}
.rw-table,.ch-table{{width:100%;border-collapse:collapse;font-size:11px;font-family:var(--mono);}}
.rw-table th,.ch-table th{{background:var(--bg2);padding:4px 8px;text-align:left;font-size:9px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);border-bottom:2px solid var(--border);}}
.rw-table td,.ch-table td{{padding:5px 8px;border-bottom:1px solid var(--border);vertical-align:middle;}}
.rw-table tr:hover td,.ch-table tr:hover td{{background:var(--bg3);}}
/* HOST CARD */
.content{{padding:12px 18px;}}
.hcard{{border:1px solid var(--border);border-radius:4px;margin-bottom:8px;overflow:hidden;}}
.hcard.filtered-out{{display:none;}}
.hcard-head{{background:var(--bg3);padding:8px 12px;display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none;}}
.hcard-head:hover{{background:#1a3050;}}
.hname{{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--teal);}}
.hplat{{font-size:9px;border:1px solid var(--border);border-radius:2px;padding:1px 4px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;background:var(--bg);}}
.hstale{{font-size:9px;color:var(--crit);border:1px solid var(--crit);border-radius:2px;padding:1px 4px;font-family:var(--mono);}}
.hts{{font-size:9px;color:var(--muted);font-family:var(--mono);}}
.hmeta{{margin-left:auto;font-family:var(--mono);font-size:10px;color:var(--muted);}}
.harrow{{color:var(--muted);font-size:10px;margin-left:4px;}}
.hbody{{padding:11px;display:block;}}
.hbody.closed{{display:none;}}
/* TABLES */
.slabel{{font-size:9px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:10px 0 4px;}}
.slabel:first-child{{margin-top:0;}}
table.dgt{{width:100%;border-collapse:collapse;font-size:10px;font-family:var(--mono);}}
.dgt thead tr{{background:var(--bg);border-bottom:2px solid var(--border);}}
.dgt th{{padding:4px 6px;text-align:right;font-size:8px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);white-space:nowrap;}}
.dgt th:first-child,.dgt th:nth-child(2),.dgt th:nth-child(3){{text-align:left;}}
.dgt tbody tr{{border-bottom:1px solid var(--border);transition:background .1s;}}
.dgt tbody tr:hover{{background:var(--bg3);}}
.dgt td{{padding:5px 6px;text-align:right;white-space:nowrap;vertical-align:middle;}}
.dgt td:first-child,.dgt td:nth-child(2),.dgt td:nth-child(3){{text-align:left;}}
.ok{{color:var(--ok);}}.warn{{color:var(--warn);}}.crit{{color:var(--crit);font-weight:700;}}.unknown{{color:var(--unk);}}
.dg-name{{font-weight:700;}}
.ubar{{display:inline-block;width:40px;height:4px;background:var(--bg);border:1px solid var(--border);border-radius:2px;overflow:hidden;vertical-align:middle;}}
.ufill{{height:100%;display:block;}}
.tag{{font-size:9px;border-radius:2px;padding:1px 3px;background:var(--bg);border:1px solid var(--border);margin-left:2px;}}
/* SNAP TABLE */
table.snap{{width:100%;border-collapse:collapse;font-size:10px;font-family:var(--mono);}}
.snap th{{background:var(--bg);padding:4px 7px;font-size:8px;text-transform:uppercase;color:var(--muted);text-align:right;border-bottom:2px solid var(--border);}}
.snap th:first-child{{text-align:left;}}
.snap td{{padding:4px 7px;border-bottom:1px solid var(--border);text-align:right;}}
.snap td:first-child{{text-align:left;}}
/* REC LIST */
.rec-list{{list-style:none;margin:0;padding:0;}}
.rec-list li{{font-size:10px;color:var(--text);padding:3px 0 3px 13px;position:relative;border-bottom:1px solid var(--border);line-height:1.5;}}
.rec-list li::before{{content:"&#x27A4;";position:absolute;left:0;color:var(--amber);font-size:9px;top:4px;}}
/* CHARTS */
.chart-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;margin-top:6px;}}
.chart-box{{background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:8px;}}
.chart-title{{font-size:10px;color:var(--teal);font-family:var(--mono);font-weight:700;margin-bottom:2px;}}
.chart-sub{{font-size:9px;color:var(--muted);margin-top:3px;font-family:var(--mono);line-height:1.5;}}
/* METHODOLOGY */
.method{{padding:10px 18px;border-top:1px solid var(--border);}}
.method h2{{font-size:11px;font-weight:700;color:var(--amber);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;cursor:pointer;}}
.method-body{{font-size:10px;font-family:var(--mono);color:var(--muted);line-height:1.7;display:none;}}
.method-body.open{{display:block;}}
.method-body dl{{display:grid;grid-template-columns:160px 1fr;gap:2px 10px;}}
.method-body dt{{color:var(--teal);font-weight:700;padding:2px 0;}}
.method-body dd{{padding:2px 0;color:var(--text);}}
/* PARSE WARN */
.parse-warn{{font-family:var(--mono);font-size:10px;color:#c39bd3;padding:3px 0;}}
/* RAW */
.rtbtn{{font-size:9px;color:var(--muted);background:none;border:1px solid var(--border);padding:2px 5px;border-radius:2px;cursor:pointer;margin:2px 2px 0 0;}}
.rtbtn:hover{{color:var(--text);}}
pre.raw{{background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:8px;overflow-x:auto;font-family:var(--mono);font-size:10px;color:var(--muted);margin-top:3px;white-space:pre;display:none;max-height:260px;}}
/* FOOTER */
.footer{{text-align:center;padding:12px;font-size:10px;color:var(--muted);font-family:var(--mono);border-top:1px solid var(--border);}}
/* TOOLTIP */
[title]{{cursor:help;border-bottom:1px dotted var(--muted);}}
/* PRINT */
@media print{{
  .sidebar,.filterbar,.harrow,.rtbtn,.method-body{{display:none!important;}}
  .main{{width:100%;}}
  .hbody.closed{{display:block!important;}}
  .method-body{{display:none!important;}}
  pre.raw{{display:none!important;}}
  body{{background:#fff;color:#000;font-size:11px;}}
  :root{{--bg:#fff;--bg2:#f5f5f5;--bg3:#eee;--text:#000;--muted:#555;--border:#ccc;--teal:#0055aa;--amber:#aa5500;--ok:#155724;--warn:#856404;--crit:#721c24;--unk:#666;}}
  .hm-ok{{background:#d4edda;color:#155724;}}.hm-warn{{background:#fff3cd;color:#856404;}}.hm-crit{{background:#f8d7da;color:#721c24;}}
}}
</style>
</head>
<body>
""")

    # LAYOUT + SIDEBAR
    w('<div class="layout"><nav class="sidebar">')
    w('<div class="sb-title">&#x2B22; Hosts</div>')
    w('<div class="sb-search"><input type="text" placeholder="Search..." oninput="sbSearch(this.value)"></div>')
    for h in host_data:
        sv = h["host_sv"]
        # FIX #30: sidebar pct = worst-severity DG pct, not raw max
        worst_dg_pct = next(
            (d["pct_used"] for d in h["dgs"] if d["ws"] == sv),
            max((d["pct_used"] for d in h["dgs"]), default=0)
        )
        idx = host_data.index(h)
        w(f'<div class="sb-item {sv}" onclick="jumpTo(\'hcard_h{idx}\')">'
          f'<span class="sb-dot {sv}"></span>'
          f'<span style="overflow:hidden;text-overflow:ellipsis">{html.escape(h["host"])}</span>'
          f'<span class="sb-pct">{worst_dg_pct:.1f}%</span>'
          f'</div>')
    w('</nav><div class="main">')

    # TOPBAR
    w(f"""<div class="topbar">
  <h1>&#x2B22; ASM Capacity</h1>
  <span class="sub">{html.escape(run_date)} &middot; v3.0</span>
  <span class="meta">Generated: {html.escape(now_str)}<br>
  {len(hosts)} hosts &middot; {lookback}d lookback &middot; {len(all_alerts)} alerts</span>
</div>""")

    # BANNERS
    if reco_critical:
        w('<div class="banner reco">&#x1F6A8; RECO DG CRITICAL &mdash; ORA-19809 RISK: '
          + " | ".join(f"+{r[1]}@{r[0]}: {r[2]:.2f}% ({r[3]:.3f}TB free)" for r in reco_critical)
          + ' &mdash; Verify FRA: SELECT space_limit/1073741824, space_used/1073741824 FROM v$recovery_file_dest</div>')
    if is_monthend:
        w(f'<div class="banner monthend">&#x1F4C5; MONTH-END in {days_to_end}d ({monthend_date}) &mdash; '
          f'Monitor RECO DGs closely for archivelog/batch growth spikes.</div>')
    if all_anomalies:
        w('<div class="banner anomaly">&#x26A1; GROWTH ANOMALIES: '
          + " | ".join(f"+{a[1]}@{a[0]}" for a in all_anomalies) + '</div>')
    if all_changes:
        w(f'<div class="banner changes">&#x1F504; {len(all_changes)} DG(s) changed severity since last week</div>')
    if host_count_changed:
        w('<div class="banner fleet-warn">&#x26A0; Fleet host count changed during lookback &mdash; '
          'fleet trend excludes incomparable periods (hosts added/removed).</div>')

    # EXEC SUMMARY
    w(f"""<div class="exec">
  <div class="status">{html.escape(exec_status)}</div>
  <p>{"<br>".join(exec_lines)}</p>
</div>""")

    # ALERT BAR
    if all_alerts:
        w('<div class="alerts">')
        for rank, ah, adg, atype, amsg in all_alerts:
            cls = "crit" if rank == 2 else "warn"
            w(f'<div class="alert-row {cls}">&#x25B2; {html.escape(amsg)}</div>')
        w('</div>')

    # PLATFORM STRIP
    w('<div class="platforms">')
    fl_w = min(fl_pct, 100)
    w(f"""<div class="plat-card">
  <div class="plat-name">All Platforms</div>
  <div class="plat-pct {fl_sv}">{fpct(fl_pct)}</div>
  <div class="bar-outer"><div class="bar-fill {fl_sv}" style="width:{fl_w:.1f}%"></div></div>
  <div class="plat-sub">{len(hosts)} hosts &middot; {ftb(fl_used)} / {ftb(fl_total)}</div>
</div>""")
    for pname, pd in sorted(platforms.items()):
        pt = pd["total"]; pu = pd["used"]
        pp = round((pu / pt) * 100, 2) if pt else 0
        psv = sev_for_dg({"pct_used": pp, "free_tb": pt - pu, "total_tb": pt, "type": "DATA"})
        pw = min(pp, 100)
        w(f"""<div class="plat-card">
  <div class="plat-name">{html.escape(pname)}</div>
  <div class="plat-pct {psv}">{fpct(pp)}</div>
  <div class="bar-outer"><div class="bar-fill {psv}" style="width:{pw:.1f}%"></div></div>
  <div class="plat-sub">{len(pd['hosts'])} hosts &middot; {ftb(pu)} / {ftb(pt)}</div>
</div>""")
    w('</div>')

    # FLEET TIME SERIES
    ts_vals  = list(fleet_ts.values())
    ts_dates = list(fleet_ts.keys())
    fl_spk   = spark(ts_vals, w=280, h=34, color=SEV_COLOR.get(fl_sv, "#5a7a99")) if len(ts_vals) >= 2 else ""
    fl_delta = round(ts_vals[-1] - ts_vals[0], 2) if len(ts_vals) >= 2 else None
    comparable_note = " (comparable hosts only)" if host_count_changed else ""
    w(f"""<div class="fleet-ts">
  <div class="fkpi"><span class="lbl">Total</span><span class="val">{ftb(fl_total)}</span></div>
  <div class="fkpi"><span class="lbl">Used</span><span class="val {fl_sv}">{ftb(fl_used)}</span></div>
  <div class="fkpi"><span class="lbl">Free</span><span class="val">{ftb(fl_free)}</span></div>
  <div class="fkpi"><span class="lbl">% Used</span><span class="val {fl_sv}">{fpct(fl_pct)}</span></div>
  <div class="fkpi"><span class="lbl">Critical</span><span class="val {"crit" if crit_count else "ok"}">{crit_count}</span></div>
  <div class="fkpi"><span class="lbl">Warning</span><span class="val {"warn" if warn_count else "ok"}">{warn_count}</span></div>
  <div class="fkpi"><span class="lbl">Anomalies</span><span class="val {"warn" if all_anomalies else "ok"}">{len(all_anomalies)}</span></div>
  <div style="flex:1;min-width:200px">
    <div style="font-size:9px;color:var(--muted);margin-bottom:2px;text-transform:uppercase;letter-spacing:.07em">
      Fleet Used TB trend{html.escape(comparable_note)} &mdash; 
      {html.escape(ts_dates[0] if ts_dates else "")} to {html.escape(ts_dates[-1] if ts_dates else "")}
      {"(" + fdelta(fl_delta) + ")" if fl_delta is not None else ""}
    </div>
    {fl_spk}
  </div>
</div>""")

    # FILTER BAR
    all_plats = sorted(set(h["platform"] for h in host_data))
    w("""<div class="filterbar">
  <button class="fbtn" onclick="setFilter('all',this)">All</button>
  <button class="fbtn fcrit" onclick="setFilter('crit',this)">&#x2716; Critical</button>
  <button class="fbtn fwarn" onclick="setFilter('warn',this)">&#x26A0; Warning</button>""")
    for pf in all_plats:
        w(f'  <button class="fbtn" onclick="setFilter(\'plat_{html.escape(pf)}\',this)">{html.escape(pf)}</button>')
    w('</div>')

    # TOP 3
    medals = ["&#x1F947; #1 Largest", "&#x1F948; #2 Largest", "&#x1F949; #3 Largest"]
    w('<div class="top3">')
    for i, dg in enumerate(top_dgs):
        h_name = next((h["host"] for h in host_data for d in h["dgs"]
                       if d["dg"] == dg["dg"] and abs(d["used_tb"] - dg["used_tb"]) < 0.001), "?")
        g   = dg["g"]; sv_ = dg["sv"]; clr = SEV_COLOR.get(sv_, "#5a7a99")
        pw  = min(dg["pct_used"], 100)
        spk_ = spark([r["used_tb"] for r in g["history"]], w=185, h=32, color=clr) if g["history"] else ""
        gs  = g["growth_state"]
        trend_s = (fdelta(g["slope_month"]).replace("&nbsp;", "") + "/mo"
                   if gs == "growing" and g["slope_month"] else
                   "Stable" if gs == "stable" else
                   "Shrinking" if gs == "shrinking" else "—")
        redund, rclr = infer_redundancy(dg["free_tb"], dg["usable_tb"])
        w(f"""<div class="t3card">
  <div class="t3rank">{medals[i]}</div>
  <div class="t3dg">+{html.escape(dg['dg'])}</div>
  <div class="t3host">{html.escape(h_name)} &middot; <span style="color:{DG_LABELS.get(dg['type'],('','var(--muted)'))[1]}">{dg['type']}</span> &middot; <span style="color:{rclr};font-size:9px" title="Estimated from USABLE/FREE ratio. Verify: SELECT redundancy FROM v$asm_diskgroup">{html.escape(redund)}</span></div>
  <div class="t3used" style="color:{clr}">{ftb(dg['used_tb'])}</div>
  <div class="bar-outer"><div class="bar-fill {sv_}" style="width:{pw:.1f}%"></div></div>
  {spk_}
  <div class="t3info">{fpct(dg['pct_used'])} used &middot; {html.escape(trend_s)}<br>
  Free: {ftb(dg['free_tb'])}<br>
  {"Full in: " + fdays_both(g['days_full'], g['days_full_14d']) + " (" + g['conf'] + " conf)" if g['days_full'] else g['growth_state'].upper()}
  </div>
</div>""")
    w('</div>')

    # HEATMAP — FIX #29: 1dp in cells
    w('<div class="heatmap"><h2>&#x25A6; Fleet Heatmap &mdash; Bird&#x27;s Eye View (sorted by severity)</h2>')
    w('<div class="hm-wrap"><table class="hm-table"><thead><tr><th class="host-th">Host</th>')
    for dgn in all_dg_names:
        dtype = classify_dg(dgn)
        tlabel, tcolor = DG_LABELS.get(dtype, ("?", "var(--muted)"))
        w(f'<th style="color:{tcolor}" title="{html.escape(tlabel)}">+{html.escape(dgn)}</th>')
    w('</tr></thead><tbody>')
    for h in host_data:
        dg_map   = {d["dg"]: d for d in h["dgs"]}
        stale_s  = " &#x23F0;" if h["stale"] else ""
        w(f'<tr><td class="host-td">{html.escape(h["host"])}{stale_s}</td>')
        for dgn in all_dg_names:
            if dgn in dg_map:
                d   = dg_map[dgn]
                sv_ = d["sv"]
                # FIX #29: 1dp for heatmap cells
                tip = (f"+{dgn}: {d['pct_used']:.2f}% | "
                       f"{d['used_tb']:.3f}/{d['total_tb']:.3f}TB | "
                       f"{d['free_tb']:.3f}TB free | {d['type']}")
                w(f'<td><span class="hm-cell hm-{sv_}" title="{html.escape(tip)}">'
                  f'{d["pct_used"]:.1f}%</span></td>')
            else:
                w('<td><span class="hm-cell hm-na">—</span></td>')
        w('</tr>')
    w('</tbody></table></div></div>')

    # RUNWAY TABLE
    if runway_list:
        w('<div class="runway"><h2>&#x231B; Capacity Runway — DGs Filling Soonest</h2>')
        w("""<table class="rw-table"><thead><tr>
  <th>Host</th><th>DG</th><th>Type</th><th>Mirror (est.)</th>
  <th>% Used</th><th>Free TB</th>
  <th>Days Full (30d)</th><th>Days Full (14d)</th>
  <th>Projected Date (30d)</th><th>Starting Point for Action</th>
</tr></thead><tbody>""")
        for days, rhost, rdg, rpct, rproj, rtype, rfree, days14, proj14 in runway_list[:15]:
            dv_ = dsev(days)
            redund, rclr = infer_redundancy(rfree, None)
            action = {
                "RECO": "Reduce RMAN retention / check v$recovery_file_dest. On standby: check redo apply.",
                "DATA": "Add diskgroup capacity or purge/archive obsolete data.",
                "OCR":  "INVESTIGATE IMMEDIATELY — OCR/VOTE should never grow.",
            }.get(rtype, "Review workload growth.")
            badge30 = (' <span style="color:var(--crit)">&#x2716; CRIT</span>' if days <= CRIT_DAYS
                       else ' <span style="color:var(--warn)">&#x26A0; WARN</span>' if days <= WARN_DAYS else "")
            badge14 = ""
            if days14 is not None:
                badge14 = (f'<span class="crit">{days14:,}d</span>' if days14 <= CRIT_DAYS
                           else f'<span class="warn">{days14:,}d</span>' if days14 <= WARN_DAYS
                           else f'{days14:,}d')
            w(f"""<tr>
  <td style="font-family:var(--mono)">{html.escape(rhost)}</td>
  <td style="font-family:var(--mono);font-weight:700">+{html.escape(rdg)}</td>
  <td style="color:{DG_LABELS.get(rtype,('','var(--muted)'))[1]};font-size:9px">{rtype}</td>
  <td style="color:{rclr};font-size:9px" title="Estimated. Verify: SELECT redundancy FROM v$asm_diskgroup">{html.escape(redund)}</td>
  <td class="{dv_}">{fpct(rpct)}</td>
  <td class="{dv_}">{ftb(rfree)}</td>
  <td class="{dv_}">{fdays(days)}{badge30}</td>
  <td>{badge14 if badge14 else '—'}</td>
  <td style="font-family:var(--mono);font-size:10px">{html.escape(str(rproj) if rproj else '—')}</td>
  <td style="font-size:10px;color:var(--text)">{html.escape(action)}</td>
</tr>""")
        w('</tbody></table>')
        w('<p style="font-size:9px;color:var(--muted);margin-top:4px;font-family:var(--mono)">'
          '30d = OLS linear regression over full lookback. '
          '14d = OLS over last 14 days (more sensitive to recent acceleration). '
          'Both are linear projections assuming constant growth rate. '
          'Actual fill date may vary due to seasonality or workload changes.</p>')
        w('</div>')

    # WEEK-OVER-WEEK CHANGES
    if all_changes:
        w('<div class="changes"><h2>&#x1F504; Week-over-Week Threshold Changes</h2>')
        w("""<table class="ch-table"><thead><tr>
  <th>Host</th><th>DG</th><th>Last Week</th><th>This Week</th><th>Delta Used</th><th>Direction</th>
</tr></thead><tbody>""")
        for ch_host, ch in all_changes:
            arrow = ("&#x2197; Degraded" if ch["new_sv"] != "ok" and ch["old_sv"] == "ok"
                     else "&#x2197; Worsened" if ch["new_sv"] == "crit" and ch["old_sv"] == "warn"
                     else "&#x2198; Improved")
            clr = "var(--crit)" if "Degrad" in arrow or "Wors" in arrow else "var(--ok)"
            w(f"""<tr>
  <td style="font-family:var(--mono)">{html.escape(ch_host)}</td>
  <td style="font-family:var(--mono);font-weight:700">+{html.escape(ch['dg'])}</td>
  <td class="{ch['old_sv']}">{fpct(ch['old_pct'])} ({ch['old_sv'].upper()})</td>
  <td class="{ch['new_sv']}">{fpct(ch['new_pct'])} ({ch['new_sv'].upper()})</td>
  <td>{fdelta(ch['delta_used'])}</td>
  <td style="color:{clr}">{arrow}</td>
</tr>""")
        w('</tbody></table></div>')

    # HOST CARDS
    w('<div class="content">')
    for idx, hd in enumerate(host_data):
        sv   = hd["host_sv"]
        iclr = SEV_COLOR.get(sv, "#5a7a99")
        icon = SEV_ICON.get(sv, "?")
        htotal = sum(d["total_tb"] for d in hd["dgs"])
        hused  = sum(d["used_tb"]  for d in hd["dgs"])
        hpct   = round((hused / htotal) * 100, 2) if htotal else 0
        cid    = f"h{idx}"

        stale_s = f'<span class="hstale">&#x23F0; STALE {hd["age_h"]:.0f}h</span>' if hd["stale"] else ""
        ts_s    = f'<span class="hts">{html.escape(hd["ts_str"][:19])}</span>' if hd["ts_str"] else ""
        corr_s  = ('<span style="color:#c39bd3;font-size:9px;font-family:var(--mono)">&#x26A1; CORRELATED</span>'
                   if hd["corr_msg"] else "")
        unk_s   = ('<span style="color:var(--unk);font-size:9px;font-family:var(--mono)">NO DG DATA</span>'
                   if not hd["dgs"] else "")

        w(f"""<div class="hcard" id="hcard_{cid}"
     data-crit="{'true' if sv=='crit' else 'false'}"
     data-warn="{'true' if sv in ('crit','warn') else 'false'}"
     data-platform="{html.escape(hd['platform'])}"
     data-host="{html.escape(hd['host'])}">
<div class="hcard-head" onclick="tog('{cid}')">
  <span style="color:{iclr}">{icon}</span>
  <span class="hname">{html.escape(hd['host'])}</span>
  <span class="hplat">{html.escape(hd['platform'])}</span>
  {stale_s}{ts_s}{corr_s}{unk_s}
  <span class="hmeta">{ftb(hused)} / {ftb(htotal)} ({hpct:.2f}%)</span>
  <span class="harrow" id="{cid}_a">&#x25BC;</span>
</div>
<div class="hbody" id="{cid}_b">
""")

        # Parse warnings
        if hd["parse_warnings"]:
            for pw in hd["parse_warnings"]:
                w(f'<div class="parse-warn">&#x26A0; {html.escape(pw)}</div>')

        # Correlated growth
        if hd["corr_msg"]:
            w(f'<p style="color:#c39bd3;font-family:var(--mono);font-size:10px;margin-bottom:8px">'
              f'&#x26A1; {html.escape(hd["corr_msg"])}</p>')

        # DG TABLE
        if hd["dgs"]:
            w('<p class="slabel">Diskgroup Capacity &amp; Growth</p>')
            w("""<table class="dgt"><thead><tr>
  <th>DG</th><th>Type</th><th>Mirror (est.)</th>
  <th>Total</th><th>Used</th><th>Free</th><th>Usable</th>
  <th colspan="2" title="USED/TOTAL physical utilisation">% Used</th>
  <th>Gr/Day</th><th>Gr/Wk</th><th>Gr/Mo</th>
  <th title="WoW = actual days shown in parentheses">WoW</th>
  <th title="MoM = actual days shown in parentheses">MoM</th>
  <th title="30d OLS regression projection">Full (30d)</th>
  <th title="14d OLS projection — more sensitive to recent acceleration">Full (14d)</th>
  <th>State</th>
  <th title="In WARN since: ≤ prefix = already in threshold at start of lookback window">WARN since</th>
  <th title="In CRIT since: ≤ prefix = already in threshold at start of lookback window">CRIT since</th>
  <th title="% recomputed = column order was auto-detected and swapped">Src</th>
  <th>Trend</th><th title="LOW&lt;7pts MED&lt;14pts HIGH>=14pts / date-range">Conf</th>
</tr></thead><tbody>""")
            for d in hd["dgs"]:
                g    = d["g"]
                sv_  = d["sv"]; dv_ = d["dv"]; ws = d["ws"]
                pw   = min(d["pct_used"], 100); clr = SEV_COLOR.get(sv_, "#5a7a99")
                spk_ = (spark([r["pct_used"] for r in g["history"]], w=50, h=12, color=clr)
                        if len(g["history"]) >= 2 else "—")
                cl_, cc_ = confidence(g["pts"], g["date_range_days"])
                tlabel, tcolor = DG_LABELS.get(d["type"], ("?", "var(--muted)"))
                redund = d["redund"]; rclr = d["redund_color"]
                audit  = d["audit"]
                anom_s = (' <span style="color:#c39bd3;font-size:9px">&#x26A1;</span>'
                          if g["anomaly"] else "")
                usable_s = ftb(d["usable_tb"]) if d["usable_tb"] is not None else "—"
                # FIX #6: mark recomputed pct
                pct_src = (
                    '<span title="% recomputed: column order auto-detected and swapped" '
                    'style="color:var(--warn);font-size:9px">R</span>'
                    if d.get("pct_recomputed") else
                    '<span style="color:var(--ok);font-size:9px">O</span>'
                )
                # FIX #21/#22: growth state cell
                gs = g["growth_state"]
                gs_cell = {
                    "stable":   '<span style="color:var(--ok);font-size:9px">Stable</span>',
                    "shrinking":'<span style="color:#9b59b6;font-size:9px">&#x2193; Shrink</span>',
                    "growing":  "",
                    "unknown":  '<span style="color:var(--unk);font-size:9px">?</span>',
                }.get(gs, "")
                # Dual projection (FIX #2)
                proj_cell = fdays_both(g["days_full"], None)   # 30d col
                proj14_cell = (f'<span class="{dsev(g["days_full_14d"])}">{fdays(g["days_full_14d"])}</span>'
                               if g["days_full_14d"] is not None else "—")
                # WoW/MoM with actual days (FIX #3)
                wow_s = fdelta(g["wow"], g["wow_days"])
                mom_s = fdelta(g["mom"], g["mom_days"])
                # Conf with pts/range (FIX #13)
                conf_s = (f'<span style="color:{cc_};font-size:9px" '
                          f'title="{g["pts"]} data points over {g["date_range_days"]} days">'
                          f'{cl_} {g["pts"]}/{g["date_range_days"]}d</span>')
                w(f"""<tr>
  <td class="dg-name {ws}">+{html.escape(d['dg'])}{anom_s}</td>
  <td><span style="color:{tcolor};font-size:9px">{html.escape(tlabel)}</span></td>
  <td><span style="color:{rclr};font-size:9px" title="Estimated from USABLE/FREE ratio. Verify: SELECT redundancy FROM v$asm_diskgroup WHERE name='{d['dg']}'">{html.escape(redund)}</span></td>
  <td>{ftb(d['total_tb'])}</td>
  <td class="{sv_}">{ftb(d['used_tb'])}</td>
  <td class="{"crit" if d["free_tb"]<MIN_FREE_TB_ABS else "ok"}">{ftb(d['free_tb'])}</td>
  <td title="Allocatable space after mirror overhead. Thresholds use USED/TOTAL, not USABLE.">{usable_s}</td>
  <td class="{sv_}">{fpct(d['pct_used'])}</td>
  <td><span class="ubar"><span class="ufill" style="width:{pw:.0f}%;background:{clr}"></span></span></td>
  <td>{fdelta(g['slope_day'])}</td>
  <td>{fdelta(g['slope_week'])}</td>
  <td>{fdelta(g['slope_month'])}</td>
  <td>{wow_s}</td>
  <td>{mom_s}</td>
  <td class="{dv_}">{fdays(g['days_full'])}</td>
  <td>{proj14_cell}</td>
  <td>{gs_cell}</td>
  <td style="font-size:9px;color:var(--warn)">{html.escape(audit['first_warn'] or '—')}</td>
  <td style="font-size:9px;color:var(--crit)">{html.escape(audit['first_crit'] or '—')}</td>
  <td>{pct_src}</td>
  <td>{spk_}</td>
  <td>{conf_s}</td>
</tr>""")
            w("</tbody></table>")
            # USABLE footnote (FIX #17)
            w('<p style="font-size:9px;color:var(--muted);margin-top:3px;font-family:var(--mono)">'
              'USABLE = allocatable space after ASM mirror overhead. '
              'Alert thresholds use USED/TOTAL (physical %). '
              'Mirror estimate from USABLE/FREE ratio &mdash; verify with v$asm_diskgroup. '
              'Conf: pts/range = data points / lookback days (sparsity matters). '
              'WARN/CRIT since: &le; prefix = DG was already in threshold at start of lookback window.</p>')

            # RECOMMENDATIONS
            all_recs = [(d["dg"], d["type"], r) for d in hd["dgs"] for r in d["recs"]
                        if "No capacity concerns" not in r]
            if all_recs:
                w('<p class="slabel" style="margin-top:8px">Recommendations &amp; Queries</p>')
                w('<ul class="rec-list">')
                for dg_n, dg_t, rec in all_recs:
                    tlabel, tcolor = DG_LABELS.get(dg_t, ("?", "var(--muted)"))
                    w(f'<li>'
                      f'<span style="color:var(--teal);font-family:var(--mono)">+{html.escape(dg_n)}</span>'
                      f'<span class="tag" style="color:{tcolor}">{html.escape(tlabel)}</span> '
                      f'{html.escape(rec)}'
                      f'</li>')
                w('</ul>')

            # SNAPSHOT COMPARISON
            dgs_snap = [d for d in hd["dgs"] if d["g"]["pts"] > 0]
            if dgs_snap:
                w('<p class="slabel" style="margin-top:8px">Historical Snapshot Comparison</p>')
                w('<table class="snap"><thead><tr>')
                w('<th>DG</th><th>Now (Used)</th>'
                  '<th>7d ago</th><th>&#x0394; 7d (actual days)</th>'
                  '<th>30d ago</th><th>&#x0394; 30d (actual days)</th>'
                  '<th>State</th><th>Trend</th>')
                w('</tr></thead><tbody>')
                for d in dgs_snap:
                    g    = d["g"]
                    h7   = round(g["history"][-1]["used_tb"] - g["wow"], 3) if g["wow"] is not None else None
                    h30  = round(g["history"][-1]["used_tb"] - g["mom"], 3) if g["mom"] is not None else None
                    spk2 = (spark([r["used_tb"] for r in g["history"]], w=65, h=12,
                                  color=SEV_COLOR.get(d["sv"], "#5a7a99"))
                            if len(g["history"]) >= 2 else "")
                    gs = g["growth_state"]
                    gs_s = "Stable" if gs == "stable" else "&#x2193;Shrink" if gs == "shrinking" else ""
                    w(f"""<tr>
  <td class="{d['ws']}">+{html.escape(d['dg'])}</td>
  <td>{ftb(g['history'][-1]['used_tb'] if g['history'] else None)}</td>
  <td>{ftb(h7)}</td><td>{fdelta(g['wow'], g['wow_days'])}</td>
  <td>{ftb(h30)}</td><td>{fdelta(g['mom'], g['mom_days'])}</td>
  <td style="font-size:9px;color:var(--ok)">{gs_s}</td>
  <td>{spk2}</td>
</tr>""")
                w('</tbody></table>')

            # GROWTH CHARTS
            dgs_hist = [d for d in hd["dgs"] if len(d["g"]["history"]) >= 2]
            if dgs_hist:
                w('<p class="slabel" style="margin-top:8px">Growth Trend Charts (Used TB)</p>')
                w('<div class="chart-grid">')
                for d in dgs_hist:
                    g    = d["g"]; clr = SEV_COLOR.get(d["sv"], "#5a7a99")
                    svg  = spark([r["used_tb"] for r in g["history"]], w=205, h=36, color=clr)
                    cl_, cc_ = confidence(g["pts"], g["date_range_days"])
                    anom_note = (f'<br><span style="color:#c39bd3">&#x26A1; {html.escape(g["anomaly_msg"][:80])}</span>'
                                 if g["anomaly"] else "")
                    shrink_note = ('<br><span style="color:#9b59b6">&#x2193; Shrinking (purge/delete detected)</span>'
                                   if g["shrinking"] else "")
                    w(f"""<div class="chart-box">
  <div class="chart-title">+{html.escape(d['dg'])} &nbsp;
    <span style="color:{cc_};font-size:9px" title="{g['pts']} pts / {g['date_range_days']}d">{cl_}</span>
  </div>
  {svg}
  <div class="chart-sub">
    {html.escape(g['history'][0]['date'])} &#x2192; {html.escape(g['history'][-1]['date'])}<br>
    30d: {fdelta(g['slope_month'])}/mo &middot; Full: <span class="{d['dv']}">{fdays(g['days_full'])}</span>
    {"/ 14d: " + fdays(g['days_full_14d']) if g['days_full_14d'] is not None else ""}
    {anom_note}{shrink_note}
  </div>
</div>""")
                w('</div>')

        else:
            # FIX #23: empty host = UNKNOWN, not OK
            w('<p style="color:var(--unk);font-style:italic;padding:5px 0">'
              'No diskgroup data parsed. Check dg_summary.txt for parse errors above.</p>')

        # SUBDIR
        if hd["subdirs"]:
            w('<p class="slabel" style="margin-top:8px">DG Root Subdir Detail</p>')
            for name, txt in hd["subdirs"]:
                rid = f"{cid}_{name}_r"
                w(f'<button class="rtbtn" onclick="togr(\'{rid}\')">{html.escape(name)}</button>')
                w(f'<pre class="raw" id="{rid}">{html.escape(txt.strip())}</pre>')

        # RAW
        w('<p class="slabel" style="margin-top:8px">Raw asmdu Output</p>')
        r2, r3 = f"{cid}_sr", f"{cid}_er"
        w(f'<button class="rtbtn" onclick="togr(\'{r2}\')">stdout</button>')
        w(f'<pre class="raw" id="{r2}">{html.escape(hd["raw_sum"].strip() or "(empty)")}</pre>')
        if hd["raw_err"].strip():
            w(f'<button class="rtbtn" onclick="togr(\'{r3}\')">stderr</button>')
            w(f'<pre class="raw" id="{r3}">{html.escape(hd["raw_err"].strip())}</pre>')

        w('</div></div>')   # hbody, hcard

    w('</div>')   # content

    # METHODOLOGY SECTION (FIX #31)
    w("""<div class="method">
<h2 onclick="togMethod()">&#x2139; Report Methodology (click to expand)</h2>
<div class="method-body" id="method_body">
<dl>
<dt>Growth Rate</dt>
<dd>Ordinary Least Squares (OLS) linear regression of USED_TB against calendar date
    over the full lookback window (30d default). Numerically stable: X values are
    centered around their mean before regression to prevent floating-point cancellation.
    Expressed as TB/day, TB/week, TB/month (day x 7, day x 30).</dd>

<dt>30d vs 14d Projection</dt>
<dd>Two projections are shown. 30d (conservative): regression over full lookback,
    less sensitive to recent spikes. 14d (aggressive): regression over last 14 days,
    picks up recent acceleration. Use 14d for early warning; use 30d for planning.
    Formula: free_TB / slope_TB_per_day. Linear projection only — assumes constant
    growth rate. Actual fill date will vary with seasonality and workload changes.</dd>

<dt>Data Points / Confidence</dt>
<dd>LOW &lt; 7 data points. MED &lt; 14 points. HIGH &ge; 14 points.
    Format: "HIGH 28/30d" = 28 actual collection days out of 30-day lookback window.
    Sparsity matters: 7 points over 30 days &lt; 7 consecutive daily points.
    Gaps occur when cron collection failed or host was unreachable.</dd>

<dt>WoW / MoM Deltas</dt>
<dd>Week-over-week: USED_TB today minus closest historical point &le; 7 days ago.
    If a collection was missed, the actual day count is shown in parentheses (e.g. "8d")
    so the DBA knows the delta spans more than 7 days.</dd>

<dt>Anomaly Detection</dt>
<dd>Recent 3-day average rate = (USED[-1] - USED[-4]) / 3 TB/day.
    Flagged if: recent rate &gt; 2.5x the 30d baseline rate AND
    recent rate &gt; 0.1 TB/day absolute minimum.
    The two-condition requirement prevents false positives from tiny DGs
    where a 3-point linreg produces noisy results.</dd>

<dt>Severity Thresholds</dt>
<dd>DATA DGs: WARN &ge; 75%, CRIT &ge; 85%.
    RECO/FRA DGs: WARN &ge; 65%, CRIT &ge; 75% (tighter — ORA-19809 risk).
    OCR/VOTE: same as DATA but growth itself is anomalous.
    Absolute floor: CRIT if free &lt; 0.2 TB regardless of %; WARN if free &lt; 0.5 TB
    on DGs &lt; 2 TB total (prevents misleading % on small DGs).
    Universal floor: WARN if free &lt; 1 TB on any DG &lt; 2 TB total.
    Per-host overrides: set warn_pct / crit_pct in meta.json or host_vars.</dd>

<dt>Mirror Estimate</dt>
<dd>Redundancy is ESTIMATED from the USABLE/FREE ratio: ratio &gt; 0.85 = EXTERNAL,
    &gt; 0.40 = NORMAL, else = HIGH. On Exadata, partner disk pre-allocation and
    smart scan extents can shift this ratio. Always verify with:
    SELECT name, redundancy FROM v$asm_diskgroup;</dd>

<dt>% Used Source</dt>
<dd>Src column: O = original value from asmdu output (preferred).
    R = recomputed from USED/TOTAL (occurs when column order was auto-detected and
    swapped). Recomputation adds &lt; 0.01% error on large DGs. If you see R on a
    DG, compare against: SELECT pct_used FROM v$asm_diskgroup WHERE name='&lt;DG&gt;'</dd>

<dt>WARN/CRIT Since</dt>
<dd>First date in the lookback window where the DG exceeded the threshold.
    A &le; prefix means the DG was ALREADY in that state at the start of the lookback
    window — the true first crossing date is earlier than shown.</dd>

<dt>Fleet Trend</dt>
<dd>Total USED_TB across all hosts per day. Only days where ALL currently-monitored
    hosts have data are included (comparable fleet). If host count changed during
    lookback, incomparable days are excluded and a warning banner is shown.</dd>

<dt>Stale Data</dt>
<dd>Host data is marked STALE if the collection timestamp in meta.json is &gt; 25h old.
    Falls back to file mtime if meta.json has no timestamp. NFS remounts can
    preserve old mtimes, so meta.json timestamp is preferred.</dd>

<dt>Seasonal Note</dt>
<dd>Month-end flag raised if run date is within 5 days of the last day of the month.
    Linear regression does not account for month-end batch/archivelog spikes.
    Treat projections near month-end with additional caution.</dd>

<dt>Disclaimer</dt>
<dd>All capacity projections are estimates based on observed historical trends.
    They assume linear growth continuation. Actual behaviour depends on workload
    patterns, DBAs purging data, ASM rebalancing, and other operational events.
    This report is an operational aid, not a guarantee. Always verify critical
    figures directly against v$asm_diskgroup and v$recovery_file_dest.</dd>
</dl>
</div>
</div>""")

    # FOOTER
    w(f"""<div class="footer">
  ASM Capacity Dashboard v3.0 &middot; {html.escape(run_date)} &middot;
  {len(hosts)} hosts &middot; {len(all_alerts)} alerts &middot; {html.escape(now_str)}
  &nbsp;|&nbsp;
  <a href="#" onclick="window.print();return false">&#x1F5A8; Print / PDF</a>
</div>
</div></div><!-- main, layout -->

<script>
function tog(id){{
  var b=document.getElementById(id+'_b'),a=document.getElementById(id+'_a');
  if(!b)return;
  if(b.classList.contains('closed')){{b.classList.remove('closed');a.innerHTML='&#x25BC;';}}
  else{{b.classList.add('closed');a.innerHTML='&#x25B6;';}}
}}
function togr(id){{
  var el=document.getElementById(id);
  if(el) el.style.display=el.style.display==='block'?'none':'block';
}}
function togMethod(){{
  var el=document.getElementById('method_body');
  if(el) el.classList.toggle('open');
}}
function jumpTo(id){{
  var el=document.getElementById(id);
  if(!el)return;
  el.scrollIntoView({{behavior:'smooth',block:'start'}});
  var idx=id.replace('hcard_','');
  var b=document.getElementById(idx+'_b');
  if(b)b.classList.remove('closed');
  var a=document.getElementById(idx+'_a');
  if(a)a.innerHTML='&#x25BC;';
}}
function sbSearch(val){{
  val=val.toLowerCase();
  document.querySelectorAll('.sb-item').forEach(function(el){{
    el.style.display=el.textContent.toLowerCase().indexOf(val)>=0?'':'none';
  }});
}}
var activeFilter='all';
function setFilter(f,btn){{
  activeFilter=f;
  document.querySelectorAll('.fbtn').forEach(function(b){{b.classList.remove('active');}});
  if(btn)btn.classList.add('active');
  document.querySelectorAll('.hcard').forEach(function(c){{
    var show=true;
    if(f==='crit')       show=c.getAttribute('data-crit')==='true';
    else if(f==='warn')  show=c.getAttribute('data-warn')==='true';
    else if(f.startsWith('plat_')) show=c.getAttribute('data-platform')===f.substring(5);
    c.style.display=show?'':'none';
  }});
}}
document.addEventListener('DOMContentLoaded',function(){{
  document.querySelectorAll('.hcard').forEach(function(c){{
    var id=c.id.replace('hcard_','');
    var b=document.getElementById(id+'_b');
    var a=document.getElementById(id+'_a');
    if(!b)return;
    if(c.getAttribute('data-crit')==='true'){{
      b.classList.remove('closed');
      if(a)a.innerHTML='&#x25BC;';
    }}else{{
      b.classList.add('closed');
      if(a)a.innerHTML='&#x25B6;';
    }}
  }});
}});
</script>
</body></html>""")

    return "\n".join(H), csv_rows

# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    p = argparse.ArgumentParser(
        description="ASMDU HTML Capacity Report Builder v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 build_html_report.py /your/nas/runs 2026-03-06
  python3 build_html_report.py /your/nas/runs 2026-03-06 --lookback 35

Output files (in NAS_RUNS_ROOT/RUN_DATE/):
  report.html  -- self-contained HTML dashboard
  report.csv   -- machine-readable data with all computed fields
""")
    p.add_argument("nas_runs_root", help="Root directory containing dated run folders")
    p.add_argument("run_date",      help="Report date YYYY-MM-DD")
    p.add_argument("--lookback",    type=int, default=30,
                   help="Days of history for growth trend analysis (default: 30)")
    args = p.parse_args()
    try:
        parse_iso_date(args.run_date)
    except ValueError:
        raise SystemExit(f"[ERROR] Invalid date '{args.run_date}' — use YYYY-MM-DD format")

    print(f"[ASMDU] Building report for {args.run_date} (lookback={args.lookback}d)...")
    html_str, csv_rows = build_report(args.nas_runs_root, args.run_date, args.lookback)

    base  = os.path.join(args.nas_runs_root, args.run_date)
    out_h = os.path.join(base, "report.html")
    out_c = os.path.join(base, "report.csv")
    with open(out_h, "w", encoding="utf-8") as f:
        f.write(html_str)
    print(f"[OK] HTML  : {out_h}  ({len(html_str):,} bytes)")
    write_csv(out_c, csv_rows)
    print(f"[OK] CSV   : {out_c}  ({len(csv_rows)} rows, {len(csv_rows[0]) if csv_rows else 0} columns)")

if __name__ == "__main__":
    main()
