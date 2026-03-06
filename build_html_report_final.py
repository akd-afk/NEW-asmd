#!/usr/bin/env python3
# Final hardened ASM Capacity Report Builder
# Python 3.6 compatible
#
# Outputs:
#   asm_capacity_report_<DATE>.html
#   asm_capacity_data_<DATE>.csv
#
# Usage:
#   python3 build_html_report_final.py <runs_root> <YYYY-MM-DD> [--lookback N]

import os
import re
import sys
import csv
import html
import math
import datetime
from collections import defaultdict

DEFAULT_LOOKBACK_DAYS = 30


def parse_iso_date(value):
    return datetime.datetime.strptime(value, "%Y-%m-%d").date()


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def clean_line(line):
    return re.sub(r'\x1b\[[0-9;]*m', '', line).rstrip("\n")


def classify_platform(host):
    h = host.lower()
    if h.startswith("ex") or "exa" in h:
        return "Exadata"
    return "VMware"


def classify_dg(dg):
    d = dg.upper().lstrip("+")
    if d in ("DATAC1", "DATA"):
        return "DB Files"
    if d in ("RECOC1", "RECO"):
        return "Arch/Backup"
    if d == "OCR":
        return "OCR/Voting"
    return "Other"


def dg_weight(dg):
    d = dg.upper().lstrip("+")
    if d in ("DATAC1", "DATA"):
        return 1
    if d in ("RECOC1", "RECO"):
        return 2
    if d == "OCR":
        return 3
    return 9


def fmt_num(v, digits=2):
    if v is None:
        return "N/A"
    return ("%0." + str(digits) + "f") % v


def parse_dg_summary(text):
    """
    Parse asmdu dg summary rows from dg_summary.txt.
    Supports rows like:
      DATAC1 HIGH 598.72 159.15 26
      RECOC1 NORMAL 149.71 135.57 90
    Treats last numeric column as % Free.
    """
    rows = []
    seen = set()

    for raw in text.splitlines():
        line = clean_line(raw).strip()
        if not line:
            continue

        low = line.lower()
        if ("instances running" in low or "diskgroup" in low or "redundancy" in low
                or "note :" in low or set(line) <= set("- ")):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        dg = parts[0].lstrip("+").upper()
        if not re.match(r'^[A-Z][A-Z0-9_-]*$', dg):
            continue

        redundancy = parts[1].upper()
        if redundancy not in ("HIGH", "NORMAL", "EXTERN", "EXT", "FLEX", "EXTEND"):
            continue

        nums = parts[2:]
        try:
            total_tb = float(nums[0])
            usable_tb = float(nums[1])
            pct_free = float(nums[2])
        except Exception:
            continue

        if dg in seen:
            continue
        seen.add(dg)

        used_tb = max(0.0, total_tb - usable_tb)
        pct_used = max(0.0, min(100.0, 100.0 - pct_free))

        rows.append({
            "dg": dg,
            "type": classify_dg(dg),
            "redundancy": redundancy,
            "total_tb": round(total_tb, 3),
            "used_tb": round(used_tb, 3),
            "free_tb": round(usable_tb, 3),
            "usable_tb": round(usable_tb, 3),
            "pct_used": round(pct_used, 1),
        })

    rows.sort(key=lambda r: dg_weight(r["dg"]))
    return rows


def parse_root_subdirs(text):
    """
    Parse root subdirectory detail:
      CDSDGP/   431.20 1293.61
      Total     439.55 1318.66
    Returns non-total rows sorted by Used TB descending.
    """
    rows = []
    total_used = None

    for raw in text.splitlines():
        line = clean_line(raw).rstrip()
        if not line.strip():
            continue

        low = line.lower()
        if ("instances running" in low or "subdirectories size" in low or "subdir" in low
                or "used tb" in low or "raw used tb" in low or set(line.strip()) <= set("- ")):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        name = parts[0]
        try:
            used_tb = float(parts[1])
            raw_used_tb = float(parts[2])
        except Exception:
            continue

        if name.lower() == "total":
            total_used = used_tb
            continue

        rows.append({
            "name": name.rstrip("/"),
            "used_tb": round(used_tb, 3),
            "raw_used_tb": round(raw_used_tb, 3),
        })

    rows.sort(key=lambda r: (-r["used_tb"], r["name"]))
    return rows, total_used


def list_run_dates(runs_root):
    out = []
    if not os.path.isdir(runs_root):
        return out
    for name in os.listdir(runs_root):
        full = os.path.join(runs_root, name)
        if not os.path.isdir(full):
            continue
        try:
            out.append((parse_iso_date(name), name))
        except Exception:
            pass
    return sorted(out)


def collect_host_history(runs_root, host, lookback_days):
    history = defaultdict(list)
    all_dates = list_run_dates(runs_root)
    if not all_dates:
        return history

    latest = all_dates[-1][0]
    cutoff = latest - datetime.timedelta(days=max(1, lookback_days))

    for d_obj, d_name in all_dates:
        if d_obj < cutoff:
            continue

        dg_path = os.path.join(runs_root, d_name, host, "dg_summary.txt")
        if not os.path.exists(dg_path):
            continue

        rows = parse_dg_summary(read_text(dg_path))
        for row in rows:
            history[row["dg"]].append((
                d_obj,
                row["used_tb"],
                row["free_tb"],
                row["usable_tb"],
                row["pct_used"],
            ))

    return history


def simple_slope(points):
    """
    points = [(date_obj, value), ...]
    Returns slope in value/day.
    """
    if len(points) < 2:
        return None

    points = sorted(points, key=lambda x: x[0])

    if len(points) < 3:
        span = float((points[-1][0] - points[0][0]).days)
        if span <= 0:
            return None
        return (points[-1][1] - points[0][1]) / span

    x0 = points[0][0]
    xs = [float((d - x0).days) for d, _ in points]
    ys = [float(v) for _, v in points]

    n = float(len(xs))
    sx = sum(xs)
    sy = sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))

    denom = (n * sxx) - (sx * sx)
    if abs(denom) < 1e-9:
        span = float((points[-1][0] - points[0][0]).days)
        if span <= 0:
            return None
        return (points[-1][1] - points[0][1]) / span

    return ((n * sxy) - (sx * sy)) / denom


def trend_label(slope):
    if slope is None:
        return "N/A"
    if slope > 0.05:
        return "Up"
    if slope < -0.05:
        return "Down"
    return "Flat"


def severity_for_dg(pct_used, growth_per_day, days_left):
    if pct_used >= 85.0 or (days_left is not None and days_left <= 30):
        return "Critical"
    if pct_used >= 70.0 or (days_left is not None and days_left <= 90) or (growth_per_day is not None and growth_per_day >= 1.0):
        return "Warning"
    return "Healthy"


def risk_score(pct_used, growth_per_day, days_left):
    score = pct_used
    if growth_per_day is not None:
        score += min(20.0, max(0.0, growth_per_day * 5.0))
    if days_left is not None:
        if days_left <= 30:
            score += 30.0
        elif days_left <= 90:
            score += 15.0
    return round(score, 1)


def top_n_consumers(rows, n, denominator):
    out = []
    for idx, row in enumerate(rows[:n], start=1):
        share = None
        if denominator and denominator > 0:
            share = round((row["used_tb"] / denominator) * 100.0, 1)
        out.append({
            "rank": idx,
            "name": row["name"],
            "used_tb": row["used_tb"],
            "share_pct": share,
        })
    return out


def build_csv(csv_path, all_csv_rows):
    fields = [
        "date",
        "host",
        "platform",
        "dg",
        "dg_type",
        "redundancy",
        "total_tb",
        "used_tb",
        "free_tb",
        "usable_tb",
        "pct_used",
        "growth_tb_day",
        "growth_7d_tb",
        "growth_30d_tb",
        "days_left",
        "trend",
        "top_consumer",
        "top_consumer_used_tb",
        "top_consumer_share_pct",
        "status",
        "action",
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in all_csv_rows:
            clean = {}
            for key in fields:
                value = row.get(key)
                if isinstance(value, float):
                    clean[key] = fmt_num(value, 2)
                else:
                    clean[key] = value
            writer.writerow(clean)


def build_report(runs_root, run_date_str, lookback_days):
    run_date = parse_iso_date(run_date_str)
    run_root = os.path.join(runs_root, run_date_str)
    if not os.path.isdir(run_root):
        raise SystemExit("Run folder not found: %s" % run_root)

    hosts = sorted([h for h in os.listdir(run_root) if os.path.isdir(os.path.join(run_root, h))])

    host_payload = []
    fleet_rows = []
    csv_rows = []

    for host in hosts:
        host_dir = os.path.join(run_root, host)
        dg_rows = parse_dg_summary(read_text(os.path.join(host_dir, "dg_summary.txt")))
        history = collect_host_history(runs_root, host, lookback_days)

        dg_details = []
        worst_score = -1.0
        worst_status = "Healthy"
        worst_dg = ""
        worst_growth = None
        worst_days_left = None
        worst_top_consumer = ""

        for dg in dg_rows:
            hist = history.get(dg["dg"], [])
            slope = simple_slope([(d, used) for (d, used, free, usable, pct) in hist])

            growth_7d = None
            growth_30d = None
            if len(hist) >= 2:
                cutoff_7 = run_date - datetime.timedelta(days=7)
                cutoff_30 = run_date - datetime.timedelta(days=30)

                pts7 = [(d, used) for (d, used, free, usable, pct) in hist if d >= cutoff_7]
                pts30 = [(d, used) for (d, used, free, usable, pct) in hist if d >= cutoff_30]

                if len(pts7) >= 2:
                    growth_7d = round(pts7[-1][1] - pts7[0][1], 2)
                if len(pts30) >= 2:
                    growth_30d = round(pts30[-1][1] - pts30[0][1], 2)

            days_left = None
            if slope is not None and slope > 0.001:
                days_left = round(dg["free_tb"] / slope, 1)

            status = severity_for_dg(dg["pct_used"], slope, days_left)
            score = risk_score(dg["pct_used"], slope, days_left)

            raw_subdir_file = os.path.join(host_dir, "%s_root_subdirs.txt" % dg["dg"])
            sub_rows, sub_total = parse_root_subdirs(read_text(raw_subdir_file))
            top3 = top_n_consumers(sub_rows, 3, dg["used_tb"])
            top_consumer = top3[0]["name"] if top3 else ""
            top_consumer_used = top3[0]["used_tb"] if top3 else None
            top_consumer_share = top3[0]["share_pct"] if top3 else None

            action = "No immediate action required."
            if status == "Critical":
                action = "%s requires immediate review. Growth is driven by %s." % (dg["dg"], top_consumer or "top consumers")
            elif status == "Warning":
                action = "%s should be reviewed. Validate growth trend and cleanup options." % dg["dg"]

            item = dict(dg)
            item.update({
                "growth_per_day": None if slope is None else round(slope, 2),
                "trend": trend_label(slope),
                "days_left": days_left,
                "status": status,
                "score": score,
                "growth_7d": growth_7d,
                "growth_30d": growth_30d,
                "top3": top3,
                "top_consumer": top_consumer,
                "action": action,
                "raw_subdir_file": os.path.basename(raw_subdir_file),
                "raw_subdir_text": read_text(raw_subdir_file),
            })
            dg_details.append(item)

            csv_rows.append({
                "date": run_date_str,
                "host": host,
                "platform": classify_platform(host),
                "dg": dg["dg"],
                "dg_type": dg["type"],
                "redundancy": dg["redundancy"],
                "total_tb": dg["total_tb"],
                "used_tb": dg["used_tb"],
                "free_tb": dg["free_tb"],
                "usable_tb": dg["usable_tb"],
                "pct_used": dg["pct_used"],
                "growth_tb_day": None if slope is None else round(slope, 2),
                "growth_7d_tb": growth_7d,
                "growth_30d_tb": growth_30d,
                "days_left": days_left,
                "trend": trend_label(slope),
                "top_consumer": top_consumer or "N/A",
                "top_consumer_used_tb": top_consumer_used,
                "top_consumer_share_pct": top_consumer_share,
                "status": status,
                "action": action,
            })

            if score > worst_score:
                worst_score = score
                worst_status = status
                worst_dg = dg["dg"]
                worst_growth = item["growth_per_day"]
                worst_days_left = item["days_left"]
                worst_top_consumer = top_consumer

        dg_details.sort(key=lambda x: ({"Critical": 0, "Warning": 1, "Healthy": 2}.get(x["status"], 9), dg_weight(x["dg"])))

        host_payload.append({
            "host": host,
            "platform": classify_platform(host),
            "dg_details": dg_details,
            "worst_status": worst_status,
            "worst_score": max(0.0, worst_score),
            "worst_dg": worst_dg,
            "worst_growth": worst_growth,
            "worst_days_left": worst_days_left,
            "worst_top_consumer": worst_top_consumer,
            "raw_dg_summary": read_text(os.path.join(host_dir, "dg_summary.txt")),
        })

        fleet_rows.append({
            "host": host,
            "platform": classify_platform(host),
            "worst_dg": worst_dg,
            "used_pct": dg_details[0]["pct_used"] if dg_details else 0.0,
            "growth_per_day": worst_growth,
            "days_left": worst_days_left,
            "top_consumer": worst_top_consumer,
            "status": worst_status,
            "score": max(0.0, worst_score),
        })

    fleet_rows.sort(key=lambda x: (-x["score"], x["host"]))
    host_payload.sort(key=lambda x: (-x["worst_score"], x["host"]))

    css = """
    body { font-family: Arial, Helvetica, sans-serif; margin: 24px; color: #111827; background: #f8fafc; }
    h1,h2,h3 { margin: 0 0 10px 0; }
    .meta { color: #475569; margin-bottom: 18px; }
    .card { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px; margin: 14px 0; box-shadow: 0 1px 2px rgba(0,0,0,.03); }
    table { border-collapse: collapse; width: 100%; }
    th, td { padding: 9px 8px; border-bottom: 1px solid #e5e7eb; text-align: left; font-size: 13px; vertical-align: top; }
    th { color: #334155; background: #f8fafc; font-weight: 700; }
    .right { text-align: right; }
    .muted { color: #64748b; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; }
    .healthy { background: #dcfce7; color: #166534; }
    .warning { background: #fef3c7; color: #92400e; }
    .critical { background: #fee2e2; color: #991b1b; }
    .bar-wrap { width: 120px; background: #e5e7eb; border-radius: 999px; height: 10px; position: relative; }
    .bar-fill-healthy { background: #16a34a; height: 10px; border-radius: 999px; }
    .bar-fill-warning { background: #f59e0b; height: 10px; border-radius: 999px; }
    .bar-fill-critical { background: #dc2626; height: 10px; border-radius: 999px; }
    details { margin-top: 10px; }
    summary { cursor: pointer; color: #0f172a; font-weight: 700; }
    pre { background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 8px; white-space: pre-wrap; overflow: auto; font-size: 12px; }
    .section-title { margin-top: 22px; }
    .tight { margin-top: 8px; }
    """

    def badge(status):
        cls = {"Healthy": "healthy", "Warning": "warning", "Critical": "critical"}.get(status, "healthy")
        return '<span class="badge %s">%s</span>' % (cls, html.escape(status))

    def bar_html(pct, status):
        width = max(0, min(100, pct))
        cls = {"Healthy": "bar-fill-healthy", "Warning": "bar-fill-warning", "Critical": "bar-fill-critical"}.get(status, "bar-fill-healthy")
        return '<div class="bar-wrap"><div class="%s" style="width:%s%%;"></div></div>' % (cls, width)

    out = []
    out.append("<!doctype html><html><head><meta charset='utf-8'><title>ASM Capacity Report</title><style>%s</style></head><body>" % css)
    out.append("<h1>ASM Capacity Report</h1>")
    out.append("<div class='meta'>Run date: %s | Lookback: %d days | Hosts analyzed: %d</div>" % (html.escape(run_date_str), lookback_days, len(host_payload)))

    out.append("<div class='card'>")
    out.append("<h2>Fleet Triage</h2>")
    out.append("<table><thead><tr><th>Host</th><th>Platform</th><th>Worst DG</th><th class='right'>Used %</th><th>Utilisation</th><th class='right'>Growth TB/day</th><th class='right'>Days Left</th><th>Top Consumer</th><th>Status</th></tr></thead><tbody>")
    for row in fleet_rows:
        out.append("<tr>")
        out.append("<td>%s</td>" % html.escape(row["host"]))
        out.append("<td>%s</td>" % html.escape(row["platform"]))
        out.append("<td>%s</td>" % html.escape(row["worst_dg"]))
        out.append("<td class='right'>%s%%</td>" % fmt_num(row["used_pct"], 1))
        out.append("<td>%s</td>" % bar_html(row["used_pct"], row["status"]))
        out.append("<td class='right'>%s</td>" % fmt_num(row["growth_per_day"], 2))
        out.append("<td class='right'>%s</td>" % fmt_num(row["days_left"], 0))
        out.append("<td>%s</td>" % html.escape(row["top_consumer"] or "N/A"))
        out.append("<td>%s</td>" % badge(row["status"]))
        out.append("</tr>")
    out.append("</tbody></table></div>")

    for host in host_payload:
        out.append("<div class='card'>")
        out.append("<h2>%s</h2>" % html.escape(host["host"]))
        out.append("<div class='meta'>Platform: %s | Overall status: %s</div>" % (html.escape(host["platform"]), badge(host["worst_status"])))
        out.append("<table><thead><tr><th>DG</th><th>Type</th><th>Redundancy</th><th class='right'>Total TB</th><th class='right'>Used TB</th><th class='right'>Free TB</th><th class='right'>Usable TB</th><th class='right'>Used %</th><th class='right'>Growth/day</th><th>7d Trend</th><th class='right'>Days Left</th><th>Status</th></tr></thead><tbody>")
        for dg in host["dg_details"]:
            out.append("<tr>")
            out.append("<td>%s</td>" % html.escape(dg["dg"]))
            out.append("<td>%s</td>" % html.escape(dg["type"]))
            out.append("<td>%s</td>" % html.escape(dg["redundancy"]))
            out.append("<td class='right'>%s</td>" % fmt_num(dg["total_tb"], 2))
            out.append("<td class='right'>%s</td>" % fmt_num(dg["used_tb"], 2))
            out.append("<td class='right'>%s</td>" % fmt_num(dg["free_tb"], 2))
            out.append("<td class='right'>%s</td>" % fmt_num(dg["usable_tb"], 2))
            out.append("<td class='right'>%s%%</td>" % fmt_num(dg["pct_used"], 1))
            out.append("<td class='right'>%s</td>" % fmt_num(dg["growth_per_day"], 2))
            out.append("<td>%s</td>" % html.escape(dg["trend"]))
            out.append("<td class='right'>%s</td>" % fmt_num(dg["days_left"], 0))
            out.append("<td>%s</td>" % badge(dg["status"]))
            out.append("</tr>")
        out.append("</tbody></table>")

        for dg in host["dg_details"]:
            out.append("<h3 class='section-title'>%s - Top 3 Consumers</h3>" % html.escape(dg["dg"]))
            if dg["top3"]:
                out.append("<table><thead><tr><th>Rank</th><th>Consumer</th><th class='right'>Used TB</th><th class='right'>Share %</th></tr></thead><tbody>")
                for c in dg["top3"]:
                    out.append("<tr>")
                    out.append("<td>%d</td>" % c["rank"])
                    out.append("<td>%s</td>" % html.escape(c["name"]))
                    out.append("<td class='right'>%s</td>" % fmt_num(c["used_tb"], 2))
                    out.append("<td class='right'>%s</td>" % (fmt_num(c["share_pct"], 1) if c["share_pct"] is not None else "N/A"))
                    out.append("</tr>")
                out.append("</tbody></table>")
            else:
                out.append("<div class='muted'>No consumer detail parsed for %s.</div>" % html.escape(dg["dg"]))

            out.append("<div class='tight'><strong>7d Growth:</strong> %s TB &nbsp; | &nbsp; <strong>30d Growth:</strong> %s TB &nbsp; | &nbsp; <strong>Action:</strong> %s</div>" % (
                fmt_num(dg["growth_7d"], 2),
                fmt_num(dg["growth_30d"], 2),
                html.escape(dg["action"])
            ))

        out.append("<details><summary>Show raw dg_summary.txt</summary><pre>%s</pre></details>" % html.escape(host["raw_dg_summary"], quote=False))
        for dg in host["dg_details"]:
            out.append("<details><summary>Show raw %s</summary><pre>%s</pre></details>" % (
                html.escape(dg["raw_subdir_file"]),
                html.escape(dg["raw_subdir_text"], quote=False)
            ))
        out.append("</div>")

    out.append("</body></html>")
    return "".join(out), csv_rows


def main():
    if len(sys.argv) < 3:
        print("Usage: build_html_report_final.py <runs_root> <YYYY-MM-DD> [--lookback N]")
        sys.exit(2)

    runs_root = sys.argv[1]
    run_date = sys.argv[2]
    lookback = DEFAULT_LOOKBACK_DAYS

    if len(sys.argv) >= 5 and sys.argv[3] == "--lookback":
        lookback = int(sys.argv[4])

    parse_iso_date(run_date)

    html_text, csv_rows = build_report(runs_root, run_date, lookback)

    run_root = os.path.join(runs_root, run_date)
    html_path = os.path.join(run_root, "asm_capacity_report_%s.html" % run_date)
    csv_path = os.path.join(run_root, "asm_capacity_data_%s.csv" % run_date)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_text)

    build_csv(csv_path, csv_rows)

    print("HTML report: %s" % html_path)
    print("CSV data: %s" % csv_path)


if __name__ == "__main__":
    main()
