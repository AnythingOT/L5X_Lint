#!/usr/bin/env python3
# l5x_cli.py — headless command-line interface.
"""
Examples:

    # Pretty text report (default)
    python -m l5x_lint analyze program.L5X

    # JSON for downstream tooling
    python -m l5x_lint analyze program.L5X --format json > findings.json

    # SARIF for CI inline annotations
    python -m l5x_lint analyze program.L5X --format sarif > findings.sarif

    # Fail the build if any ERROR-or-worse finding exists
    python -m l5x_lint analyze program.L5X --fail-on ERROR

Exit codes:
    0  no findings at or above the --fail-on threshold
    1  at least one finding at or above the threshold
    2  parse / I/O error
"""

import argparse
import json
import sys
import os

# Make sibling modules importable when invoked as `python l5x_cli.py`
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from base_check import SEV_ORDER


_SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}


def _load_default_cfg():
    # Mirrors app.DEFAULT_CONFIG without importing Flask.
    return {"disabled_rules": [], "lifecycle_enabled": True, "sizes": {"loose_bool_min": 1}, "urs": {}}


def _load_cfg(path):
    if not path:
        return _load_default_cfg()
    with open(path, "r", encoding="utf-8") as f:
        saved = json.load(f)
    cfg = _load_default_cfg()
    for key in ("sizes", "urs"):
        if isinstance(saved.get(key), dict):
            cfg[key].update(saved[key])
    if isinstance(saved.get("lifecycle_enabled"), bool):
        cfg["lifecycle_enabled"] = saved["lifecycle_enabled"]
    if isinstance(saved.get("disabled_rules"), list):
        cfg["disabled_rules"] = saved["disabled_rules"]
    return cfg


def cmd_analyze(args):
    import analysis
    from output_formats import json_report, sarif_report, flatten_findings

    try:
        with open(args.file, "r", encoding="utf-8-sig") as f:
            content = f.read()
    except OSError as e:
        print(f"could not read {args.file}: {e}", file=sys.stderr)
        return 2

    cfg = _load_cfg(args.config)
    report = None
    for event in analysis.run_analysis(content, cfg):
        if event["type"] == "error":
            print(f"analysis error: {event['message']}", file=sys.stderr)
            return 2
        if event["type"] == "done":
            report = event["report"]

    if report is None:
        print("analysis did not complete", file=sys.stderr)
        return 2

    if args.format == "json":
        sys.stdout.write(json_report(report))
        sys.stdout.write("\n")
    elif args.format == "sarif":
        sys.stdout.write(sarif_report(report, source_file=os.path.basename(args.file)))
        sys.stdout.write("\n")
    else:
        _print_text(report, args.file)

    # Exit-code gating
    if args.fail_on:
        threshold = args.fail_on.upper()
        if threshold not in _SEV_RANK:
            print(f"--fail-on must be one of {SEV_ORDER}", file=sys.stderr)
            return 2
        worst_rank = _SEV_RANK.get(threshold)
        findings = flatten_findings(report)
        for f in findings:
            r = _SEV_RANK.get((f.get("severity") or "").upper())
            if r is not None and r <= worst_rank:
                return 1
    return 0


def _print_text(report, fname):
    counts = report.get("severity_counts", {})
    meta = report.get("meta", {})
    print(f"L5X: {fname}")
    print(f"Controller: {meta.get('controller_name')}   "
          f"Firmware: {meta.get('firmware')}   "
          f"Programs: {meta.get('program_count')}   "
          f"Rungs: {meta.get('rung_count')}")
    print(f"Findings — CRITICAL: {counts.get('CRITICAL',0)}   "
          f"ERROR: {counts.get('ERROR',0)}   "
          f"WARNING: {counts.get('WARNING',0)}   "
          f"INFO: {counts.get('INFO',0)}")
    for n in report.get("not_verified") or []:
        print(f"Not verified — {n}")
    sup = report.get("suppressed_count", 0)
    if sup:
        print(f"({sup} suppressed via in-source directives)")
    print()
    from output_formats import flatten_findings
    fs = flatten_findings(report)
    fs.sort(key=lambda f: _SEV_RANK.get(f.get("severity"), 9))
    for f in fs:
        print(f"[{f.get('code','?'):6}] {f.get('check_name','?')[:28]:28} "
              f"{f.get('location','')}")
        print(f"           {f.get('message','')}")


def cmd_lifecycle_info(_args):
    from lifecycle import dataset_info, is_available
    info = dataset_info()
    print(json.dumps({"available": is_available(), **info}, indent=2))
    return 0


def cmd_lifecycle_import(args):
    """Import a JSON or CSV lifecycle dataset into lifecycle.json."""
    import lifecycle
    try:
        with open(args.file, "r", encoding="utf-8-sig") as f:
            text = f.read()
    except OSError as e:
        print(f"could not read {args.file}: {e}", file=sys.stderr)
        return 2

    if args.file.lower().endswith(".json"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as e:
            print(f"invalid JSON: {e}", file=sys.stderr)
            return 2
        meta = payload.pop("_meta", {}) if isinstance(payload, dict) else {}
        records = payload
    elif args.file.lower().endswith(".csv"):
        records, errors = lifecycle.parse_csv(text)
        for e in errors:
            print(f"warning: {e}", file=sys.stderr)
        if not records:
            print("no valid records in CSV", file=sys.stderr)
            return 2
        meta = {"source_note": f"Imported from CSV '{os.path.basename(args.file)}'."}
    else:
        print("file must be .json or .csv", file=sys.stderr)
        return 2

    if args.scraped_at:
        meta["scraped_at"] = args.scraped_at
    result = lifecycle.import_dataset(records, meta=meta,
                                    merge=not args.replace)
    print(json.dumps(result, indent=2))
    return 0 if result["imported"] else 2


def cmd_batch(args):
    """Analyze many files; emit one summary line per file plus aggregated exit code."""
    import analysis
    from output_formats import flatten_findings

    cfg = _load_cfg(args.config)
    worst_exit = 0
    summary = []
    for path in args.files:
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                content = f.read()
        except OSError as e:
            print(f"{path}\tERROR\t{e}")
            worst_exit = max(worst_exit, 2)
            continue
        report = None
        for ev in analysis.run_analysis(content, cfg):
            if ev["type"] == "done":
                report = ev["report"]
            elif ev["type"] == "error":
                print(f"{path}\tERROR\t{ev['message']}")
                worst_exit = max(worst_exit, 2)
                break
        if report is None:
            continue
        c = report.get("severity_counts", {})
        line = f"{path}\tC={c.get('CRITICAL',0)}\tE={c.get('ERROR',0)}\t" \
               f"W={c.get('WARNING',0)}\tI={c.get('INFO',0)}"
        print(line)
        summary.append((path, c, report))

    if args.fail_on:
        threshold = args.fail_on.upper()
        worst_rank = _SEV_RANK.get(threshold)
        if worst_rank is None:
            print(f"--fail-on invalid: {threshold}", file=sys.stderr)
            return 2
        for _, _, rpt in summary:
            for f in flatten_findings(rpt):
                if _SEV_RANK.get(f.get("severity"), 9) <= worst_rank:
                    return 1
    return worst_exit


def main():
    p = argparse.ArgumentParser(prog="l5x-lint")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="Analyze a single L5X file")
    a.add_argument("file")
    a.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    a.add_argument("--config", help="Path to evaluator_config.json")
    a.add_argument("--fail-on",
                   help="Exit 1 if any finding at this severity or worse "
                        f"(one of {SEV_ORDER[:4]})")
    a.set_defaults(func=cmd_analyze)

    b = sub.add_parser("batch", help="Analyze many L5X files")
    b.add_argument("files", nargs="+")
    b.add_argument("--config")
    b.add_argument("--fail-on")
    b.set_defaults(func=cmd_batch)

    li = sub.add_parser("lifecycle-info", help="Show lifecycle dataset metadata")
    li.set_defaults(func=cmd_lifecycle_info)

    lim = sub.add_parser("lifecycle-import",
                         help="Import a lifecycle dataset (.json or .csv)")
    lim.add_argument("file")
    lim.add_argument("--replace", action="store_true",
                     help="Replace the dataset instead of merging")
    lim.add_argument("--scraped-at", dest="scraped_at",
                     help="ISO date the data was sourced (shown as freshness)")
    lim.set_defaults(func=cmd_lifecycle_import)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
