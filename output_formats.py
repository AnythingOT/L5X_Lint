# output_formats.py — render analysis output as JSON or SARIF 2.1.0
"""
Two output formats for headless / CI use:

- json_report(report): flat, simple JSON. The same `report` dict the SSE
  stream emits, plus a top-level `findings` list flattened from all
  buckets (top_issues / controller_findings / per-program / AOI).

- sarif_report(report, source_file): SARIF 2.1.0 (the format GitHub,
  GitLab, and Azure DevOps render natively as inline PR annotations).

Severity → SARIF level mapping:
  CRITICAL → error
  ERROR    → error
  WARNING  → warning
  INFO     → note
"""

import json
import datetime


_SARIF_LEVEL = {
    "CRITICAL": "error",
    "ERROR":    "error",
    "WARNING":  "warning",
    "INFO":     "note",
}


def flatten_findings(report: dict) -> list:
    """Collect every finding from every bucket in the report, deduplicated."""
    seen = set()
    out = []

    def _push(f):
        if not isinstance(f, dict):
            return
        key = (f.get("check_id"), f.get("location"), f.get("message"))
        if key in seen:
            return
        seen.add(key)
        out.append(f)

    for f in report.get("controller_findings", []) or []:
        _push(f)
    for tab in report.get("task_program_tabs", []) or []:
        s = tab.get("sections", {}) or {}
        for bucket in ("unused_tags", "no_desc", "other"):
            for f in s.get(bucket, []) or []:
                _push(f)
        for v in (s.get("routines", {}) or {}).values():
            for f in v or []:
                _push(f)
    for aoi in report.get("aoi_sections", []) or []:
        for bucket in ("no_desc", "ctrl_tag", "other"):
            for f in aoi.get(bucket, []) or []:
                _push(f)
        for v in (aoi.get("routines", {}) or {}).values():
            for f in v or []:
                _push(f)
    return out


def json_report(report: dict) -> str:
    """Pretty-printed JSON suitable for CI artifacts or `jq` filtering."""
    payload = {
        "schema":              "l5x-lint-report/1",
        "generated_at":        datetime.datetime.now().isoformat(timespec="seconds"),
        "meta":                report.get("meta", {}),
        "severity_counts":     report.get("severity_counts", {}),
        "suppressed_count":    report.get("suppressed_count", 0),
        "findings":            flatten_findings(report),
        "suppressed_findings": report.get("suppressed_findings", []),
        "modules":             report.get("modules", []),
        "not_verified":        report.get("not_verified", []),
    }
    return json.dumps(payload, indent=2, default=str)


def sarif_report(report: dict, source_file: str = "input.L5X") -> str:
    """SARIF 2.1.0 document. Tested against GitHub's SARIF importer."""
    findings = flatten_findings(report)

    # Build the rules table from the unique check IDs encountered.
    rules = {}
    for f in findings:
        cid = f.get("code") or f.get("check_id") or "unknown"
        if cid not in rules:
            rules[cid] = {
                "id": cid,
                "name": f.get("check_name") or cid,
                "shortDescription": {"text": f.get("check_name") or cid},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.get("severity"), "warning")},
            }

    results = []
    for f in findings:
        results.append({
            "ruleId": f.get("code") or f.get("check_id") or "unknown",
            "level":  _SARIF_LEVEL.get(f.get("severity"), "warning"),
            "message": {"text": f.get("message", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": source_file},
                    # We don't track byte offsets in the L5X (deliberate —
                    # they're not meaningful to a PLC engineer reviewing
                    # in Studio 5000). The L5X path lives in the message.
                    "region": {"startLine": 1, "startColumn": 1},
                },
                "logicalLocations": [{
                    "fullyQualifiedName": f.get("location", ""),
                    "kind": "module",
                }],
            }],
            "properties": {
                "l5xLocation": f.get("location", ""),
                "detail":      f.get("detail", ""),
            },
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name":           "l5x-lint",
                    "informationUri": "https://example.local/l5x-lint",
                    "version":        "1.0",
                    "rules":          list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)

