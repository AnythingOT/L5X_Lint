"""
UDT rules: padding (layout via udt_layout), member order, unused
definitions, member descriptions.
"""

import logging
from base_check import Finding, effective_severity
from udt_layout import natural_key
from checks.common import _P
log = logging.getLogger(__name__)


def _check_udts(data: dict, sev: dict) -> list:
    """
    WAR010 — UDTs where reordering members would save >= 4 bytes of padding.
    Layout input comes from the loader's single XML parse (data["udt_layout"]).
    """
    s = effective_severity("udt_pad", sev)
    if s == "DISABLED":
        return []
    layout = data.get("udt_layout")
    if not layout or not layout.get("udts"):
        return []
    import udt_layout
    findings = []
    try:
        for r in udt_layout.analyse(layout):
            name = r["name"]
            if r["opt_needed"] is None:
                # N/A — all members use unknown types
                skipped_types = r["skipped_types"]
                if skipped_types:
                    findings.append(Finding(
                        "udt_pad", "UDT Cannot Be Analysed", "INFO",
                        f"'{name}' — member types not resolved "
                        f"({', '.join(skipped_types[:4])}{'…' if len(skipped_types)>4 else ''}). "
                        f"Upload full program L5X to resolve.",
                        location=f"DataType:{name}"
                    ))
                continue
            # Size only. Member ORDER is a separate rule (udt_order / WAR011);
            # a reorder that saves nothing is not a padding finding.
            size_before, size_after = r["size_before"], r["size_after"]
            saved = max(0, size_before - size_after)
            if not r["opt_needed"] or saved < 4:
                continue
            findings.append(Finding(
                "udt_pad", "UDT Padding Waste", s,
                f"'{name}' is {size_before} bytes; reordering members by type "
                f"would make it {size_after} bytes ({saved} bytes saved).",
                location=f"DataType:{name}",
            ))
    except ValueError as e:
        findings.append(Finding(
            "udt_pad", "UDT Dependency Cycle", "ERROR",
            str(e), location="DataType"))
    except Exception as e:
        # Never let the UDT check crash the whole analysis.
        log.exception("UDT layout check failed")
        findings.append(Finding(
            "udt_pad", "UDT Check Error", "INFO",
            f"UDT layout check encountered an error: {e}", location="DataType"))
    return findings


def unused_type(ctx):
    used = set()
    def add(dt):
        if dt:
            used.add(dt.upper())
    for t in ctx.data.get("tags", []):
        add(t.get("data_type"))
    for p in ctx.data.get("programs", []):
        for t in p.get("tags", []):
            add(t.get("data_type"))
    for d in ctx.data.get("datatypes", []):
        for m in d.get("members", []):
            add(m.get("data_type"))
    for a in ctx.data.get("aois", []):
        for p in a.get("parameters", []):
            add(p.get("data_type"))
    for a in ctx.data.get("aois", []):                 # AOI local tags (#11)
        for t in a.get("tags", []):
            add(t.get("data_type"))
    text = ("\n".join(r[1] for r in ctx.rungs) + "\n" + ctx.usage_text).upper()
    out = []
    for d in ctx.data.get("datatypes", []):
        if d["name"].upper() not in used:
            out.append(Finding("unused_type", "", _P,
                f"UDT '{d['name']}' is not used anywhere.", location=f"DataType:{d['name']}"))
    for a in ctx.data.get("aois", []):
        n = a["name"].upper()
        if n not in used and (n + "(") not in text:
            out.append(Finding("unused_type", "", _P,
                f"AOI '{a['name']}' is defined but never instantiated or called.",
                location=f"AOI:{a['name']}"))
    return out


def udt_member_desc(ctx):
    out = []
    for d in ctx.data.get("datatypes", []):
        for m in d.get("members", []):
            if not m.get("hidden") and not (m.get("description") or "").strip():
                out.append(Finding("udt_member_desc", "", _P,
                    f"Member '{d['name']}.{m['name']}' has no description.",
                    location=f"DataType:{d['name']}"))
    return out


def _udt_order(data, sev):
    """
    Members of the same exact datatype must be contiguous, and sorted by
    natural name order within the group (same key the UDT optimiser uses,
    so the tool's own fix always satisfies this rule). The sequence of
    groups is not checked — the URS doesn't specify it; padding is
    covered by udt_pad.
    """
    s = effective_severity("udt_order", sev)
    if s == "DISABLED":
        return []
    out = []
    for d in data.get("datatypes", []):
        mem = [m for m in d.get("members", []) if not m.get("hidden")]
        if len(mem) < 2:
            continue
        def gkey(m):
            t = (m.get("data_type") or "").upper()
            t = "BOOL" if t == "BIT" else t
            return (t, bool((m.get("dimension") or "0") not in ("", "0")))
        seen, cur, split = set(), None, False
        groups = {}
        for m in mem:
            k = gkey(m)
            groups.setdefault(k, []).append(m["name"])
            if k != cur:
                if k in seen:
                    split = True
                seen.add(k); cur = k
        unsorted = any(names != sorted(names, key=natural_key) for names in groups.values())
        problems = (["Data types are not grouped."] if split else []) + \
                   (["Members are not in alphabetical order."] if unsorted else [])
        if problems:
            out.append(Finding("udt_order", "UDT Member Order", s, " ".join(problems),
                location=f"DataType:{d['name']}"))
    return out
