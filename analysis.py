# analysis.py  —  L5X Lint
from l5x_loader  import load, L5XParseError
from cross_ref import build as build_xref
from severity    import severity_counts
from suppression import apply_suppressions
from rules        import apply_registry
from checks       import run_rules
from checks.program import _check_tasks, _check_uncalled_programs, _check_forced_tags, _check_aois
from checks.tags  import _check_tags
from checks.logic import _check_rungs
from checks.udt   import _check_udts

import logging
log = logging.getLogger(__name__)


def run_analysis(content: str, cfg: dict, session_id: str = ""):
    findings = []

    yield _prog(5,  "Parsing XML structure", "Loading L5X…")
    try:
        data = load(content)
    except L5XParseError as e:
        yield {"type": "error", "message": str(e)}
        return
    except Exception as e:
        yield {"type": "error", "message": f"Unexpected parse error: {e}"}
        return

    from rules import build_gate
    sev   = build_gate(cfg)          # disabled rules → "DISABLED": checks skip their work
    progs = data["programs"]
    aois  = data["aois"]

    yield _prog(15, "Building cross-reference index", f"{len(progs)} programs…")
    xref = build_xref(data)

    yield _prog(25, "Task & controller checks", "")
    findings += _check_tasks(data, sev)
    findings += _check_uncalled_programs(data, sev)
    findings += _check_forced_tags(content, sev)

    yield _prog(30, "Module lifecycle check", f"{len(data['modules'])} modules…")
    # Lifecycle master switch (Settings → Lifecycle). Off = no lifecycle
    # findings and no lifecycle data on modules or in exports.
    lc_on = bool(cfg.get("lifecycle_enabled", True))
    data["_lc_on"] = lc_on
    if lc_on:
        from lifecycle import lifecycle_findings
        findings += lifecycle_findings(data["modules"], sev)

    yield _prog(36, "Checklist rules", "")
    rule_f, rule_errors, undetermined = run_rules(data, cfg, sev)
    findings += rule_f

    yield _prog(40, "Data type checks", f"{len(data['datatypes'])} UDTs…")
    findings += _check_udts(data, sev)

    yield _prog(48, "Tag checks", "Controller + program tags…")
    loose_min = int(((cfg.get("sizes") or {}).get("loose_bool_min") or 1))
    findings += _check_tags(data, xref, sev, loose_min=max(1, loose_min))

    pct_per_prog = 25 / max(len(progs), 1)
    for i, prog in enumerate(progs):
        pct = 58 + int(i * pct_per_prog)
        yield _prog(pct, f"Rung checks — {prog['name']}",
                    f"{sum(len(r['rungs']) for r in prog['routines'])} rungs")
        findings += _check_rungs(prog, xref, sev, scope=prog["name"])

    yield _prog(82, "AOI checks", f"{len(aois)} AOIs…")
    findings += _check_aois(aois, xref, sev, data)

    yield _prog(90, "Applying checklist & suppressions", "")
    findings = apply_registry(findings, cfg)
    findings, suppressed = apply_suppressions(findings, data)

    yield _prog(95, "Building report", "")
    sev_counts = severity_counts(findings)
    report = _build_report(data, findings, sev_counts, data["modules"],
                           len(suppressed))
    # Suppressed findings travel with the report so the UI can show them
    # on demand (greyed out) — hidden-but-inspectable, never invisible.
    report["suppressed_findings"] = [f.to_dict() for f in suppressed]
    # Rules that could not be evaluated because the export lacks the data
    # they need — shown in the banner and exports, never a silent pass.
    report["not_verified"] = [f"{code}: {why}" for code, why in undetermined.items()]
    report["rule_errors"] = rule_errors
    from rules import LIFECYCLE_CODES
    report["meta"]["disabled_rules"] = sorted(set(cfg.get("disabled_rules") or []) - LIFECYCLE_CODES)
    # Coverage note: non-ladder routines are not analysed by any rule.
    report["meta"]["non_rll_routines"] = sum(
        1 for p in progs for r in p["routines"] if r.get("non_rll"))
    report["meta"]["protected_routines"] = sum(
        1 for p in progs for r in p["routines"] if r.get("protected")) + sum(
        1 for a in aois for r in a.get("routines", []) if r.get("protected"))
    report["meta"]["encoded_aois"] = data.get("encoded_aois", 0)

    yield {"type": "done", "session_id": session_id, "report": report}


# ── Task checks ───────────────────────────────────────────────────────────


# ── UDT checks (udt_layout: pure layout arithmetic on the parsed XML) ──────


# ── Tag type helpers ─────────────────────────────────────────────────────


# ── Tag checks ────────────────────────────────────────────────────────────


# ── Rung checks ───────────────────────────────────────────────────────────


# ── AOI checks ────────────────────────────────────────────────────────────


# ── Report builder ────────────────────────────────────────────────────────

def _task_label(task: dict) -> str:
    """Format task label suffix: [10ms] / [Cont] / [Evt] / [Uns]"""
    t = task["type"].upper()
    if t == "CONTINUOUS":
        return f"{task['name']}[Cont]"
    elif t == "EVENT":
        return f"{task['name']}[Evt]"
    elif t == "PERIODIC":
        try:
            ms = float(task["period"])
            ms_str = str(int(ms)) if ms == int(ms) else str(ms)
            return f"{task['name']}[{ms_str}ms]"
        except (ValueError, TypeError):
            return f"{task['name']}[Per]"
    return f"{task['name']}[Uns]"


def _build_report(data, findings, sev_counts, modules, n_suppressed=0):
    progs      = data["programs"]
    tasks      = data["tasks"]
    sev_order  = {"CRITICAL":0,"ERROR":1,"WARNING":2,"INFO":3}

    total_rungs = sum(len(r["rungs"]) for p in progs for r in p["routines"])
    total_tags  = len(data["tags"]) + sum(len(p["tags"]) for p in progs)
    top = sorted(findings, key=lambda f: sev_order.get(f.severity,9))[:10]

    # Annotate modules with lifecycle status (if dataset present)
    from lifecycle import get_status, is_available, dataset_info
    lifecycle_on = data.get("_lc_on", True)
    lifecycle_active = is_available() and lifecycle_on
    annotated_modules = []
    for m in modules:
        entry = dict(m)
        if lifecycle_active and m.get("catalog"):
            entry["lifecycle"] = get_status(m["catalog"])
        else:
            entry["lifecycle"] = None
        annotated_modules.append(entry)

    # Build program→task mapping
    prog_task = {}   # prog_name → task dict
    for task in tasks:
        for pname in task["programs"]:
            prog_task[pname] = task
    # Unscheduled programs
    unscheduled_task = {"name": "Unscheduled", "type": "UNSCHEDULED",
                        "period": "", "watchdog": "", "programs": []}

    # Build per-program finding sections
    def _prog_sections(pname, pf):
        unused   = [f.to_dict() for f in pf if f.check_id == "unused_tag"]
        nodesc   = [f.to_dict() for f in pf if f.check_id == "no_desc_tag"]
        rung_f   = [f for f in pf if f.check_id == "rung_no_desc"]
        other    = [f.to_dict() for f in pf if f.check_id not in
                    ("unused_tag","no_desc_tag","rung_no_desc")]
        # Group rung findings by routine name
        by_rtn = {}
        for f in rung_f:
            parts = f.location.split(" / ")
            rtn = parts[1] if len(parts) >= 2 else "Unknown"
            by_rtn.setdefault(rtn, []).append(f.to_dict())
        return {
            "unused_tags": unused,
            "no_desc":     nodesc,
            "routines":    by_rtn,
            "other":       other,
        }

    # Assign every finding to its program in ONE pass (was programs × findings).
    # Logix names cannot contain ':' or ' /', so a finding's owner is the text
    # before the first of those delimiters — identical to the old prefix test.
    prog_names = {p["name"] for p in progs}
    by_prog = {}
    for f in findings:
        loc = f.location
        cut = min([i for i in (loc.find(" /"), loc.find(":")) if i >= 0], default=-1)
        owner = loc[:cut] if cut >= 0 else None
        if owner in prog_names:
            by_prog.setdefault(owner, []).append(f)

    # Group programs by task
    task_program_tabs = []
    seen_tasks = {}   # task_name → index in task_program_tabs

    for prog in progs:
        pname = prog["name"]
        pf    = by_prog.get(pname, [])

        task     = prog_task.get(pname, unscheduled_task)
        tk_label = _task_label(task)
        tab_label = f"{tk_label}→{pname}"

        task_program_tabs.append({
            "task_name":   task["name"],
            "task_label":  tk_label,
            "prog_name":   pname,
            "tab_label":   tab_label,
            "has_errors":  any(f.severity in ("CRITICAL","ERROR") for f in pf),
            "finding_count": len(pf),
            "sections":    _prog_sections(pname, pf),
        })

    # AOI findings structured by AOI name
    aoi_raw = [f for f in findings if f.location.startswith("AOI:")]
    aoi_by_name = {}
    for f in aoi_raw:
        loc_prefix = f.location.split("/")[0].strip()   # e.g. "AOI:MotorCTRL" or "AOI:MotorCTRL.RunFB"
        raw_name   = loc_prefix[4:] if loc_prefix.startswith("AOI:") else loc_prefix
        # Strip parameter suffix — "MotorCTRL.RunFB" → "MotorCTRL"
        aname = raw_name.split(".")[0]
        aoi_by_name.setdefault(aname, []).append(f)

    aoi_sections = []
    for aname, afs in sorted(aoi_by_name.items()):
        no_desc   = [f.to_dict() for f in afs if f.check_id in ("no_desc_tag","no_desc_aoi")]
        ctrl_tag  = [f.to_dict() for f in afs if f.check_id == "aoi_ctrl_tag"]
        rung_f    = [f for f in afs if f.check_id == "rung_no_desc"]
        other_f   = [f.to_dict() for f in afs if f.check_id not in
                     ("no_desc_tag","no_desc_aoi","aoi_ctrl_tag","rung_no_desc")]
        by_rtn = {}
        for f in rung_f:
            parts = f.location.split(" / ")
            rtn = parts[1] if len(parts) >= 2 else "Logic"
            by_rtn.setdefault(rtn, []).append(f.to_dict())
        aoi_sections.append({
            "name":      aname,
            "has_errors": any(f.severity in ("CRITICAL","ERROR") for f in afs),
            "count":     len(afs),
            "no_desc":   no_desc,
            "ctrl_tag":  ctrl_tag,
            "routines":  by_rtn,
            "other":     other_f,
        })

    in_prog = {id(f) for lst in by_prog.values() for f in lst}
    ctrl_findings = [f.to_dict() for f in findings
                     if id(f) not in in_prog and not f.location.startswith("AOI:")]

    # ── Routine type counts ───────────────────────────────────────────
    rtype_map = {"RLL":"LD","FBD":"FBD","ST":"ST","SFC":"SFC"}
    routine_types = {"LD":0,"FBD":0,"ST":0,"SFC":0}
    for p in progs:
        for r in p["routines"]:
            key = rtype_map.get(r["type"].upper(), "LD")
            routine_types[key] += 1

    local_tag_count = sum(len(p["tags"]) for p in progs)

    # ── Task tree ─────────────────────────────────────────────────────
    task_tree = []
    for task in tasks:
        t_entry = {
            "label":    _task_label(task),
            "type":     task["type"],
            "programs": []
        }
        for idx, pname in enumerate(task["programs"]):
            prog = next((p for p in progs if p["name"] == pname), None)
            if not prog:
                continue
            t_entry["programs"].append({
                "number":    idx + 1,
                "name":      pname,
                "tag_count": len(prog["tags"]),
                "routines":  [{
                    "name":       r["name"],
                    "type":       rtype_map.get(r["type"].upper(), r["type"]),
                    "rung_count": len(r["rungs"]),
                } for r in prog["routines"]]
            })
        task_tree.append(t_entry)

    # Unscheduled programs
    scheduled_all = {pn for t in tasks for pn in t["programs"]}
    uns_progs = [p for p in progs if p["name"] not in scheduled_all]
    if uns_progs:
        uns_entry = {"label":"[Uns]","type":"UNSCHEDULED","programs":[]}
        for idx, prog in enumerate(uns_progs):
            uns_entry["programs"].append({
                "number":idx+1,"name":prog["name"],"tag_count":len(prog["tags"]),
                "routines":[{"name":r["name"],"type":rtype_map.get(r["type"].upper(),r["type"]),
                             "rung_count":len(r["rungs"])} for r in prog["routines"]]
            })
        task_tree.append(uns_entry)

    return {
        "severity_counts":   sev_counts,
        "suppressed_count":  n_suppressed,
        "meta": {
            "controller_name":  data["controller"]["name"],
            "firmware":         f"v{data['controller']['major_rev']}.{data['controller']['minor_rev']}",
            "processor_type":   data["controller"]["processor_type"],
            "program_count":    len(progs),
            "task_count":       len(tasks),
            "tag_count":        len(data["tags"]),
            "local_tag_count":  local_tag_count,
            "rung_count":       total_rungs,
            "aoi_count":        len(data["aois"]),
            "udt_count":        len(data["datatypes"]),
            "routine_types":    routine_types,
            "task_tree":        task_tree,
            "lifecycle":        (dataset_info() if lifecycle_active
                                 else {"available": False, "disabled": not lifecycle_on}),
        },
        "top_issues":          [f.to_dict() for f in top],
        "controller_findings": ctrl_findings,
        "aoi_sections":        aoi_sections,
        "task_program_tabs":   task_program_tabs,
        "modules":             annotated_modules,
    }


def _prog(pct, phase, detail="", status="processing"):
    return {"type":"progress","pct":pct,"phase":phase,"detail":detail,"status":status}
