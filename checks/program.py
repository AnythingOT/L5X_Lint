"""
Task / program / controller rules: forces, watchdog, scheduling, fault
handlers, task naming, AOI checks.
"""

import re
from base_check import Finding, effective_severity
from rung_parser import parse_rung, operand_base
from checks.common import _P, _downgrade
from checks.logic import _check_rungs


def _check_tasks(data, sev):
    findings = []
    tasks = data["tasks"]
    continuous = [t for t in tasks if t["type"].upper() == "CONTINUOUS"]
    if len(continuous) > 1:
        s = effective_severity("cont_task", sev)
        if s != "DISABLED":
            findings.append(Finding("cont_task", "More Than 1 Continuous Task", s,
                f"{len(continuous)} continuous tasks — only 1 recommended.",
                location="Controller / Tasks"))
    for t in tasks:
        if t["type"].upper() != "PERIODIC":
            continue
        try:
            period, watchdog = float(t["period"]), float(t["watchdog"])
        except (ValueError, TypeError):
            continue
        if period <= 0:
            continue
        # Rockwell guidance: watchdog must comfortably exceed worst-case scan.
        # A watchdog at or below the task period guarantees nuisance faults.
        # A watchdog *very* close to the period (< 1.5×) leaves no margin.
        s = effective_severity("watchdog", sev)
        if s == "DISABLED":
            continue
        if watchdog <= period:
            findings.append(Finding(
                "watchdog", "Watchdog ≤ Period", s,
                f"Watchdog {watchdog}ms is not greater than period {period}ms — "
                f"task will fault on any overrun. Suggest ≥ {int(period*2)}ms.",
                location=f"Task:{t['name']}"))
        elif watchdog < 1.5 * period:
            findings.append(Finding(
                "watchdog", "Watchdog Close to Period", s,
                f"Watchdog {watchdog}ms leaves <50% margin over period {period}ms — "
                f"suggest ~{int(period*2)}ms.",
                location=f"Task:{t['name']}"))
    return findings


def _check_uncalled_programs(data, sev):
    findings = []
    scheduled = {p for t in data["tasks"] for p in t["programs"]}
    # Child programs run under their parent: propagate scheduling down.
    children = {p["name"]: p.get("children", []) for p in data["programs"]}
    stack = list(scheduled)
    while stack:
        for c in children.get(stack.pop(), []):
            if c not in scheduled:
                scheduled.add(c); stack.append(c)
    # Controller Fault Handler and Power-Up Handler programs are run by the
    # controller itself and are never scheduled in a task.
    ctrl = data.get("controller", {})
    handlers = {ctrl.get("major_fault_program"), ctrl.get("power_loss_program")} - {None, ""}
    for prog in data["programs"]:
        if prog["name"] not in scheduled and prog["name"] not in handlers:
            s = effective_severity("uncall_prog", sev)
            if s != "DISABLED":
                findings.append(Finding("uncall_prog", "Program Not Assigned to Task", s,
                    f"'{prog['name']}' not assigned to any task — dead code.",
                    location=f"Program:{prog['name']}"))
    return findings


def _check_forced_tags(content, sev):
    s = effective_severity("forced_tag", sev)
    if s == "DISABLED":
        return []
    idx = content.find("<ForcedTags>")
    if idx != -1 and "<Tag " in content[idx:idx+500]:
        return [Finding("forced_tag", "Forced Tags Present", s,
            "Program has forced tags. Remove all forces before deployment.",
            location="Controller / ForcedTags")]
    return []


def _check_aois(aois, xref, sev, data):
    findings = []
    ctrl_tags = {t["name"] for t in data.get("tags",[])}
    s_nodesc   = effective_severity("no_desc_aoi",  sev)
    s_ctrl_tag = effective_severity("aoi_ctrl_tag", sev)

    for aoi in aois:
        name = aoi["name"]
        if not aoi["description"] and s_nodesc != "DISABLED":
            findings.append(Finding("no_desc_aoi","AOI Without Description", s_nodesc,
                f"AOI '{name}' has no description.", location=f"AOI:{name}"))
        for p in aoi["parameters"]:
            if not p["description"] and s_nodesc != "DISABLED":
                findings.append(Finding("no_desc_aoi","AOI Parameter Without Description", s_nodesc,
                    f"AOI '{name}' parameter '{p['name']}' has no description.",
                    location=f"AOI:{name}.{p['name']}"))

        if s_ctrl_tag != "DISABLED":
            allowed = {p["name"] for p in aoi["parameters"]} | {t["name"] for t in aoi.get("tags",[])}
            for rtn in aoi["routines"]:
                for rung in rtn["rungs"]:
                    for instr in parse_rung(rung["text"]):
                        for op in instr["operands"]:
                            base = operand_base(op)
                            if base in ctrl_tags and base not in allowed:
                                findings.append(Finding("aoi_ctrl_tag",
                                    "AOI Using Controller-Scoped Tag", s_ctrl_tag,
                                    f"AOI '{name}' references controller tag '{base}' — pass via parameter.",
                                    location=f"AOI:{name} / {rtn['name']} / Rung {rung['number']}"))

        # Run rung checks inside AOI at downgraded severity
        fake = {"name": f"AOI:{name}", "main_routine": aoi["routines"][0]["name"] if aoi["routines"] else "",
                "fault_routine": "", "routines": aoi["routines"], "tags": aoi.get("tags",[])}
        for f in _check_rungs(fake, xref, sev, scope=f"AOI:{name}"):
            f.severity = _downgrade(f.severity)
            f.message  = f"[AOI — offline download required] {f.message}"
            findings.append(f)

    return findings


def task_period_name(ctx):
    out = []
    for t in ctx.data.get("tasks", []):
        if (t.get("type") or "").upper() != "PERIODIC":
            continue
        try:
            ms = float(t.get("period") or "")
        except ValueError:
            continue
        ms_s = str(int(ms)) if ms == int(ms) else str(ms)
        forms = [rf"(?<!\d){re.escape(ms_s)}\s*MS(?![A-Z])"]
        if ms >= 1000 and ms % 1000 == 0:
            forms.append(rf"(?<!\d){int(ms // 1000)}\s*S(?![A-Z])")
        if not any(re.search(f, t["name"], re.IGNORECASE) for f in forms):
            out.append(Finding("task_period_name", "", _P,
                f"Periodic task '{t['name']}' runs every {ms_s} ms but its name doesn't say so "
                f"(e.g. '{t['name']}_{ms_s}MS').", location=f"Task:{t['name']}"))
    return out


def _ctrl_fault_handler(data, sev, und):
    s = effective_severity("ctrl_fault_handler", sev)
    if s == "DISABLED":
        return []
    mfp = data["controller"].get("major_fault_program")
    if mfp is None:
        und["ERR007"] = ("MajorFaultProgram attribute absent from this "
                                  "export — verify the Controller Fault Handler in Studio 5000.")
        return []
    progs = {p["name"] for p in data.get("programs", [])}
    if not mfp:
        return [Finding("ctrl_fault_handler", "No Controller Fault Handler", s,
            "No Controller Fault Handler program is configured — a major fault "
            "will stop the controller with no recovery or logging logic.",
            location=f"Controller:{data['controller']['name']}")]
    if mfp not in progs:
        return [Finding("ctrl_fault_handler", "Controller Fault Handler Missing", s,
            f"MajorFaultProgram references '{mfp}', which is not in the project.",
            location=f"Controller:{data['controller']['name']}")]
    return []


def _prog_fault_routine(data, sev):
    s = effective_severity("prog_fault_routine", sev)
    if s == "DISABLED":
        return []
    c = data["controller"]
    handlers = {c.get("major_fault_program"), c.get("power_loss_program")}
    out = []
    for p in data.get("programs", []):
        if p["name"] in handlers:
            continue
        fr = p.get("fault_routine") or ""
        rtns = {r["name"] for r in p.get("routines", [])}
        if not fr:
            out.append(Finding("prog_fault_routine", "No Program Fault Routine", s,
                f"Program '{p['name']}' has no Fault Routine assigned.",
                location=f"{p['name']}:(FaultRoutine)"))
        elif fr not in rtns:
            out.append(Finding("prog_fault_routine", "Fault Routine Missing", s,
                f"Program '{p['name']}' names fault routine '{fr}', which does not exist.",
                location=f"{p['name']}:(FaultRoutine)"))
    return out
