"""
Rung logic rules: AFI, OTE/OTL/OTU, MSG gating and writes, controller-managed
bits, duplicate instructions, array-index and division guards, jumps,
timer/counter/one-shot use, empty branches, MOV REAL→integer, MSG staggering,
JSR call depth.
"""

import re
from collections import defaultdict
from base_check import Finding, effective_severity
from rung_parser import parse_rung, find_instructions, operand_member
import rung_tree
from checks.common import COUNTERS, INT_TYPES, REAL_TYPES, TIMERS, _INT_LIT, _MSG_RE, _P, _REAL_LIT, _guarded, _idents, _keyed, _strip_parens


_TC_PROTECTED  = {"DN","EN","TT","CU","CD","OV","UN"}


_MSG_PROTECTED = {"ER","DN","TT","ST","TO","EN"}


_NUMERIC_RE    = re.compile(r'^-?\d+\.?\d*$')


_WRITE_INSTRS  = {"MOV","ADD","SUB","MUL","DIV","MOD","CPT","AND","OR","XOR"}


def _check_rungs(prog, xref, sev, scope):
    findings  = []
    ote_map   = defaultdict(list)
    otl_map   = defaultdict(list)
    otu_map   = defaultdict(list)
    called    = {prog.get("main_routine",""), prog.get("fault_routine","")}

    s_afi      = effective_severity("afi",        sev)
    s_otedup   = effective_severity("ote_dup",    sev)
    s_otlmulti = effective_severity("otl_multi",  sev)
    s_otumulti = effective_severity("otu_multi",  sev)
    s_msggate  = effective_severity("msg_gated",  sev)
    s_msgwrite = effective_severity("msg_write",  sev)
    s_timerwr  = effective_severity("timer_wr",   sev)
    s_hardcode = effective_severity("hardcode",   sev)
    s_empty    = effective_severity("empty_rung", sev)
    s_jsr      = effective_severity("jsr_depth",  sev)
    s_uncallrtn= effective_severity("uncall_rtn", sev)
    s_rungdesc = effective_severity("rung_no_desc", sev)
    s_nonrll   = effective_severity("non_rll_routine", sev)

    for rtn in prog["routines"]:
        rname = rtn["name"]
        # Warn the user when we *can't* analyse a routine — silent skipping
        # creates a false sense of cleanliness.
        if rtn.get("non_rll") and s_nonrll != "DISABLED":
            findings.append(Finding(
                "non_rll_routine", "Non-Ladder Routine Not Analysed", s_nonrll,
                f"Routine '{rname}' is {rtn.get('type','?')} — this tool only "
                f"performs ladder analysis. Logic-quality checks were skipped.",
                location=f"{scope} / {rname}"))
            # Don't try to lint zero rungs from FBD/ST as "empty rungs".
            continue
        for rung in rtn["rungs"]:
            rnum = rung["number"]
            text = rung["text"]
            loc  = f"{scope} / {rname} / Rung {rnum}"

            if not text:
                if s_empty != "DISABLED":
                    findings.append(Finding("empty_rung","Empty Rung", s_empty,
                        "Rung has no instructions.", location=loc))
                continue

            # ── Rung without comment
            if s_rungdesc != "DISABLED" and not rung.get("comment", "").strip():
                findings.append(Finding("rung_no_desc", "Rung Without Description", s_rungdesc,
                    "Rung has no comment — add a description of the rung's intent.",
                    location=loc))

            instrs = parse_rung(text)

            if s_afi != "DISABLED":
                for _ in find_instructions(instrs, "AFI"):
                    findings.append(Finding("afi","AFI Instruction", s_afi,
                        "AFI disables entire rung — remove or replace with proper logic.",
                        location=loc))

            for i in find_instructions(instrs, "OTE"):
                if i["operands"]: ote_map[i["operands"][0]].append((rname, rnum))
            for i in find_instructions(instrs, "OTL"):
                if i["operands"]: otl_map[i["operands"][0]].append((rname, rnum))
            for i in find_instructions(instrs, "OTU"):
                if i["operands"]: otu_map[i["operands"][0]].append((rname, rnum))

            if s_msggate != "DISABLED":
                if find_instructions(instrs, "MSG"):
                    has_ons   = bool(find_instructions(instrs, "ONS","OSR","OSF"))
                    has_timer = any(operand_member(op).upper() in ("DN","TT","EN")
                                    for i in find_instructions(instrs,"XIC","XIO")
                                    for op in i["operands"])
                    if not has_ons and not has_timer:
                        findings.append(Finding("msg_gated","MSG Without Gate", s_msggate,
                            "MSG fires every scan — gate with ONS or timer contact.", location=loc))

            if s_hardcode != "DISABLED":
                for i in instrs:
                    if i["name"] not in _WRITE_INSTRS: continue
                    for op in i["operands"][:-1]:
                        if _NUMERIC_RE.match(op) and op not in ("0","1","-1"):
                            findings.append(Finding("hardcode","Hardcoded Literal", s_hardcode,
                                f"{i['name']}(…{op}…) — use a named constant tag.",
                                location=loc))
                            break

            for i in find_instructions(instrs, "JSR","JXR"):
                if i["operands"]: called.add(i["operands"][0])

    if s_otedup != "DISABLED":
        for tag, locs in ote_map.items():
            if len(locs) > 1:
                findings.append(Finding("ote_dup","OTE Duplicate Output", s_otedup,
                    f"'{tag}' driven by OTE in {len(locs)} places: " +
                    "; ".join(f"{r}/Rung {n}" for r,n in locs),
                    location=f"{scope}:{tag}"))

    if s_otlmulti != "DISABLED":
        for tag, locs in otl_map.items():
            if len(locs) > 1:
                findings.append(Finding("otl_multi","Multiple OTL on Same Tag", s_otlmulti,
                    f"'{tag}' has OTL in {len(locs)} rungs — latching conflict.",
                    location=f"{scope}:{tag}"))

    if s_otumulti != "DISABLED":
        for tag, locs in otu_map.items():
            if len(locs) > 1:
                findings.append(Finding("otu_multi","Multiple OTU on Same Tag", s_otumulti,
                    f"'{tag}' has OTU in {len(locs)} rungs — unlatching conflict.",
                    location=f"{scope}:{tag}"))

    if s_uncallrtn != "DISABLED":
        # Routines called from ST/FBD (JSR there is invisible to ladder parsing)
        st_text = "\n".join(r.get("usage_text", "") for r in prog["routines"])
        st_called = set(re.findall(r"[A-Za-z_]\w*", st_text))
        # AOI support routines are run by the controller, never by JSR.
        exempt = {"Logic", "Prescan", "Postscan", "EnableInFalse"} if scope.startswith("AOI:") else set()
        for rtn in prog["routines"]:
            if rtn.get("protected"):
                continue
            if rtn["name"] not in called and rtn["name"] not in exempt and rtn["name"] not in st_called:
                findings.append(Finding("uncall_rtn","Uncalled Routine", s_uncallrtn,
                    f"'{rtn['name']}' never called by JSR and not main/fault routine.",
                    location=f"{scope} / {rtn['name']}"))

    if s_jsr != "DISABLED":
        _check_jsr_depth(prog, sev, findings, scope)

    return findings


def _check_jsr_depth(prog, sev, findings, scope):
    graph = defaultdict(set)
    for rtn in prog["routines"]:
        for rung in rtn["rungs"]:
            for i in find_instructions(parse_rung(rung["text"]), "JSR"):
                if i["operands"]: graph[rtn["name"]].add(i["operands"][0])

    def depth(node, on_path):
        # on_path is the current call stack; cycle → stop, don't infinite-recurse.
        if node in on_path:
            return 0
        new_path = on_path | {node}
        children = graph.get(node, set())
        return 1 + max((depth(c, new_path) for c in children), default=0)

    main = prog.get("main_routine","")
    if main and depth(main, set()) > 4:
        s = effective_severity("jsr_depth", sev)
        if s != "DISABLED":
            findings.append(Finding("jsr_depth","Nested JSR Depth > 4", s,
                f"Call chain from '{main}' exceeds 4 levels — risk of stack overflow.",
                location=f"{scope} / {main}"))


def dup_instr(ctx):
    out = []
    for loc, text, *_ in ctx.rungs:
        tree = rung_tree.parse(text)
        for seq in rung_tree.sequences(tree):
            seen = {}
            for it in seq:
                if it[0] != "I" or not it[2]:
                    continue
                k = rung_tree.key(it)
                if k in seen:
                    out.append(Finding("dup_instr", "", _P,
                        f"{rung_tree.fmt(it)} appears twice in series.", location=loc))
                else:
                    seen[k] = it
        for br in rung_tree.branches(tree):
            legs = [tuple(rung_tree.key(i) for i in leg) for leg in br[1]]
            for j, leg in enumerate(legs):
                if leg and leg in legs[:j]:
                    out.append(Finding("dup_instr", "", _P,
                        "Identical parallel branch legs: "
                        + "".join(rung_tree.fmt(i) for i in br[1][j]) + ".", location=loc))
    return out


def array_bounds(ctx):
    out = []
    for loc, text, *_ in ctx.rungs:
        bad = []
        for it, before in rung_tree.walk_series(rung_tree.parse(text)):
            for o in it[2]:
                for inner in re.findall(r"\[([^\]]*)\]", o):
                    for ident in _idents(inner):
                        if not _guarded(before, ident) and ident not in bad:
                            bad.append(ident)
        for ident in bad:
            out.append(Finding("array_bounds", "", _P,
                f"Index '{ident}' is used without a range check (LIM/LES/GRT…) before it on the same path.",
                location=loc))
    return out


_CPT_DIV = re.compile(r"(?:/|\bMOD\b)\s*([A-Za-z_][\w.:\[\]]*|[-+]?\d+(?:\.\d*)?)")


def div_zero(ctx):
    out = []
    for loc, text, *_ in ctx.rungs:
        for it, before in rung_tree.walk_series(rung_tree.parse(text)):
            name, ops = it[1].upper(), it[2]
            divisors = []
            if name in ("DIV", "MOD") and len(ops) >= 2:
                divisors.append(ops[1].strip())
            elif name == "CPT" and len(ops) >= 2:
                divisors += _CPT_DIV.findall(",".join(ops[1:]))
            for d in divisors:
                if _INT_LIT.match(d) or _REAL_LIT.match(d):
                    if float(d) == 0:
                        out.append(Finding("div_zero", "", _P, "Division by literal zero.", location=loc))
                    continue
                if not _guarded(before, d):
                    out.append(Finding("div_zero", "", _P,
                        f"Divisor '{d}' is not checked against zero before the division on the same path.",
                        location=loc))
    return out


def jmp_back(ctx):
    out = []
    by_rtn = defaultdict(list)
    for r in ctx.rungs:
        by_rtn[(r[3], r[4], r[5])].append(r)
    for rungs in by_rtn.values():
        lbl = {}
        for loc, text, instrs, *_, idx in rungs:
            for i in instrs:
                if i["name"] == "LBL" and i["operands"]:
                    lbl.setdefault(i["operands"][0].strip(), idx)
        for loc, text, instrs, *_, idx in rungs:
            for i in instrs:
                if i["name"] == "JMP" and i["operands"]:
                    tgt = i["operands"][0].strip()
                    if tgt in lbl and lbl[tgt] <= idx:
                        out.append(Finding("jmp_back", "", _P,
                            f"JMP({tgt}) jumps backward to a label at or above this rung.",
                            location=loc))
    return out


def timer_reuse(ctx):
    out = []
    for (scope, op), uses in _keyed(ctx, TIMERS | COUNTERS).items():
        names = [n for n, _ in uses]
        timers = [n for n in names if n in TIMERS]
        ctrs = [n for n in names if n in COUNTERS]
        ok_updown = sorted(ctrs) == ["CTD", "CTU"] and not timers
        if len(uses) > 1 and not ok_updown:
            out.append(Finding("timer_reuse", "", _P,
                f"'{op}' is used by {len(uses)} instructions: "
                + ", ".join(f"{n} @ {l}" for n, l in uses[:4]) + ".",
                location=uses[0][1]))
    return out


def oneshot_reuse(ctx):
    out = []
    storage = _keyed(ctx, {"ONS", "OSR", "OSF"})
    writes = _keyed(ctx, {"OTE", "OTL", "OTU", "CLR"})
    for key, uses in storage.items():
        extra = writes.get(key, [])
        if len(uses) > 1 or extra:
            why = []
            if len(uses) > 1:
                why.append(f"shared by {len(uses)} one-shots")
            if extra:
                why.append("also written by " + ", ".join(n for n, _ in extra[:3]))
            out.append(Finding("oneshot_reuse", "", _P,
                f"Storage bit '{key[1]}' is " + " and ".join(why) + ".",
                location=uses[0][1]))
    return out


def res_missing(ctx):
    out = []
    all_text = "\n".join(r[1] for r in ctx.rungs)
    for (scope, op), uses in _keyed(ctx, {"RTO", "RTOR", "CTU", "CTD", "CTUD"}).items():
        if "[" in op:
            # Array element: a RES or .ACC write on the same array with ANY
            # index (constant or variable, e.g. RES(Arr[i]) in a loop) counts.
            tgt = re.escape(op.split("[", 1)[0]) + r"\[[^\]]*\]"
        else:
            tgt = re.escape(op)
        if re.search(r"\bRES\(\s*" + tgt + r"\s*\)", all_text):
            continue
        if re.search(r",\s*" + tgt + r"\.ACC\s*\)|\bCLR\(\s*" + tgt + r"\.ACC\s*\)", all_text):
            continue
        out.append(Finding("res_missing", "", _P,
            f"'{op}' ({uses[0][0]}) is never reset — no RES and no write to .ACC.",
            location=uses[0][1]))
    return out


_MSG_BITS = {"EN", "DN", "ER", "ST", "TO", "EW", "TT", "EN_CC"}


_TC_BITS  = {"DN", "EN", "TT", "CU", "CD", "OV", "UN"}


_MSG_ONLY = {"ER", "ST", "TO", "EW"}          # unambiguous without a type


_TC_ONLY  = {"CU", "CD", "OV", "UN"}


def _write_targets(it):
    """Operands an instruction WRITES (destination), by instruction."""
    n, ops = it[1].upper(), it[2]
    if n in ("OTE", "OTL", "OTU", "CLR", "ONS") and ops:
        return [ops[0]]
    if n in ("MOV", "COP", "CPS", "TRN", "NEG", "NOT", "FRD", "TOD", "SWPB") and len(ops) >= 2:
        return [ops[-1] if n not in ("COP", "CPS") else ops[1]]
    if n in ("ADD", "SUB", "MUL", "DIV", "MOD", "AND", "OR", "XOR") and len(ops) >= 3:
        return [ops[2]]
    if n == "CPT" and ops:
        return [ops[0]]
    return []


def protected_writes(ctx):
    out = []
    for loc, text, instrs, prog, aoi, *_ in ctx.rungs:
        for it, _b in rung_tree.walk_series(rung_tree.parse(text)):
            for tgt in _write_targets(it):
                tgt = tgt.strip()
                if "." not in tgt:
                    continue
                parent, member = tgt.rsplit(".", 1)
                member = member.upper()
                if member not in _MSG_BITS | _TC_BITS:
                    continue
                ptype = (ctx.resolve_type(parent, prog, aoi) or "").upper()
                if ptype == "MESSAGE" or (not ptype and member in _MSG_ONLY):
                    out.append(Finding("msg_write", "", _P,
                        f"{it[1]}({','.join(it[2])}) writes .{member} of MESSAGE '{parent}', which the controller manages.",
                        location=loc))
                elif ptype in ("TIMER", "COUNTER") or (not ptype and member in _TC_ONLY):
                    kind = ptype or "COUNTER"
                    out.append(Finding("timer_wr", "", _P,
                        f"{it[1]}({','.join(it[2])}) writes .{member} of {kind} '{parent}', which the controller manages.",
                        location=loc))
    return out


def empty_branch(ctx):
    out = []
    for loc, text, *_ in ctx.rungs:
        s = re.sub(r"\s+", "", _strip_parens(text or ""))
        if re.search(r"\[,|,,|,\]|\[\]", s):
            out.append(Finding("empty_branch", "", _P,
                "Rung has an empty branch leg (always-true bypass).", location=loc))
    return out


def mov_real_int(ctx):
    out = []
    for loc, text, instrs, prog, aoi, *_ in ctx.rungs:
        for i in instrs:
            if i["name"] != "MOV" or len(i["operands"]) < 2:
                continue
            src, dst = i["operands"][0].strip(), i["operands"][1].strip()
            st, dt = ctx.resolve_type(src, prog, aoi), ctx.resolve_type(dst, prog, aoi)
            if st in REAL_TYPES and dt in INT_TYPES:
                out.append(Finding("mov_real_int", "", _P,
                    f"MOV({src},{dst}) converts {st} to {dt}.", location=loc))
    return out


def _msg_stagger(rungs, sev):
    s = effective_severity("msg_stagger", sev)
    if s == "DISABLED":
        return []
    by_trigger = {}
    for loc, text in rungs:
        for m in _MSG_RE.finditer(text or ""):
            tag = m.group(1)
            pre = (text[:m.start()]).replace(tag, "§")   # own tag → placeholder
            pre = re.sub(r"\s+", "", pre)
            by_trigger.setdefault(pre, []).append((tag, loc))
    out = []
    for pre, items in by_trigger.items():
        if len(items) < 2:
            continue
        cond = pre if pre else "(unconditional)"
        out.append(Finding("msg_stagger", "MSGs Not Staggered", s,
            f"{len(items)} MSG instructions share the same trigger condition "
            f"{cond!r} and will fire together. Stagger their enables.",
            location=items[0][1],
            detail="; ".join(f"{t} @ {l}" for t, l in items[:20])))
    return out
