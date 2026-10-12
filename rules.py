# rules.py — the rule checklist. Single source of truth for codes,
# titles, descriptions and severities. Severity is FIXED per rule: the code
# prefix (CRT/ERR/WAR/INF) encodes it, so a configurable severity would make
# the code lie. Rules can only be enabled or disabled.
#
# check_id is the internal emitter name; code is what users see.

LIFECYCLE_CODES = {"ERR017", "WAR021", "INF009"}

SEV_PREFIX = {"CRITICAL": "CRT", "ERROR": "ERR", "WARNING": "WAR", "INFO": "INF"}
SEV_SHORT_LABEL = {"CRT": "Critical", "ERR": "Error", "WAR": "Warning", "INF": "Info"}

RULES = [
 # code,   check_id,          title,                           description
 ("CRT001","forced_tag",      "Forces Present",                "The export contains forced I/O or tag values. Forces must be removed before the project is released."),
 ("CRT002","afi",             "AFI In Rung",                   "An AFI (Always False) instruction disables the whole rung. Remove it or replace it with proper logic."),

 ("ERR001","ote_dup",         "Duplicate OTE",                 "The same tag or bit is driven by more than one OTE. Only the last one in scan order takes effect."),
 ("ERR002","otl_multi",       "Multiple OTL",                  "A tag is latched (OTL) from more than one place, which makes its state hard to trace."),
 ("ERR003","otu_multi",       "Multiple OTU",                  "A tag is unlatched (OTU) from more than one place, which makes its state hard to trace."),
 ("ERR004","msg_write", "Write to MSG Status Bit", "Logic writes a status bit (.EN, .DN, .ER …) of a MESSAGE tag, which the controller manages. The tag type is resolved through UDTs and arrays."),
 ("ERR005","timer_wr", "Write to Timer/Counter Bit", "Logic writes a .DN, .EN, .TT (or counter) bit of a TIMER or COUNTER, which the controller manages. The tag type is resolved through UDTs and arrays."),
 ("ERR006","msg_gated",       "MSG Not Gated",                 "A MSG instruction runs without ONS or timer gating, so it is re-triggered every scan."),
 ("ERR007","ctrl_fault_handler","Controller Fault Handler",    "No Controller Fault Handler program is configured, or it names a program that doesn't exist."),
 ("ERR008","prog_fault_routine","Program Fault Routine",       "A program has no Fault Routine assigned, or names a routine that doesn't exist."),
 ("ERR009","aoi_ctrl_tag",    "AOI Uses Controller Tag",       "AOI logic references a controller-scoped tag directly, which breaks AOI encapsulation."),
 ("ERR010","dup_instr", "Duplicate Instruction In Rung", "The same instruction with the same operand appears twice in one series chain, or two parallel branch legs are identical. Shared instructions in legs with other conditions are valid OR logic and not reported."),
 ("ERR011","array_bounds", "Unchecked Array Index", "An array is indexed by a tag (Arr[Idx]) without a LIM/LES/GRT range check on the index placed before it on the same path. An out-of-range index causes a major fault."),
 ("ERR012","div_zero", "Unguarded Division", "A DIV, MOD or '/' in CPT divides by a tag that is not compared against zero before it on the same path."),
 ("ERR013","jmp_back",        "Backward Jump",                 "A JMP jumps to a LBL at or above itself, creating a loop inside the scan (watchdog risk)."),
 ("ERR014","timer_reuse",     "Timer/Counter Reused",          "One TIMER or COUNTER tag is used by more than one timer/counter instruction. (One CTU plus one CTD on the same counter is allowed.)"),
 ("ERR015","oneshot_reuse",   "One-Shot Storage Reused",       "An ONS/OSR/OSF storage bit is shared by several one-shots, or is also written by other logic, so edges get missed."),
 ("ERR016","res_missing",     "No Reset For RTO/Counter",      "An RTO or counter accumulates but is never reset (no RES and no write to .ACC). For arrays, a reset of any element via an index counts."),
 ("ERR017","lc_discontinued", "Discontinued Module",           "An I/O module catalog is Discontinued according to the lifecycle dataset. Spares may be unobtainable."),

 ("WAR001","safety_std_map",  "Safety Map Naming",             "A standard tag mapped to safety tag SFTY_X must be named STD_X."),
 ("WAR002","pc_naming",       "Produced/Consumed Naming",      "A consumed tag must use the same name as the produced tag it maps to, with PRO replaced by CON."),
 ("WAR003","task_period_name","Task Name Missing Period",      "A periodic task's name must state its period (e.g. Task_10MS for a 10 ms task)."),
 ("WAR004","uncall_rtn",      "Uncalled Routine",              "A routine is not called by any JSR in its program."),
 ("WAR005","uncall_prog",     "Unscheduled Program",           "A program is not scheduled in any task."),
 ("WAR006","empty_rung",      "Empty Rung",                    "A rung contains no instructions."),
 ("WAR007","empty_branch",    "Empty Branch",                  "A branch leg contains no instructions, which acts as an always-true bypass."),
 ("WAR008","timer_pre",       "Timer Preset Not Set",          "A timer used in logic has preset 0 in its tag data and logic never sets .PRE. Timer arrays are checked per element."),
 ("WAR009","watchdog",        "Watchdog Margin Too Small",     "A task's watchdog is less than 1.5 × its period, so one slow scan can fault the controller."),
 ("WAR010","udt_pad",         "UDT Padding Waste",             "Reordering this UDT's members would save at least 4 bytes of alignment padding."),
 ("WAR011","udt_order", "UDT Member Order", "UDT members are not grouped by data type, or not in alphabetical order (natural order: Valve2 before Valve10)."),
  # WAR012 retired (Write-Type MSG) — code kept reserved, not reused.
 ("WAR013","msg_stagger",     "MSGs Not Staggered",            "Two or more MSGs share the same trigger condition and fire together."),
 ("WAR014","jsr_depth",       "JSR Nesting Too Deep",          "A JSR call chain is nested deeper than the limit."),
 ("WAR015","mov_real_int",    "MOV REAL To Integer",           "A MOV converts a REAL into an integer type. MOV rounds silently (.5 to even) and can overflow. Use TRN or explicit, commented rounding."),
 ("WAR016","small_int",       "INT/SINT Instead Of DINT",      "A tag uses INT or SINT. Logix is 32-bit native, so DINT is faster and avoids conversion."),
 ("WAR017","io_unmapped", "Physical I/O Point Not Mapped", "No direct mapping logic references a field-data point of a physical I/O module (e.g. Local:4:I.Data.3, Ch0Data). Points covered by an alias are reported by WAR022 instead. Status and fault members are excluded."),
 ("WAR018","io_no_desc", "Physical I/O Point Without Comment", "An I/O point referenced directly in logic has no comment on the module I/O tag. One finding per point."),
 ("WAR019","desc_spare", "Used Tag Marked Spare", "A tag, array element or bit is used in logic but its description or comment contains the word 'spare' or 'unused'."),
 ("WAR020","unused_type",     "Unused UDT/AOI Definition",     "A UDT or AOI definition is never used by any tag, member, parameter or rung."),
 ("WAR021","lc_eol",          "End-of-Life Module",            "An I/O module catalog has reached End of Life according to the lifecycle dataset. Plan migration."),
 ("WAR022","io_alias",        "Alias Used For Physical I/O",   "A tag is an alias of a physical I/O tag or point. The standard is direct mapping logic; the message says whether the alias is used in logic (replace) or not (delete)."),

 ("INF001","unused_tag",      "Unused Tag",                    "A tag is declared but never read or written."),
 ("INF002","loose_bool",      "Loose BOOL Tags",               "Standalone BOOL tags are used. Pack them into a DINT, BOOL array or UDT."),
 ("INF003","no_desc_tag", "Tag Without Description", "A used tag has no description, or a bit that logic addresses individually has no comment."),
 ("INF004","rung_no_desc",    "Rung Without Comment",          "A rung has no comment."),
 ("INF005","no_desc_aoi",     "AOI Without Description",       "An AOI or AOI parameter has no description."),
 ("INF006","udt_member_desc", "UDT Member Without Description", "A UDT member has no description. One finding per member."),
 ("INF007","hardcode",        "Hard-Coded Literal",            "A numeric literal (other than 0, 1, -1) is used in a write instruction."),
 ("INF008","ekey_disabled", "Electronic Keying Not Compatible", "An I/O module's electronic keying is not Compatible Module (Exact Match, Disabled or other). Compatible Module allows like-for-like spares while still blocking the wrong module."),
 ("INF009","lc_mature",       "Active Mature Module",          "An I/O module catalog is Active Mature. Newer alternatives exist; consider them for new designs."),
]

_SEV_FROM_PREFIX = {v: k for k, v in SEV_PREFIX.items()}
BY_CHECK = {}
BY_CODE = {}
for _code, _cid, _title, _desc in RULES:
    _rec = {"code": _code, "check_id": _cid, "title": _title, "desc": _desc,
            "severity": _SEV_FROM_PREFIX[_code[:3]]}
    BY_CHECK[_cid] = _rec
    BY_CODE[_code] = _rec


def build_gate(cfg: dict) -> dict:
    """{check_id: "DISABLED"} for rules switched off in Settings, so checks
    can skip the work instead of running and having findings discarded.
    Lifecycle rules are gated by the Lifecycle switch, not here."""
    disabled = set(((cfg or {}).get("disabled_rules") or [])) - LIFECYCLE_CODES
    return {BY_CODE[c]["check_id"]: "DISABLED" for c in disabled if c in BY_CODE}


def is_enabled(check_id: str, gate: dict) -> bool:
    return gate.get(check_id) != "DISABLED"


def apply_registry(findings: list, cfg: dict) -> list:
    """
    Keep only findings from registered, enabled rules; stamp code, title
    and the rule's fixed severity. Findings from unregistered emitters are
    dropped — the checklist is the contract.
    """
    # Lifecycle rules are controlled only by the Lifecycle switch (analysis
    # emits them only when it is on) — never by the per-rule list.
    disabled = set(((cfg or {}).get("disabled_rules") or [])) - LIFECYCLE_CODES
    out = []
    for f in findings:
        rec = BY_CHECK.get(f.check_id)
        if rec is None or rec["code"] in disabled:
            continue
        f.code = rec["code"]
        f.severity = rec["severity"]
        f.check_name = rec["title"]
        out.append(f)
    return out


def rule_list() -> list:
    return [dict(BY_CODE[c]) for c, *_ in RULES]
