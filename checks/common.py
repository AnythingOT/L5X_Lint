"""
Shared context and helpers for all checks: parsed-rung context (Ctx), operand
type resolution, constants, and small helpers used across categories.
"""

import re
from collections import defaultdict
from rung_parser import parse_rung


_DESC_REQUIRED = {"BOOL","SINT","INT","DINT","LINT","USINT","UINT","UDINT","ULINT","REAL","LREAL"}


_DESC_SKIP     = {"TIMER","TON","TOF","RTO","COUNTER","CTU","CTD","STRING","MESSAGE","AXIS"}


_BIT_CAPABLE   = {"DINT","INT","SINT","LINT","UDINT","UINT","USINT","ULINT"}


def _is_array(tag: dict) -> bool:
    return bool(tag.get("dimensions", "")) or "[" in tag.get("data_type", "")


def _is_udt(tag: dict, known_udts: set) -> bool:
    return tag["data_type"].split("[")[0].upper() in known_udts


def _desc_should_flag(tag: dict, known_udts: set) -> bool:
    dt = tag["data_type"].split("[")[0].upper()
    if _is_array(tag):   return False
    if dt in _DESC_SKIP: return False
    if _is_udt(tag, known_udts): return False
    return dt in _DESC_REQUIRED


def _downgrade(sev):
    order = ["CRITICAL","ERROR","WARNING","INFO"]
    idx = order.index(sev) if sev in order else -1
    return order[min(idx+1, 3)] if idx >= 0 else sev


_P = "WARNING"   # placeholder severity; registry overrides


INT_TYPES  = {"SINT", "INT", "DINT", "LINT", "USINT", "UINT", "UDINT", "ULINT"}


REAL_TYPES = {"REAL", "LREAL"}


TIMERS     = {"TON", "TOF", "RTO", "TONR", "TOFR", "RTOR"}


COUNTERS   = {"CTU", "CTD", "CTUD"}


COMPARE    = {"LIM", "LES", "LEQ", "GRT", "GEQ", "EQU", "NEQ", "MEQ", "CMP"}


IO_CATALOG = re.compile(r"^(1756|1769|1734|1794|5069|5094)-(I|O)")


_BUILTIN_MEMBERS = {
    "TIMER":   {"PRE": "DINT", "ACC": "DINT"},
    "COUNTER": {"PRE": "DINT", "ACC": "DINT"},
    "CONTROL": {"LEN": "DINT", "POS": "DINT"},
}


_INT_LIT  = re.compile(r"^[-+]?\d+$")


_REAL_LIT = re.compile(r"^[-+]?(\d+\.\d*|\.\d+|\d+(\.\d*)?[eE][-+]?\d+)$")


class Ctx:
    def __init__(self, data):
        self.data = data
        self.ctrl = {t["name"]: t for t in data.get("tags", [])}
        self.prog = {p["name"]: {t["name"]: t for t in p.get("tags", [])}
                     for p in data.get("programs", [])}
        # AOI scope = parameters + local tags (LocalTags/LocalTag).
        self.aoi_params = {a["name"]: {**{t["name"]: t for t in a.get("tags", [])},
                                       **{p["name"]: p for p in a.get("parameters", [])}}
                           for a in data.get("aois", [])}
        # Text of ST/FBD/SFC routines: rules don't analyse it, but references
        # in it count as USAGE (a tag used only in ST is not unused).
        self.usage_text = "\n".join(
            r.get("usage_text", "") for p in data.get("programs", []) for r in p.get("routines", [])
        ) + "\n" + "\n".join(
            r.get("usage_text", "") for a in data.get("aois", []) for r in a.get("routines", []))
        self.udts = {d["name"]: d for d in data.get("datatypes", [])}
        # rungs: (location, text, instrs, prog_name|None, aoi_name|None, routine, index)
        self.rungs = []
        for p in data.get("programs", []):
            for r in p.get("routines", []):
                for i, g in enumerate(r.get("rungs", [])):
                    self.rungs.append((f"{p['name']} / {r['name']} / Rung {g['number']}",
                                       g.get("text", ""), parse_rung(g.get("text", "")),
                                       p["name"], None, r["name"], i))
        for a in data.get("aois", []):
            for r in a.get("routines", []):
                for i, g in enumerate(r.get("rungs", [])):
                    self.rungs.append((f"AOI:{a['name']} / {r['name']} / Rung {g['number']}",
                                       g.get("text", ""), parse_rung(g.get("text", "")),
                                       None, a["name"], r["name"], i))

    def scope_of(self, base, prog, aoi):
        if aoi and base in self.aoi_params.get(aoi, {}):
            return f"aoi:{aoi}"
        if prog and base in self.prog.get(prog, {}):
            return f"prog:{prog}"
        return "ctrl"

    def base_type(self, base, prog, aoi):
        if aoi and base in self.aoi_params.get(aoi, {}):
            return self.aoi_params[aoi][base].get("data_type", "")
        if prog and base in self.prog.get(prog, {}):
            return self.prog[prog][base].get("data_type", "")
        if base in self.ctrl:
            return self.ctrl[base].get("data_type", "")
        return None

    def resolve_type(self, operand, prog, aoi):
        """Datatype of an operand, or None if it can't be resolved."""
        op = (operand or "").strip()
        if _INT_LIT.match(op):
            return "DINT"
        if _REAL_LIT.match(op):
            return "REAL"
        parts = re.sub(r"\[[^\]]*\]", "", op).split(".")
        if not parts or not re.match(r"^[A-Za-z_]\w*$", parts[0]):
            return None
        t = self.base_type(parts[0], prog, aoi)
        if not t:
            return None
        t = t.upper()
        for part in parts[1:]:
            if part.isdigit():
                return "BOOL"
            udt = next((u for n, u in self.udts.items() if n.upper() == t), None)
            if udt:
                m = next((m for m in udt.get("members", [])
                          if m["name"].upper() == part.upper()), None)
                if not m:
                    return None
                t = (m.get("data_type") or "").upper()
                t = "BOOL" if t == "BIT" else t
            elif t in _BUILTIN_MEMBERS:
                t = _BUILTIN_MEMBERS[t].get(part.upper(), "BOOL")
            else:
                return None
        return t


def _idents(s):
    return re.findall(r"[A-Za-z_][\w.:]*", s or "")


def _guarded(before, tag):
    """True if a compare on `tag` precedes the instruction in series on its path."""
    pat = re.compile(r"(?<![\w.:])" + re.escape(tag) + r"(?![\w])")
    return any(it[1].upper() in COMPARE and any(pat.search(o) for o in it[2]) for it in before)


def _concrete(op):
    """Operand usable as an identity key (no variable index)."""
    return all(re.fullmatch(r"\s*\d+(\s*,\s*\d+)*\s*", x)
               for x in re.findall(r"\[([^\]]*)\]", op))


def _keyed(ctx, names, op_index=0):
    """{(scope, operand): [(instr, loc)]} for instructions in `names`."""
    acc = defaultdict(list)
    for loc, text, instrs, prog, aoi, *_ in ctx.rungs:
        for i in instrs:
            if i["name"] in names and len(i["operands"]) > op_index:
                op = i["operands"][op_index].strip()
                if not _concrete(op):
                    continue
                base = re.split(r"[.\[]", op)[0]
                acc[(ctx.scope_of(base, prog, aoi), op)].append((i["name"], loc))
    return acc


def _strip_parens(text):
    out, depth = [], 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)


DEFAULT_URS_CFG = {
    "safety_prefix":       "SFTY_",
    "std_prefix":          "STD_",
    "udt_case_exclude":    ["P_", "raP_", "raC_"],   # PlantPAx / Rockwell libraries
    "module_name_pattern": r"^R\d{2}S\d{2}$",
    "io_catalog_pattern":  r"^(1756|1769|1734|1794|5069|5094)-(I|O)",
    "heartbeat_pattern":   r"(?i)(heart_?beat|^hb_|_hb$|^hb$|alive|watchdog|wdg)",
    "required_tags":       [],   # [{req, label, pattern, data_type}]
}


_MSG_RE   = re.compile(r"\bMSG\(\s*([^,)\s]+)")


def _ucfg(cfg):
    out = dict(DEFAULT_URS_CFG)
    out.update(((cfg or {}).get("urs") or {}))
    return out


def _all_rungs(data):
    """Yield (location, text) for every ladder rung incl. AOI logic."""
    for prog in data.get("programs", []):
        for rtn in prog.get("routines", []):
            for r in rtn.get("rungs", []):
                yield f"{prog['name']} / {rtn['name']} / Rung {r['number']}", r.get("text", "")
    for aoi in data.get("aois", []):
        for rtn in aoi.get("routines", []):
            for r in rtn.get("rungs", []):
                yield f"AOI:{aoi['name']} / {rtn['name']} / Rung {r['number']}", r.get("text", "")


def _all_tags(data):
    """Yield (location, tag) for controller + program tags."""
    for t in data.get("tags", []):
        yield f"Controller:{t['name']}", t
    for prog in data.get("programs", []):
        for t in prog.get("tags", []):
            yield f"{prog['name']}:{t['name']}", t
