import re
# parser/cross_ref.py
"""
Builds a cross-reference index mapping every tag name to all locations
where it appears as an instruction operand.

Index structure:
  {
    "TagName": [
      { "scope": "Controller" | program_name | aoi_name,
        "routine": routine_name,
        "rung": rung_number_str,
        "instruction": "OTE",
        "operand_full": "TagName.DN",
      }, ...
    ]
  }

Also builds:
  write_index  — operands written: OTE/OTL/OTU, MOV/COP/CPT/math destinations, RES, timers, counters
  ote_index    — tags driven by OTE specifically
  otl_index    — tags driven by OTL
  otu_index    — tags driven by OTU
"""

from collections import defaultdict
from rung_parser import parse_rung, operand_base

# Which operand an instruction writes, by position (Logix operand order):
#   OTE(Dest)  MOV(Source,Dest)  COP(Source,Dest,Length)  ADD(A,B,Dest)  CPT(Dest,Expression)
_DEST_FIRST  = {"OTE", "OTL", "OTU", "CLR", "ONS", "RES", "TON", "TOF", "RTO", "CTU", "CTD", "CPT"}
_DEST_SECOND = {"COP", "CPS", "FLL"}
_DEST_THIRD  = {"BTD"}
_DEST_LAST   = {"MOV", "MOVE", "TRN", "NEG", "NOT", "FRD", "TOD", "SWPB", "SQR", "ABS", "LN", "LOG",
                "ADD", "SUB", "MUL", "DIV", "MOD", "AND", "OR", "XOR"}


def _dest_index(iname: str, ops: list) -> int | None:
    if not ops:
        return None
    if iname in _DEST_FIRST:
        return 0
    if iname in _DEST_SECOND and len(ops) >= 2:
        return 1
    if iname in _DEST_THIRD and len(ops) >= 3:
        return 2
    if iname in _DEST_LAST and len(ops) >= 2:
        return len(ops) - 1
    return None


# Pure output coil instructions
_COIL_INSTRS = {"OTE", "OTL", "OTU"}


def build(program_data: dict) -> dict:
    """
    Build and return the full cross-reference structure.

    program_data is the parsed dict from l5x_loader.load().
    """
    tag_index   = defaultdict(list)
    write_index = defaultdict(list)
    ote_index   = defaultdict(list)
    otl_index   = defaultdict(list)
    otu_index   = defaultdict(list)

    def process_routines(routines, scope):
        for rtn in routines:
            rtn_name = rtn["name"]
            for rung in rtn["rungs"]:
                rung_num = rung["number"]
                instrs   = parse_rung(rung["text"])
                for instr in instrs:
                    iname = instr["name"]
                    ops   = instr["operands"]
                    loc   = {
                        "scope":    scope,
                        "routine":  rtn_name,
                        "rung":     rung_num,
                        "instruction": iname,
                    }

                    for idx, op in enumerate(ops):
                        base = operand_base(op)
                        if not base:
                            continue
                        entry = {**loc, "operand_full": op}
                        tag_index[base].append(entry)

                        # Write tracking
                        if idx == _dest_index(iname, ops):
                            write_index[op].append(entry)  # full operand (with .member)

                        if iname == "OTE" and idx == 0:
                            ote_index[op].append(entry)
                        elif iname == "OTL" and idx == 0:
                            otl_index[op].append(entry)
                        elif iname == "OTU" and idx == 0:
                            otu_index[op].append(entry)

    def process_usage_text(routines, scope):
        """ST/FBD/SFC routines: every identifier counts as a reference."""
        for rtn in routines:
            txt = rtn.get("usage_text") or ""
            for op in set(re.findall(r"[A-Za-z_][\w:]*(?:\[[^\]]*\])?(?:\.[\w\[\],]+)*", txt)):
                base = operand_base(op)
                if base:
                    tag_index[base].append({"scope": scope, "routine": rtn["name"], "rung": None,
                                            "instruction": "ST/FBD", "operand_full": op})

    # Controller-scoped routines (rare but possible via Add-On)
    for prog in program_data.get("programs", []):
        process_routines(prog["routines"], scope=prog["name"])
        process_usage_text(prog["routines"], scope=prog["name"])

    # AOI internal routines
    for aoi in program_data.get("aois", []):
        process_routines(aoi["routines"], scope=f"AOI:{aoi['name']}")
        process_usage_text(aoi["routines"], scope=f"AOI:{aoi['name']}")

    return {
        "tag_index":   dict(tag_index),
        "write_index": dict(write_index),
        "ote_index":   dict(ote_index),
        "otl_index":   dict(otl_index),
        "otu_index":   dict(otu_index),
    }


def all_declared_tags(program_data: dict) -> dict:
    """
    Return a dict of all declared tags by scope.
    { "Controller": [tag,...], "ProgramName": [tag,...] }
    """
    result = {}
    result["Controller"] = program_data.get("tags", [])
    for prog in program_data.get("programs", []):
        result[prog["name"]] = prog.get("tags", [])
    return result


