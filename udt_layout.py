# udt_layout.py — Rockwell UDT memory layout: size, padding and optimal order.
"""
Pure computation on already-parsed XML (no second parse, no XML generation).

The layout arithmetic, type tables, sort key, cycle detection and topological
sort below were moved VERBATIM from the former L5XOpt_UDT / L5XGen_UDT
modules (which generated full L5X documents just to read back two numbers).
Equivalence with the old engine was verified by fuzzing; see CHANGES_v2.md.

Public:
  collect(root)        -> layout input from the parsed L5X root, or None
  analyse(layout)      -> per-UDT results in dependency order
  natural_key, member_sort_key   (used by the UDT member-order rule)
"""

import re
import logging

log = logging.getLogger(__name__)

TYPE_SIZES = {
    "BOOL":    1,
    "SINT":    1,
    "INT":     2,
    "DINT":    4,
    "LINT":    8,
    "REAL":    4,
    "LREAL":   8,
    "STRING":  88,
    "TIMER":   12,
    "COUNTER": 12,
    "CONTROL": 12,
    "MESSAGE": 50,
}


SCALAR_GROUP = {
    "BOOL":    0,
    "SINT":    1,
    "INT":     2,
    "DINT":    3,
    "REAL":    5,
    "LREAL":   6,
    "LINT":    7,
    "STRING":  8,
    "TIMER":   9,
    "COUNTER": 9,
    "CONTROL": 9,
    "MESSAGE": 9,
}


ARRAY_SUBGROUP = {
    "BOOL":    0,
    "SINT":    1,
    "INT":     2,
    "DINT":    3,
    "REAL":    4,
    "LREAL":   5,
    "LINT":    6,
    "STRING":  7,
    "TIMER":   8,
    "COUNTER": 8,
    "CONTROL": 8,
    "MESSAGE": 8,
}


SUPPORTED_TYPES = {
    "BOOL", "SINT", "INT", "DINT", "LINT",
    "REAL", "LREAL", "STRING",
    "TIMER", "COUNTER", "CONTROL", "MESSAGE",
}


def natural_key(name: str) -> list:
    parts = re.split(r'(\d+)', name.lower())
    return [int(p) if p.isdigit() else p for p in parts]


def member_sort_key(member: dict, udt_registry: dict = None, aoi_registry: dict = None) -> tuple:
    """AOI types sort with group 9 (TIMER/COUNTER group)."""
    base_type = member["type"].upper()
    is_array  = member.get("dimension", 0) > 0
    is_native = base_type in SUPPORTED_TYPES
    is_udt    = (not is_native) and (udt_registry and member["type"] in udt_registry)
    is_aoi    = (not is_native) and (not is_udt) and (aoi_registry and member["type"] in aoi_registry)
    nk        = natural_key(member["name"])

    # base_type sits between the group and the name so that types sharing
    # a group (TIMER/COUNTER/CONTROL/MESSAGE, AOIs, all UDT-typed members)
    # stay contiguous per exact type instead of interleaving by name.
    # Required by URS REQ-AUT-PLC-018 ("grouped with respect to datatype").
    # Padding-neutral: every type within a shared group is DINT-aligned.
    if is_array:
        sub = ARRAY_SUBGROUP.get(base_type, 9 if (is_udt or is_aoi) else 10)
        return (4, sub, base_type, nk)

    if is_aoi:
        return (9, base_type, nk)

    grp = SCALAR_GROUP.get(base_type, 10 if is_udt else 11)
    return (grp, base_type, nk)


_TYPE_ALIGNMENT = {
    "BOOL":    1,
    "SINT":    1,
    "INT":     2,
    "DINT":    4,
    "LINT":    8,
    "REAL":    4,
    "LREAL":   8,
    "STRING":  4,
    "TIMER":   4,
    "COUNTER": 4,
    "CONTROL": 4,
    "MESSAGE": 2,
}


def _align(offset: int, alignment: int) -> int:
    """Round offset up to the next multiple of alignment."""
    return (offset + alignment - 1) & ~(alignment - 1)


def _detect_cycles(graph: dict) -> list:
    """DFS cycle detection. Returns list of cycle description strings."""
    visited, rec_stack, cycles = set(), set(), []

    def dfs(node, path):
        visited.add(node); rec_stack.add(node)
        for nb in graph.get(node, set()):
            if nb not in visited:
                dfs(nb, path + [nb])
            elif nb in rec_stack:
                idx = path.index(nb) if nb in path else 0
                cycles.append(" → ".join(path[idx:] + [nb]))
        rec_stack.discard(node)

    for node in list(graph):
        if node not in visited:
            dfs(node, [node])
    return cycles


def _topological_sort(all_udts: dict) -> list:
    """Return UDT names in dependency order (leaves first).

    Raises ValueError if a dependency cycle exists — callers should catch
    and present this as a parse error rather than silently producing
    a bogus ordering.
    """
    dep_graph = {
        name: {m["type"] for m in udt.get("members", []) if m["type"] in all_udts}
        for name, udt in all_udts.items()
    }

    cycles = _detect_cycles(dep_graph)
    if cycles:
        raise ValueError("UDT dependency cycle(s) detected: " + "; ".join(cycles))

    order, visited = [], set()

    def visit(node):
        if node in visited:
            return
        visited.add(node)
        for dep in dep_graph.get(node, set()):
            visit(dep)
        order.append(node)

    for name in all_udts:
        visit(name)
    return order


def _estimate_udt_size(udt: dict, registry: dict, aoi_registry: dict = None) -> int:
    """
    Rockwell-accurate byte-size estimate (verified against Studio 5000).

    Layout rules:
    - Consecutive BIT members → packed into SINT(s), SINT block 4B-aligned.
    - BOOL[N] arrays → stored as DINT array (N/32 × 4B), 4B-aligned.
    - AOI instances → sized from their parameter list.
    - All other types → natural alignment per _TYPE_ALIGNMENT.
    - Final total padded to 4B minimum.
    """
    if aoi_registry is None:
        aoi_registry = {}

    members   = udt.get("members", [])
    offset    = 0
    max_align = 4
    i = 0

    while i < len(members):
        m     = members[i]
        mtype = m.get("type", "").upper()
        raw   = m.get("type", "")
        dim   = m.get("dimension", 0)

        if mtype == "BIT":
            bits = 0
            while i < len(members) and members[i].get("type", "").upper() == "BIT":
                bits += 1
                i    += 1
            n_bytes = (bits + 7) // 8
            offset  = _align(offset, 4)
            offset += n_bytes
            continue

        elif mtype == "BOOL" and dim > 0:
            sz  = ((dim + 31) // 32) * 4
            aln = 4

        elif mtype == "BOOL" and dim == 0:
            sz  = 1
            aln = 1

        elif mtype in TYPE_SIZES:
            sz  = TYPE_SIZES[mtype] * max(dim, 1)
            aln = _TYPE_ALIGNMENT.get(mtype, 1)

        elif raw in registry:
            sz  = registry[raw] * max(dim, 1)
            aln = min(registry[raw], 4)

        elif raw in aoi_registry:
            sz  = aoi_registry[raw] * max(dim, 1)
            aln = min(aoi_registry[raw], 4)

        else:
            sz  = 4 * max(dim, 1)
            aln = 4

        max_align = max(max_align, aln)
        offset    = _align(offset, aln)
        offset   += sz
        i        += 1

    return _align(offset, max_align)


def _compute_member_list_size(members: list, registry: dict, aoi_registry: dict = None) -> int:
    """Compute aligned size from a flat list of {type, dimension} dicts."""
    return _estimate_udt_size({"members": members}, registry, aoi_registry or {})


def _members_order_changed(original_members: list, opt_member_names: list) -> bool:
    orig_names = [m["name"] for m in original_members
                  if not m.get("hidden") and not m["name"].startswith("ZZZZZZZZZZ")]
    return orig_names != opt_member_names


# ── input: same selection rules as the old engine ────────────────────────────

def _parse_members(dt_element) -> list:
    """Members of a <DataType>, skipping hidden ZZZZZZZZZZ host members."""
    members = []
    for m in dt_element.findall("./Members/Member"):
        mname = m.get("Name", "")
        if not mname or mname.startswith("ZZZZZZZZZZ"):
            continue
        try:
            dimension = int(m.get("Dimension", "0"))
        except ValueError:
            dimension = 0
        members.append({
            "name":      mname,
            "type":      m.get("DataType", ""),
            "dimension": dimension,
            "hidden":    m.get("Hidden", "false").lower() == "true",
        })
    return members


def _aoi_size(aoi_element) -> int:
    """AOI instance size from its parameter list, declared order."""
    members = [{"type": p.get("DataType", "DINT"), "dimension": 0}
               for p in aoi_element.findall("./Parameters/Parameter")]
    return _estimate_udt_size({"members": members}, {})


def collect(root):
    """
    Layout input from the parsed L5X root:
      {"udts": {name: {"name", "members"}}, "aoi_sizes": {name: bytes}}
    Every <DataType> anywhere except Class="System" (custom string types
    included). Returns None where the old engine produced no UDT results
    (non-controller export with several UDTs and no Use="Target").
    """
    l5x_type = {"DataType": "single_udt", "Controller": "full_program"}.get(
        root.get("TargetType", ""), "unknown")
    aoi_sizes = {}
    for aoi in root.findall(".//AddOnInstructionDefinition"):
        if aoi.get("Name"):
            aoi_sizes[aoi.get("Name")] = _aoi_size(aoi)
    udts, target = {}, None
    for dt in root.findall(".//DataType"):
        name = dt.get("Name")
        if not name or dt.get("Class", "User") == "System":
            continue
        if dt.get("Use") == "Target":
            target = name
        udts[name] = {"name": name, "members": _parse_members(dt)}
    if not target and len(udts) != 1 and l5x_type != "full_program":
        return None
    return {"udts": udts, "aoi_sizes": aoi_sizes}


# ── analysis: same results as the old optimise-and-regenerate path ──────────

def analyse(layout):
    """
    Yields per UDT, in dependency order:
      {"name", "size_before", "size_after", "opt_needed", "skipped_types"}
    opt_needed is None when no member type could be resolved.
    Raises ValueError on a UDT dependency cycle.
    """
    udts, aoi = layout["udts"], layout["aoi_sizes"]
    order = _topological_sort(udts)
    reg = {}
    for name in order:
        reg[name] = _estimate_udt_size(udts[name], reg, aoi)
    for name in order:
        udt = udts[name]
        size_before = _estimate_udt_size(udt, reg, aoi)
        skipped, sortable = set(), []
        for m in udt["members"]:
            raw = m.get("type", "DINT")
            up = raw.upper()
            base = "BOOL" if up == "BIT" else up
            native, known, is_aoi = base in SUPPORTED_TYPES, raw in udts, raw in aoi
            if not native and not known and not is_aoi:
                skipped.add(raw)
                continue
            if (known or is_aoi) and not native:
                base = raw
            dim = m.get("dimension", 0)
            nested = (not native) and (base in reg)
            aoi_tag = (not native) and (not nested) and (base in aoi)
            sortable.append({"name": m["name"], "type": base.upper() if native else base,
                             "dimension": dim, "is_nested_udt": nested or aoi_tag,
                             "is_aoi": aoi_tag, "hidden": m.get("hidden", False)})
        if not sortable:
            yield {"name": name, "size_before": size_before, "size_after": size_before,
                   "opt_needed": None, "skipped_types": sorted(skipped)}
            continue
        ordered = sorted(sortable, key=lambda x: member_sort_key(x, reg, aoi))
        opt_names = [t["name"] for t in ordered if not t.get("hidden")]
        opt_members = [{"type": "BIT", "dimension": 0} if (t["type"].upper() == "BOOL" and t["dimension"] == 0)
                       else {"type": t["type"], "dimension": t["dimension"]} for t in ordered]
        yield {"name": name, "size_before": size_before,
               "size_after": _compute_member_list_size(opt_members, reg, aoi),
               "opt_needed": _members_order_changed(udt["members"], opt_names),
               "skipped_types": sorted(skipped)}
