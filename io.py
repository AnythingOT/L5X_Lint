"""
Physical I/O rules: unmapped points, aliases, point comments, electronic keying.
"""

import re
from base_check import Finding
from checks.common import IO_CATALOG, _P


def _io_modules(ctx):
    return [m for m in ctx.data.get("modules", []) if IO_CATALOG.search(m.get("catalog") or "")]


def io_tag_name(m, suffix):
    """
    Logix module I/O tag name. Ethernet-connected modules use their own
    name ("Drive1:I"); modules on a backplane use the chassis owner and slot
    ("Local:4:I" in the controller chassis, "<Bridge>:4:I" in a remote one).
    """
    up = (m.get("upstream_type") or "").lower()
    slot = m.get("slot")
    if up == "ethernet" or slot is None:
        prefix = m["name"]
    else:
        parent = m.get("parent") or "Local"
        prefix = f"Local:{slot}" if parent == "Local" else f"{parent}:{slot}"
    return f"{prefix}:{suffix}"


def _point_count(catalog):
    """Digital point count from the catalog number: 1756-IB16 → 16, 1756-OW16I → 16."""
    m = re.search(r"-[A-Z]+(\d+)", (catalog or "").upper())
    return int(m.group(1)) if m else 0


def _io_points(m, io):
    """Field-data points of an I/O tag, as operand suffixes in display case."""
    pts = []
    for mem in io.get("data_members", []):
        if mem.lower() == "data":
            n = _point_count(m.get("catalog"))
            pts += [f".{mem}.{b}" for b in range(n)] if n else [f".{mem}"]
        else:
            pts.append(f".{mem}")
    return pts


def _alias_map(ctx):
    """[(alias_name, scope_label, resolved_target_upper)] — alias chains followed."""
    raw = {}
    entries = []
    for t in ctx.data.get("tags", []):
        if t.get("alias_for"):
            raw[t["name"].upper()] = t["alias_for"]
            entries.append((t["name"], "Controller", t["alias_for"]))
    for p in ctx.data.get("programs", []):
        for t in p.get("tags", []):
            if t.get("alias_for"):
                entries.append((t["name"], p["name"], t["alias_for"]))
    def resolve(target, depth=0):
        tgt = re.sub(r"\s+", "", target)
        base = re.split(r"[.\[]", tgt, 1)[0].upper()
        if depth < 10 and base in raw:
            return resolve(raw[base] + tgt[len(base):], depth + 1)
        return tgt.upper()
    return [(n, sc, resolve(a)) for n, sc, a in entries]


def _io_tags_all(ctx):
    """[(module, io, display_name, upper_name)] for physical I/O modules."""
    out = []
    for m in _io_modules(ctx):
        for io in m.get("io_tags", []):
            n = io_tag_name(m, io["suffix"])
            out.append((m, io, n, n.upper()))
    return out


def _direct_refs(ctx, name_u):
    """Operand suffixes of an I/O tag referenced DIRECTLY by logic (ladder, ST/FBD)."""
    corpus = ("\n".join(r[1] for r in ctx.rungs) + "\n" + ctx.usage_text).upper()
    pat = re.compile(r"(?<![\w:])" + re.escape(name_u) + r"((?:\.[A-Z0-9_]+|\[[^\]]*\])*)(?![\w:])")
    return set(pat.findall(corpus))


def _alias_cover(aliases, name_u):
    """Suffixes of an I/O tag covered by alias targets ('' = whole tag)."""
    out = set()
    for _n, _sc, tgt in aliases:
        if tgt == name_u or tgt.startswith(name_u + ".") or tgt.startswith(name_u + "["):
            out.add(tgt[len(name_u):])
    return out


def _covers(pt_u, refs):
    """A point is covered by an exact reference or any reference to a parent
    (whole word '.DATA', or the whole tag '')."""
    if pt_u in refs or "" in refs:
        return True
    parts = pt_u.split(".")
    for i in range(2, len(parts)):
        if ".".join(parts[:i]) in refs:
            return True
    return False


def io_unmapped(ctx):
    """WAR017 — a field-data point with no direct mapping logic and no alias.
    Points covered by an alias are reported by WAR022 instead."""
    aliases = _alias_map(ctx)
    out = []
    for m, io, name, name_u in _io_tags_all(ctx):
        direct = _direct_refs(ctx, name_u)
        aliased = _alias_cover(aliases, name_u)
        for pt in _io_points(m, io):
            u = pt.upper()
            if not _covers(u, direct) and not _covers(u, aliased):
                out.append(Finding("io_unmapped", "", _P,
                    "No direct mapping logic references this I/O point.",
                    location=f"IO:{name}{pt}"))
    return out


def io_alias(ctx):
    """WAR022 — an alias tag that points at a physical I/O tag or point.
    The standard is direct mapping; one finding per alias tag."""
    aliases = _alias_map(ctx)
    io_names = [(n, nu) for _m, _io, n, nu in _io_tags_all(ctx)]
    corpus = ("\n".join(r[1] for r in ctx.rungs) + "\n" + ctx.usage_text)
    out = []
    for alias, scope, tgt in aliases:
        hit = next((n for n, nu in io_names
                    if tgt == nu or tgt.startswith(nu + ".") or tgt.startswith(nu + "[")), None)
        if not hit:
            continue
        used = re.search(r"(?<![\w.:])" + re.escape(alias) + r"(?![\w])", corpus) is not None
        target = hit + tgt[len(hit):].replace(".DATA", ".Data")
        why = ("is used in logic: replace it with direct mapping." if used
               else "is not used in logic: delete it.")
        loc = f"Controller:{alias}" if scope == "Controller" else f"{scope}:{alias}"
        out.append(Finding("io_alias", "", _P,
            f"Alias '{alias}' → {target} {why}", location=loc))
    return out


def io_no_desc(ctx):
    """WAR018 — a field-data point used directly in logic with no comment on
    the module I/O tag. (Alias descriptions do not count: aliases are not
    part of the standard.)"""
    out = []
    for m, io, name, name_u in _io_tags_all(ctx):
        direct = _direct_refs(ctx, name_u)
        for pt in _io_points(m, io):
            u = pt.upper()
            if u in direct and u not in io["comments"]:
                out.append(Finding("io_no_desc", "", _P,
                    "I/O point is used but has no comment.", location=f"IO:{name}{pt}"))
    return out


def ekey_disabled(ctx):
    """INF008 — module electronic keying must be Compatible Module. Any other
    State (Exact Match, Disabled, or unexpected) is reported with its value.
    The schema types State as a free string, so no value list is assumed."""
    out = []
    ctrl_name = (ctx.data.get("controller") or {}).get("name")
    for m in ctx.data.get("modules", []):
        st = m.get("ekey")
        if st is None or m.get("name") == "Local":
            continue                       # no EKey element / the controller itself
        if re.sub(r"[\s_]", "", st).lower() == "compatiblemodule":
            continue
        out.append(Finding("ekey_disabled", "", _P,
            f"Module '{m['name']}' ({m.get('catalog')}) has keying '{st}'; must be Compatible Module.",
            location=f"Module:{m['name']}"))
    return out
