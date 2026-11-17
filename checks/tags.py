"""
Tag rules: unused tags, descriptions and bit comments, loose BOOLs,
INT/SINT, spare-marked tags, timer presets, produced/consumed and safety naming.
"""

import re
from base_check import Finding, effective_severity
from cross_ref import all_declared_tags
from checks.common import _BIT_CAPABLE, _P, _all_tags, _desc_should_flag, _is_array


def _check_tags(data, xref, sev, loose_min=8):
    findings = []
    tag_idx  = xref.get("tag_index", {})
    s_loose  = effective_severity("loose_bool",  sev)
    s_unused = effective_severity("unused_tag",  sev)
    s_nodesc = effective_severity("no_desc_tag", sev)

    known_udts = {d["name"].upper() for d in data.get("datatypes", [])}
    known_udts |= {a["name"].upper() for a in data.get("aois", [])}

    for scope, tags in all_declared_tags(data).items():
        if scope.startswith("AOI:"):
            continue

        bools = []

        for tag in tags:
            name     = tag["name"]
            dt       = tag["data_type"].split("[")[0].upper()
            used     = name in tag_idx
            ext_acc  = tag.get("external_access", "").strip()
            is_ext   = ext_acc.lower() not in ("none", "")

            # ── Loose BOOL
            if dt == "BOOL" and not _is_array(tag) and s_loose != "DISABLED":
                bools.append(name)

            # ── Unused tag (merged with ExternalAccess note)
            if s_unused != "DISABLED" and not used:
                where = "anywhere in the PLC program" if scope == "Controller" \
                        else f"anywhere in {scope}"
                msg = f"'{name}' is not used {where}."
                if is_ext:
                    msg += f"  (ExternalAccess: {ext_acc} — may be used by HMI/SCADA)"

                findings.append(Finding(
                    "unused_tag", "Unused Tag", s_unused,
                    msg, location=f"{scope}:{name}"))

            # ── No description on scalar used tags
            if used and not tag["description"] and s_nodesc != "DISABLED":
                if _desc_should_flag(tag, known_udts):
                    findings.append(Finding(
                        "no_desc_tag", "Tag Without Description", s_nodesc,
                        f"'{name}' has no description.",
                        location=f"{scope}:{name}"))

            # ── Bit-level comments: only bits referenced individually in logic
            if s_nodesc != "DISABLED":
                _check_array_bit_comments(tag, name, scope, findings, s_nodesc, xref)

        # ── Loose BOOL cluster
        if len(bools) >= loose_min and s_loose != "DISABLED":
            findings.append(Finding("loose_bool", "Loose BOOL Tags", s_loose,
                f"{len(bools)} standalone BOOL tags in '{scope}'. "
                f"Consider packing into a DINT or UDT.",
                location=scope,
                detail=", ".join(bools[:20]) + ("…" if len(bools) > 20 else "")))

    return findings


def _check_array_bit_comments(tag, name, scope, findings, severity, xref=None):
    """
    INF003 at bit level: one finding per bit that logic references
    individually (e.g. XIC(Flags[2].5)) and that has no comment. Bits that
    are never addressed individually are not reported — a DINT array used
    as plain data storage needs no bit comments.
    """
    dt = tag["data_type"].split("[")[0].upper()
    if dt not in _BIT_CAPABLE:
        return
    comments = {k.replace(" ", ""): v for k, v in (tag.get("comments") or {}).items()}
    refs = set()
    for e in (xref or {}).get("tag_index", {}).get(name, []):
        op = re.sub(r"\s+", "", e.get("operand_full") or "")
        if op.startswith(name):
            refs.add(op[len(name):])
    bit_re = re.compile(r"^(\[\d+(?:,\d+)*\])?\.\d+$")
    for op in sorted(r for r in refs if bit_re.match(r)):
        if op not in comments:
            findings.append(Finding(
                "no_desc_tag", "Bit Without Comment", severity,
                f"'{name}{op}' has no comment.", location=f"{scope}:{name}"))


def pc_naming(ctx, pro="PRO", con="CON"):
    tok = lambda t: re.compile(r"(?<![A-Za-z0-9])" + re.escape(t) + r"(?![A-Za-z0-9])")
    pro_re, con_re = tok(pro), tok(con)
    out = []
    for t in ctx.data.get("tags", []):
        tt = (t.get("tag_type") or "").lower()
        if tt == "produced" and not pro_re.search(t["name"]):
            out.append(Finding("pc_naming", "", _P,
                f"Produced tag '{t['name']}' has no '{pro}' token in its name.",
                location=f"Controller:{t['name']}"))
        elif tt == "consumed":
            remote = t.get("remote_tag") or ""
            if not remote:
                continue
            if not pro_re.search(remote):
                out.append(Finding("pc_naming", "", _P,
                    f"Consumed tag '{t['name']}' maps to '{remote}', which has no '{pro}' token.",
                    location=f"Controller:{t['name']}"))
                continue
            expected = pro_re.sub(con, remote)
            if t["name"] != expected:
                out.append(Finding("pc_naming", "", _P,
                    f"Consumed tag '{t['name']}' maps to '{remote}' and must be named '{expected}'.",
                    location=f"Controller:{t['name']}"))
    return out


def small_int(ctx):
    out = []
    def chk(loc, t):
        if (t.get("tag_type") or "").lower() == "alias":
            return
        if (t.get("data_type") or "").upper() in ("INT", "SINT"):
            out.append(Finding("small_int", "", _P,
                f"'{t['name']}' is {t['data_type'].upper()}"
                + (f"[{t['dimensions']}]" if t.get("dimensions") else "") + "; use DINT.",
                location=loc))
    for t in ctx.data.get("tags", []):
        chk(f"Controller:{t['name']}", t)
    for p in ctx.data.get("programs", []):
        for t in p.get("tags", []):
            chk(f"{p['name']}:{t['name']}", t)
    return out


_SPARE = re.compile(r"(?i)\bspare\b|\bunused\b")   # whole words: SPARE_1 does not match


def desc_spare(ctx):
    text = "\n".join(r[1] for r in ctx.rungs) + "\n" + ctx.usage_text
    used = set(re.findall(r"[A-Za-z_]\w*", text))
    used_ops = {re.sub(r"\s+", "", o).upper()
                for r in ctx.rungs for i in r[2] for o in i["operands"]}
    out = []
    def chk(loc, t):
        if t["name"] in used and _SPARE.search(t.get("description") or ""):
            out.append(Finding("desc_spare", "", _P,
                f"'{t['name']}' is used in logic but described as "
                f"\"{(t.get('description') or '')[:60]}\".", location=loc))
        # Array elements / bits / members commented as spare but used.
        for operand, txt in (t.get("comments") or {}).items():
            full = (t["name"] + operand).upper()
            if _SPARE.search(txt or "") and any(o == full or o.startswith(full + ".") for o in used_ops):
                out.append(Finding("desc_spare", "", _P,
                    f"'{t['name']}{operand}' is used in logic but commented as \"{txt[:60]}\".",
                    location=loc))
    for t in ctx.data.get("tags", []):
        chk(f"Controller:{t['name']}", t)
    for p in ctx.data.get("programs", []):
        for t in p.get("tags", []):
            chk(f"{p['name']}:{t['name']}", t)
    return out


def timer_pre(ctx):
    """
    A timer used in logic whose preset is 0 in the tag data and is never
    set by logic. Arrays are checked per element: presets live on the
    elements, never on the array tag itself. Elements are considered only if
    referenced (any variable index counts as all elements).
    """
    out = []
    def scan(loc, t, texts):
        presets = t.get("timer_presets")
        if not presets:
            return                       # not a TIMER, or no data exported
        base = re.escape(t["name"])
        refs = re.findall(r"(?<![\w.:])" + base + r"(\[[^\]]*\])?(?![\w\[])", texts)
        if not refs:
            return                       # unused — INF001's job
        idx_used = {re.sub(r"\s+", "", r) for r in refs}
        any_var = any(r and not re.fullmatch(r"\[[\d,]+\]", r) for r in idx_used)
        pre_refs = {re.sub(r"\s+", "", r) for r in
                    re.findall(r"(?<![\w.:])" + base + r"(\[[^\]]*\])?\.PRE\b", texts)}
        pre_any = any(r and not re.fullmatch(r"\[[\d,]+\]", r) for r in pre_refs)
        if "" in presets:                # scalar timer
            if presets[""] == 0 and "" not in pre_refs:
                out.append(Finding("timer_pre", "", _P,
                    f"Timer '{t['name']}' has preset 0 and logic never sets .PRE.", location=loc))
            return
        if pre_any:
            return                       # e.g. MOV(x, Arr[i].PRE) covers all elements
        zero = [ix for ix, pre in presets.items()
                if pre == 0 and (any_var or ix in idx_used) and ix not in pre_refs]
        if zero:
            zero.sort(key=lambda x: [int(n) for n in re.findall(r"\d+", x)])
            for ix in zero:
                out.append(Finding("timer_pre", "", _P,
                    f"Timer '{t['name']}{ix}' has preset 0 and logic never sets .PRE.", location=loc))
    all_text = "\n".join(r[1] for r in ctx.rungs)
    for t in ctx.data.get("tags", []):
        scan(f"Controller:{t['name']}", t, all_text)
    for p in ctx.data.get("programs", []):
        ptext = "\n".join(r[1] for r in ctx.rungs if r[3] == p["name"])
        for t in p.get("tags", []):
            scan(f"{p['name']}:{t['name']}", t, ptext)
    return out


def _safety_std_map(data, sev, u, und):
    s = effective_severity("safety_std_map", sev)
    if s == "DISABLED":
        return []
    pairs = data["controller"].get("safety_tag_map") or []
    if not pairs:
        return []
    sp, stp = u["safety_prefix"], u["std_prefix"]
    safety_names = {t["name"] for _, t in _all_tags(data) if t.get("class") == "Safety"}
    out = []
    for a, b in pairs:
        # Resolve sides by tag Class rather than assuming map direction.
        if b in safety_names:
            std, saf = a, b
        elif a in safety_names:
            std, saf = b, a
        else:
            und["WAR001"] = (f"Could not resolve safety side of mapping "
                                      f"'{a}={b}' (neither is a Safety-class tag).")
            continue
        core = saf[len(sp):] if saf.startswith(sp) else saf
        expected = stp + core
        if std != expected:
            out.append(Finding("safety_std_map", "Mapped Standard Tag Name", s,
                f"Standard tag '{std}' is mapped to safety tag '{saf}'; "
                f"URS requires it to be named '{expected}'.",
                location=f"Controller:{std}"))
    return out
