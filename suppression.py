# suppression.py — in-source lint:disable directives.
"""
New checks added in this iteration:

- naming        : configurable regex per scope (controller, program, AOI param)
- routine_size  : flags routines exceeding a configurable rung count
- aoi_param_max : flags AOIs with too many parameters

And a suppression layer:

- apply_suppressions(findings, data) drops findings the user has marked as
  ignored via in-source directives. Two forms are recognised:
      `lint:disable`                   — disable all checks at this scope
      `lint:disable=CRT002,INF007`    — disable specific rules (code or check id)
  Suppression scopes:
      • rung comments — apply to that rung only
      • tag descriptions — apply to that tag (any scope)
      • AOI descriptions — apply to that AOI

Suppressions are intentionally a simple substring/regex match so the
syntax is robust to whatever whitespace Studio 5000 round-trips.
"""

import re


# ─── Source suppression filter ────────────────────────────────────────────

# `lint:disable` and `lint:disable=id1,id2` — case-insensitive, anywhere
# in a rung comment or tag/AOI description.
_DIRECTIVE_RE = re.compile(
    r'lint:disable(?:=([a-z0-9_,\s]*))?', re.IGNORECASE)


def _parse_directive(text: str):
    """Return None (no directive), '*' (disable all), or set of check_ids."""
    if not text:
        return None
    m = _DIRECTIVE_RE.search(text)
    if not m:
        return None
    arg = m.group(1)
    if not arg:
        return "*"
    ids = {x.strip().lower() for x in arg.split(",") if x.strip()}
    return ids or "*"


def build_suppression_index(data: dict) -> dict:
    """
    Return a dict mapping suppression scope strings to their disabled set.

    Scope strings mirror the `Finding.location` format produced by the
    analyzer:
        "Controller:TagName"             tag-scope (controller)
        "ProgramName:TagName"            tag-scope (program)
        "ProgramName / RoutineName / Rung N"  rung-scope
        "AOI:Name"                       AOI-scope (parameter-level too)
    """
    sup = {}

    def _add(loc, dir_):
        if dir_:
            sup[loc] = dir_

    # Tag descriptions — controller and program
    for tag in data.get("tags", []):
        _add(f"Controller:{tag['name']}", _parse_directive(tag.get("description", "")))
    for prog in data.get("programs", []):
        for tag in prog.get("tags", []):
            _add(f"{prog['name']}:{tag['name']}", _parse_directive(tag.get("description", "")))
        # Rung comments
        for rtn in prog.get("routines", []):
            for rung in rtn.get("rungs", []):
                d = _parse_directive(rung.get("comment", ""))
                if d:
                    _add(f"{prog['name']} / {rtn['name']} / Rung {rung['number']}", d)

    # AOIs
    for aoi in data.get("aois", []):
        d = _parse_directive(aoi.get("description", ""))
        if d:
            _add(f"AOI:{aoi['name']}", d)

    return sup


def apply_suppressions(findings: list, data: dict) -> tuple:
    """
    Filter findings against in-source suppression directives.
    Returns (kept, suppressed) — both lists, so callers can surface
    *which* findings were suppressed rather than a bare count. Hiding
    things without an audit trail erodes trust in the tool.
    """
    sup = build_suppression_index(data)
    if not sup:
        return findings, []

    kept = []
    suppressed = []
    for f in findings:
        loc = f.location
        # Exact-location match
        directive = sup.get(loc)
        if directive is None:
            # Also honour an AOI-wide suppression for any finding inside that AOI
            if loc.startswith("AOI:"):
                head = loc.split("/")[0].strip().split(".")[0]
                directive = sup.get(head)
        if directive is None:
            kept.append(f)
            continue
        if directive == "*" or f.check_id.lower() in directive or (f.code or "").lower() in directive:
            suppressed.append(f)
            continue
        kept.append(f)
    return kept, suppressed
