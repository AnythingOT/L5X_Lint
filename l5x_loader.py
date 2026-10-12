import re
# parser/l5x_loader.py
"""
Parses a full-program L5X file into a structured dictionary.
All XML access goes through this module — no xml.etree calls elsewhere.
"""
import xml.etree.ElementTree as ET


class L5XParseError(Exception):
    pass


def load(content: str) -> dict:
    """
    Parse L5X XML content and return a normalised program dict.

    Returns:
    {
      "controller": { name, processor_type, major_rev, minor_rev, ... },
      "tasks":      [ { name, type, period, watchdog, programs: [name,...] } ],
      "programs":   [ { name, main_routine, fault_routine,
                        routines: [ { name, type, rungs: [ { number, text, comment } ] } ],
                        tags: [ { name, data_type, description, value } ] } ],
      "datatypes":  [ { name, members: [ { name, data_type, ... } ] } ],
      "aois":       [ { name, description, parameters: [...], routines: [...] } ],
      "modules":    [ { name, catalog, slot, parent } ],
      "tags":       [ { name, data_type, description } ],   # controller-scoped
    }
    """
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise L5XParseError(f"XML parse error: {e}")

    # Validate it's a controller export
    target = root.get("TargetType", "")
    if target != "Controller":
        raise L5XParseError(
            f"Expected a full Controller export (TargetType='Controller'), got '{target}'. "
            "Please export the full program from Studio 5000 (Save As → L5X)."
        )

    ctrl_el = root.find("Controller")
    if ctrl_el is None:
        raise L5XParseError("No <Controller> element found.")

    import udt_layout
    return {
        # UDT layout input from this same parse (WAR010 padding check).
        "udt_layout": udt_layout.collect(root),
        "controller": _parse_controller(ctrl_el),
        "tasks":      _parse_tasks(ctrl_el),
        "programs":   _parse_programs(ctrl_el),
        "datatypes":  _parse_datatypes(ctrl_el),
        "aois":       _parse_aois(ctrl_el),
        "modules":    _parse_modules(ctrl_el),
        "encoded_aois": count_encoded_aois(ctrl_el),
        "tags":       _parse_tags(ctrl_el),
    }


# ── Controller metadata ───────────────────────────────────────────────────

def _parse_controller(ctrl: ET.Element) -> dict:
    return {
        "name":           ctrl.get("Name", ""),
        "processor_type": ctrl.get("ProcessorType", ""),
        "major_rev":      ctrl.get("MajorRev", ""),
        "minor_rev":      ctrl.get("MinorRev", ""),
        "time_slice":     ctrl.get("TimeSlice", ""),
        "project_sn":     ctrl.get("ProjectSN", ""),
        # Controller fault handler / power-up handler program names.
        # None = attribute absent (cannot distinguish "not configured" from
        # "not exported" on every firmware — callers must treat None as
        # not-determinable, '' as explicitly empty).
        "major_fault_program": ctrl.get("MajorFaultProgram"),
        "power_loss_program":  ctrl.get("PowerLossProgram"),
        "ptp_enable":          _attr_of(ctrl, "TimeSynchronize", "PTPEnable"),
        "dst_adjust":          _attr_of(ctrl, "WallClockTime", "LocalTimeAdjustment"),
        "safety_tag_map":      _safety_tag_map(ctrl),
    }


def _attr_of(ctrl: ET.Element, child: str, attr: str):
    el = ctrl.find("./" + child)
    return None if el is None else el.get(attr)


def _safety_tag_map(ctrl: ET.Element) -> list:
    """
    Parse <SafetyTagMap> into [(left, right), ...] pairs. The text is a
    comma-separated list of 'A=B' entries. Which side is the safety tag
    is resolved by the caller against tag Class — not assumed here.
    """
    el = ctrl.find(".//SafetyTagMap")
    if el is None or not (el.text or "").strip():
        return []
    pairs = []
    for entry in el.text.split(","):
        if "=" in entry:
            a, b = entry.split("=", 1)
            if a.strip() and b.strip():
                pairs.append((a.strip(), b.strip()))
    return pairs


# ── Tasks ─────────────────────────────────────────────────────────────────

def _parse_tasks(ctrl: ET.Element) -> list:
    tasks = []
    for t in ctrl.findall("./Tasks/Task"):
        scheduled = []
        for sp in t.findall("./ScheduledPrograms/ScheduledProgram"):
            scheduled.append(sp.get("Name", ""))
        tasks.append({
            "name":     t.get("Name", ""),
            "type":     t.get("Type", ""),        # CONTINUOUS / PERIODIC / EVENT
            "period":   t.get("Period", ""),       # ms, periodic only
            "watchdog": t.get("Watchdog", ""),     # ms
            "programs": scheduled,
        })
    return tasks


# ── Programs ──────────────────────────────────────────────────────────────

def _parse_programs(ctrl: ET.Element) -> list:
    programs = []
    for prog in ctrl.findall("./Programs/Program"):
        programs.append({
            "name":          prog.get("Name", ""),
            "main_routine":  prog.get("MainRoutineName", ""),
            "fault_routine": prog.get("FaultRoutineName", ""),
            "children":      [c.get("Name", "") for c in prog.findall("./ChildPrograms/ChildProgram")],
            "routines":      _parse_routines(prog),
            "tags":          _parse_tags(prog),
        })
    return programs


def _parse_routines(parent: ET.Element) -> list:
    routines = []
    for rtn in parent.findall("./Routines/Routine"):
        rtype = rtn.get("Type", "RLL")
        rungs = _parse_rungs(rtn)
        non_rll = (rtype.upper() != "RLL") or _routine_has_non_rll_content(rtn)
        routines.append({
            "name":      rtn.get("Name", ""),
            "type":      rtype,
            "rungs":     rungs,
            "non_rll":   non_rll,
            # License-protected (encrypted) content cannot be read.
            "protected": rtn.find("EncryptionInfo") is not None,
            # ST/FBD/SFC: not rule-checked, but its tag/routine references
            # count as usage.
            "usage_text": _usage_text(rtn) if non_rll else "",
        })
    # Source-protected routines are exported as <EncodedData> siblings of
    # <Routine> — their logic is not readable at all.
    for enc in parent.findall("./Routines/EncodedData"):
        routines.append({"name": enc.get("Name", ""), "type": enc.get("Type", ""),
                         "rungs": [], "non_rll": False, "protected": True})
    return routines


def _parse_rungs(rtn: ET.Element) -> list:
    rungs = []
    # RLLContent — ladder rungs (the only routine type we deep-analyse).
    for rung in rtn.findall("./RLLContent/Rung"):
        text_el    = rung.find("Text")
        comment_el = rung.find("Comment")
        rungs.append({
            "number":  rung.get("Number", ""),
            "type":    rung.get("Type", "N"),
            "text":    text_el.text.strip() if text_el is not None and text_el.text else "",
            "comment": comment_el.text.strip() if comment_el is not None and comment_el.text else "",
        })
    return rungs


def _usage_text(rtn: ET.Element) -> str:
    """
    Every identifier-bearing string in a non-ladder routine: ST line text,
    and FBD/SFC element attributes such as Operand, Routine, Tag, Name.
    """
    parts = []
    for el in rtn.iter():
        if el.tag == "Line" and el.text:
            parts.append(el.text)
        for k in ("Operand", "Routine", "Tag", "Name", "ArrayIndex", "Expression"):
            v = el.get(k)
            if v:
                parts.append(v)
        if el.tag in ("Expression", "Condition", "Action") and el.text:
            parts.append(el.text)
    return "\n".join(parts)


def _routine_has_non_rll_content(rtn: ET.Element) -> bool:
    """True if a routine has FBD / SFC / ST content we don't inspect."""
    return any(rtn.find(tag) is not None
               for tag in ("FBDContent", "SFCContent", "STContent"))


# ── Data types ────────────────────────────────────────────────────────────

def _parse_datatypes(ctrl: ET.Element) -> list:
    dtypes = []
    for dt in ctrl.findall("./DataTypes/DataType"):
        # Skip Rockwell built-in families (DECORATED, UNKNOWN etc) but keep user-defined
        family = dt.get("Family", "")
        # Skip built-in / non-user families. The previous "" branch was
        # unreachable (already excluded by `if family`).
        if family and family.upper() != "NOFAMILY":
            continue
        members = []
        for m in dt.findall("./Members/Member"):
            members.append({
                "name":      m.get("Name", ""),
                "data_type": m.get("DataType", ""),
                "dimension": m.get("Dimension", ""),
                "radix":     m.get("Radix", ""),
                "hidden":    m.get("Hidden", "false").lower() == "true",
                "target":    m.get("Target", ""),
                "bit_number":m.get("BitNumber", ""),
                "description": _get_description(m),
            })
        dtypes.append({
            "name":        dt.get("Name", ""),
            "family":      dt.get("Family", ""),
            "description": _get_description(dt),
            "members":     members,
        })
    return dtypes


# ── AOIs ─────────────────────────────────────────────────────────────────

def count_encoded_aois(ctrl: ET.Element) -> int:
    return len(ctrl.findall("./AddOnInstructionDefinitions/EncodedData"))


def _parse_aois(ctrl: ET.Element) -> list:
    aois = []
    for aoi in ctrl.findall("./AddOnInstructionDefinitions/AddOnInstructionDefinition"):
        params = []
        for p in aoi.findall("./Parameters/Parameter"):
            params.append({
                "name":        p.get("Name", ""),
                "data_type":   p.get("DataType", ""),
                "usage":        p.get("Usage", ""),
                "description": _get_description(p),
            })
        aois.append({
            "class":       aoi.get("Class", "Standard"),
            "name":        aoi.get("Name", ""),
            "description": _get_description(aoi),
            "revision":    aoi.get("Revision", ""),
            "parameters":  params,
            "routines":    _parse_routines(aoi),
            "tags":        _parse_tags(aoi, "./LocalTags/LocalTag"),   # AOI local tags (schema: LocalTags/LocalTag)
        })
    return aois


# ── Modules ───────────────────────────────────────────────────────────────

def _parse_modules(ctrl: ET.Element) -> list:
    modules = []
    for mod in ctrl.findall("./Modules/Module"):
        catalog = mod.get("CatalogNumber", "")
        # Strip series suffix  e.g. "1756-IB16/B" → "1756-IB16"
        catalog_base = catalog.split("/")[0].strip() if catalog else ""
        slot = None
        ports_el = mod.find("./Ports")
        if ports_el is not None:
            for port in ports_el.findall("Port"):
                if port.get("Type", "") in ("ICP", ""):
                    slot = port.get("Address", None)
                    break
        modules.append({
            "name":         mod.get("Name", ""),
            "catalog":      catalog_base,
            "catalog_full": catalog,
            "parent":       mod.get("ParentModule", ""),
            "slot":         slot,
            # Electronic keying: "Disabled" / "CompatibleModule" / "ExactMatch".
            # None when the export has no EKey element.
            "ekey":         (mod.find("./EKey").get("State") if mod.find("./EKey") is not None else None),
            # Module I/O tags and how many point comments they carry.
            "upstream_type": next((p.get("Type", "") for p in mod.findall("./Ports/Port")
                                   if (p.get("Upstream") or "").lower() == "true"), ""),
            # Module I/O tags: name suffix ("I", "O", "I1" …), the tag's own
            # description, and per-point comments {operand_upper: text}.
            "io_tags": [{
                "suffix":   io.get("Suffix", "I" if io.tag == "InputTag" else "O"),
                "kind":     "input" if io.tag == "InputTag" else "output",
                "desc":     _get_description(io),
                "comments": {(c.get("Operand") or "").upper(): (c.text or "").strip()
                             for c in io.findall("./Comments/Comment")},
                "data_members": _io_data_members(io),
            } for io in list(mod.iter("InputTag")) + list(mod.iter("OutputTag"))],
        })
    return modules


# ── Tags ─────────────────────────────────────────────────────────────────

def _parse_tags(parent: ET.Element, path: str = "./Tags/Tag") -> list:
    tags = []
    for tag in parent.findall(path):
        tags.append({
            "name":            tag.get("Name", ""),
            "data_type":       tag.get("DataType", ""),
            "tag_type":        tag.get("TagType", ""),   # Base / Alias / Produced / Consumed
            "alias_for":       tag.get("AliasFor", ""),
            "description":     _get_description(tag),
            "external_access": tag.get("ExternalAccess", ""),
            "dimensions":      tag.get("Dimensions", ""),  # e.g. "9" for DINT[9]
            "comments":        _parse_comments(tag),       # {operand: text}
            # Safety controllers mark each tag Standard/Safety. Absent on
            # standard-only controllers — treated as Standard.
            "class":           tag.get("Class", "Standard"),
            # MSG configuration lives in the tag data, not the rung.
            "message_type":    _message_type(tag),
            "timer_presets":   _timer_presets(tag),
            "remote_tag":      (tag.find("ConsumeInfo").get("RemoteTag", "")
                                if tag.find("ConsumeInfo") is not None else ""),
        })
    return tags


def _timer_presets(tag_el: ET.Element):
    """
    For TIMER tags: {index: PRE} from the Decorated data — "" for a scalar
    timer, "[n]" per element for arrays. None if not a TIMER or no data.
    """
    if not (tag_el.get("DataType", "") or "").upper().startswith("TIMER"):
        return None
    data = tag_el.find("./Data[@Format='Decorated']")
    if data is None:
        return None
    out = {}
    def pre_of(struct):
        for m in struct.findall("./DataValueMember"):
            if (m.get("Name") or "").upper() == "PRE":
                try:
                    return int(float(m.get("Value", "0")))
                except ValueError:
                    return None
        return None
    st = data.find("./Structure")
    if st is not None:
        out[""] = pre_of(st)
    for el in data.findall("./Array/Element"):
        s = el.find("./Structure")
        if s is not None:
            out[el.get("Index", "")] = pre_of(s)
    return out or None


def _io_data_members(io: ET.Element) -> list:
    """
    Names of field-data members in a module I/O tag's decorated data:
    'Data' (digital word), 'Ch0Data'… (analog), and 'Ch00.Data' style for
    structured channels. Status / fault / config members are excluded.
    """
    data = io.find("./Data[@Format='Decorated']")
    if data is None:
        return []
    st = data.find("./Structure")
    if st is None:
        return []
    out = []
    for m in st.findall("./DataValueMember"):
        n = m.get("Name", "")
        if n.lower() == "data" or re.fullmatch(r"(?i)ch\d+data", n):
            out.append(n)
    for sm in st.findall("./StructureMember"):
        n = sm.get("Name", "")
        if re.fullmatch(r"(?i)ch\d+", n) and any((d.get("Name") or "").lower() == "data"
                                                for d in sm.findall("./DataValueMember")):
            out.append(n + ".Data")
    return out


def _message_type(tag_el: ET.Element) -> str:
    """MessageType of a MESSAGE tag ('CIP Data Table Read', ...) or ''."""
    if (tag_el.get("DataType", "") or "").upper() != "MESSAGE":
        return ""
    mp = tag_el.find(".//MessageParameters")
    return mp.get("MessageType", "") if mp is not None else ""


def _parse_comments(tag_el: ET.Element) -> dict:
    """
    Parse <Comments><Comment Operand="[0].3">text</Comment>...</Comments>
    Returns dict of { operand_str: comment_text }
    e.g. {"[0].0": "Motor Tripped", "[0].1": "Failed to Start"}
    """
    result = {}
    comments_el = tag_el.find("Comments")
    if comments_el is None:
        return result
    for c in comments_el.findall("Comment"):
        op   = c.get("Operand", "")
        text = c.text.strip() if c.text else ""
        if op:
            result[op] = text
    return result


# ── Helpers ───────────────────────────────────────────────────────────────

def _get_description(el: ET.Element) -> str:
    desc = el.find("Description")
    if desc is not None and desc.text:
        return desc.text.strip()
    return ""
