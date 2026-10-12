import functools
# parser/rung_parser.py
"""
Parses Rockwell ASCII ladder rung text into a structured list of instructions.

Handles:
  - Simple sequential:  XIC(Tag1)XIC(Tag2)OTE(Output);
  - Parallel branches:  BST XIC(A) NXB XIC(B) BND OTE(Out);
  - Nested brackets:    [XIC(En),[TON(T,?,?),OTE(Done)]];
  - Function blocks:    TON(Timer,?,?), MOV(Src,Dest), etc.
  - No-operand:         NOP; AFI;

Each instruction is returned as:
  { "name": "XIC", "operands": ["Tag1"], "raw": "XIC(Tag1)" }
"""

import re
from typing import List, Dict

# Instructions that are structural (branch markers), not real instructions
_STRUCTURAL = {"BST", "NXB", "BND"}

# Regex: instruction name followed by optional ( operands )
_INSTR_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)'  # instruction name
    r'(?:\(([^()]*(?:\([^()]*\)[^()]*)*)\))?'  # optional (operands) — one level deep
)


def _parse_rung_uncached(text: str) -> List[Dict]:
    """
    Parse a rung text string and return a flat list of instruction dicts.
    Branch structure (BST/NXB/BND) is flattened — all instructions returned.
    """
    if not text:
        return []
    # Remove trailing semicolons and brackets at rung level
    text = text.strip().rstrip(";").strip()
    # Remove outer [ ] if present
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]

    instructions = []
    _extract_instructions(text, instructions)
    return instructions


def _extract_instructions(text: str, out: list) -> None:
    """Recursively extract all instructions from text, handling nested brackets."""
    pos = 0
    n   = len(text)

    while pos < n:
        # Skip whitespace and commas
        while pos < n and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= n:
            break

        ch = text[pos]

        # Nested [ ] block — recurse
        if ch == "[":
            end = _find_close(text, pos, "[", "]")
            inner = text[pos+1:end]
            _extract_instructions(inner, out)
            pos = end + 1
            continue

        # Try to match an instruction
        m = _INSTR_RE.match(text, pos)
        if m:
            name = m.group(1)
            raw_ops = m.group(2) or ""
            operands = _split_operands(raw_ops) if raw_ops else []

            if name not in _STRUCTURAL:
                out.append({
                    "name":     name.upper(),
                    "operands": operands,
                    "raw":      m.group(0),
                })
            pos = m.end()
        else:
            pos += 1  # skip unrecognised character


def _find_close(text: str, open_pos: int, open_ch: str, close_ch: str) -> int:
    """Find the matching closing bracket, handling nesting."""
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1  # fallback


def _split_operands(raw: str) -> List[str]:
    """Split operand string by commas, respecting nested parentheses."""
    parts = []
    depth = 0
    current = []
    for ch in raw:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


# ── Convenience helpers used by checks ───────────────────────────────────


def find_instructions(instructions: List[Dict], *names: str) -> List[Dict]:
    """Filter instructions by name (case-insensitive)."""
    upper = {n.upper() for n in names}
    return [i for i in instructions if i["name"] in upper]


def operand_base(operand: str) -> str:
    """
    Strip bit/member suffix from an operand for base-tag lookup.
    e.g. "Timer.DN" → "Timer",  "Tag[0].1" → "Tag"
    Only returns up to the first dot or bracket.
    """
    return re.split(r'[.\[]', operand)[0]


def operand_member(operand: str) -> str:
    """
    Return the dot-notation member path without array indices.
    e.g. "Timer.DN" → "DN",  "Msg.ER" → "ER"
    """
    parts = operand.split(".")
    return parts[-1].split("[")[0] if len(parts) > 1 else ""


# Each rung is needed by several rules and by the cross-reference; parse it
# once. Results are SHARED between callers — treat them as read-only.
# Bounded so memory cannot grow without limit across many sessions.
parse_rung = functools.lru_cache(maxsize=65536)(_parse_rung_uncached)
