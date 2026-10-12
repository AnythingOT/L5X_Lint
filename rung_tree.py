import functools
# rung_tree.py — branch-aware structure of a ladder rung.
"""
Rung text grammar (neutral text format of L5X):
    rung     := sequence ';'
    sequence := ( instruction | branch )*
    branch   := '[' sequence ( ',' sequence )* ']'
    instruction := NAME '(' operands ')'        (brackets inside the
                                                 parentheses are array
                                                 indices, not branches)

parse(text) -> list of items, each either
    ("I", name, operands_tuple)
    ("B", [leg_sequence, leg_sequence, ...])
"""

import re

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _split_operands(raw):
    out, depth, cur = [], 0, []
    for ch in raw:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip()); cur = []
        else:
            cur.append(ch)
    if cur or out:
        out.append("".join(cur).strip())
    return tuple(o for o in out)


def _parse_uncached(text):
    s = text or ""
    pos = 0

    def seq():
        nonlocal pos
        items = []
        while pos < len(s):
            ch = s[pos]
            if ch.isspace():
                pos += 1
            elif ch == "[":
                pos += 1
                legs = [seq()]
                while pos < len(s) and s[pos] == ",":
                    pos += 1
                    legs.append(seq())
                if pos < len(s) and s[pos] == "]":
                    pos += 1
                items.append(("B", legs))
            elif ch in ",];":
                return items
            else:
                m = _NAME.match(s, pos)
                if not m:
                    pos += 1
                    continue
                name = m.group(0)
                pos = m.end()
                ops = ()
                if pos < len(s) and s[pos] == "(":
                    depth, start = 0, pos
                    while pos < len(s):
                        if s[pos] == "(":
                            depth += 1
                        elif s[pos] == ")":
                            depth -= 1
                            if depth == 0:
                                break
                        pos += 1
                    ops = _split_operands(s[start + 1:pos])
                    pos += 1
                items.append(("I", name, ops))
        return items

    return seq()


def key(item):
    """Canonical comparable form of an item (for identity checks)."""
    if item[0] == "I":
        return ("I", item[1].upper(), tuple(re.sub(r"\s+", "", o) for o in item[2]))
    return ("B", tuple(tuple(key(i) for i in leg) for leg in item[1]))


def fmt(item):
    if item[0] == "I":
        return f"{item[1]}({','.join(item[2])})"
    return "[" + ",".join("".join(fmt(i) for i in leg) for leg in item[1]) + "]"


def walk_series(tree):
    """
    Yield (instruction, before) for every instruction, where `before` is the
    list of instructions that are guaranteed to execute in series BEFORE it
    on its path: earlier items of its own sequence and of every enclosing
    sequence up to the branch it sits in. Instructions inside a sibling
    parallel leg, or after it, are not in `before`.
    """
    def go(items, before):
        local = list(before)
        for it in items:
            if it[0] == "I":
                yield it, list(local)
                local.append(it)
            else:
                for leg in it[1]:
                    yield from go(leg, local)
                # after a branch, only the common prefix is guaranteed
    yield from go(tree, [])


def sequences(tree):
    """Yield every sequence (the main rung and each branch leg)."""
    yield tree
    for it in tree:
        if it[0] == "B":
            for leg in it[1]:
                yield from sequences(leg)


def branches(tree):
    for it in tree:
        if it[0] == "B":
            yield it
            for leg in it[1]:
                yield from branches(leg)


# Each rung is needed by several rules and by the cross-reference; parse it
# once. Results are SHARED between callers — treat them as read-only.
# Bounded so memory cannot grow without limit across many sessions.
parse = functools.lru_cache(maxsize=65536)(_parse_uncached)
