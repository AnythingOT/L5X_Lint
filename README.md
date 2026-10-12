# L5X Lint

Static analysis for Rockwell Studio 5000 `.L5X` exports. L5X Lint reads the
export, checks it against a fixed checklist of 49 programming rules, and
reports the findings. **It only reports. It never modifies your project.**
All corrections are made by the engineer in Studio 5000.

Everything runs locally: no cloud, no internet access (no web fonts or CDNs),
suitable for an air-gapped OT network.

## Quick start

```bash
pip install -r requirements.txt     # flask, openpyxl, reportlab
python app.py                       # opens http://127.0.0.1:5002
```

Options: `--port N`, `--no-browser`. Drop one `.L5X` (single report) or
several (batch summary) onto the page.

## Rule codes and severity

Every rule has a code whose prefix is its severity:

| Prefix | Severity | Meaning |
| --- | --- | --- |
| CRT | Critical | Do not download to a controller until resolved |
| ERR | Error | Defect or fault risk |
| WAR | Warning | Standards violation or maintainability risk |
| INF | Info | Documentation and housekeeping |

Severity is **fixed** by the code. In Settings → Rule Checklist each rule can
only be switched on or off; a configurable severity would make the code lie.

## Rule checklist

| Code | Rule | Description |
| --- | --- | --- |
| CRT001 | Forces Present | The export contains forced I/O or tag values. Forces must be removed before the project is released. |
| CRT002 | AFI In Rung | An AFI (Always False) instruction disables the whole rung. Remove it or replace it with proper logic. |
| ERR001 | Duplicate OTE | The same tag or bit is driven by more than one OTE. Only the last one in scan order takes effect. |
| ERR002 | Multiple OTL | A tag is latched (OTL) from more than one place, which makes its state hard to trace. |
| ERR003 | Multiple OTU | A tag is unlatched (OTU) from more than one place, which makes its state hard to trace. |
| ERR004 | Write to MSG Status Bit | Logic writes a status bit (.EN, .DN, .ER …) of a MESSAGE tag, which the controller manages. The tag type is resolved through UDTs and arrays. |
| ERR005 | Write to Timer/Counter Bit | Logic writes a .DN, .EN, .TT (or counter) bit of a TIMER or COUNTER, which the controller manages. The tag type is resolved through UDTs and arrays. |
| ERR006 | MSG Not Gated | A MSG instruction runs without ONS or timer gating, so it is re-triggered every scan. |
| ERR007 | Controller Fault Handler | No Controller Fault Handler program is configured, or it names a program that doesn't exist. |
| ERR008 | Program Fault Routine | A program has no Fault Routine assigned, or names a routine that doesn't exist. |
| ERR009 | AOI Uses Controller Tag | AOI logic references a controller-scoped tag directly, which breaks AOI encapsulation. |
| ERR010 | Duplicate Instruction In Rung | The same instruction with the same operand appears twice in one series chain, or two parallel branch legs are identical. Shared instructions in legs with other conditions are valid OR logic and not reported. |
| ERR011 | Unchecked Array Index | An array is indexed by a tag (Arr[Idx]) without a LIM/LES/GRT range check on the index placed before it on the same path. An out-of-range index causes a major fault. |
| ERR012 | Unguarded Division | A DIV, MOD or '/' in CPT divides by a tag that is not compared against zero before it on the same path. |
| ERR013 | Backward Jump | A JMP jumps to a LBL at or above itself, creating a loop inside the scan (watchdog risk). |
| ERR014 | Timer/Counter Reused | One TIMER or COUNTER tag is used by more than one timer/counter instruction. (One CTU plus one CTD on the same counter is allowed.) |
| ERR015 | One-Shot Storage Reused | An ONS/OSR/OSF storage bit is shared by several one-shots, or is also written by other logic, so edges get missed. |
| ERR016 | No Reset For RTO/Counter | An RTO or counter accumulates but is never reset (no RES and no write to .ACC). For arrays, a reset of any element via an index counts. |
| ERR017 | Discontinued Module | An I/O module catalog is Discontinued according to the lifecycle dataset. Spares may be unobtainable. |
| WAR001 | Safety Map Naming | A standard tag mapped to safety tag SFTY_X must be named STD_X. |
| WAR002 | Produced/Consumed Naming | A consumed tag must use the same name as the produced tag it maps to, with PRO replaced by CON. |
| WAR003 | Task Name Missing Period | A periodic task's name must state its period (e.g. Task_10MS for a 10 ms task). |
| WAR004 | Uncalled Routine | A routine is not called by any JSR in its program. |
| WAR005 | Unscheduled Program | A program is not scheduled in any task. |
| WAR006 | Empty Rung | A rung contains no instructions. |
| WAR007 | Empty Branch | A branch leg contains no instructions, which acts as an always-true bypass. |
| WAR008 | Timer Preset Not Set | A timer used in logic has preset 0 in its tag data and logic never sets .PRE. Timer arrays are checked per element. |
| WAR009 | Watchdog Margin Too Small | A task's watchdog is less than 1.5 × its period, so one slow scan can fault the controller. |
| WAR010 | UDT Padding Waste | Reordering this UDT's members would save at least 4 bytes of alignment padding. |
| WAR011 | UDT Member Order | UDT members are not grouped by data type, or not in alphabetical order (natural order: Valve2 before Valve10). |
| WAR013 | MSGs Not Staggered | Two or more MSGs share the same trigger condition and fire together. |
| WAR014 | JSR Nesting Too Deep | A JSR call chain is nested deeper than the limit. |
| WAR015 | MOV REAL To Integer | A MOV converts a REAL into an integer type. MOV rounds silently (.5 to even) and can overflow. Use TRN or explicit, commented rounding. |
| WAR016 | INT/SINT Instead Of DINT | A tag uses INT or SINT. Logix is 32-bit native, so DINT is faster and avoids conversion. |
| WAR017 | Physical I/O Point Not Mapped | No direct mapping logic references a field-data point of a physical I/O module (e.g. Local:4:I.Data.3, Ch0Data). Points covered by an alias are reported by WAR022 instead. Status and fault members are excluded. |
| WAR018 | Physical I/O Point Without Comment | An I/O point referenced directly in logic has no comment on the module I/O tag. One finding per point. |
| WAR019 | Used Tag Marked Spare | A tag, array element or bit is used in logic but its description or comment contains the word 'spare' or 'unused'. |
| WAR020 | Unused UDT/AOI Definition | A UDT or AOI definition is never used by any tag, member, parameter or rung. |
| WAR021 | End-of-Life Module | An I/O module catalog has reached End of Life according to the lifecycle dataset. Plan migration. |
| WAR022 | Alias Used For Physical I/O | A tag is an alias of a physical I/O tag or point. The standard is direct mapping logic; the message says whether the alias is used in logic (replace) or not (delete). |
| INF001 | Unused Tag | A tag is declared but never read or written. |
| INF002 | Loose BOOL Tags | Standalone BOOL tags are used. Pack them into a DINT, BOOL array or UDT. |
| INF003 | Tag Without Description | A used tag has no description, or a bit that logic addresses individually has no comment. |
| INF004 | Rung Without Comment | A rung has no comment. |
| INF005 | AOI Without Description | An AOI or AOI parameter has no description. |
| INF006 | UDT Member Without Description | A UDT member has no description. One finding per member. |
| INF007 | Hard-Coded Literal | A numeric literal (other than 0, 1, -1) is used in a write instruction. |
| INF008 | Electronic Keying Not Compatible | An I/O module's electronic keying is not Compatible Module (Exact Match, Disabled or other). Compatible Module allows like-for-like spares while still blocking the wrong module. |
| INF009 | Active Mature Module | An I/O module catalog is Active Mature. Newer alternatives exist; consider them for new designs. |

WAR012 (Write-Type MSG) is retired: the code is reserved and not reused, so
WAR013 onward keep their numbers.

**How rung structure is read.** Rungs are parsed into series chains and
parallel branches. ERR010 compares within one chain and across identical
legs; ERR011/ERR012 accept a guard only if it sits in series *before* the
instruction on the same path (a check in a sibling leg does not count).

**Physical I/O standard: direct mapping, no aliases.** Each field-data
point is reported under exactly one rule: WAR017 when nothing maps it, WAR022
when an alias covers it (message says whether to replace or delete the
alias). Fixing a WAR022 by deleting the alias moves an unmapped point to
WAR017 — the next piece of work. WAR018 counts only comments on the module
I/O tag itself.

**Heuristic rules.** WAR017 derives digital point counts from the catalog
number (1756-IB16 → 16 points); analog channels come from the module tag
data. ST/FBD/SFC routines are not rule-checked, but tag and routine
references inside them count as usage (INF001, WAR004, WAR017). A clean result on these means "no evidence of a
problem", not proof.

**Coverage notes.** FBD, SFC and ST routines, source/license-protected
routines and encoded AOIs cannot be analysed; the banner states how many the
file contains. If an export lacks the data a rule
needs (e.g. no fault-handler attribute for ERR007), the banner and both
reports say "Not verified" for that rule instead of passing silently.

## Web report

- **Verdict banner**: the overall answer first ("1 critical issue — do not
  download"), plus coverage warnings.
- **Sidebar tree**: Task → Program and AOIs, with finding counts per node.
  Click to scope; click again to clear.
- **By rule / By location** grouping. Rule groups show the code; hovering
  any code shows severity, rule name and description.
- **Side pane**: Expand / Collapse all task sections, click a section to
  collapse it, or ◀ Hide the pane entirely (▶ rail brings it back).
- **Filters**: severity chips (CRT/ERR/WAR/INF), text search (matches code,
  rule, tag, location, message), show suppressed.
- **Views**: Findings, Hardware (I/O modules + lifecycle status).
- **⟲ New file** in the toolbar closes the report and returns to upload;
  an **↑** button bottom-right returns to the top after scrolling.
- **One row per item**: I/O points, UDT members, timer elements and bits
  are reported individually, so group counts are item counts.
- **Export**: ⬇ Excel or ⬇ PDF of exactly what is on screen — severity
  chips, search text and sidebar scope. The report states those filters and
  lists any rules disabled in Settings; the Checklist sheet shows enabled
  rules only.
- **Settings round trip**: Save Settings (or ← Back to report) returns to
  the report, re-analysed with the new rule selection — no re-upload needed
  (within the 1-hour session). A browser refresh does the same.
- **Progress**: a centred ring shows the % and current analysis phase for
  uploads, reloads and batch files (indeterminate while a file transfers).

## Reports

Export needs `openpyxl` (Excel) and `reportlab` (PDF). If either is missing
the console warns at startup and the button is disabled with a tooltip —
run `pip install -r requirements.txt` and restart. Any other export failure
shows its actual reason; the full traceback is in the console.

**Excel** — sheets: Summary (counts are live formulas), Findings,
Suppressed, Hardware, Checklist (findings per rule).

**PDF** — A4 landscape: summary, findings table (header repeats on each
page), and hardware & lifecycle (when lifecycle is on).
Footer on every page: page x of y, generated by (computer \ user),
generated on (DD/MM/YYYY HH:mm:ss), template version.

## Suppressing a finding

Put a directive in a rung comment (that rung), a tag description (that tag)
or an AOI description (that AOI):

```
lint:disable                  all rules at this scope
lint:disable=ERR010           one rule (code or internal check id)
lint:disable=ERR010,INF007    several rules
```

Suppressed findings are not hidden silently: they are counted in the banner,
viewable with "Show suppressed", and listed on the Excel Suppressed sheet.

## Lifecycle

I/O module status comes from `lifecycle.json` (seed data, unverified —
verify against Rockwell PCDC before procurement decisions).

**On/off:** Settings → Lifecycle → *Lifecycle checks* is the only control
for ERR017/WAR021/INF009 (they are locked in the Rule Checklist). Off removes
those findings and the whole hardware/lifecycle section from both reports —
no Hardware sheet or page, no lifecycle wording.

**Refreshing the data** (e.g. with an online assistant):

1. Export the sheet: **⬇ Lifecycle sheet** in the Hardware view (catalogs in
   the loaded project) or **⬇ Export dataset (Excel)** in Settings (all).
2. Fill it in. The Instructions sheet has a ready-to-paste prompt; Status is
   a dropdown, dates are text (YYYY-MM-DD), and each row should cite a
   **Source URL** — rows without one are imported but shown as *unverified*.
   Rows left **Unknown** are not imported, so nothing is guessed.
3. Settings → Lifecycle → **⤒ Import** the .xlsx or .csv. A review shows
   every status change, new catalogs and missing sources; nothing is saved
   until you click **Apply changes**.

Why Excel/CSV and not JSON for this round trip: a sheet is easy to review,
assistants read and write tables reliably, and the Status dropdown limits
values to the four valid ones. JSON remains the stored format (and can be
imported directly as a backup restore).

Assistants can state lifecycle data confidently and wrongly — treat imported
rows without a source as unverified.

## Command line

```bash
python l5x_cli.py analyze Line1.L5X                       # text
python l5x_cli.py analyze Line1.L5X --format json          # JSON
python l5x_cli.py analyze Line1.L5X --format sarif         # CI annotations
python l5x_cli.py analyze Line1.L5X --fail-on ERROR        # exit 1 on ERR/CRT
python l5x_cli.py batch *.L5X
```

Exit codes: 0 clean (below threshold), 1 findings at/above `--fail-on`,
2 parse or I/O error.

## Configuration

`evaluator_config.json` (written by Settings; do not commit it):

```json
{
  "disabled_rules": ["INF004", "WAR016"],
  "sizes": {"loose_bool_min": 1},
  "urs":   {"safety_prefix": "SFTY_", "std_prefix": "STD_"}
}
```

Saving from Settings merges into this file; sections the page doesn't
edit are preserved.

## Project layout

```
app.py              Flask app: upload, live analysis stream, exports, settings, lifecycle
l5x_cli.py          Command line (text / JSON / SARIF, --fail-on, batch)
analysis.py         Pipeline (load → rules → checklist → suppression) and report builder
rules.py            The rule checklist: codes, titles, descriptions, fixed severities

checks/             All rules, grouped by what they look at
  __init__.py       run_rules() — fixed execution order (= finding order in reports)
  common.py         Shared context: parsed rungs, operand type resolution, helpers
  logic.py          Rung logic (AFI, OTE/OTL/OTU, MSG, guards, jumps, timers, JSR depth…)
  tags.py           Tags (unused, descriptions, BOOL/INT, spare, presets, P/C + safety naming)
  io.py             Physical I/O (mapping, aliases, point comments, keying)
  udt.py            UDTs (padding, member order, unused, member descriptions)
  program.py        Tasks / programs / controller (forces, watchdog, scheduling, fault handlers, AOIs)

l5x_loader.py       Single XML parse → data model
udt_layout.py       Rockwell UDT memory layout (sizes, padding, optimal order)
cross_ref.py        Tag read/write cross-reference
rung_parser.py      Flat instruction list of a rung (cached)
rung_tree.py        Series/parallel branch structure of a rung (cached)
lifecycle.py        Module lifecycle dataset, lookup, sheet export/import
suppression.py      lint:disable directives
report_export.py    Excel and PDF reports
output_formats.py   JSON and SARIF
base_check.py       Finding dataclass, rule gate
severity.py         Severity counts
templates/, static/ Web UI
tests/test_rules.py Test suite
```

To add a rule: register its code in `rules.py`, write the function in the
matching `checks/` module, add it to the order in `checks/__init__.py`, and
add a violating and a compliant case to the tests.

## Tests

```bash
python tests/test_rules.py
```

Every rule has a violating and a compliant case. The suite also renders the
web UI against a real report (Node.js required) and exercises the export
endpoints and CLI. Test-only dependency: `pypdf` (reads exported PDFs).

## Limitations

- Ladder only (see coverage note above).
- Single-rung heuristics for ERR011–ERR013 and WAR017.
- L5X attribute names for electronic keying, module comments, safety tag
  maps and fault-handler programs were written from the documented schema;
  confirm against a real export from your Studio 5000 version.
- The lifecycle seed dataset is unverified.
