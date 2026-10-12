# Changes (v2)

This iteration applies the directives from the design review. Everything
here is in addition to the v1 fixes in `CHANGES.md`.

## Removed

- **The scoring system is gone.** `scorer.py` deleted. Reports no longer
  carry a `scores` field. The dashboard should surface severity counts
  instead — a single 0-100 number invites teams to game the rule config
  to chase the score. Severity counts give the same information without
  the perverse incentive. `weights` removed from the config schema.
- **HMI cross-reference (`hmi_xref`) is gone.** Removed from defaults
  and from the dimension map. Re-introducing HMI awareness would mean
  parsing four vendors' project formats; out of scope.
- **All LLM scaffolding is gone.** `suggester.py` deleted. Nothing in the
  pipeline calls Claude or any other model. The `_prefix_cluster` heuristic
  it housed is not currently consumed by any check — removed cleanly. If
  BOOL-grouping suggestions are wanted later they can be reintroduced as
  a pure rule-based check.

## Added

### New analysis rules

- **Naming convention check.** Configurable regex per scope:
  `controller_tag`, `program_tag`, `aoi_parameter`, `routine`, `program`,
  `udt`. Empty pattern = check disabled for that scope. An invalid regex
  in config surfaces a single `Naming Config Error` finding rather than
  silently doing nothing.
- **Size check.** Three configurable thresholds: `routine_max_rungs`,
  `aoi_max_parameters`, `program_max_routines`. Defaults: 200 / 20 / 50.
- **Source suppression directives.** A rung comment containing
  `lint:disable` suppresses all findings on that rung; `lint:disable=afi,hardcode`
  suppresses only the named check IDs. The same syntax works in tag
  descriptions (scoped to that tag) and AOI descriptions (scoped to the
  AOI). Suppressed-finding count is reported back to the user.

### Output formats

- **JSON output** (`output_formats.json_report`). Stable schema
  (`"schema": "l5x-lint-report/1"`) with a top-level `findings` array
  flattened from all buckets, plus meta, severity counts, suppression
  counts, and module list.
- **SARIF 2.1.0 output** (`output_formats.sarif_report`). Tested shape
  works with GitHub's SARIF importer for inline PR annotations. Severity
  maps: `CRITICAL`/`ERROR` → SARIF `error`; `WARNING` → `warning`;
  `INFO` → `note`. Each rule appears once in `tool.driver.rules`.

### CLI

- **`l5x_cli.py` / `python -m L5X_Lint_v2`** with three subcommands:
  - `analyze FILE [--format text|json|sarif] [--config PATH] [--fail-on LEVEL]`
  - `batch FILE [FILE ...] [--config] [--fail-on]` — tab-separated
    summary lines, one per file
  - `lifecycle-info` — print the dataset metadata
- Exit codes: `0` clean (or below threshold), `1` violations at/above the
  `--fail-on` severity, `2` parse / I/O error. Suitable as a Git
  pre-commit hook or a CI gate.

### Lifecycle

- `checker.py` rewritten to load from a static JSON file
  (`lifecycle.json`) shipping with the tool. Schema described in the
  file's `_meta` block. To refresh: hand-edit the JSON (Phase 2 plan to
  add a `scrape-lifecycle` CLI command later — entry point is reserved
  in the meta note).
- A seed dataset of 14 common 1756-series catalog numbers is included
  so the feature works on first install. Modules in the report now
  carry a `lifecycle` annotation; `1756-ENBT` correctly reports as
  "End of Life" against the seed data.
- `is_available()` and `dataset_info()` expose the dataset state.

### Findings save / load

- **`GET /save_findings/<session_id>`** returns the analysis as a
  downloadable `<name>_findings.json` file (the same JSON shape the CLI
  emits).
- **`POST /load_findings`** accepts a previously-saved findings JSON
  back and returns the report shape for re-rendering. Schema is
  validated. Fixers are not available on a loaded session because the
  original L5X is gone — explicit limitation by design.

### Fix preview (dry-run diff)

- **`POST /preview_fixes/<session_id>`** applies the selected fixes
  in memory and returns a unified diff against the original, plus the
  manifest of applied/failed fixes and the byte delta. Diff is capped
  at 200 KB with a `truncated` flag. The user sees exactly what changes
  before downloading the corrected file.

### Bookmarks

- **`bookmarks.py`** — content-addressed triage state persisted to a
  JSON file next to the config. Each finding has a stable 16-char
  fingerprint over `(check_id, location, message)`. States: `wontfix`,
  `in_progress`, `fixed`, `snoozed` (with `snooze_until` ISO date).
- Endpoints: `GET /api/bookmarks`, `PUT /api/bookmarks/<fp>`,
  `DELETE /api/bookmarks/<fp>`.
- The analyzer now attaches a `bookmark` field to every finding dict
  in the report. Snoozed entries past their `snooze_until` date carry
  `hidden=True` so the UI can collapse them.
- A bookmark survives across analyses as long as `check_id`, `location`,
  and `message` are identical. If the finding genuinely changes — say
  the message text shifts because the analyzer became more precise —
  the bookmark detaches, which is correct: it's a different finding now.

### Multi-file batch

- **`POST /upload_batch`** — accepts up to 50 `.l5x` files in one form
  (key `files`). Returns a `[{filename, session_id}, ...]` list. Each
  file gets its own session and can be streamed individually.
- **`POST /batch_summary`** — given a list of session IDs, returns
  one-row-per-file severity counts for a batch dashboard view.

## What the UI still needs (not done here)

- Templates (`templates/index.html`, `templates/settings.html`) still
  reference the score and weights. They need updates to:
  - drop the score widgets and weight sliders
  - show suppression counts
  - render the lifecycle column / badge on modules
  - surface bookmark state per finding with set/clear buttons
  - call `/preview_fixes/...` before `/download_corrected/...`
  - present a batch upload view that consumes `/upload_batch`
  - have a "Save findings" download button and a "Load findings" upload

These are mechanical template edits but they're enough work that I'd
rather hand them over than fake them. The backend is solid; the
endpoints exist and are tested.

## Test coverage

- `tests/test_smoke.py` — 10 v1 tests (still green)
- `tests/test_v2.py` — 18 v2 tests covering naming, sizes, suppression,
  JSON/SARIF, lifecycle, bookmarks, fix-preview endpoint, and the CLI

Total: 28/28 green.

## On the lifecycle "manual scrape" plan

You said: "for now manually have the option to scrape json static from
rockwell website". The structure is in place — `lifecycle.json` is the
single source of truth, the loader doesn't care how it gets populated.
A future scraper subcommand can be a one-shot script that writes to the
same file. I did not implement the scraper itself because (a) Rockwell's
site requires PCDC credentials for most lifecycle data and (b) any
scraper here would be a maintenance burden that the curated-JSON model
specifically avoids. The 14-entry seed in `lifecycle.json` is a usable
starting point; add to it as needed.

---

# Changes (v3) — lifecycle first-class + UI catch-up

## Lifecycle (priority work)

- **Lifecycle now generates findings, not just table decoration.** New
  `module_lifecycle` check (default ERROR): a Discontinued module in the
  I/O tree produces an ERROR finding with the suggested replacement and
  final-availability date in the message; End of Life produces one level
  softer; Active Mature produces an INFO planning note. Visible in the
  web report, the CLI text output, JSON, and SARIF.
- **Dataset import — three paths:**
  - UI: Settings → Lifecycle tab → Import (.json or .csv, merge or replace)
  - API: `POST /api/lifecycle/import` (multipart or raw JSON body)
  - CLI: `python l5x_cli.py lifecycle-import data.csv --scraped-at 2026-06-01`
- **CSV ingestion is header-flexible** — recognises common column-name
  variants ("Catalog Number", "Part Number", "Lifecycle Status", etc.)
  and normalises status spellings (EOL → End of Life, Obsolete →
  Discontinued). Bad rows are skipped with per-row warnings, never
  silently dropped.
- **Atomic writes + cache reload** — imports write `lifecycle.json.tmp`
  then `os.replace`, and refresh the in-memory cache, so a crash
  mid-import can't corrupt the dataset.
- **Seed dataset expanded to 41 catalogs** across ControlLogix 5560/5570/
  5580, CompactLogix 5370/5380, comms modules, POINT/FLEX I/O, MicroLogix,
  SLC, PLC-5, and PowerFlex. The `_meta.verified=false` flag is shown in
  the UI as "unverified seed data — verify against PCDC". Statuses
  reflect publicly announced discontinuations but MUST be confirmed
  before procurement decisions; the tool says so in the UI.
- **Why still no scraper:** Rockwell PCDC requires sign-in for most
  lifecycle pages and redesigns periodically. A scraper here would be
  the least reliable component of the entire tool. The import pipeline
  is the deliberate alternative: you control the data, the tool shows
  its age (`scraped_at`) so staleness is visible, and a future scraper —
  if ever written — just needs to emit the same JSON/CSV.

## Templates (catch-up on v2 backend)

### index.html
- Module table now reads the `lifecycle` dict per module: status badge
  (with note tooltip), EOL Date column, Replacement column. "Pending"
  fallback replaced with "Unknown".
- Dataset freshness line under the module table ("data as of YYYY-MM-DD,
  N catalogs, seed/unverified flag") with a link to Settings → Lifecycle.
  When no dataset is loaded, an explicit "lifecycle checks inactive"
  notice with an import link — never silent.
- XLSX module export gains EOL Date + Replacement columns.
- Suppressed-findings pill in the severity row (with tooltip explaining
  lint:disable).
- **Fix preview**: "👁 Preview Changes" button opens a colorised unified
  diff modal (adds green, deletes red, hunks blue) with the applied/failed
  manifest, before "Apply & Download".
- **Save / Load findings**: "💾 Save Findings" downloads the report JSON;
  "⤒ Load saved findings" on the upload card re-renders a saved report
  read-only (fix buttons hidden — no live session backs it).
- **Bookmarks**: per-finding WF / IP / FX buttons (hover-revealed),
  persisted via the bookmarks API; wontfix rows dim, fixed rows
  strike through, server-side fingerprints stamped on every finding
  (`fp` field) so client and server can never disagree on identity.
- **Batch mode**: selecting or dropping multiple .l5x files uploads via
  /upload_batch and renders a per-file severity-count table with an
  "Open" button per row to stream that file's full report.
- Download flow surfaces the X-Fixes-Applied / X-Fixes-Failed headers —
  partial failures are now announced, not silent.

### settings.html
- Scoring weights / profiles UI removed entirely (scoring is gone).
- New Conventions tab: six naming-pattern regex fields + three size
  thresholds, loaded from and saved to the config.
- New Lifecycle tab: dataset info (count, freshness, verified flag),
  import control with merge/replace toggle, CSV template, CLI hint.
- New rules registered in the Rules tab: naming, size, non_rll_routine,
  module_lifecycle (under a "Hardware Rules" section).
- Stale "Watchdog vs Period Mismatch" label corrected to "Watchdog
  Margin Too Small" (the rule was inverted in v1).

## Fixes found while rechecking the output

- `bookmarks.annotate` now stamps `fp` on EVERY finding (not only
  bookmarked ones). Without this, the client would have needed to
  re-derive sha1 fingerprints in JS and any mismatch would orphan
  bookmarks. Caught during template work.
- Test runner bug: tests appended after the `if __name__` block were
  silently never collected (18/18 "passing" while 25 existed). Runner
  moved to end of file; 25/25 now collected and passing.
- Two stale test assertions still expected 1756-ENBT = "End of Life";
  the corrected seed marks it Discontinued (it was discontinued in 2022).

## Test totals
- tests/test_smoke.py: 10/10
- tests/test_v2.py:    25/25 (7 new lifecycle/fp tests)

---

# Changes (v4) — UI rebuilt from scratch

## Architecture

`templates/index.html` rewritten completely. The old version was ~1,000
lines of string-concatenated HTML with state scattered across globals.
The new one is built around a single state object:

    S = { sid, report, findings, filters, groupBy, view, basket, batch, readOnly }

Actions mutate S and call render(); render functions are pure reads of
S. No framework, no build step — the discipline of one without the
dependency. All findings are flattened client-side into one array with
scope keys ('ctrl', 'prog:Name', 'aoi:Name'), and every view is a
filter+group over that array.

## What changed for the user

- **Verdict banner.** The first thing on screen is the answer:
  "⛔ 2 CRITICAL issues — do not download to a controller until
  reviewed" / "✔ No issues at WARNING or above." Clean files get a
  designed payoff instead of vacant divs.
- **Sidebar tree replaces the horizontal tab bar.** Mirrors the
  Controller Organizer (Task → Program, then AOIs), with a live count
  badge per node coloured by worst severity. Scales to 40 programs;
  carries information scent the tabs never had. Clicking a node scopes
  the findings list; clicking again unscopes.
- **Group-by pivot: By rule / By location.** By-rule is the triage
  view — one collapsible group per check, sorted by severity × count,
  so "kill all unused tags first" is one group, not twelve tabs.
- **Severity chips are filters now**, not decoration. Click to toggle.
- **Text search** across message, location, rule name, rule id.
- **"Hide bookmarked" and "Show N suppressed" toggles.** Suppressed
  findings are now carried in the report (greyed out, labelled
  "suppressed in source") — hidden-but-inspectable instead of a bare
  count you had to take on faith. Backend change: apply_suppressions
  returns the suppressed list; report carries `suppressed_findings`;
  saved-findings JSON round-trips them.
- **Fix basket replaces "select all fixes".** Checking a fix adds it to
  a basket chip (🧺 N fixes). The basket panel lists every selected fix
  with its location and a per-item remove — you always see exactly what
  you're about to change, in one place, regardless of where you checked
  it. Preview diff and Apply & Download live in the basket flow. The
  old UI let you bulk-select fixes in tabs you'd never opened; that
  pattern is gone.
- **Findings | Hardware view split.** The module lifecycle table is a
  deliverable, not a finding group; it now has its own view with the
  dataset-freshness banner and XLSX export front and centre.
- **Batch breadcrumb.** Opening a file from the batch summary shows
  "Batch (5 files) ▸ name" with "← Back to batch" — the summary is no
  longer a dead-end you can't return to.
- **Bookmark buttons always visible** (small, solid) instead of
  hover-revealed at 35% opacity. Hover doesn't exist on touch.
- **Print stylesheet.** Ctrl-P hides the chrome, expands all groups,
  and produces something attachable to a commissioning package.

## Bug found by the rebuild's end-to-end test

**The fixer mis-scoped self-closing tags.** `<Tag Name="orphan"
DataType="DINT"/>` — the block regex's `[^>]*` happily includes `/`,
so the opening-tag group swallowed the self-closing tag and `(.*?)` ran
on into the NEXT tag's block. Consequence: the fixer attributed the
neighbouring tag's `<Description>` to `orphan` and refused with "tag
already has a Description" — and in a file where the neighbour had
none, it would have inserted the description into the wrong tag's
block. Fixed two ways: the block regex now has a `(?<!/)` lookbehind so
it cannot match self-closing tags at all, and a separate code path
expands `<Tag .../>` into an open/close pair (preserving the tag's own
indentation) before inserting. Three regression tests added.

This is the second wrong-target bug in the fixer's history (after the
CDATA destruction in v1) — both caught by tests, neither by reading
the code. The lesson stands: every fixer path needs an end-to-end test
against realistic XML, including the boring variants like self-closing
elements.

## Test totals
- tests/test_smoke.py: 10/10
- tests/test_v2.py:    28/28 (3 new self-closing regression tests)

---

# Changes (v4.1) — bug-hunt pass over the new UI

1. **Quote-escaping order bug (injection + breakage).** Inline onclick
   handlers were built as `X(value).replace(/'/g,"\\'")` — but X()
   converts the quote to `&#39;` first, so the JS-escape never fired,
   and the browser's HTML decoder handed the JS engine a raw quote: a
   program named O'Brien produced an unterminated string (dead handler,
   and an injection surface). New `JS()` helper escapes for JS *first*,
   then HTML, so `\'` round-trips correctly. Applied at all four
   user-data call sites (tree scope keys, batch filenames, basket fix
   ids, finding fix ids); audited the rest — only fixed-set values
   (severity names, hex fingerprints) remain inline.
2. **exportModules stacked script tags.** Every click appended another
   XLSX `<script>`; second click double-fired. Now reuses window.XLSX
   when present.
3. **openBatchItem showed stale UI.** Opening a file from the batch
   summary left the previous file's verdict, toolbar, and sidebar on
   screen while the new analysis streamed (progress was invisible —
   the status line lives in the hidden upload card). Now clears the
   report UI and streams progress into the main pane.
4. **Structural XML test for the self-closing fix.** The v4 regression
   tests were regex-only; malformed output could pass them. New test
   parses the corrected file with ElementTree and asserts the
   description is structurally inside the correct <Tag> element.
5. **Rendered-JS syntax check.** Both inline script blocks are now
   extracted from the Jinja-rendered page and pass `node --check` —
   guards against template edits that render fine but die on first
   click.

Old configs (pre-module_lifecycle) verified to degrade gracefully:
missing severity key falls back to WARNING, never crashes.

Tests: 10/10 smoke + 29/29 v2.


---

# Changes (v5) — URS rules (CSG/CNT/23-24/STD001 R0)

- 16 new static rules (urs_checks.py), each traced to its URS clause.
- `Finding.req_ids` + central map (urs_map.py): existing rules gain
  traceability without modification.
- Compliance matrix over all 47 PLC clauses + PAx-019, in the report,
  JSON output, `--format compliance` CSV, and a Compliance view in the UI.
- Loader: tag Class, MSG MessageType, controller fault/power-loss
  programs, PTP flag, DST adjustment, SafetyTagMap, AOI Class.
- Naming check gains controller, task, produced and consumed scopes.
- `loose_bool` threshold configurable (`sizes.loose_bool_min`).

Bugs found while doing it:
- **UDT optimiser violated REQ-018.** TIMER/COUNTER/CONTROL/MESSAGE
  shared one sort group, as did all UDT-typed members, so they
  interleaved by name. Exact type added as a tiebreak — padding-neutral
  (all DINT-aligned). Test pins that the optimiser's output passes the
  new udt_order rule.
- **Settings save erased hand-written config.** save_config overwrote
  the whole file; the Settings page never posts "urs", so required_tags
  vanished on the next UI save. Now merges, atomic write, regression test.
- Restore Defaults would have written "undefined" into the new naming
  fields; DEFAULTS extended.
- Compliance note said "Needs urs.required_tags entry" on configured rows.

Name collision to be aware of: the old `msg_write` rule checks writes TO
a MSG's status bits — it does NOT verify REQ-026. `msg_type_write` does.

Tests: 10 smoke + 29 v2 + 23 URS = 62.

---

# Changes (v6) — final checklist, report-only

- Rule set replaced by the final checklist (rules.py): codes CRT/ERR/WAR/INF,
  severity fixed by code, rules can only be enabled/disabled. Lifecycle kept
  as ERR017 / WAR021 / INF009.
- New rules: ERR010–ERR016, WAR002, WAR003, WAR007, WAR015–WAR020, INF006, INF008.
- Dropped (not on checklist): naming/size, safety prefix, UDT uppercase,
  periodic-only tasks, PTP/DST, heartbeat, required tags, module naming,
  MSG error monitoring, fault-log GSV. Their URS clauses show EXCLUDED.
- All fix functionality removed (fixer, preview/download endpoints, basket).
- Save → Excel / PDF reports (report_export.py), following the URS reporting clauses.
- Settings → rule checklist toggles + lifecycle.
- Bugs: blank sidebar nodes / stray counters (UI read prog_name/task_name
  under the wrong keys); WAR010 firing at 0 bytes saved; zero badges;
  nested <main> spacing; clipped search box; report rows sorted Rung 10
  before Rung 2; Google Fonts request removed (air-gapped OT networks).
- Tests consolidated into tests/test_rules.py (45), including a UI render
  against a real report shape and a headless-browser pass during development.


---

# Changes (v6.1)

- Export fixed for large projects: reports are cached when analysis finishes
  (export no longer re-runs the analysis); PDF table chunked (13.5k findings:
  25 s → 10 s); buttons show "Generating…" and surface server errors instead
  of navigating to a raw error page.
- Settings: "← Back to report" restores the report with new rule toggles
  applied (new GET /api/report/<sid>).
- Side pane: Expand / Collapse all, per-section collapse with totals, Hide
  to a rail.
- Removed: bookmarks (WF/IP/FX), URS REQ IDs, compliance view/CSV.
  "Not verified" rule notes now appear in the banner and both reports.
- Fixed: section labels clipped underscores (FAST_10MS shown as FAST 10MS).


---

# Changes (v6.2) — schema-verified (XSD v34–v38)

- Export: missing openpyxl/reportlab detected at startup, button disabled
  with install hint; failures now report the real reason.
- WAR008 redesigned: preset read from tag data (Decorated), timer arrays
  checked per used element; only preset 0 + never set by logic is flagged.
- Array handling: ERR016 accepts indexed resets (RES(Arr[i])); WAR019 checks
  element/bit comments.
- WAR017/WAR018 now check module I/O tags (<prefix>:<Suffix>, from the
  schema's InputTag/OutputTag Suffix and Port Upstream/Type) and I/O points
  used in logic, not modules.
- WAR005: controller Fault Handler / Power-Up Handler programs and child
  programs (ChildPrograms) are no longer reported as unscheduled.
- WAR012 retired (code reserved).
- Source-protected (EncodedData) and license-protected (EncryptionInfo)
  routines and encoded AOIs are counted and reported in the banner.
- Settings: Save returns to the report automatically.


---

# Changes (v6.3)

1. ERR010 uses a branch-aware rung parser (rung_tree.py): series duplicates
   within one chain; parallel only when legs are identical.
2. "Load saved findings (.json)" removed (button, endpoint, read-only mode).
3. ERR004 classifies by resolved datatype (through UDTs/arrays); TIMER bits
   no longer reported as MSG. Also fixed: MOV was checked on its source.
4. WAR011 text: "Data types are not grouped." / "Members are not in
   alphabetical order."
5. WAR019 matches only whole words "spare" / "unused".
6. WAR018 one finding per I/O point.
7. WAR017 one finding per field-data point (Data.n from catalog point count,
   ChnData from module data; status/fault/config members excluded).
8. ERR005 by resolved datatype (mirror of ERR004).
9. ERR011/ERR012 guards must precede the instruction on the same path.
10. Per-item reporting: INF006 per member, WAR008 per timer element, ERR010
    per duplicate, INF003 per bit — and INF003 bit-level now reports only
    bits referenced individually (it used to enumerate every bit of every
    DINT array, used or not).
11. AOI local tags parsed (schema LocalTags/LocalTag).
12. WAR004 no longer reports AOI Logic/Prescan/Postscan/EnableInFalse.
13. ST/FBD/SFC references count as usage for INF001, WAR004, WAR017.


---

# Changes (v6.4)

- INF008: keying must be Compatible Module; Exact Match, Disabled or any
  other State is reported with its value (schema types State as free text).
- WAR017: no direct mapping and no alias (aliases no longer count as mapping).
- WAR022 (new): Alias Used For Physical I/O — one per alias tag, chains
  resolved, message says used (replace) / unused (delete).
- WAR018: only comments on the module I/O tag count.
- UI: "⟲ New file" toolbar button; back-to-top button (hidden in print).


---

# Changes (v6.5)

- Reload (after Settings or browser refresh) now re-analyses through the live
  stream, so phases and % are shown. New POST /api/rerun/<id>; GET
  /api/report/<id> removed — one analysis path instead of two.
- Loader: progress ring with % inside plus the phase name (upload, reload,
  batch open); indeterminate ring while transferring. Replaces the rotating
  text glyph and the thin progress bar.


---

# Changes (v6.6)

- Exports follow all on-screen filters (severity, search, scope) and state
  them; Checklist sheet lists enabled rules only; disabled rules listed.
- Lifecycle master switch (Settings → Lifecycle).
- Loading ring centred on screen in an overlay.
- Lifecycle refresh round trip: Excel sheet export (project or full dataset,
  Status dropdown, text dates, Instructions + prompt) → import .xlsx/.csv
  with review-before-save (changes, new, missing Source URL, Unknown skipped).
  Entries without a Source URL are marked unverified.


---

# Changes (v6.7)

- PDF: signature (Verified by / Reviewed by) block removed.
- Lifecycle has one control: the Lifecycle switch. ERR017/WAR021/INF009 are
  locked in the Rule Checklist and ignored in disabled_rules.
- Lifecycle off: no Hardware sheet (Excel), no Hardware page (PDF), no
  lifecycle wording in either report.

---

# Changes (v6.8) — cleanup & performance (no behaviour change)

Verified: full reports byte-identical before/after on 5 inputs (fixture, 13.5k-finding
project, 150-UDT project, disabled rules, lifecycle off); 10 screenshots (5 pages ×
light/dark) pixel-identical; tests 76/76.

Removed
- Unreachable Python (~190 lines): UDT optimiser XML-writer (auto-fix era), superseded
  I/O and guard helpers, all_routine_names, get_all_operands, get_status_batch.
- Unused imports in 7 modules; SEV_WEIGHT (scoring leftover).
- 102 dead CSS rules from style.css (597 → 316 lines), plus .sl-text/.sl-sub.

Fixed
- L5XOpt_UDT called logging.basicConfig at import, hijacking the app's logging setup;
  now a module logger, chatter at DEBUG.
- Dark mode flashed light on every page load (theme applied after first paint); now set
  in <head> before paint.

Performance
- Report bucketing was programs × findings (986k calls on a 124-program project); now
  one pass. 800 programs / 114k findings: 31.7 s → 3.9 s.
- Each rung parsed once (LRU cache) instead of ~6 times. 13.5k-finding project:
  1.01 s → 0.39 s.
- Disabled rules are now skipped instead of run-and-discarded: the per-rule
  "DISABLED" guards are fed from Settings via rules.build_gate (they were unreachable).


---

# Changes (v6.9) — Tier 3: UDT layout rewrite + rule restructure (no behaviour change)

Verified: full reports byte-identical on 5 inputs; UDT engine fuzzed old vs new —
400 random projects, 3,473 UDTs (BIT packing, BOOL arrays, nested, AOI-typed,
unknown, custom string, System types), 0 mismatches; tests 79/79; browser passes.

- UDT padding (WAR010) now uses udt_layout.py: layout arithmetic, type tables, sort
  key and cycle handling moved verbatim from L5XOpt_UDT/L5XGen_UDT, fed from the
  loader's single XML parse. Removed L5XOpt_UDT.py and L5XGen_UDT.py (963 lines;
  they built a full L5X document per UDT to read back two numbers and parsed the
  file two extra times).
- Rules consolidated into the checks/ package by category (common, logic, tags, io,
  udt, program) with one runner, run_rules(), in the original execution order.
  analysis.py is now pipeline + report builder only (806 → 340 lines).
- Renamed: checker.py → lifecycle.py, extra_checks.py → suppression.py;
  new_rules.py and urs_checks.py dissolved into checks/.
- Comparison harness hardened: it now fails loudly if the snapshot run crashes
  (it previously could compare against a stale file).
