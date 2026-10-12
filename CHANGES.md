# Changes

A focused pass on the issues raised in the review. What's *fixed* and what
I deliberately *did not* touch are both listed below — read both.

## Fixed

### Correctness / data safety

- **`fixer.py` rewritten.** The previous implementation parsed the entire
  L5X with `xml.etree.ElementTree` and called `ET.indent`, which (a) silently
  drops `<![CDATA[ ... ]]>` wrapping around rung text, (b) re-escapes special
  characters inside it, and (c) reformats every line in the document. The
  new implementation does *text-level surgical edits* on the source string:
  it locates `<Tag Name="...">` blocks (scoped to the right `<Program>` or
  to the controller-level `<Tags>` only) and splices in `<Description>` or
  `<Comment>` elements with proper CDATA wrapping. UDT optimisation still
  uses the generated text path but only the targeted `<DataType>` blocks
  are replaced — surrounding XML is untouched. A regression test
  (`test_fixer_preserves_cdata_in_rung_text`) locks this in.

- **`apply_fixes` now returns a manifest.** Previously it returned a
  string and the user had no way to tell if any of the requested fixes
  silently failed. It now returns `(corrected_content, manifest)` where
  the manifest carries `applied` and `failed` lists with reasons.
  `app.py` exposes the counts via `X-Fixes-Applied` / `X-Fixes-Failed`
  response headers so the UI can warn the user.

- **`apply_fixes_legacy()`** keeps the old string-only API for callers
  that don't want the manifest.

- **`json_decode_fix_id`** now validates the shape and rejects unknown
  fix types, so a malformed (or hand-crafted) fix ID fails closed rather
  than being silently dropped further down.

- **SSE session no longer popped** on `/stream/<id>`. `EventSource`
  auto-reconnects on network blips; the old code popped the session on
  first contact, so any reconnect produced "Session not found" and forced
  a re-upload. Sessions now live for `_SESSION_TTL` (1 hour) and are
  evicted on every upload / index / ping request.

- **`_check_array_bit_comments` aggregated.** A `DINT[100]` array with
  no comments used to produce 3,200 separate `Finding` objects, each
  with its own fix payload — enough to crash the report UI on real
  industrial files. The check now produces *one* finding per tag with
  a sample of operands, plus a bulk-fix payload that the fixer expands
  back into individual `<Comment>` elements. Arrays over 1024 elements
  are noted with an INFO finding and skipped entirely.

- **`_check_timer_pre` exact base match.** The previous substring test
  matched `Timer1` against `Timer10.PRE`, `MyTimer1.PRE`, etc. It now
  decomposes each written operand with `operand_base` / `operand_member`
  and checks the base tag against the timer's base tag exactly. The
  finding message also no longer asserts that hardcoded presets are bad
  — it's now phrased as a conditional caution.

- **`_check_tasks` watchdog rule inverted.** The previous rule warned
  when `watchdog > 3 * period`, which is the *opposite* of Rockwell's
  guidance (watchdog should comfortably exceed worst-case scan time, so
  a generous watchdog is good). The check now warns when watchdog ≤
  period (guaranteed nuisance fault) or when the margin is under 50%.

- **`_check_jsr_depth`** no longer mutates the discovered-set across
  recursion branches. Cycles in the call graph terminate cleanly instead
  of producing misleading depth numbers.

- **Controller-finding bucket prefix collision** in `_build_report`
  fixed — uses the same delimiter-aware predicate as program-tab matching.

- **Non-ladder routines now produce a finding.** `_parse_routines`
  flags FBD / SFC / ST routines, and `_check_rungs` emits a
  `non_rll_routine` finding for each one (default severity INFO). Before
  this, those routines silently produced zero findings — i.e. looked
  clean — even though the tool can't inspect their logic at all.

- **`_topological_sort` (in `L5XOpt_UDT.py`) now uses `_detect_cycles`**
  and raises `ValueError` on a cyclic UDT graph. The analyzer catches
  that and surfaces a clear `UDT Dependency Cycle` finding instead of
  recursing oddly.

- **`base_check.effective_severity`** docstring now matches behaviour
  (WARNING fallback). Invalid values in saved config also fall back to
  WARNING rather than being returned as-is.

- **`Finding.fix`** moved from a `dict = None` literal default to a
  `field(default=None)` — same observable behaviour, no dataclass
  mutable-default trap when the class is ever subclassed or refactored.

- **`l5x_loader._parse_datatypes`** filter cleaned up — the `""` branch
  was unreachable because of the preceding `if family`. (Same behaviour,
  no functional change; flagged for readability.)

### Security / robustness

- **`MAX_CONTENT_LENGTH = 64 MB`** on the Flask app — defends against
  OOM via a giant `.l5x` upload. A 413 is returned cleanly.

- **CSRF / DNS-rebinding guard.** A `before_request` hook rejects any
  state-changing request whose `Origin` / `Referer` doesn't point at
  `127.0.0.1` / `localhost`. The server still binds to 127.0.0.1 only.

- **No more raw `str(e)` in JSON responses.** `download_corrected` and
  `post_settings` log the exception server-side and return a generic
  user-facing message.

- **`sqlite3.connect(..., check_same_thread=False)`** in `checker.py` so
  the cache survives Flask's threaded request handling. (Currently the
  cache code is dormant because the lifecycle check is disabled, but the
  fix is in place for when it's enabled.)

- **`silent=True`** on `request.get_json` calls so a malformed body
  produces a clean 400, not a Flask traceback.

- **`resource_path` bare `except:`** narrowed to `AttributeError`.

- **Sessions stored under a lock** (`threading.Lock`) and expired on a
  TTL. Eviction runs on every upload / index / ping hit.

- **`--port` and `--no-browser` CLI flags** added.

### Honesty about features

- **`checker.get_status` now returns `status="Unavailable"`** with
  `confidence="N/A"` instead of `"Pending"`. A `checker.is_available()`
  helper is added so the UI can hide the column entirely until Phase 2
  ships. Previously the UI implied per-module status was "being checked"
  when in fact nothing was ever going to happen.

- The `suggester.generate_report_narrative` still returns `""` — it's
  not user-facing today so leaving it as-is is fine, but the docstring
  is clearer about it being intentionally disabled.

### Tests

- **`tests/test_smoke.py`** — ten test cases covering parse + analyse,
  watchdog rule, AFI detection, non-RLL warning, CDATA preservation
  through the fixer (the big one), per-scope tag resolution in the
  fixer, bulk-fix expansion, malformed-fix-id handling, cyclic-UDT
  detection, and severity fallback. Run with `python3 tests/test_smoke.py`
  from the project root. All ten pass against this build.

## Not fixed — intentional

- **The lifecycle checker is still not implemented.** Wiring Playwright
  in, plus the URL-discovery + caching dance, is a feature, not a fix.
  I made the stub honest (`Unavailable`, `is_available()`) so the UI
  can stop pretending; the templates themselves still need a small edit
  to consult `is_available()` before rendering the column.

- **The LLM narrative is still empty.** Same reasoning.

- **No real unit-test coverage for the rung parser or cross-ref index.**
  The smoke tests cover the high-stakes paths end-to-end; the parser
  deserves its own fixture-driven test file but that's a half-day of
  work, not a bug fix.

- **`encode_fix_id` is still unsigned.** For a local-only single-user
  tool this is acceptable; if you ever expose this beyond localhost,
  HMAC-sign the payload.

- **Templates not changed.** The existing UI still works because all
  existing fix types still exist and `manifest` data is exposed via
  response headers. If you want the UI to surface the "X applied / Y
  failed" counts, that's a `templates/index.html` edit.

- **AOI-local tags still aren't checked for unused / no-desc.** The
  scope check in `_check_tags` skips `AOI:*`. AOI parameters are
  checked. Fixing the local-tag side requires deciding how AOI scope
  should appear in the report; punted.

- **Hardcode-literal noise reduction.** The check still flags `MOV(60,
  Timer.PRE)` as INFO. Context-aware filtering (e.g. allow integer
  literals adjacent to `.PRE` or `.ACC`) is a real design decision, not
  a one-line fix. Left as-is.
