# app.py  —  L5X Lint
import sys, os, uuid, json, threading, webbrowser, time, io, logging
from flask import Flask, request, jsonify, render_template, Response, stream_with_context, send_file, abort

# Ensure the app directory is on sys.path so flat modules are importable
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

import analysis

log = logging.getLogger("l5x_lint")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def resource_path(rel):
    # PyInstaller bundles set _MEIPASS; everywhere else we use the script dir.
    try:
        base = sys._MEIPASS  # type: ignore[attr-defined]
    except AttributeError:
        base = os.path.abspath(".")
    return os.path.join(base, rel)


app = Flask(__name__,
    template_folder=resource_path("templates"),
    static_folder=resource_path("static"))

# Hard cap upload size to defend against OOM via a giant L5X.
# 64 MB is generous for real-world Studio 5000 exports.
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024

# ─── Session store with TTL ───────────────────────────────────────────────
# Sessions hold (content, cfg, created_at). We do NOT pop on SSE connect
# because EventSource auto-reconnects and stream/<id> should be replayable
# while the session is alive.
_SESSION_TTL = 3600  # seconds
_session_lock = threading.Lock()
_sessions: dict      = {}  # session_id → (content, cfg, created_at)
_content_store: dict = {}  # session_id → (content, orig_name, created_at)
_report_cache: dict  = {}  # session_id → (report, created_at) — finished analysis


def _evict_expired():
    now = time.time()
    with _session_lock:
        for d in (_sessions, _content_store, _report_cache):
            stale = [k for k, v in d.items() if now - v[-1] > _SESSION_TTL]
            for k in stale:
                d.pop(k, None)


CONFIG_PATH = os.path.join(os.path.dirname(__file__), "evaluator_config.json")

DEFAULT_CONFIG = {
    # Severity is fixed per rule by its code (see rules.py). Rules can only
    # be switched off, by code: e.g. ["INF004", "WAR016"].
    "disabled_rules": [],
    "lifecycle_enabled": True,      # Settings → Lifecycle master switch
    "sizes": {
        "loose_bool_min": 1,     # INF002: any standalone BOOL is reported
    },
    "urs": {},                   # safety_prefix / std_prefix (WAR001)
}


def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                saved = json.load(f)
            cfg = json.loads(json.dumps(DEFAULT_CONFIG))
            for key in ("sizes", "urs"):
                if isinstance(saved.get(key), dict):
                    cfg[key].update(saved[key])
            if isinstance(saved.get("lifecycle_enabled"), bool):
                cfg["lifecycle_enabled"] = saved["lifecycle_enabled"]
            if isinstance(saved.get("disabled_rules"), list):
                cfg["disabled_rules"] = [str(x) for x in saved["disabled_rules"]]
            return cfg
        except (OSError, json.JSONDecodeError) as e:
            log.warning("Corrupted config at %s — using defaults (%s)", CONFIG_PATH, e)
    return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(cfg):
    """
    Merge posted sections into the on-disk config rather than replacing it.
    The Settings page only posts what it edits; sections it doesn't know
    about (e.g. a hand-written "urs" block with required_tags) must survive
    a save. Atomic write so a crash can't leave a truncated file.
    """
    existing = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                existing = json.load(f) or {}
        except (OSError, json.JSONDecodeError):
            existing = {}
    for k, v in cfg.items():
        existing[k] = v
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(existing, f, indent=2)
    os.replace(tmp, CONFIG_PATH)


# ─── Local-only origin / CSRF defence ────────────────────────────────────
# This server binds to 127.0.0.1. Browsers on the same machine can still
# reach it cross-origin via DNS rebinding or a malicious tab. We reject
# state-changing requests whose Origin/Referer don't point at localhost.
_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


def _origin_host(req) -> str:
    origin = req.headers.get("Origin") or req.headers.get("Referer") or ""
    if not origin:
        return ""
    # Strip scheme then take everything up to the next slash
    after_scheme = origin.split("://", 1)[-1]
    return after_scheme.split("/", 1)[0].split(":", 1)[0].lower()


@app.before_request
def _csrf_guard():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    # Allow same-origin requests (Origin/Referer points at our own host)
    host = _origin_host(request)
    if host and host not in _ALLOWED_HOSTS:
        abort(403)


# ─── Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    from rules import rule_list
    _evict_expired()
    return render_template("index.html",
                           rule_desc={r["code"]: r["desc"] for r in rule_list()},
                           missing_deps=_missing_export_deps())


@app.route("/settings")
def settings():
    from rules import rule_list
    from rules import LIFECYCLE_CODES
    return render_template("settings.html", active_page="settings", rules=rule_list(),
                           lifecycle_codes=LIFECYCLE_CODES)


@app.route("/api/settings", methods=["GET"])
def get_settings():
    return jsonify(load_config())


@app.route("/api/settings", methods=["POST"])
def post_settings():
    data = request.get_json(force=True, silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"success": False, "error": "No data"}), 400
    try:
        save_config(data)
        return jsonify({"success": True})
    except OSError:
        log.exception("save_config failed")
        return jsonify({"success": False, "error": "could not write configuration"}), 500


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename.lower().endswith(".l5x"):
        return jsonify({"success": False, "error": "A .l5x file is required."}), 400
    try:
        content = f.read().decode("utf-8-sig")
    except UnicodeDecodeError as e:
        return jsonify({"success": False, "error": f"Could not read file: {e}"}), 400

    orig_name = os.path.splitext(os.path.basename(f.filename))[0]
    now = time.time()
    session_id = str(uuid.uuid4())

    with _session_lock:
        _sessions[session_id]      = (content, load_config(), now)
        _content_store[session_id] = (content, orig_name, now)

    _evict_expired()
    return jsonify({"success": True, "session_id": session_id})


@app.route("/stream/<session_id>")
def stream(session_id):
    """
    SSE analysis stream. Does NOT pop the session — EventSource is allowed
    to reconnect and replay. Session is cleared by TTL eviction.
    """
    with _session_lock:
        sess = _sessions.get(session_id)
    if sess is None:
        def err():
            yield f"data: {json.dumps({'type':'error','message':'Session not found or expired'})}\n\n"
        return Response(stream_with_context(err()), mimetype="text/event-stream")

    content, cfg, _ = sess

    @stream_with_context
    def generate():
        last_ping = time.time()
        try:
            for event in analysis.run_analysis(content, cfg, session_id=session_id):
                if event.get("type") == "done":
                    # Cache so exports don't re-run the analysis.
                    with _session_lock:
                        _report_cache[session_id] = (event["report"], time.time())
                yield f"data: {json.dumps(event)}\n\n"
                if time.time() - last_ping > 10:
                    yield ": ping\n\n"
                    last_ping = time.time()
        except Exception:
            log.exception("analysis crashed for session %s", session_id)
            yield f"data: {json.dumps({'type':'error','message':'Internal error during analysis'})}\n\n"
        yield ": end\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                             "X-Content-Type-Options": "nosniff"})


@app.route("/api/ping")
def ping():
    _evict_expired()
    return jsonify({"ok": True, "sessions": len(_sessions), "stored": len(_content_store)})


# ─── Findings save / load ────────────────────────────────────────────────

def _run_to_report(content, cfg):
    """Helper: run analysis and return only the final report dict, or None."""
    report = None
    for ev in analysis.run_analysis(content, cfg):
        if ev.get("type") == "done":
            report = ev["report"]
        elif ev.get("type") == "error":
            return None
    return report


def _missing_export_deps() -> dict:
    """{'xlsx': 'openpyxl'} / {'pdf': 'reportlab'} for packages not installed."""
    import importlib.util
    out = {}
    if importlib.util.find_spec("openpyxl") is None:
        out["xlsx"] = "openpyxl"
    if importlib.util.find_spec("reportlab") is None:
        out["pdf"] = "reportlab"
    return out


# ─── Report export (Excel / PDF) ─────────────────────────────────────────

@app.route("/report/<session_id>.<fmt>")
def export_report(session_id, fmt):
    """
    Lint report as .xlsx or .pdf. Optional ?sev=CRITICAL,ERROR,... limits the
    findings to the severities currently shown in the UI.
    """
    if fmt not in ("xlsx", "pdf"):
        abort(404)
    with _session_lock:
        store = _content_store.get(session_id)
    if store is None:
        return jsonify({"error": "Session expired — upload the file again."}), 404
    content, orig_name, _ = store
    with _session_lock:
        cached = _report_cache.get(session_id)
    report = cached[0] if cached else _run_to_report(content, load_config())
    if report is None:
        return jsonify({"error": "Analysis failed"}), 500
    sev = [x for x in (request.args.get("sev") or "").upper().split(",") if x] or None
    q = (request.args.get("q") or "")[:200]
    scope = request.args.get("scope") or "all"
    missing = _missing_export_deps().get(fmt)
    if missing:
        return jsonify({"error": f"{fmt.upper()} export needs the '{missing}' package. "
                                 f"Run: pip install -r requirements.txt — then restart L5X Lint."}), 500
    import report_export
    try:
        if fmt == "xlsx":
            data = report_export.build_xlsx(report, orig_name, sev, q, scope)
            mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        else:
            data = report_export.build_pdf(report, orig_name, sev, q, scope)
            mime = "application/pdf"
    except Exception as e:
        log.exception("report export failed")
        # Local single-user tool: the real reason is more useful than a
        # generic message (full traceback is in the console log).
        return jsonify({"error": f"Report generation failed — {type(e).__name__}: {str(e)[:300]}"}), 500
    return send_file(io.BytesIO(data), mimetype=mime, as_attachment=True,
                     download_name=f"{orig_name}_lint_report.{fmt}")


# ─── Re-run (after visiting Settings / page reload) ───────────────────────

@app.route("/api/rerun/<session_id>", methods=["POST"])
def rerun(session_id):
    """
    Re-queue an uploaded file with the CURRENT settings so the page can
    reconnect to /stream/<id> and show live phases and % — the same path as
    a fresh upload. Used when the report is restored after Settings or a
    browser refresh.
    """
    with _session_lock:
        store = _content_store.get(session_id)
        if store is None:
            return jsonify({"success": False, "error": "Session expired"}), 404
        content, _name, _ = store
        _sessions[session_id] = (content, load_config(), time.time())
        _report_cache.pop(session_id, None)      # stale until the stream finishes
    return jsonify({"success": True})


# ─── Multi-file batch ────────────────────────────────────────────────────

@app.route("/upload_batch", methods=["POST"])
def upload_batch():
    """
    Accept multiple .l5x files in one form (key 'files'). Returns a list of
    (filename, session_id) so the UI can stream each session in turn.
    Each file gets its own session like /upload.
    """
    files = request.files.getlist("files")
    if not files:
        return jsonify({"success": False, "error": "No files uploaded."}), 400
    if len(files) > 50:
        return jsonify({"success": False, "error": "Batch limited to 50 files."}), 400

    results = []
    cfg = load_config()
    now = time.time()
    for f in files:
        if not f.filename.lower().endswith(".l5x"):
            results.append({"filename": f.filename, "error": "Not a .l5x file"})
            continue
        try:
            content = f.read().decode("utf-8-sig")
        except UnicodeDecodeError as e:
            results.append({"filename": f.filename, "error": f"Read failed: {e}"})
            continue
        sid = str(uuid.uuid4())
        with _session_lock:
            _sessions[sid]      = (content, cfg, now)
            _content_store[sid] = (content,
                                   os.path.splitext(os.path.basename(f.filename))[0],
                                   now)
        results.append({"filename": f.filename, "session_id": sid})

    _evict_expired()
    return jsonify({"success": True, "files": results})


@app.route("/batch_summary", methods=["POST"])
def batch_summary():
    """
    POST {"session_ids": [...]} → returns a compact summary table without
    re-running the analyses (uses cached content + fresh analysis per id).
    Intended for the batch-view UI: one row per file with severity counts.
    """
    body = request.get_json(force=True, silent=True) or {}
    sids = body.get("session_ids", [])
    if not isinstance(sids, list):
        return jsonify({"error": "session_ids must be a list"}), 400

    rows = []
    for sid in sids:
        with _session_lock:
            store = _content_store.get(sid)
        if not store:
            rows.append({"session_id": sid, "error": "expired"})
            continue
        content, name, _ = store
        report = _run_to_report(content, load_config())
        if report is None:
            rows.append({"session_id": sid, "filename": name, "error": "analysis failed"})
            continue
        c = report.get("severity_counts", {})
        rows.append({
            "session_id": sid,
            "filename":   name,
            "controller": report.get("meta", {}).get("controller_name"),
            "counts":     c,
            "suppressed": report.get("suppressed_count", 0),
        })
    return jsonify({"rows": rows})


# ─── Lifecycle dataset ───────────────────────────────────────────────────

@app.route("/api/lifecycle/info")
def lifecycle_info():
    from lifecycle import dataset_info
    return jsonify(dataset_info())


_lc_pending: dict = {}   # token -> (records, created) — imports awaiting review


@app.route("/api/lifecycle/template.xlsx")
def lifecycle_template():
    """
    Lifecycle sheet for an LLM / manual refresh.
      ?scope=project&sid=<id>  — catalogs in the loaded project
      ?scope=all               — every catalog in the dataset
    """
    import lifecycle
    if _missing_export_deps().get("xlsx"):
        return jsonify({"error": "Excel needs the 'openpyxl' package — run: pip install -r requirements.txt"}), 500
    scope = request.args.get("scope", "all")
    if scope == "project":
        sid = request.args.get("sid", "")
        with _session_lock:
            cached = _report_cache.get(sid)
        if not cached:
            return jsonify({"error": "Load a project first (or the session expired)."}), 404
        names = {}
        for m in cached[0].get("modules") or []:
            cat = (m.get("catalog") or "").strip()
            if cat:
                names.setdefault(cat, []).append(m.get("name") or "")
        cats = [(c, ", ".join(n[:4]) + (" …" if len(n) > 4 else "")) for c, n in sorted(names.items())]
        title = f"Catalogs used in the loaded project ({len(cats)})."
        fname = "lifecycle_project.xlsx"
    else:
        lifecycle._load()
        cats = [(c, "") for c in sorted(lifecycle._cache["data"].keys())]
        title = f"Full lifecycle dataset ({len(cats)} catalogs)."
        fname = "lifecycle_dataset.xlsx"
    data = lifecycle.build_template_xlsx(cats, title)
    return send_file(io.BytesIO(data), as_attachment=True, download_name=fname,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.route("/api/lifecycle/preview", methods=["POST"])
def lifecycle_preview():
    """Parse an uploaded .xlsx/.csv and report what WOULD change. Nothing is saved."""
    import lifecycle, secrets
    f = request.files.get("file")
    if not f:
        return jsonify({"success": False, "error": "No file uploaded."}), 400
    try:
        records, skipped, errors = lifecycle.parse_upload(f.filename, f.read())
    except Exception as e:
        log.exception("lifecycle preview failed")
        return jsonify({"success": False, "error": f"Could not read the file — {type(e).__name__}: {e}"}), 400
    if not records:
        return jsonify({"success": False, "error": "; ".join(errors[:5]) or "No usable rows.",
                        "skipped": skipped}), 400
    token = secrets.token_hex(8)
    now = time.time()
    for k in [k for k, v in _lc_pending.items() if now - v[1] > 1800]:
        _lc_pending.pop(k, None)
    _lc_pending[token] = (records, now)
    return jsonify({"success": True, "token": token, "rows": len(records),
                    "skipped": skipped, "errors": errors, **lifecycle.preview_import(records)})


@app.route("/api/lifecycle/apply", methods=["POST"])
def lifecycle_apply():
    """Save a previewed import (merge into the dataset)."""
    import lifecycle
    body = request.get_json(force=True, silent=True) or {}
    pending = _lc_pending.pop(body.get("token", ""), None)
    if not pending:
        return jsonify({"success": False, "error": "Preview expired — upload the file again."}), 400
    records = pending[0]
    n_src = sum(1 for e in records.values() if str(e.get("source_url") or "").lower().startswith("http"))
    result = lifecycle.import_dataset(records, meta={
        "source_note": f"Imported lifecycle sheet: {len(records)} rows, {n_src} with a source URL. "
                       f"Verify against Rockwell PCDC before procurement decisions.",
        "verified": False}, merge=True)
    return jsonify({"success": result["imported"] > 0, **result, "info": lifecycle.dataset_info()})


@app.route("/api/lifecycle/import", methods=["POST"])
def lifecycle_import():
    """
    Import a lifecycle dataset. Accepts either:
      • multipart upload (key 'file') of a .json or .csv
      • raw JSON body: {"records": {...}, "merge": true, "scraped_at": "..."}

    JSON record shape: { "<catalog>": {status, eol_date?, replacement?, note?}, ... }
    CSV needs at least Catalog and Status columns (flexible header names).
    """
    import lifecycle

    merge = True
    records = None
    meta = {}

    f = request.files.get("file")
    if f:
        try:
            text = f.read().decode("utf-8-sig")
        except UnicodeDecodeError as e:
            return jsonify({"success": False, "error": f"Could not decode file: {e}"}), 400
        merge = request.form.get("merge", "true").lower() != "false"
        if f.filename.lower().endswith(".json"):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as e:
                return jsonify({"success": False, "error": f"Invalid JSON: {e}"}), 400
            meta = payload.pop("_meta", {}) if isinstance(payload, dict) else {}
            records = payload
        elif f.filename.lower().endswith(".csv"):
            records, errors = lifecycle.parse_csv(text)
            if not records:
                return jsonify({"success": False, "error": "; ".join(errors[:5])}), 400
            meta = {"source_note": f"Imported from CSV '{f.filename}'."}
        else:
            return jsonify({"success": False, "error": "Upload a .json or .csv file."}), 400
    else:
        body = request.get_json(force=True, silent=True) or {}
        records = body.get("records")
        merge = bool(body.get("merge", True))
        if body.get("scraped_at"):
            meta["scraped_at"] = body["scraped_at"]
        if not records:
            return jsonify({"success": False, "error": "No records provided."}), 400

    result = lifecycle.import_dataset(records, meta=meta, merge=merge)
    if result["imported"] == 0:
        return jsonify({"success": False, **result}), 400
    return jsonify({"success": True, **result, "info": lifecycle.dataset_info()})


@app.errorhandler(413)
def _too_large(_e):
    return jsonify({"success": False,
                    "error": "File too large (limit 64 MB)."}), 413


def main():
    for fmt, pkg in _missing_export_deps().items():
        log.warning("%s export disabled: package '%s' not installed "
                    "(pip install -r requirements.txt)", fmt.upper(), pkg)
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5002)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://127.0.0.1:{args.port}")).start()
    print(f"L5X Lint running at http://127.0.0.1:{args.port}")
    app.run(host="127.0.0.1", port=args.port, debug=False,
            threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
