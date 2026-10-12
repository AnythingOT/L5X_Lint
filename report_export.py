# report_export.py — lint report as Excel (.xlsx) or PDF.
"""
Report layout follows the reporting clauses of URS CSG/CNT/23-24/STD001
where they apply: A4 (RPT-006), footer with page x of y, generated-by
computer + user, generated-on and template version (RPT-008), date format
DD/MM/YYYY HH:mm:ss (RPT-009), verified/reviewed signature block (RPT-012),
repeating table headers (RPT-015).
"""

import io, datetime, getpass, socket
from rules import rule_list, SEV_PREFIX

LIFECYCLE_CODES = {"ERR017", "WAR021", "INF009"}   # controlled only by the Lifecycle switch
TEMPLATE_VERSION = "L5X Lint Report Template v1.0"
SEV_ORDER = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3}
SEV_COLORS = {"CRITICAL": ("EFE0FF", "6B21A8"), "ERROR": ("FDE2E2", "B42318"),
              "WARNING": ("FEF3C7", "92400E"), "INFO": ("E0ECFF", "1E40AF")}


def _now():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def _who():
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    return f"{socket.gethostname()} \\ {user}"


def _scoped(report):
    """(scope, finding) for every finding, scope keys as in the web UI:
    'ctrl', 'prog:<name>', 'aoi:<name>'."""
    seen = set()
    def emit(scope, f):
        k = (f.get("code"), f.get("location"), f.get("message"))
        if k not in seen:
            seen.add(k)
            yield scope, f
    for f in report.get("controller_findings") or []:
        yield from emit("ctrl", f)
    for tab in report.get("task_program_tabs") or []:
        sc = "prog:" + (tab.get("prog_name") or "?")
        sec = tab.get("sections") or {}
        for b in ("unused_tags", "no_desc", "other"):
            for f in sec.get(b) or []:
                yield from emit(sc, f)
        for lst in (sec.get("routines") or {}).values():
            for f in lst or []:
                yield from emit(sc, f)
    for a in report.get("aoi_sections") or []:
        sc = "aoi:" + (a.get("name") or "?")
        for b in ("no_desc", "ctrl_tag", "other"):
            for f in a.get(b) or []:
                yield from emit(sc, f)
        for lst in (a.get("routines") or {}).values():
            for f in lst or []:
                yield from emit(sc, f)


def describe_filters(sev_filter, q, scope):
    parts = ["Severities: " + (", ".join(sev_filter) if sev_filter else "all")]
    if scope and scope != "all":
        parts.append("Scope: " + {"ctrl": "Controller"}.get(scope, scope.split(":", 1)[-1]))
    if q:
        parts.append(f"Search: '{q}'")
    return " · ".join(parts)


def _rows(report, sev_filter, q="", scope="all"):
    """Findings matching the on-screen filters: severity chips, search text
    (code, rule, check id, location, message) and sidebar scope."""
    keep = set(sev_filter) if sev_filter else set(SEV_ORDER)
    ql = (q or "").strip().lower()
    fs = []
    for sc, f in _scoped(report):
        if f.get("severity") not in keep:
            continue
        if scope and scope != "all" and sc != scope:
            continue
        if ql and not any(ql in (f.get(k) or "").lower()
                          for k in ("code", "check_name", "check_id", "location", "message")):
            continue
        fs.append(f)
    # Natural order on location so "Rung 2" sorts before "Rung 10".
    from udt_layout import natural_key
    fs.sort(key=lambda f: (SEV_ORDER.get(f.get("severity"), 9), f.get("code", ""),
                           natural_key(f.get("location", ""))))
    return fs


# ─── Excel ────────────────────────────────────────────────────────────────

def build_xlsx(report, file_name, sev_filter=None, q="", scope="all") -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.formatting.rule import FormulaRule
    from openpyxl.utils import get_column_letter

    AR = "Arial"
    hdr_font = Font(name=AR, bold=True, color="FFFFFF", size=10)
    hdr_fill = PatternFill("solid", fgColor="1E3A5F")
    body = Font(name=AR, size=10)
    thin = Side(style="thin", color="C8CED6")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    wrap = Alignment(wrap_text=True, vertical="top")
    center = Alignment(horizontal="center", vertical="top")

    def table(ws, headers, rows, widths, sev_col=None):
        for j, h in enumerate(headers, 1):
            c = ws.cell(1, j, h)
            c.font, c.fill, c.border, c.alignment = hdr_font, hdr_fill, border, center
        from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
        for i, r in enumerate(rows, 2):
            for j, v in enumerate(r, 1):
                if isinstance(v, str) and not v.startswith("="):
                    v = ILLEGAL_CHARACTERS_RE.sub("", v)[:32000]
                c = ws.cell(i, j, v)
                c.font, c.border, c.alignment = body, border, wrap
        for j, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(j)].width = w
        ws.freeze_panes = "A2"
        last = max(1, len(rows) + 1)
        ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{last}"
        if sev_col and rows:
            col = get_column_letter(sev_col)
            for sv, (bg, fg) in SEV_COLORS.items():
                ws.conditional_formatting.add(f"{col}2:{col}{last}", FormulaRule(
                    formula=[f'{col}2="{sv}"'], fill=PatternFill("solid", fgColor=bg),
                    font=Font(name=AR, bold=True, color=fg)))
        return last

    findings = _rows(report, sev_filter, q, scope)
    meta = report.get("meta", {}) or {}
    wb = Workbook()

    # Findings
    wf = wb.active
    wf.title = "Findings"
    f_last = table(wf, ["Code", "Severity", "Rule", "Location", "Message"],
                   [[f.get("code", ""), f.get("severity", ""), f.get("check_name", ""),
                     f.get("location", ""), f.get("message", "")]
                    for f in findings],
                   [10, 12, 30, 40, 90], sev_col=2)

    # Suppressed
    sup = report.get("suppressed_findings") or []
    ws_s = wb.create_sheet("Suppressed")
    table(ws_s, ["Code", "Severity", "Rule", "Location", "Message"],
          [[f.get("code", ""), f.get("severity", ""), f.get("check_name", ""),
            f.get("location", ""), f.get("message", "")] for f in sup],
          [10, 12, 30, 40, 80], sev_col=2)

    # Hardware & lifecycle — omitted entirely when lifecycle is switched off
    mods = report.get("modules") or []
    lc_off = bool((report.get("meta") or {}).get("lifecycle", {}).get("disabled"))
    base = lambda m: [m.get("catalog", ""), m.get("name", ""),
                      m.get("slot") if m.get("slot") is not None else "", m.get("parent", "")]
    if not lc_off:
        wh = wb.create_sheet("Hardware")
        table(wh, ["Catalog", "Module", "Slot", "Parent", "Lifecycle", "EOL Date", "Replacement"],
              [base(m) + [(m.get("lifecycle") or {}).get("status", "Unknown"),
                          (m.get("lifecycle") or {}).get("eol_date") or "",
                          (m.get("lifecycle") or {}).get("replacement") or ""] for m in mods],
              [20, 28, 8, 20, 16, 12, 18])

    # Checklist (counts are live formulas over the Findings sheet)
    wc = wb.create_sheet("Checklist")
    disabled = set((report.get("meta") or {}).get("disabled_rules") or []) - LIFECYCLE_CODES
    hidden = disabled | (LIFECYCLE_CODES if lc_off else set())
    rules = [r for r in rule_list() if r["code"] not in hidden]
    table(wc, ["Code", "Rule", "Description", "Findings"],
          [[r["code"], r["title"], r["desc"], f'=COUNTIF(Findings!$A$2:$A${f_last},A{i})']
           for i, r in enumerate(rules, 2)],
          [10, 32, 90, 10])

    # Summary (first sheet)
    w = wb.create_sheet("Summary", 0)
    w.column_dimensions["A"].width = 30
    w.column_dimensions["B"].width = 50
    w["A1"] = "L5X Lint Report"
    w["A1"].font = Font(name=AR, bold=True, size=16, color="1E3A5F")
    info = [
        ("File", file_name),
        ("Controller", meta.get("controller_name", "")),
        ("Processor", meta.get("processor_type", "")),
        ("Firmware", meta.get("firmware", "")),
        ("Programs / Rungs", f"{meta.get('program_count', 0)} / {meta.get('rung_count', 0)}"),
        ("Filters", describe_filters(sev_filter, q, scope)),
        ("Rules disabled", (", ".join(sorted(disabled)) if disabled else "None")),
        ("Generated on", _now()),
        ("Generated by", _who()),
        ("Template", TEMPLATE_VERSION),
    ]
    r = 3
    for k, v in info:
        w.cell(r, 1, k).font = Font(name=AR, bold=True, size=10)
        w.cell(r, 2, v).font = body
        r += 1
    r += 1
    w.cell(r, 1, "Findings by severity").font = hdr_font
    w.cell(r, 1).fill = hdr_fill
    w.cell(r, 2).fill = hdr_fill
    r += 1
    for sv in ("CRITICAL", "ERROR", "WARNING", "INFO"):
        c = w.cell(r, 1, sv)
        bg, fg = SEV_COLORS[sv]
        c.fill = PatternFill("solid", fgColor=bg)
        c.font = Font(name=AR, bold=True, color=fg)
        w.cell(r, 2, f'=COUNTIF(Findings!$B$2:$B${f_last},"{sv}")').font = body
        r += 1
    w.cell(r, 1, "Total").font = Font(name=AR, bold=True)
    w.cell(r, 2, f"=SUM(B{r-4}:B{r-1})").font = Font(name=AR, bold=True)
    r += 1
    w.cell(r, 1, "Suppressed in source").font = body
    w.cell(r, 2, f"=COUNTA(Suppressed!$A$2:$A${max(2, len(sup)+1)})").font = body
    r += 2
    notes = []
    if meta.get("non_rll_routines"):
        notes.append(f"{meta['non_rll_routines']} non-ladder routine(s) (FBD/SFC/ST) were not analysed.")
    for e in report.get("rule_errors") or []:
        notes.append(f"Rule failed to run: {e}")
    for n in report.get("not_verified") or []:
        notes.append(f"Not verified — {n}")
    lc = meta.get("lifecycle") or {}
    if not lc.get("disabled"):
        notes.append(f"Lifecycle data as of {lc.get('scraped_at')} ({lc.get('count', 0)} catalogs)"
                     + ("" if lc.get("verified") else " — unverified seed data")
                     if lc.get("available") else "No lifecycle dataset loaded.")
    for n in notes:
        w.cell(r, 1, "Note").font = Font(name=AR, bold=True, size=9)
        c = w.cell(r, 2, n)
        c.font = Font(name=AR, size=9)
        c.alignment = wrap
        r += 1
    w.sheet_view.showGridLines = False

    wb.calculation.fullCalcOnLoad = True
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# ─── PDF ──────────────────────────────────────────────────────────────────

def build_pdf(report, file_name, sev_filter=None, q="", scope="all") -> bytes:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Table, TableStyle,
                                    Spacer, PageBreak)
    from reportlab.pdfgen import canvas
    from xml.sax.saxutils import escape

    page = landscape(A4)
    gen_on, gen_by = _now(), _who()
    st = {
        "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=16, leading=20,
                             textColor=colors.HexColor("#1E3A5F")),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11, leading=14,
                             spaceBefore=8, spaceAfter=4, textColor=colors.HexColor("#1E3A5F")),
        "b":  ParagraphStyle("b", fontName="Helvetica", fontSize=8, leading=10),
        "bb": ParagraphStyle("bb", fontName="Helvetica-Bold", fontSize=8, leading=10),
        "hd": ParagraphStyle("hd", fontName="Helvetica-Bold", fontSize=8, leading=10,
                             textColor=colors.white),
    }
    P = lambda t, s="b": Paragraph(escape(str(t if t is not None else "")), st[s])

    class NumberedCanvas(canvas.Canvas):
        """Two-pass canvas so the footer can say 'Page x of y'."""
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._saved = []
        def showPage(self):
            self._saved.append(dict(self.__dict__))
            self._startPage()
        def save(self):
            total = len(self._saved)
            for s in self._saved:
                self.__dict__.update(s)
                self._footer(total)
                super().showPage()
            super().save()
        def _footer(self, total):
            self.setFont("Helvetica", 7)
            self.setFillColor(colors.HexColor("#555555"))
            y = 8 * mm
            self.drawString(12 * mm, y, f"Page {self._pageNumber} of {total}")
            self.drawCentredString(page[0] / 2, y,
                                   f"Generated by {gen_by}  ·  Generated on {gen_on}")
            self.drawRightString(page[0] - 12 * mm, y, TEMPLATE_VERSION)
            self.drawString(12 * mm, page[1] - 8 * mm, f"L5X Lint Report — {file_name}")

    meta = report.get("meta", {}) or {}
    findings = _rows(report, sev_filter, q, scope)
    story = [P("L5X Lint Report", "h1"), Spacer(1, 4)]

    grid = TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C8CED6")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ])

    info = [["File", file_name], ["Controller", meta.get("controller_name", "")],
            ["Processor / Firmware", f"{meta.get('processor_type','')} / {meta.get('firmware','')}"],
            ["Programs / Rungs", f"{meta.get('program_count',0)} / {meta.get('rung_count',0)}"],
            ["Filters", describe_filters(sev_filter, q, scope)],
            ["Rules disabled", ", ".join(sorted(set(meta.get("disabled_rules") or []) - LIFECYCLE_CODES)) or "None"]]
    t = Table([[P(k, "bb"), P(v)] for k, v in info], colWidths=[45 * mm, 120 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C8CED6")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t, Spacer(1, 6)]

    counts = {sv: sum(1 for f in findings if f.get("severity") == sv) for sv in SEV_ORDER}
    ct = Table([[P(SEV_PREFIX[sv] + " — " + sv.title(), "hd") for sv in SEV_ORDER],
                [P(counts[sv], "bb") for sv in SEV_ORDER]], colWidths=[40 * mm] * 4)
    cts = TableStyle(grid.getCommands())
    for j, sv in enumerate(SEV_ORDER):
        bg, fg = SEV_COLORS[sv]
        cts.add("BACKGROUND", (j, 1), (j, 1), colors.HexColor("#" + bg))
        cts.add("BACKGROUND", (j, 0), (j, 0), colors.HexColor("#" + fg))
    ct.setStyle(cts)
    story += [P("Summary", "h2"), ct]

    notes = []
    sup = report.get("suppressed_findings") or []
    if sup:
        notes.append(f"{len(sup)} finding(s) suppressed in source (lint:disable) — not listed.")
    if meta.get("non_rll_routines"):
        notes.append(f"{meta['non_rll_routines']} non-ladder routine(s) (FBD/SFC/ST) were not analysed.")
    for e in report.get("rule_errors") or []:
        notes.append(f"Rule failed to run: {e}")
    for n in report.get("not_verified") or []:
        notes.append(f"Not verified — {n}")
    for n in notes:
        story.append(P("• " + n))

    story += [P("Findings", "h2")]
    if not findings:
        story.append(P("No findings at the selected severities."))
    else:
        # One giant Table is laid out in O(n^2) by reportlab (each page split
        # re-measures the remainder). Chunks of 150 rows keep it linear; the
        # header is repeated per chunk and per page.
        head = [P(h, "hd") for h in ("Code", "Rule", "Location", "Message")]
        CH = 150
        for start in range(0, len(findings), CH):
            part = findings[start:start + CH]
            data = [head]
            for f in part:
                msg = f.get("message", "")
                if len(msg) > 1200:
                    msg = msg[:1200] + " …"
                data.append([P(f.get("code", ""), "bb"), P(f.get("check_name", "")),
                             P(f.get("location", "")), P(msg)])
            ft = Table(data, colWidths=[16 * mm, 45 * mm, 70 * mm, 142 * mm], repeatRows=1)
            fts = TableStyle(grid.getCommands())
            for i, f in enumerate(part, 1):
                bg, fg = SEV_COLORS.get(f.get("severity"), ("FFFFFF", "000000"))
                fts.add("BACKGROUND", (0, i), (0, i), colors.HexColor("#" + bg))
            ft.setStyle(fts)
            story.append(ft)

    mods = report.get("modules") or []
    lc_off = bool(meta.get("lifecycle", {}).get("disabled"))
    if mods and not lc_off:
        story += [PageBreak(), P("Hardware & Lifecycle", "h2")]
        data = [[P(h, "hd") for h in ("Catalog", "Module", "Slot", "Parent",
                                      "Lifecycle", "EOL Date", "Replacement")]]
        for m in mods:
            lcr = m.get("lifecycle") or {}
            data.append([P(m.get("catalog", "")), P(m.get("name", "")),
                         P(m.get("slot") if m.get("slot") is not None else ""), P(m.get("parent", "")),
                         P(lcr.get("status", "Unknown")), P(lcr.get("eol_date") or ""),
                         P(lcr.get("replacement") or "")])
        ht = Table(data, colWidths=[38 * mm, 50 * mm, 14 * mm, 40 * mm, 30 * mm, 28 * mm, 40 * mm],
                   repeatRows=1)
        ht.setStyle(grid)
        story.append(ht)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=page, leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm,
                            title=f"L5X Lint Report — {file_name}", author=gen_by)
    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
