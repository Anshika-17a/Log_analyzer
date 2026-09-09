import io
import re
from datetime import datetime

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


# ── colour palette ───────────────────────────────────────────────
C_DARK   = colors.HexColor("#0f172a")
C_MID    = colors.HexColor("#334155")
C_MUTED  = colors.HexColor("#64748b")
C_BORDER = colors.HexColor("#e2e8f0")
C_WHITE  = colors.white

C_CRITICAL = colors.HexColor("#ef4444")
C_HIGH     = colors.HexColor("#f97316")
C_MEDIUM   = colors.HexColor("#3b82f6")
C_LOW      = colors.HexColor("#10b981")

RISK_COLORS = {
    "Critical": (colors.HexColor("#450a0a"), colors.HexColor("#f87171")),
    "High":     (colors.HexColor("#431407"), colors.HexColor("#fdba74")),
    "Medium":   (colors.HexColor("#1e3a5f"), colors.HexColor("#93c5fd")),
    "Low":      (colors.HexColor("#052e16"), colors.HexColor("#86efac")),
}

PRIORITY_COLORS = {
    "IMMEDIATE": (colors.HexColor("#450a0a"), colors.HexColor("#f87171")),
    "HIGH":      (colors.HexColor("#431407"), colors.HexColor("#fdba74")),
    "MEDIUM":    (colors.HexColor("#1e3a5f"), colors.HexColor("#93c5fd")),
    "LOW":       (colors.HexColor("#052e16"), colors.HexColor("#86efac")),
}


def _styles():
    base = getSampleStyleSheet()
    def s(name, parent="Normal", **kw):
        return ParagraphStyle(name, parent=base[parent], **kw)

    return {
        "title":     s("T", "Title",   fontSize=22, textColor=C_DARK,  spaceAfter=4, leading=26),
        "subtitle":  s("ST","Normal",  fontSize=10, textColor=C_MUTED, spaceAfter=14),
        "h2":        s("H2","Heading2",fontSize=13, textColor=C_DARK,  spaceBefore=18, spaceAfter=6, leading=18),
        "h3":        s("H3","Heading3",fontSize=10, textColor=C_MID,   spaceBefore=10, spaceAfter=4, leading=14),
        "body":      s("B", "Normal",  fontSize=9.5,textColor=C_MID,   leading=15, spaceAfter=4),
        "bullet":    s("BL","Normal",  fontSize=9.5,textColor=C_MID,   leading=15, leftIndent=14, spaceAfter=3),
        "evidence":  s("EV","Normal",  fontSize=8.5,textColor=colors.HexColor("#4f46e5"), leading=13, leftIndent=10, spaceAfter=2),
        "kpi_num":   s("KN","Normal",  fontSize=24, textColor=C_DARK,  alignment=TA_CENTER, leading=28),
        "kpi_lbl":   s("KL","Normal",  fontSize=7.5,textColor=C_MUTED, alignment=TA_CENTER, leading=10),
        "footer":    s("FT","Normal",  fontSize=7.5,textColor=C_MUTED, alignment=TA_CENTER),
        "tag":       s("TG","Normal",  fontSize=8,  textColor=C_WHITE, alignment=TA_CENTER, leading=10),
    }


def _divider(color=C_BORDER, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=6, spaceBefore=2)


def _risk_tag(risk_level, styles):
    bg, fg = RISK_COLORS.get(risk_level, (C_MUTED, C_WHITE))
    label = risk_level.upper()
    t = Table([[Paragraph(label, ParagraphStyle("x", fontSize=8, textColor=fg, alignment=TA_CENTER, leading=10))]],
              colWidths=[0.85*inch], rowHeights=[0.22*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), bg),
        ("ROUNDEDCORNERS", [4]),
        ("BOX", (0,0), (-1,-1), 0, bg),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 2),
        ("BOTTOMPADDING", (0,0), (-1,-1), 2),
    ]))
    return t


def _priority_tag(priority, styles):
    bg, fg = PRIORITY_COLORS.get(priority, (C_MUTED, C_WHITE))
    t = Table([[Paragraph(priority, ParagraphStyle("x", fontSize=7, textColor=fg, alignment=TA_CENTER, leading=9))]],
              colWidths=[0.75*inch], rowHeights=[0.2*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), bg),
        ("BOX", (0,0), (-1,-1), 0, bg),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 2),
        ("BOTTOMPADDING", (0,0), (-1,-1), 2),
    ]))
    return t


def _section_header(text, styles):
    return [
        Spacer(1, 6),
        Paragraph(text.upper(), ParagraphStyle(
            "SH", fontSize=7.5, textColor=C_MUTED,
            spaceBefore=6, spaceAfter=4, leading=11,
            fontName="Helvetica-Bold", letterSpacing=1.2
        )),
        _divider(),
    ]


def generate_incident_report_md(incident, alerts, actions):
    """Markdown version — kept for API ?format=md endpoint."""
    reasoning = []
    rule_pts = max([a.points for a in alerts if a.rule_id != "ml_anomaly_001"] or [0])
    if rule_pts > 0:
        reasoning.append(
            f"A known deterministic security rule was breached with a baseline severity of {rule_pts} points."
        )
    ml_alerts = [a for a in alerts if a.rule_id == "ml_anomaly_001"]
    if ml_alerts:
        ml_score = max([a.ml_anomaly_score for a in ml_alerts if a.ml_anomaly_score is not None] or [0])
        reasoning.append(
            f"The system detected highly unusual behaviour, scoring an anomaly confidence of {ml_score:.2f}. "
            "This indicates the user is acting significantly outside their historical baseline."
        )
    if len(alerts) > 1:
        reasoning.append(
            f"The activity was frequent, firing {len(alerts)} distinct alerts in a condensed window, "
            "indicating an organised or automated pattern."
        )
    translation = " ".join(reasoning) if reasoning else "No significant contributing factors found."

    md = f"""# Security Incident Report — #{incident.id}

**User:** {incident.user}  
**Risk Level:** {incident.risk_level}  
**Score:** {incident.score}  
**Status:** {incident.status}  
**Period:** {incident.first_event_time} → {incident.last_event_time}

## Executive Summary
{translation}

## Rules Triggered
"""
    for r in set(a.rule_name for a in alerts):
        md += f"- {r}\n"
    md += "\n## Evidence\n"
    for a in alerts:
        md += f"- {a.evidence}\n"
    md += "\n## Recommended Actions\n"
    if actions:
        seen = set()
        for act in actions:
            if act.action not in seen:
                seen.add(act.action)
                md += f"- **[{act.priority}]** {act.action}\n"
    else:
        md += "- No specific automated actions recommended.\n"
    return md


def generate_summary_report_md(incidents):
    total = len(incidents)
    counts = {l: sum(1 for i in incidents if i.risk_level == l)
              for l in ("Critical", "High", "Medium", "Low")}
    md = f"""# Security Summary Report
Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}

## Threat Landscape
| Level | Count |
|---|---|
| Critical | {counts["Critical"]} |
| High | {counts["High"]} |
| Medium | {counts["Medium"]} |
| Low | {counts["Low"]} |
| **Total** | **{total}** |

## High-Priority Incidents
"""
    hi = sorted([i for i in incidents if i.risk_level in ("Critical","High")],
                key=lambda x: x.score, reverse=True)
    if hi:
        for i in hi:
            md += f"- **#{i.id} ({i.user})** — Score {i.score} — {i.rules}\n"
    else:
        md += "No critical or high risk incidents currently active.\n"
    return md


# ── PROFESSIONAL PDF ────────────────────────────────────────────────────────

def _build_incident_pdf(incident, alerts, actions) -> bytes:
    buf = io.BytesIO()
    ST = _styles()

    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch,
    )

    W = letter[0] - 1.5*inch   # usable width
    story = []

    # ── HEADER BANNER ──────────────────────────────────────────────
    risk_bg, risk_fg = RISK_COLORS.get(incident.risk_level, (C_MUTED, C_WHITE))
    header_data = [[
        Paragraph(f"<b>SECURITY INCIDENT REPORT</b><br/><font size=9 color='#94a3b8'>Incident #{incident.id}  ·  Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</font>",
                  ParagraphStyle("HH", fontSize=16, textColor=C_WHITE, leading=22)),
        Paragraph(f"<b>{incident.risk_level.upper()}</b><br/><font size=8>RISK LEVEL</font>",
                  ParagraphStyle("HR", fontSize=13, textColor=risk_fg, alignment=TA_RIGHT, leading=18)),
    ]]
    ht = Table(header_data, colWidths=[W*0.72, W*0.28])
    ht.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_DARK),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",  (0,0), (0,-1), 18),
        ("RIGHTPADDING", (-1,0),(-1,-1), 18),
        ("TOPPADDING",   (0,0), (-1,-1), 16),
        ("BOTTOMPADDING",(0,0), (-1,-1), 16),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(ht)
    story.append(Spacer(1, 14))

    # ── KPI ROW ────────────────────────────────────────────────────
    kpi_data = [[
        Paragraph(str(incident.score), ST["kpi_num"]),
        Paragraph(str(len(alerts)),    ST["kpi_num"]),
        Paragraph(str(len(actions)),   ST["kpi_num"]),
        Paragraph(incident.status.replace("_"," ").title(), ST["kpi_num"]),
    ],[
        Paragraph("Risk Score",    ST["kpi_lbl"]),
        Paragraph("Alerts Fired",  ST["kpi_lbl"]),
        Paragraph("Actions",       ST["kpi_lbl"]),
        Paragraph("Current Status",ST["kpi_lbl"]),
    ]]
    cw = W / 4
    kt = Table(kpi_data, colWidths=[cw]*4, rowHeights=[0.42*inch, 0.22*inch])
    kt.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ("BOX",  (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0),(-1,-1), 6),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(kt)
    story.append(Spacer(1, 18))

    # ── IDENTITY ────────────────────────────────────────────────────
    story += _section_header("Incident Identity", ST)
    meta_rows = [
        ["User Account",   incident.user],
        ["Risk Level",     incident.risk_level],
        ["First Seen",     str(incident.first_event_time)],
        ["Last Seen",      str(incident.last_event_time)],
        ["Rules Matched",  incident.rules or "—"],
    ]
    mt = Table(
        [[Paragraph(f"<b>{r}</b>", ParagraphStyle("ML", fontSize=9, textColor=C_MUTED, leading=13)),
          Paragraph(v, ParagraphStyle("MV", fontSize=9.5, textColor=C_DARK, leading=13))]
         for r, v in meta_rows],
        colWidths=[1.6*inch, W-1.6*inch]
    )
    mt.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(0,-1),  0),
        ("LINEBELOW", (0,0),(-1,-2), 0.3, C_BORDER),
    ]))
    story.append(mt)

    # ── EXECUTIVE SUMMARY ──────────────────────────────────────────
    story += _section_header("Executive Summary — What Happened?", ST)
    reasoning = []
    rule_pts = max([a.points for a in alerts if a.rule_id != "ml_anomaly_001"] or [0])
    if rule_pts > 0:
        reasoning.append(
            f"A known security rule was triggered with a baseline severity of <b>{rule_pts} points</b>. "
            "This means the system recognised a signature that matches a documented attack pattern."
        )
    ml_alerts = [a for a in alerts if a.rule_id == "ml_anomaly_001"]
    if ml_alerts:
        ml_score = max([a.ml_anomaly_score for a in ml_alerts if a.ml_anomaly_score is not None] or [0])
        reasoning.append(
            f"The machine learning model flagged this user's behaviour as <b>highly anomalous</b> "
            f"(confidence: <b>{ml_score:.2f}/1.00</b>). The user's actions were significantly different "
            "from their own historical patterns — even if no explicit rule was broken."
        )
    if len(alerts) > 2:
        reasoning.append(
            f"<b>{len(alerts)} separate alert signals</b> were triggered in a short window. "
            "This volume suggests a coordinated or automated activity, not a one-off mistake."
        )
    if not reasoning:
        reasoning.append("The incident reached this risk level through a combination of rule matches and behavioural deviation scores.")

    for line in reasoning:
        story.append(Paragraph(f"• {line}", ST["bullet"]))
    story.append(Spacer(1, 4))

    # ── RECOMMENDED ACTIONS ────────────────────────────────────────
    story += _section_header("Recommended Actions", ST)
    if actions:
        seen = set()
        for act in actions:
            if act.action in seen:
                continue
            seen.add(act.action)
            p_bg, p_fg = PRIORITY_COLORS.get(act.priority, (C_MUTED, C_WHITE))
            tag_para = Paragraph(
                act.priority,
                ParagraphStyle("PT", fontSize=7, textColor=p_fg, alignment=TA_CENTER, leading=9)
            )
            tag_cell = Table([[tag_para]], colWidths=[0.8*inch], rowHeights=[0.2*inch])
            tag_cell.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,-1), p_bg),
                ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0,0),(-1,-1), 2),
                ("BOTTOMPADDING", (0,0),(-1,-1), 2),
            ]))
            action_text = Paragraph(
                f"<b>{act.action}</b><br/><font size=8 color='#64748b'>{act.reason or ''}</font>",
                ParagraphStyle("AT", fontSize=9.5, textColor=C_DARK, leading=14)
            )
            row = Table([[tag_cell, action_text]], colWidths=[0.9*inch, W-0.9*inch])
            row.setStyle(TableStyle([
                ("VALIGN", (0,0),(-1,-1), "TOP"),
                ("TOPPADDING",    (0,0),(-1,-1), 6),
                ("BOTTOMPADDING", (0,0),(-1,-1), 6),
                ("LEFTPADDING",   (0,0),(0,-1),  0),
                ("LINEBELOW", (0,0),(-1,-1), 0.3, C_BORDER),
            ]))
            story.append(row)
    else:
        story.append(Paragraph("No specific automated actions are recommended for this incident.", ST["body"]))

    # ── EVIDENCE ───────────────────────────────────────────────────
    story += _section_header(f"Evidence — {len(alerts)} Alert Signal(s)", ST)
    accent = colors.HexColor("#6366f1")
    for i, a in enumerate(alerts, 1):
        ev_row = Table(
            [[Paragraph(f"{i}.", ParagraphStyle("EN", fontSize=8.5, textColor=C_MUTED, alignment=TA_RIGHT, leading=13)),
              Paragraph(a.evidence or "—", ParagraphStyle("EV", fontSize=8.5, textColor=colors.HexColor("#312e81"), leading=13))]],
            colWidths=[0.3*inch, W-0.3*inch]
        )
        ev_row.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,-1), colors.HexColor("#eef2ff")),
            ("VALIGN",  (0,0),(-1,-1), "TOP"),
            ("LEFTPADDING",   (1,0),(1,-1), 8),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("LINEAFTER", (0,0),(0,-1), 2, accent),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ]))
        story.append(ev_row)
        story.append(Spacer(1, 3))

    # ── FOOTER ─────────────────────────────────────────────────────
    story.append(Spacer(1, 18))
    story.append(_divider(C_BORDER, 0.5))
    story.append(Paragraph(
        f"Security Log Analyzer  ·  Confidential  ·  Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ST["footer"]
    ))

    doc.build(story)
    return buf.getvalue()


def _build_summary_pdf(incidents) -> bytes:
    buf = io.BytesIO()
    ST = _styles()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch,
    )
    W = letter[0] - 1.5*inch
    story = []
    total = len(incidents)
    counts = {l: sum(1 for i in incidents if i.risk_level == l) for l in ("Critical","High","Medium","Low")}

    # Banner
    hdr = Table([[
        Paragraph("<b>SECURITY SUMMARY REPORT</b><br/><font size=9 color='#94a3b8'>Organisation-wide Threat Landscape  ·  Open Incidents Only</font>",
                  ParagraphStyle("HH", fontSize=16, textColor=C_WHITE, leading=22)),
        Paragraph(f"<b>{datetime.utcnow().strftime('%Y-%m-%d')}</b><br/><font size=8>{datetime.utcnow().strftime('%H:%M UTC')}</font>",
                  ParagraphStyle("HR", fontSize=11, textColor=colors.HexColor("#94a3b8"), alignment=TA_RIGHT, leading=18)),
    ]], colWidths=[W*0.72, W*0.28])
    hdr.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), C_DARK),
        ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
        ("LEFTPADDING",(0,0),(0,-1), 18),
        ("RIGHTPADDING",(-1,0),(-1,-1), 18),
        ("TOPPADDING",(0,0),(-1,-1), 16),
        ("BOTTOMPADDING",(0,0),(-1,-1), 16),
        ("ROUNDEDCORNERS",[6]),
    ]))
    story.append(hdr)
    story.append(Spacer(1, 14))

    # KPI row
    kd = [[
        Paragraph(str(counts["Critical"]), ST["kpi_num"]),
        Paragraph(str(counts["High"]),     ST["kpi_num"]),
        Paragraph(str(counts["Medium"]),   ST["kpi_num"]),
        Paragraph(str(counts["Low"]),      ST["kpi_num"]),
        Paragraph(str(total),              ST["kpi_num"]),
    ],[
        Paragraph("Critical", ParagraphStyle("kl",fontSize=7.5,textColor=C_CRITICAL,alignment=TA_CENTER)),
        Paragraph("High",     ParagraphStyle("kl",fontSize=7.5,textColor=C_HIGH,alignment=TA_CENTER)),
        Paragraph("Medium",   ParagraphStyle("kl",fontSize=7.5,textColor=C_MEDIUM,alignment=TA_CENTER)),
        Paragraph("Low",      ParagraphStyle("kl",fontSize=7.5,textColor=C_LOW,alignment=TA_CENTER)),
        Paragraph("Total",    ST["kpi_lbl"]),
    ]]
    cw = W/5
    kt = Table(kd, colWidths=[cw]*5, rowHeights=[0.42*inch,0.22*inch])
    kt.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1), colors.HexColor("#f8fafc")),
        ("BOX",(0,0),(-1,-1),0.5,C_BORDER),
        ("INNERGRID",(0,0),(-1,-1),0.5,C_BORDER),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING",(0,0),(-1,-1),6),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("ROUNDEDCORNERS",[4]),
    ]))
    story.append(kt)
    story.append(Spacer(1, 18))

    # Table of incidents
    story += _section_header("All Active Incidents (sorted by risk score)", ST)

    hi = sorted(incidents, key=lambda x: x.score, reverse=True)
    rows = [[
        Paragraph("<b>ID</b>",    ParagraphStyle("th",fontSize=8,textColor=C_MUTED,leading=10)),
        Paragraph("<b>User</b>",  ParagraphStyle("th",fontSize=8,textColor=C_MUTED,leading=10)),
        Paragraph("<b>Risk</b>",  ParagraphStyle("th",fontSize=8,textColor=C_MUTED,leading=10)),
        Paragraph("<b>Score</b>", ParagraphStyle("th",fontSize=8,textColor=C_MUTED,leading=10)),
        Paragraph("<b>Rules Triggered</b>", ParagraphStyle("th",fontSize=8,textColor=C_MUTED,leading=10)),
        Paragraph("<b>Status</b>",ParagraphStyle("th",fontSize=8,textColor=C_MUTED,leading=10)),
    ]]
    for i in hi:
        _, fg = RISK_COLORS.get(i.risk_level, (C_MUTED, C_WHITE))
        rows.append([
            Paragraph(f"#{i.id}", ParagraphStyle("td",fontSize=8.5,textColor=C_MUTED,leading=12)),
            Paragraph(f"<b>{i.user}</b>", ParagraphStyle("td",fontSize=8.5,textColor=C_DARK,leading=12)),
            Paragraph(i.risk_level, ParagraphStyle("td",fontSize=8.5,textColor=fg,leading=12)),
            Paragraph(str(i.score), ParagraphStyle("td",fontSize=8.5,textColor=C_DARK,leading=12)),
            Paragraph(i.rules or "—", ParagraphStyle("td",fontSize=7.5,textColor=C_MID,leading=11)),
            Paragraph(i.status, ParagraphStyle("td",fontSize=8.5,textColor=C_MID,leading=12)),
        ])

    col_w = [0.45*inch, 1.3*inch, 0.75*inch, 0.55*inch, W-3.75*inch, 0.7*inch]
    tbl = Table(rows, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0), colors.HexColor("#f1f5f9")),
        ("LINEBELOW",(0,0),(-1,0), 1, C_BORDER),
        ("LINEBELOW",(0,1),(-1,-1), 0.3, C_BORDER),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1),4),
    ]))
    story.append(tbl)

    story.append(Spacer(1, 18))
    story.append(_divider(C_BORDER))
    story.append(Paragraph(
        f"Security Log Analyzer  ·  Confidential  ·  Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ST["footer"]
    ))
    doc.build(story)
    return buf.getvalue()


def convert_markdown_to_pdf(md_content: str, incident=None, alerts=None, actions=None, summary_incidents=None) -> bytes:
    """Route to the right builder. Falls back gracefully."""
    if incident is not None:
        return _build_incident_pdf(incident, alerts or [], actions or [])
    if summary_incidents is not None:
        return _build_summary_pdf(summary_incidents)
    # legacy plain-text fallback
    return _build_incident_pdf_from_md(md_content)


def _build_incident_pdf_from_md(md_content: str) -> bytes:
    """Last-resort plain builder from raw markdown string."""
    buf = io.BytesIO()
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    clean = md_content.replace("**", "")
    for para in clean.split("\n\n"):
        para = para.strip()
        if not para: continue
        if para.startswith("# "):
            story.append(Paragraph(para[2:], styles["Heading1"]))
        elif para.startswith("## "):
            story.append(Paragraph(para[3:], styles["Heading2"]))
        else:
            for line in para.split("\n"):
                line = line.strip()
                if line.startswith("- "):
                    story.append(Paragraph("• " + line[2:], styles["Normal"]))
                elif line:
                    story.append(Paragraph(line, styles["Normal"]))
        story.append(Spacer(1, 10))
    doc.build(story)
    return buf.getvalue()
