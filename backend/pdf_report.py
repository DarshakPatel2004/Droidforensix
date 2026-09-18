"""
DroidForensix PDF Report Generator

Produces a forensic analysis report covering:
- Sample metadata
- LLM severity assessment (Step 7)
- Obfuscation indicators
- C2 infrastructure
- Suspicious class/method analysis with LLM summaries
"""

import io
from datetime import datetime, timezone
from typing import Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether, CondPageBreak
)

# -- Colour palette -----------------------------------------------------------
C_DARK      = colors.HexColor('#0f172a')
C_MID       = colors.HexColor('#1e293b')
C_ACCENT    = colors.HexColor('#6366f1')
C_ROSE      = colors.HexColor('#f43f5e')
C_AMBER     = colors.HexColor('#f59e0b')
C_EMERALD   = colors.HexColor('#10b981')
C_CYAN      = colors.HexColor('#06b6d4')
C_MUTED     = colors.HexColor('#64748b')
C_LIGHT_BG  = colors.HexColor('#f8fafc')
C_BORDER    = colors.HexColor('#e2e8f0')
C_WHITE     = colors.white

SEVERITY_COLORS = {
    'critical': colors.HexColor('#ef4444'),
    'high':     colors.HexColor('#f97316'),
    'medium':   colors.HexColor('#eab308'),
    'low':      colors.HexColor('#22c55e'),
}

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm

# Sections the user may toggle on/off for the Quick PDF.
# Cover page and executive summary are always rendered; the rest is optional.
QUICK_PDF_DEFAULT_SECTIONS = {
    'metadata':           True,
    'llm_assessment':     True,
    'obfuscation':        True,
    'c2_infrastructure':  True,
    'suspicious_methods': True,
}

AVAILABLE_SECTIONS = list(QUICK_PDF_DEFAULT_SECTIONS.keys())


def _styles():
    def s(name, **kw):
        return ParagraphStyle(name, **kw)
    return {
        'title':      s('DFTitle',    fontName='Helvetica-Bold',   fontSize=22, textColor=C_DARK,   spaceAfter=4, leading=28),
        'subtitle':   s('DFSub',      fontName='Helvetica',        fontSize=11, textColor=C_MUTED,  spaceAfter=2),
        'h1':         s('DFH1',       fontName='Helvetica-Bold',   fontSize=14, textColor=C_DARK,   spaceBefore=14, spaceAfter=6),
        'h2':         s('DFH2',       fontName='Helvetica-Bold',   fontSize=11, textColor=C_ACCENT, spaceBefore=10, spaceAfter=4),
        'h3':         s('DFH3',       fontName='Helvetica-Bold',   fontSize=9,  textColor=C_MID,    spaceBefore=6,  spaceAfter=3),
        'body':       s('DFBody',     fontName='Helvetica',        fontSize=9,  textColor=C_DARK,   leading=14, spaceAfter=4),
        'mono':       s('DFMono',     fontName='Courier',          fontSize=8,  textColor=C_DARK,   leading=12, spaceAfter=2),
        'mono_small': s('DFMonoSm',   fontName='Courier',          fontSize=7,  textColor=C_MUTED,  leading=11),
        'muted':      s('DFMuted',    fontName='Helvetica',        fontSize=8,  textColor=C_MUTED,  leading=12),
        'label':      s('DFLabel',    fontName='Helvetica-Bold',   fontSize=8,  textColor=C_MUTED,  spaceAfter=2),
        'llm':        s('DFLLM',      fontName='Helvetica-Oblique',fontSize=9,  textColor=colors.HexColor('#334155'), leading=14, spaceAfter=3, leftIndent=8),
        'finding':    s('DFFinding',  fontName='Helvetica',        fontSize=9,  textColor=C_DARK,   leading=13, spaceAfter=2, leftIndent=12),
        'footer':     s('DFFooter',   fontName='Helvetica',        fontSize=7,  textColor=C_MUTED,  alignment=TA_CENTER),
    }


def _hr(story, color=C_BORDER, thickness=0.5, sb=4, sa=8):
    story.append(Spacer(1, sb))
    story.append(HRFlowable(width='100%', thickness=thickness, color=color))
    story.append(Spacer(1, sa))


def _safe(text, max_len=800):
    s = str(text or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return s[:max_len] + ('...' if len(s) > max_len else '')


def _kv_table(data, col_widths=None):
    usable = PAGE_W - 2 * MARGIN
    col_widths = col_widths or [usable * 0.32, usable * 0.68]
    kstyle = ParagraphStyle('kk', fontName='Helvetica-Bold', fontSize=8, textColor=C_MUTED)
    vstyle = ParagraphStyle('vv', fontName='Helvetica',      fontSize=9, textColor=C_DARK)
    rows = [[Paragraph(str(k), kstyle), Paragraph(_safe(v), vstyle)] for k, v in data]
    t = Table(rows, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [C_LIGHT_BG, C_WHITE]),
        ('GRID',           (0, 0), (-1, -1), 0.3, C_BORDER),
        ('VALIGN',         (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',     (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING',  (0, 0), (-1, -1), 4),
        ('LEFTPADDING',    (0, 0), (-1, -1), 6),
        ('RIGHTPADDING',   (0, 0), (-1, -1), 6),
    ]))
    return t


# -- Section builders ---------------------------------------------------------

def _section_cover(story, st, result, threat_data, sample_id):
    meta     = result.get('metadata', {})
    manifest = result.get('manifest', {})
    pkg      = meta.get('package_name') or meta.get('package') or 'Unknown Package'
    severity = result.get('llm_assessment', {}).get('severity', 'unknown')
    sev_col  = SEVERITY_COLORS.get(severity.lower(), C_MUTED)
    risk     = result.get('llm_assessment', {}).get('risk_score', 'N/A')
    generated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph('DroidForensix', ParagraphStyle('brand', fontName='Helvetica-Bold', fontSize=10, textColor=C_ACCENT)))
    story.append(Paragraph('Android Malware Analysis Report', st['title']))
    story.append(Paragraph(f'Package: {_safe(pkg)}', st['subtitle']))
    story.append(Spacer(1, 4))

    sev_table = Table(
        [[Paragraph(f'<b>Severity: {severity.upper()}</b>',
            ParagraphStyle('sev', fontName='Helvetica-Bold', fontSize=13, textColor=C_WHITE, alignment=TA_CENTER))]],
        colWidths=[PAGE_W - 2 * MARGIN]
    )
    sev_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), sev_col),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 6))
    story.append(_kv_table([
        ('Sample ID',       sample_id),
        ('Risk Score',      f'{risk} / 100'),
        ('Report Generated', generated),
    ]))
    _hr(story, sb=8)


def _section_metadata(story, st, result):
    story.append(Paragraph('1. Sample Metadata', st['h1']))
    meta       = result.get('metadata', {})
    manifest   = result.get('manifest', {})
    extraction = result.get('extraction', {})

    rows = [
        ('Package Name',       meta.get('package_name') or meta.get('package', 'N/A')),
        ('Sample Name',        meta.get('sample_name', 'N/A')),
        ('SHA-256',            meta.get('sha256') or result.get('sample_id', 'N/A')),
        ('MD5',                meta.get('md5', 'N/A')),
        ('File Size',          f"{meta.get('file_size_bytes', 0):,} bytes" if meta.get('file_size_bytes') else 'N/A'),
        ('Version',            f"{manifest.get('version_name', 'N/A')} (code {manifest.get('version_code', 'N/A')})"),
        ('Min SDK',            str(manifest.get('min_sdk_version', 'N/A'))),
        ('Target SDK',         str(manifest.get('target_sdk_version', 'N/A'))),
        ('Decompiled Classes', str(extraction.get('decompiled_classes', 'N/A'))),
    ]
    story.append(_kv_table(rows))

    # Declared permissions
    perms = manifest.get('uses_permissions', [])
    if perms:
        story.append(Spacer(1, 6))
        story.append(Paragraph('<b>Declared Permissions</b>', st['label']))
        for p in perms[:30]:
            story.append(Paragraph(f'- {_safe(p)}', st['mono_small']))

    _hr(story)


def _section_llm_assessment(story, st, result):
    story.append(Paragraph('2. LLM Threat Assessment', st['h1']))
    llm = result.get('llm_assessment', {})
    if not llm:
        story.append(Paragraph('LLM assessment not available for this sample.', st['muted']))
        _hr(story)
        return

    severity   = llm.get('severity', 'unknown')
    risk       = llm.get('risk_score', 'N/A')
    narrative  = llm.get('narrative', '')
    threat     = llm.get('primary_threat', 'N/A')
    conf       = llm.get('confidence', None)
    actions    = llm.get('recommended_actions', [])
    indicators = llm.get('threat_indicators', [])
    raw        = llm.get('raw_llm_output', '')

    story.append(_kv_table([
        ('Severity',       severity.upper()),
        ('Risk Score',     f'{risk} / 100'),
        ('Primary Threat', threat.replace('_', ' ').title() if threat else 'N/A'),
        ('Confidence',     f'{int(conf * 100)}%' if conf is not None else 'N/A'),
    ]))
    story.append(Spacer(1, 6))

    if narrative:
        story.append(Paragraph('<b>Threat Narrative</b>', st['label']))
        story.append(Paragraph(_safe(narrative, 2000), st['body']))
    elif raw:
        story.append(Paragraph('<b>LLM Output</b>', st['label']))
        story.append(Paragraph(_safe(raw, 1500), st['body']))

    if indicators:
        story.append(Spacer(1, 4))
        story.append(Paragraph('<b>Key Technical Indicators</b>', st['label']))
        for ind in indicators:
            story.append(Paragraph(f'- {_safe(ind)}', st['finding']))

    if actions:
        story.append(Spacer(1, 4))
        story.append(Paragraph('<b>Recommended Actions</b>', st['label']))
        for action in actions:
            story.append(Paragraph(f'- {_safe(action)}', st['finding']))

    _hr(story)


def _section_obfuscation(story, st, obfuscation):
    story.append(Paragraph('3. Obfuscation Analysis', st['h1']))
    if not obfuscation:
        story.append(Paragraph('Obfuscation data not available.', st['muted']))
        _hr(story)
        return

    score      = obfuscation.get('obfuscation_score', 0)
    level      = obfuscation.get('obfuscation_level', 'unknown')
    techniques = obfuscation.get('techniques', [])
    indicators = obfuscation.get('indicators', {})

    story.append(_kv_table([
        ('Obfuscation Score',  f'{score} ({level.upper()})'),
        ('Reflection Usages',  str(len(indicators.get('reflection', [])))),
        ('Dynamic Loading',    str(len(indicators.get('dynamic_loading', [])))),
        ('Crypto API Usages',  str(len(indicators.get('crypto_apis', [])))),
        ('Suspicious APIs',    str(len(indicators.get('suspicious_apis', [])))),
        ('Dangerous Perms',    str(len(indicators.get('dangerous_permissions', [])))),
    ]))

    if techniques:
        story.append(Spacer(1, 6))
        story.append(Paragraph('<b>Detected Techniques</b>', st['label']))
        for t in techniques[:15]:
            name  = t.get('name', t.get('key', ''))
            count = t.get('count', 0)
            story.append(Paragraph(f'- {_safe(name)}: {count} instance(s)', st['finding']))

    perms = indicators.get('dangerous_permissions', [])
    if perms:
        story.append(Spacer(1, 6))
        story.append(Paragraph('<b>Dangerous Permissions Detected</b>', st['label']))
        for p in perms[:20]:
            story.append(Paragraph(f'- {_safe(p)}', st['mono_small']))

    _hr(story)


def _section_c2(story, st, threat_data):
    story.append(Paragraph('4. C2 Infrastructure', st['h1']))
    c2s = threat_data.get('c2_infrastructure', [])
    if not c2s:
        story.append(Paragraph('No C2 indicators detected.', st['muted']))
        _hr(story)
        return

    story.append(Paragraph(f'{len(c2s)} indicator(s) identified.', st['body']))
    story.append(Spacer(1, 4))

    usable = PAGE_W - 2 * MARGIN
    th = ParagraphStyle('th', fontName='Helvetica-Bold', fontSize=8, textColor=C_WHITE)
    td = ParagraphStyle('td', fontName='Courier',        fontSize=7, textColor=C_DARK)
    ts = ParagraphStyle('ts', fontName='Helvetica',      fontSize=8, textColor=C_MUTED)

    rows = [[Paragraph(h, th) for h in ['Indicator', 'Protocol', 'Status', 'Classification']]]
    for c2 in c2s[:50]:
        indicator = c2.get('domain') or c2.get('ip') or 'unknown'
        port = c2.get('port', '')
        path = c2.get('path', '/')
        detail = f'{indicator}:{port}{path}' if port else f'{indicator}{path}'
        rows.append([
            Paragraph(_safe(detail, 60), td),
            Paragraph(_safe(c2.get('protocol', 'N/A')), ts),
            Paragraph(_safe(c2.get('status', 'N/A')), ts),
            Paragraph(_safe(c2.get('ip_classification', 'N/A')), ts),
        ])

    t = Table(rows, colWidths=[usable*0.45, usable*0.15, usable*0.18, usable*0.22])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  C_DARK),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_LIGHT_BG, C_WHITE]),
        ('GRID',          (0,0), (-1,-1), 0.3, C_BORDER),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING',    (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING',   (0,0), (-1,-1), 5),
        ('RIGHTPADDING',  (0,0), (-1,-1), 5),
    ]))
    story.append(t)
    _hr(story)


def _section_methods(story, st, annotated_methods):
    story.append(Paragraph('5. Suspicious Method Analysis', st['h1']))

    if not annotated_methods:
        story.append(Paragraph('No suspicious methods analysed.', st['muted']))
        _hr(story)
        return

    # Separate high-value from benign
    high_value = [m for m in annotated_methods if m.get('llm', {}).get('threat_type', 'unknown') not in ('benign',)]
    benign     = [m for m in annotated_methods if m.get('llm', {}).get('threat_type', 'unknown') == 'benign']

    story.append(Paragraph(
        f'{len(annotated_methods)} method(s) analysed. '
        f'{len(high_value)} flagged as suspicious, {len(benign)} assessed as benign.',
        st['body']
    ))

    if high_value:
        story.append(Spacer(1, 4))
        story.append(Paragraph('5.1 Suspicious Methods', st['h2']))
        _render_method_list(story, st, high_value)

    if benign:
        story.append(Spacer(1, 4))
        story.append(Paragraph('5.2 Benign Methods (for completeness)', st['h2']))
        story.append(Paragraph(
            'The following methods were flagged by keyword matching but assessed as benign by LLM analysis.',
            st['muted']
        ))
        _render_method_list(story, st, benign, compact=True)

    _hr(story)


def _render_method_list(story, st, methods, compact=False):
    for entry in methods:
        class_name  = entry.get('class_name', 'Unknown')
        method_name = entry.get('method_name', 'Unknown')
        llm         = entry.get('llm', {})
        line_anns   = entry.get('line_annotations', {})
        flags       = entry.get('flags', [])

        summary     = llm.get('summary', '')
        threat_type = llm.get('threat_type', 'unknown')
        confidence  = llm.get('confidence', None)

        block = []
        block.append(Paragraph(
            f'<b>{_safe(class_name)}</b>  <font face="Courier">{_safe(method_name)}</font>',
            st['h3']
        ))

        meta_parts = []
        if flags:
            meta_parts.append(f'Flags: {", ".join(flags[:6])}')
        if threat_type and threat_type != 'unknown':
            meta_parts.append(f'Type: {threat_type.replace("_", " ").title()}')
        if confidence is not None:
            meta_parts.append(f'Confidence: {int(confidence * 100)}%')
        if meta_parts:
            block.append(Paragraph(' | '.join(meta_parts), st['muted']))

        if summary:
            block.append(Paragraph(_safe(summary, 1500), st['llm']))

        # Line annotations — deduplicate by label, cap at 8 unique
        if line_anns and not compact:
            seen_labels = set()
            unique_anns = []
            for line_idx, ann in sorted(line_anns.items(), key=lambda x: int(x[0])):
                label = ann.get('label', '')
                key = (ann.get('type', ''), label)
                if key not in seen_labels:
                    seen_labels.add(key)
                    unique_anns.append((line_idx, ann))
                if len(unique_anns) >= 8:
                    break

            if unique_anns:
                block.append(Paragraph('<b>Pattern Annotations</b>', st['label']))
                for line_idx, ann in unique_anns:
                    block.append(Paragraph(
                        f'Line {int(line_idx) + 1}: {_safe(ann.get("label", ""))}',
                        st['finding']
                    ))

        block.append(Spacer(1, 5))
        story.append(KeepTogether(block))


def _section_footer_note(story, st, mode):
    story.append(Paragraph(
        f'Report generated by DroidForensix  |  '
        f'{"Quick export (top 30 methods)" if mode == "quick" else "Full export (all suspicious methods)"}  |  '
        f'{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}',
        st['footer']
    ))


# -- Public entry point -------------------------------------------------------

def generate_report(
    sample_id: str,
    sample_result: dict,
    threat_data: dict,
    obfuscation: dict,
    annotated_methods: list,
    mode: str = 'quick',
    selected_sections: Optional[dict] = None,
) -> bytes:
    # Quick mode lets the caller pick which sections to include. Full mode
    # always renders everything (forensic record completeness rule).
    if mode == 'full':
        sections = {k: True for k in QUICK_PDF_DEFAULT_SECTIONS}
    else:
        sections = {**QUICK_PDF_DEFAULT_SECTIONS}
        if selected_sections:
            # Only accept keys we know about; ignore anything else.
            sections.update({
                k: bool(v) for k, v in selected_sections.items()
                if k in QUICK_PDF_DEFAULT_SECTIONS
            })

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=MARGIN,
        title=f'DroidForensix Report - {sample_id[:16]}',
        author='DroidForensix',
        subject='Android Malware Analysis Report',
    )

    st = _styles()
    story = []

    # Cover page always renders (forensic identity / chain-of-custody header).
    _section_cover(story, st, sample_result, threat_data, sample_id)

    if sections.get('metadata'):
        _section_metadata(story, st, sample_result)
    if sections.get('llm_assessment'):
        _section_llm_assessment(story, st, sample_result)
    if sections.get('obfuscation'):
        _section_obfuscation(story, st, obfuscation)
    if sections.get('c2_infrastructure'):
        _section_c2(story, st, threat_data)
    # Only insert PageBreak if there are methods to show
    if annotated_methods and sections.get('suspicious_methods'):
        story.append(CondPageBreak(80 * mm))
        _section_methods(story, st, annotated_methods)
    _section_footer_note(story, st, mode)

    doc.build(story)
    return buf.getvalue()