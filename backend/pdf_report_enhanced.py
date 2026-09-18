"""
Enhanced PDF Report Generation for DroidForensix

Generates Quick (customizable) and Full forensic reports with threat intelligence.
Includes export timing and progress tracking.

Usage:
    generator = DroidForensixPDFGenerator(enable_ti=True)
    timer, pdf_bytes = generator.generate_quick_pdf(
        sample_id="abc123", sample_result=result,
        threat_data=threat_data, obfuscation=obfuscation_data,
        annotated_methods=methods,
        selected_sections={"metadata": True, "c2_infrastructure": True}
    )
    timer, pdf_bytes = generator.generate_full_pdf(
        sample_id="abc123", sample_result=result,
        threat_data=threat_data, obfuscation=obfuscation_data,
        annotated_methods=methods,
    )
"""

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List, Any, Tuple
from io import BytesIO
import logging

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
    PageBreak, Image, KeepTogether, PageTemplate, Frame,
    HRFlowable, CondPageBreak,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY

from backend import threat_intel as ti
from backend.config import settings
from backend.threat_intelligence import ThreatIntelligenceEnricher, TIResult

logger = logging.getLogger(__name__)

# -- Colour palette -----------------------------------------------------------
C_DARK      = colors.HexColor("#0f172a")
C_MID       = colors.HexColor("#1e293b")
C_ACCENT    = colors.HexColor("#6366f1")
C_ROSE      = colors.HexColor("#f43f5e")
C_AMBER     = colors.HexColor("#f59e0b")
C_EMERALD   = colors.HexColor("#10b981")
C_CYAN      = colors.HexColor("#06b6d4")
C_MUTED     = colors.HexColor("#64748b")
C_LIGHT_BG  = colors.HexColor("#f8fafc")
C_BORDER    = colors.HexColor("#e2e8f0")
C_WHITE     = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#ef4444"),
    "high":     colors.HexColor("#f97316"),
    "medium":   colors.HexColor("#eab308"),
    "low":      colors.HexColor("#22c55e"),
}

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


@dataclass
class ExportTimer:
    """Track export timing across phases."""
    start_time: float
    phase_times: Dict[str, float]

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def total_seconds(self) -> float:
        return self.elapsed

    def as_timedelta(self) -> timedelta:
        return timedelta(seconds=self.elapsed)

    def mark_phase(self, phase_name: str) -> None:
        self.phase_times[phase_name] = time.time() - self.start_time

    def get_phase_duration(self, phase_name: str) -> float:
        return self.phase_times.get(phase_name, 0.0)

    def summary(self) -> str:
        lines = [f"Export completed in {self.total_seconds:.2f}s"]
        for phase, elapsed in sorted(self.phase_times.items()):
            pct = (elapsed / self.total_seconds) * 100
            lines.append(f"  {phase}: {elapsed:.2f}s ({pct:.1f}%)")
        return "\n".join(lines)


class DroidForensixPDFGenerator:
    """Generate forensic reports with optional threat intelligence."""

    QUICK_PDF_DEFAULTS = {
        "metadata": True,
        "llm_assessment": True,
        "threat_intelligence": True,
        "obfuscation": True,
        "c2_infrastructure": True,
        "suspicious_methods": True,
        "benign_methods": False,
    }

    FULL_PDF_SECTIONS = {
        "metadata": True,
        "llm_assessment": True,
        "threat_intelligence": True,
        "obfuscation": True,
        "c2_infrastructure": True,
        "suspicious_methods": True,
        "benign_methods": True,
        "stix_export": True,
    }

    def __init__(
        self,
        enable_ti: bool = True,
        vt_key: Optional[str] = None,
        otx_key: Optional[str] = None,
        shodan_key: Optional[str] = None,
        censys_token: Optional[str] = None,
        censys_org_id: Optional[str] = None,
    ):
        self.enable_ti = enable_ti
        self.styles = self._setup_styles()

        self.ti_enricher: Optional[ThreatIntelligenceEnricher] = None
        if enable_ti and any([vt_key, otx_key, shodan_key, censys_token]):
            self.ti_enricher = ThreatIntelligenceEnricher(
                vt_key=vt_key,
                otx_key=otx_key,
                shodan_key=shodan_key,
                censys_token=censys_token,
                censys_org_id=censys_org_id,
            )

    def generate_quick_pdf(
        self,
        sample_id: str,
        sample_result: Dict[str, Any],
        threat_data: Dict[str, Any],
        obfuscation: Dict[str, Any],
        annotated_methods: List[Dict[str, Any]],
        selected_sections: Optional[Dict[str, bool]] = None,
    ) -> Tuple[ExportTimer, bytes]:
        timer = ExportTimer(start_time=time.time(), phase_times={})
        sections = {**self.QUICK_PDF_DEFAULTS}
        if selected_sections:
            sections.update(selected_sections)
        logger.info(f"Generating Quick PDF with sections: {sections}")

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=letter,
            rightMargin=0.5 * inch, leftMargin=0.5 * inch,
            topMargin=0.5 * inch, bottomMargin=0.5 * inch,
        )
        story = []

        self._build_title_section(story, sample_result, sample_id)
        timer.mark_phase("title")

        self._build_executive_summary(story, sample_result, obfuscation, threat_data, annotated_methods)
        timer.mark_phase("executive_summary")

        if sections.get("metadata"):
            self._build_metadata_section(story, sample_result, obfuscation)
            timer.mark_phase("metadata")

        if sections.get("threat_intelligence") and self.enable_ti and threat_data:
            self._build_ti_section(story, threat_data, sample_id)
            timer.mark_phase("threat_intelligence")

        if sections.get("llm_assessment"):
            self._build_llm_section(story, sample_result)
            timer.mark_phase("llm_assessment")

        self._build_risk_methodology_section(story, sample_result, obfuscation, threat_data)
        timer.mark_phase("risk_methodology")

        if sections.get("obfuscation"):
            self._build_obfuscation_section(story, obfuscation)
            timer.mark_phase("obfuscation")

        if sections.get("c2_infrastructure"):
            self._build_c2_section(story, threat_data)
            timer.mark_phase("c2_infrastructure")

        if sections.get("suspicious_methods"):
            self._build_suspicious_methods_section(
                story, annotated_methods, limit=10
            )
            timer.mark_phase("suspicious_methods")

        self._build_limitations_section(story)
        timer.mark_phase("limitations")

        timer.mark_phase("layout_start")
        doc.build(story)
        timer.mark_phase("pdf_render")

        pdf_bytes = buffer.getvalue()
        logger.info(
            f"Quick PDF generated: {len(pdf_bytes)} bytes in {timer.total_seconds:.2f}s"
        )
        logger.info(timer.summary())
        return timer, pdf_bytes

    def generate_full_pdf(
        self,
        sample_id: str,
        sample_result: Dict[str, Any],
        threat_data: Dict[str, Any],
        obfuscation: Dict[str, Any],
        annotated_methods: List[Dict[str, Any]],
    ) -> Tuple[ExportTimer, bytes]:
        timer = ExportTimer(start_time=time.time(), phase_times={})
        logger.info("Generating Full PDF")

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=letter,
            rightMargin=0.5 * inch, leftMargin=0.5 * inch,
            topMargin=0.5 * inch, bottomMargin=0.5 * inch,
        )
        story = []

        self._build_title_section(story, sample_result, sample_id)
        timer.mark_phase("title")

        self._build_executive_summary(story, sample_result, obfuscation, threat_data, annotated_methods)
        timer.mark_phase("executive_summary")

        self._build_metadata_section(story, sample_result, obfuscation)
        timer.mark_phase("metadata")

        if self.enable_ti and threat_data:
            self._build_ti_section(story, threat_data, sample_id)
            timer.mark_phase("threat_intelligence")

        self._build_llm_section(story, sample_result)
        timer.mark_phase("llm_assessment")

        self._build_risk_methodology_section(story, sample_result, obfuscation, threat_data)
        timer.mark_phase("risk_methodology")

        self._build_obfuscation_section(story, obfuscation)
        timer.mark_phase("obfuscation")

        self._build_c2_section(story, threat_data)
        timer.mark_phase("c2_infrastructure")

        self._build_suspicious_methods_section(story, annotated_methods)
        timer.mark_phase("suspicious_methods")

        self._build_benign_methods_section(story, annotated_methods)
        timer.mark_phase("benign_methods")

        self._build_limitations_section(story)
        timer.mark_phase("limitations")

        self._build_stix_section(story, threat_data, sample_id)
        timer.mark_phase("stix_export")

        timer.mark_phase("layout_start")
        doc.build(story)
        timer.mark_phase("pdf_render")

        pdf_bytes = buffer.getvalue()
        logger.info(
            f"Full PDF generated: {len(pdf_bytes)} bytes in {timer.total_seconds:.2f}s"
        )
        logger.info(timer.summary())
        return timer, pdf_bytes
    # ============ Section Builders ============

    def _hr(self, story, color=C_BORDER, thickness=0.5, sb=4, sa=8):
        story.append(Spacer(1, sb))
        story.append(HRFlowable(width="100%", thickness=thickness, color=color))
        story.append(Spacer(1, sa))

    def _safe(self, text, max_len=800):
        s = str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return s[:max_len] + ("..." if len(s) > max_len else "")

    def _kv_table(self, data, col_widths=None):
        usable = PAGE_W - 2 * MARGIN
        col_widths = col_widths or [usable * 0.32, usable * 0.68]
        kstyle = ParagraphStyle("kk", fontName="Helvetica-Bold", fontSize=8, textColor=C_MUTED)
        vstyle = ParagraphStyle("vv", fontName="Helvetica", fontSize=9, textColor=C_DARK)
        rows = [[Paragraph(str(k), kstyle), Paragraph(self._safe(v), vstyle)] for k, v in data]
        t = Table(rows, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_LIGHT_BG, C_WHITE]),
            ("GRID",           (0, 0), (-1, -1), 0.3, C_BORDER),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",     (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
            ("LEFTPADDING",    (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        return t

    def _build_title_section(self, story, result, sample_id):
        meta = result.get("metadata", {})
        manifest = result.get("manifest", {})
        pkg = meta.get("package_name") or meta.get("package") or "Unknown Package"
        severity = result.get("llm_assessment", {}).get("severity", "unknown")
        sev_col = SEVERITY_COLORS.get(severity.lower(), C_MUTED)
        risk = result.get("llm_assessment", {}).get("risk_score", "N/A")
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        story.append(Spacer(1, 10 * mm))
        story.append(Paragraph("DroidForensix", ParagraphStyle(
            "brand", fontName="Helvetica-Bold", fontSize=10, textColor=C_ACCENT
        )))
        story.append(Paragraph("Android Malware Analysis Report", self.styles["DFTitle"]))
        story.append(Paragraph("Package: " + self._safe(pkg), self.styles["DFSub"]))
        story.append(Spacer(1, 4))

        sev_table = Table(
            [[Paragraph("<b>Severity: " + severity.upper() + "</b>",
                ParagraphStyle("sev", fontName="Helvetica-Bold", fontSize=13,
                               textColor=C_WHITE, alignment=TA_CENTER))]],
            colWidths=[PAGE_W - 2 * MARGIN]
        )
        sev_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), sev_col),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 6))
        story.append(self._kv_table([
            ("Sample ID",       sample_id),
            ("Risk Score",      f"{risk} / 100"),
            ("Report Generated", generated),
        ]))
        self._hr(story, sb=8)

    def _build_executive_summary(self, story, result, obfuscation, threat_data, annotated_methods):
        story.append(Paragraph("Executive Summary", self.styles["DFH1"]))
        llm = result.get("llm_assessment", {})
        severity = llm.get("severity", "unknown")
        risk_score = llm.get("risk_score", 0)
        primary_threat = llm.get("primary_threat", "unknown")
        confidence = llm.get("confidence")
        narrative = llm.get("narrative", "")

        # Obfuscation summary
        obf_score = obfuscation.get("obfuscation_score", 0)
        obf_level = obfuscation.get("obfuscation_level", "unknown")
        techniques = obfuscation.get("techniques", [])
        total_techniques = sum(t.get("count", 0) for t in techniques)

        # C2 summary
        c2s = threat_data.get("c2s", []) if threat_data else []
        if not c2s:
            c2s = threat_data.get("c2_infrastructure", []) if threat_data else []
        c2_count = len(c2s)

        # Method summary
        high_conf = [m for m in annotated_methods if (m.get("llm", {}).get("confidence") or 0) >= 0.85]
        flagged = [m for m in annotated_methods if m.get("llm", {}).get("threat_type", "unknown") != "benign"]

        # Risk level badge
        risk_level = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW"
        risk_color = SEVERITY_COLORS.get(severity.lower(), C_MUTED)

        summary_rows = [
            ("Risk Level", risk_level),
            ("Risk Score", f"{risk_score} / 100"),
            ("Primary Threat", primary_threat.replace("_", " ").title() if primary_threat else "N/A"),
            ("Confidence", f"{int(confidence * 100)}%" if confidence is not None else "N/A"),
            ("Obfuscation", f"{obf_level.upper()} ({obf_score}/100, {total_techniques} indicators)"),
            ("C2 Indicators", str(c2_count) if c2_count > 0 else "None detected"),
            ("Suspicious Methods", f"{len(flagged)} flagged, {len(high_conf)} high-confidence"),
        ]
        story.append(self._kv_table(summary_rows))

        # Key actions (mix of static template + LLM-generated)
        story.append(Spacer(1, 6))
        story.append(Paragraph("<b>Recommended Actions</b>", self.styles["DFLabel"]))

        # Static template actions based on severity
        static_actions = {
            "critical": [
                "ISOLATE device immediately from all networks",
                "DO NOT reinstall or restore from backup without full sanitization",
                "Preserve device image for forensic investigation",
            ],
            "high": [
                "Disconnect from network and remove the application",
                "Monitor financial accounts for unauthorized activity",
                "Change all passwords stored or entered on this device",
            ],
            "medium": [
                "Review application permissions and remove if unnecessary",
                "Monitor network traffic for suspicious outbound connections",
                "Update device and all applications to latest versions",
            ],
            "low": [
                "Continue monitoring for behavioral changes",
                "Review app permissions periodically",
            ],
        }
        actions = static_actions.get(severity.lower(), static_actions["medium"])

        # Add LLM-generated specific actions if available
        llm_actions = llm.get("recommended_actions", [])
        if llm_actions:
            actions.extend(llm_actions[:3])

        for action in actions:
            story.append(Paragraph("- " + self._safe(action), self.styles["DFFinding"]))

        self._hr(story)

    def _build_metadata_section(self, story, result, obfuscation=None):
        story.append(Paragraph("1. Sample Metadata", self.styles["DFH1"]))
        meta = result.get("metadata", {})
        manifest = result.get("manifest", {})
        extraction = result.get("extraction", {})

        # Prefer total_classes from obfuscation view (Androguard DEX count) for consistency
        obf_total_classes = (obfuscation or {}).get("total_classes", 0)
        decompiled_classes = obf_total_classes or extraction.get("decompiled_classes", "N/A")

        rows = [
            ("Package Name", meta.get("package_name") or meta.get("package", "N/A")),
            ("Sample Name", meta.get("sample_name", "N/A")),
            ("SHA-256", meta.get("sha256") or "N/A"),
            ("MD5", meta.get("md5", "N/A")),
            ("File Size", f"{meta.get('file_size_bytes', 0):,} bytes" if meta.get('file_size_bytes') else "N/A"),
            ("Version", f"{manifest.get('version_name', 'N/A')} (code {manifest.get('version_code', 'N/A')})"),
            ("Min SDK", str(manifest.get("min_sdk_version", "N/A"))),
            ("Target SDK", str(manifest.get("target_sdk_version", "N/A"))),
            ("Decompiled Classes", str(decompiled_classes)),
            ("Sample Source", meta.get("source", "Unknown")),
        ]
        story.append(self._kv_table(rows))

        perms = manifest.get("uses_permissions", [])
        if perms:
            story.append(Spacer(1, 6))
            story.append(Paragraph("<b>Declared Permissions</b>", self.styles["DFLabel"]))
            for p in perms[:30]:
                story.append(Paragraph("- " + self._safe(p), self.styles["DFMonoSm"]))
        self._hr(story)

    def _build_ti_section(self, story, threat_data, sample_id):
        story.append(Paragraph("2. Threat Intelligence Summary", self.styles["DFH1"]))
        story.append(Spacer(1, 0.1 * inch))

        c2s = threat_data.get("c2s", [])
        dns = threat_data.get("dns", {})
        classification = threat_data.get("classification", {})

        domains = sorted(set(c2.get("domain") for c2 in c2s if c2.get("domain")))
        ips = sorted(set(c2.get("ip") for c2 in c2s if c2.get("ip")))

        story.append(self._kv_table([
            ("Total C2 Indicators", str(threat_data.get("totals", {}).get("c2s", len(c2s)))),
            ("Domains", str(len(domains))),
            ("IPs", str(len(ips))),
            ("DNS Active", str(dns.get("active", 0))),
            ("DNS Dead", str(dns.get("dead", 0))),
            ("Benign", str(classification.get("benign", 0))),
            ("Suspicious", str(classification.get("suspicious", 0))),
            ("Malicious", str(classification.get("malicious", 0))),
        ]))

        if domains:
            story.append(Spacer(1, 6))
            story.append(Paragraph("<b>Command & Control Domains:</b>", self.styles["DFLabel"]))
            for domain in domains[:10]:
                story.append(Paragraph("- " + self._safe(domain), self.styles["DFFinding"]))
                if self.ti_enricher:
                    try:
                        ti_result = self.ti_enricher.enrich(domain, "domain")
                        for ev in ti_result.evidence[:2]:
                            story.append(Paragraph(
                                "    -> " + self._safe(ev),
                                self.styles["DFMuted"]
                            ))
                    except Exception as e:
                        logger.debug("Failed to enrich domain %s: %s", domain, e)

        if ips:
            story.append(Spacer(1, 6))
            story.append(Paragraph("<b>Command & Control IPs:</b>", self.styles["DFLabel"]))
            for ip_entry in ips[:10]:
                story.append(Paragraph("- " + self._safe(ip_entry), self.styles["DFFinding"]))
                if self.ti_enricher:
                    try:
                        ti_result = self.ti_enricher.enrich(ip_entry, "ip")
                        for ev in ti_result.evidence[:2]:
                            story.append(Paragraph(
                                "    -> " + self._safe(ev),
                                self.styles["DFMuted"]
                            ))
                    except Exception as e:
                        logger.debug("Failed to enrich IP %s: %s", ip_entry, e)

        geolocated = threat_data.get("ips_geolocated", [])
        if geolocated:
            story.append(Spacer(1, 6))
            story.append(Paragraph("<b>IP Geolocation:</b>", self.styles["DFLabel"]))
            for geo in geolocated[:10]:
                parts = [v for v in [geo.get("city"), geo.get("region"), geo.get("country")] if v]
                loc = ", ".join(parts) or "Unknown"
                story.append(Paragraph(
                    "- " + self._safe(geo.get("ip", "")) + " (" + self._safe(loc) + ")",
                    self.styles["DFFinding"]
                ))
        story.append(PageBreak())

    def _build_llm_section(self, story, result):
        story.append(Paragraph("LLM Threat Assessment", self.styles["DFH1"]))
        story.append(Spacer(1, 0.1 * inch))

        llm = result.get("llm_assessment", {})
        if not llm:
            story.append(Paragraph("LLM assessment not available.", self.styles["DFMuted"]))
            self._hr(story)
            return

        severity = llm.get("severity", "unknown")
        risk = llm.get("risk_score", "N/A")
        narrative = llm.get("narrative", "")
        threat = llm.get("primary_threat", "N/A")
        conf = llm.get("confidence", None)
        actions = llm.get("recommended_actions", [])
        indicators = llm.get("threat_indicators", [])

        story.append(self._kv_table([
            ("Severity", severity.upper()),
            ("Risk Score", f"{risk} / 100"),
            ("Primary Threat", threat.replace("_", " ").title() if threat else "N/A"),
            ("Confidence", f"{int(conf * 100)}%" if conf is not None else "N/A"),
        ]))
        story.append(Spacer(1, 6))

        if narrative:
            story.append(Paragraph("<b>Threat Narrative</b>", self.styles["DFLabel"]))
            story.append(Paragraph(self._safe(narrative, 2000), self.styles["DFBody"]))

        if indicators:
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Key Technical Indicators</b>", self.styles["DFLabel"]))
            for ind in indicators:
                story.append(Paragraph("- " + self._safe(ind), self.styles["DFFinding"]))

        if actions:
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Recommended Actions</b>", self.styles["DFLabel"]))
            for action in actions:
                story.append(Paragraph("- " + self._safe(action), self.styles["DFFinding"]))
        self._hr(story)

    def _build_risk_methodology_section(self, story, result, obfuscation, threat_data):
        story.append(Paragraph("Risk Score Methodology", self.styles["DFH1"]))
        story.append(Paragraph(
            "The risk score (0-100) is computed through a three-layer process:",
            self.styles["DFBody"]
        ))

        # Layer 1: LLM Assessment
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Layer 1: LLM Threat Assessment</b>", self.styles["DFLabel"]))
        story.append(Paragraph(
            "An LLM analyzes threat chains, C2 indicators, obfuscation data, and permission patterns "
            "to assign an initial risk score and severity level. The model uses these alignment guidelines:",
            self.styles["DFBody"]
        ))
        layer1_data = [
            ("Severity", "Risk Score Range", "Criteria"),
            ("Critical", "80-100", "Active C2 + payload delivery + evasion techniques"),
            ("High", "60-79", "C2 present or significant obfuscation + dangerous permissions"),
            ("Medium", "30-59", "Suspicious patterns without confirmed C2"),
            ("Low", "0-29", "Minimal risk indicators"),
        ]
        story.append(self._kv_table(layer1_data))

        # Layer 2: Sanity Check
        story.append(Spacer(1, 6))
        story.append(Paragraph("<b>Layer 2: Cross-Validation Sanity Check</b>", self.styles["DFLabel"]))
        story.append(Paragraph(
            "Automated rules correct LLM misclassifications by cross-referencing detected indicators:",
            self.styles["DFBody"]
        ))
        sanity_rules = [
            "C2 present but severity low -> elevate to medium (risk >= 35)",
            "No C2 but severity critical -> lower to medium (risk <= 55)",
            "No chains, no C2, but obfuscation >= 50 -> elevate to medium (risk >= 50)",
            "Obfuscation >= 70 with medium severity -> elevate to high (risk >= 65)",
            "Narrative claims C2 but none extracted -> add correction note",
        ]
        for rule in sanity_rules:
            story.append(Paragraph("- " + rule, self.styles["DFFinding"]))

        # Layer 3: Post-Processing
        story.append(Spacer(1, 6))
        story.append(Paragraph("<b>Layer 3: Pattern-Based Corrections</b>", self.styles["DFLabel"]))
        story.append(Paragraph(
            "Known malware patterns and benign false-positive corrections are applied:",
            self.styles["DFBody"]
        ))
        post_rules = [
            "Metasploit stager: small APK (< 100KB) + reflection >= 3 + dynamic_loading >= 1 -> force high (risk >= 85)",
            "Known benign package (e.g., calculator apps) -> force low (risk <= 25)",
        ]
        for rule in post_rules:
            story.append(Paragraph("- " + rule, self.styles["DFFinding"]))

        # Obfuscation Score Breakdown
        obf_score = obfuscation.get("obfuscation_score", 0)
        techniques = obfuscation.get("techniques", [])
        tech_counts = {}
        for t in techniques:
            tech_counts[t.get("key", "")] = t.get("count", 0)

        story.append(Spacer(1, 6))
        story.append(Paragraph("<b>Obfuscation Score Factors</b>", self.styles["DFLabel"]))
        obf_factors = [
            ("Factor", "Weight", "Cap", "This Sample"),
            ("Reflection usages", "x2 each", "20 pts", str(tech_counts.get("reflection", 0))),
            ("Dynamic loading", "x5 each", "20 pts", str(tech_counts.get("dynamic_loading", 0))),
            ("Native loading", "x3 each", "10 pts", str(tech_counts.get("native_loading", 0))),
            ("Crypto APIs", "x1.5 each", "15 pts", str(tech_counts.get("crypto_apis", 0))),
            ("Suspicious APIs", "x1.5 each", "15 pts", str(tech_counts.get("suspicious_apis", 0))),
            ("Dangerous permissions", "x2 each", "10 pts", str(tech_counts.get("dangerous_permissions", 0))),
            ("DEX packing bonus", "+15", "15 pts", "Yes" if any(d.get("likely_packed") for d in obfuscation.get("dex_entropy", [])) else "No"),
        ]
        story.append(self._kv_table(obf_factors))

        self._hr(story)

    def _build_obfuscation_section(self, story, obfuscation):
        story.append(Paragraph("Obfuscation Analysis", self.styles["DFH1"]))
        if not obfuscation:
            story.append(Paragraph("Obfuscation data not available.", self.styles["DFMuted"]))
            self._hr(story)
            return

        score = obfuscation.get("obfuscation_score", 0)
        level = obfuscation.get("obfuscation_level", "unknown")
        techniques = obfuscation.get("techniques", [])

        # Derive header counts from techniques list (consistent with view output)
        tech_counts = {}
        for t in techniques:
            key = t.get("key", "")
            tech_counts[key] = t.get("count", 0)

        story.append(self._kv_table([
            ("Obfuscation Score", f"{score} ({level.upper()})"),
            ("Reflection Usages", str(tech_counts.get("reflection", 0))),
            ("Dynamic Loading", str(tech_counts.get("dynamic_loading", 0))),
            ("Crypto API Usages", str(tech_counts.get("crypto_apis", 0))),
            ("Suspicious APIs", str(tech_counts.get("suspicious_apis", 0))),
            ("Dangerous Perms", str(tech_counts.get("dangerous_permissions", 0))),
        ]))

        if techniques:
            story.append(Spacer(1, 6))
            story.append(Paragraph("<b>Detected Techniques</b>", self.styles["DFLabel"]))
            for t in techniques[:15]:
                name = t.get("name", t.get("key", ""))
                count = t.get("count", 0)
                story.append(Paragraph(
                    "- " + self._safe(name) + ": " + str(count) + " instance(s)",
                    self.styles["DFFinding"]
                ))

        perms = indicators.get("dangerous_permissions", [])
        if perms:
            story.append(Spacer(1, 6))
            story.append(Paragraph("<b>Dangerous Permissions Detected</b>", self.styles["DFLabel"]))
            for p in perms[:20]:
                story.append(Paragraph("- " + self._safe(p), self.styles["DFMonoSm"]))
        self._hr(story)

    def _build_c2_section(self, story, threat_data):
        story.append(Paragraph("C2 Infrastructure", self.styles["DFH1"]))
        c2s = threat_data.get("c2s", []) if threat_data else []
        if not c2s:
            c2s = threat_data.get("c2_infrastructure", []) if threat_data else []
        if not c2s:
            story.append(Paragraph("No C2 indicators detected.", self.styles["DFMuted"]))
            self._hr(story)
            return

        story.append(Paragraph(f"{len(c2s)} indicator(s) identified.", self.styles["DFBody"]))
        story.append(Spacer(1, 4))

        usable = PAGE_W - 2 * MARGIN
        th = ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=8, textColor=C_WHITE)
        td = ParagraphStyle("td", fontName="Courier", fontSize=7, textColor=C_DARK)
        ts = ParagraphStyle("ts", fontName="Helvetica", fontSize=8, textColor=C_MUTED)

        rows = [[Paragraph(h, th) for h in ["Indicator", "Protocol", "Status", "Classification"]]]
        for c2 in c2s[:50]:
            indicator = c2.get("domain") or c2.get("ip") or "unknown"
            port = c2.get("port", "")
            path = c2.get("path", "/")
            detail = f"{indicator}:{port}{path}" if port else f"{indicator}{path}"
            rows.append([
                Paragraph(self._safe(detail, 60), td),
                Paragraph(self._safe(c2.get("protocol", "N/A")), ts),
                Paragraph(self._safe(c2.get("status", "N/A")), ts),
                Paragraph(self._safe(c2.get("ip_classification", "N/A")), ts),
            ])

        t = Table(rows, colWidths=[usable*0.45, usable*0.15, usable*0.18, usable*0.22])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT_BG, C_WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ]))
        story.append(t)
        self._hr(story)

    def _build_suspicious_methods_section(self, story, annotated_methods, limit=None):
        story.append(Paragraph("Suspicious Methods Analysis", self.styles["DFH1"]))
        if not annotated_methods:
            story.append(Paragraph("No suspicious methods analysed.", self.styles["DFMuted"]))
            self._hr(story)
            return

        # Confidence band legend
        story.append(Paragraph("<b>Confidence Bands:</b>", self.styles["DFLabel"]))
        band_data = [
            ("Band", "Range", "Description"),
            ("High", ">= 85%", "Strong indicators of malicious behavior"),
            ("Medium", "70-84%", "Suspicious patterns, may need further analysis"),
            ("Low", "< 70%", "Weak indicators, possibly benign context"),
        ]
        story.append(self._kv_table(band_data))
        story.append(Spacer(1, 4))

        high_conf = [m for m in annotated_methods
                     if m.get("llm", {}).get("threat_type", "unknown") != "benign"
                     and (m.get("llm", {}).get("confidence") or 0) >= 0.85]
        medium_conf = [m for m in annotated_methods
                       if m.get("llm", {}).get("threat_type", "unknown") != "benign"
                       and 0.70 <= (m.get("llm", {}).get("confidence") or 0) < 0.85]
        low_conf = [m for m in annotated_methods
                    if m.get("llm", {}).get("threat_type", "unknown") != "benign"
                    and (m.get("llm", {}).get("confidence") or 0) < 0.70]
        benign = [m for m in annotated_methods
                  if m.get("llm", {}).get("threat_type", "unknown") == "benign"]

        total_flagged = len(high_conf) + len(medium_conf) + len(low_conf)

        # Apply limit to high-confidence methods first, then medium
        if limit:
            high_conf = high_conf[:limit]
            remaining = limit - len(high_conf)
            if remaining > 0:
                medium_conf = medium_conf[:remaining]

        story.append(Paragraph(
            f"{total_flagged} flagged as suspicious ({len(high_conf)} high, "
            f"{len(medium_conf)} medium, {len(low_conf)} low confidence), "
            f"{len(benign)} assessed as benign.",
            self.styles["DFBody"]
        ))

        if high_conf:
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>High Confidence (>= 85%)</b>", self.styles["DFLabel"]))
            self._render_method_list(story, high_conf)

        if medium_conf:
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Medium Confidence (70-84%)</b>", self.styles["DFLabel"]))
            self._render_method_list(story, medium_conf)

        if low_conf and not limit:
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Low Confidence (< 70%) - Collapsed</b>", self.styles["DFLabel"]))
            story.append(Paragraph(
                f"{len(low_conf)} method(s) with weak indicators. "
                "These may be benign in context and are shown for completeness.",
                self.styles["DFMuted"]
            ))
            self._render_method_list(story, low_conf)

        self._hr(story)

    def _build_benign_methods_section(self, story, annotated_methods):
        story.append(Paragraph("Benign Methods", self.styles["DFH1"]))
        benign = [m for m in annotated_methods
                  if m.get("llm", {}).get("threat_type", "unknown") == "benign"]
        story.append(Paragraph(
            f"Verified {len(benign)} methods as benign.",
            self.styles["DFBody"]
        ))

    def _build_limitations_section(self, story):
        story.append(Paragraph("Limitations", self.styles["DFH1"]))
        story.append(Paragraph(
            "This analysis has the following limitations that should be considered when interpreting results:",
            self.styles["DFBody"]
        ))
        limitations = [
            "Obfuscation may prevent full extraction of network indicators (domains, IPs). "
            "Encrypted or packed payloads can hide C2 infrastructure from static analysis.",
            "Known SDK code (Facebook, Google, Firebase, analytics) is filtered but may not be "
            "completely excluded. Some legitimate SDK methods may still appear as flagged.",
            "No dynamic analysis (sandboxing) was performed. Behavioral indicators "
            "(runtime network calls, file system access) are not captured.",
            "LLM threat assessment is advisory, not definitive. Risk scores reflect "
            "statistical patterns, not confirmed malware classification.",
            "Static analysis only. Code execution paths, conditional logic, and "
            "runtime-generated payloads may be missed.",
            "Sample provenance and distribution context are not verified. "
            "The sample may be a test file, benign app with suspicious patterns, "
            "or known malware family variant.",
        ]
        for lim in limitations:
            story.append(Paragraph("- " + self._safe(lim), self.styles["DFFinding"]))
        self._hr(story)

    def _build_stix_section(self, story, threat_data, sample_id):
        story.append(Paragraph("STIX 2.0 Export", self.styles["DFH1"]))
        c2s = threat_data.get("c2s", []) if threat_data else []
        sample_result = {"c2_infrastructure": c2s, "metadata": {}}
        try:
            stix_bundle = ti.to_stix(sample_result, sample_id)
            obj_count = len(stix_bundle.get("objects", []))
            story.append(Paragraph(
                f"STIX 2.0 bundle generated with {obj_count} indicator(s).",
                self.styles["DFBody"]
            ))
        except Exception:
            story.append(Paragraph(
                "STIX export not available for this sample.",
                self.styles["DFMuted"]
            ))

    def _render_method_list(self, story, methods):
        for entry in methods:
            class_name  = entry.get("class_name", "Unknown")
            method_name = entry.get("method_name", "Unknown")
            llm         = entry.get("llm", {})
            line_anns   = entry.get("line_annotations", {})
            flags       = entry.get("flags", [])

            summary     = llm.get("summary", "")
            threat_type = llm.get("threat_type", "unknown")
            confidence  = llm.get("confidence", None)

            block = []
            block.append(Paragraph(
                "<b>" + self._safe(class_name) + "</b>  <font face='Courier'>"
                + self._safe(method_name) + "</font>",
                self.styles["DFH3"]
            ))

            meta_parts = []
            if flags:
                meta_parts.append("Flags: " + ", ".join(flags[:6]))
            if threat_type and threat_type != "unknown":
                meta_parts.append("Type: " + threat_type.replace("_", " ").title())
            if confidence is not None:
                meta_parts.append(f"Confidence: {int(confidence * 100)}%")
            if meta_parts:
                block.append(Paragraph(" | ".join(meta_parts), self.styles["DFMuted"]))

            if summary:
                block.append(Paragraph(self._safe(summary, 1500), self.styles["DFLLM"]))

            if line_anns:
                seen_labels = set()
                unique_anns = []
                for line_idx, ann in sorted(line_anns.items(), key=lambda x: int(x[0])):
                    label = ann.get("label", "")
                    key = (ann.get("type", ""), label)
                    if key not in seen_labels:
                        seen_labels.add(key)
                        unique_anns.append((line_idx, ann))
                    if len(unique_anns) >= 8:
                        break
                if unique_anns:
                    block.append(Paragraph("<b>Pattern Annotations</b>", self.styles["DFLabel"]))
                    for line_idx, ann in unique_anns:
                        block.append(Paragraph(
                            "Line " + str(int(line_idx) + 1) + ": "
                            + self._safe(ann.get("label", "")),
                            self.styles["DFFinding"]
                        ))

            block.append(Spacer(1, 5))
            story.append(KeepTogether(block))

    # ============ Styling ============

    def _setup_styles(self):
        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(
            name="DFTitle",
            parent=styles["Title"],
            fontSize=24,
            textColor=C_DARK,
            spaceAfter=6,
            alignment=TA_CENTER,
        ))
        styles.add(ParagraphStyle(
            name="DFSub",
            parent=styles["Normal"],
            fontSize=11,
            textColor=C_MUTED,
            spaceAfter=2,
        ))
        styles.add(ParagraphStyle(
            name="DFH1",
            parent=styles["Heading1"],
            fontSize=14,
            textColor=C_DARK,
            spaceBefore=14,
            spaceAfter=6,
        ))
        styles.add(ParagraphStyle(
            name="DFH2",
            parent=styles["Heading2"],
            fontSize=11,
            textColor=C_ACCENT,
            spaceBefore=10,
            spaceAfter=4,
        ))
        styles.add(ParagraphStyle(
            name="DFH3",
            parent=styles["Heading3"],
            fontSize=9,
            textColor=C_MID,
            spaceBefore=6,
            spaceAfter=3,
        ))
        styles.add(ParagraphStyle(
            name="DFBody",
            parent=styles["Normal"],
            fontSize=9,
            textColor=C_DARK,
            leading=14,
            spaceAfter=4,
        ))
        styles.add(ParagraphStyle(
            name="DFMono",
            parent=styles["Code"],
            fontSize=8,
            textColor=C_DARK,
            leading=12,
            spaceAfter=2,
        ))
        styles.add(ParagraphStyle(
            name="DFMonoSm",
            parent=styles["Code"],
            fontSize=7,
            textColor=C_MUTED,
            leading=11,
        ))
        styles.add(ParagraphStyle(
            name="DFMuted",
            parent=styles["Normal"],
            fontSize=8,
            textColor=C_MUTED,
            leading=12,
        ))
        styles.add(ParagraphStyle(
            name="DFLabel",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=C_MUTED,
            spaceAfter=2,
        ))
        styles.add(ParagraphStyle(
            name="DFLLM",
            parent=styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=9,
            textColor=colors.HexColor("#334155"),
            leading=14,
            spaceAfter=3,
            leftIndent=8,
        ))
        styles.add(ParagraphStyle(
            name="DFFinding",
            parent=styles["Normal"],
            fontSize=9,
            textColor=C_DARK,
            leading=13,
            spaceAfter=2,
            leftIndent=12,
        ))
        return styles


# ============ Utility Functions ============

def get_quick_pdf_default_sections() -> Dict[str, bool]:
    """Get default sections for Quick PDF."""
    return DroidForensixPDFGenerator.QUICK_PDF_DEFAULTS.copy()


def get_available_sections() -> List[str]:
    """Get list of available sections for customization."""
    return list(DroidForensixPDFGenerator.FULL_PDF_SECTIONS.keys())
