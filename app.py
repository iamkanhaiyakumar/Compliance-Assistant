import re
import streamlit as st
import streamlit.components.v1 as components
import io
import time
import os
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from dotenv import load_dotenv

# Import modules
from parsers import parse_pdf, parse_txt, parse_csv
from detector import run_regex_and_entropy_scan, run_spacy_ner_scan, run_llm_hybrid_scan
from compliance import calculate_risk_metrics, map_findings_to_standards, generate_ai_recommendations
from redactor import generate_html_highlighted_text, mask_text_content, highlight_binary_pdf, redact_binary_pdf, SEVERITY_COLORS
from qa_engine import DocVectorStore, ask_compliance_copilot
from audit import get_file_hash, get_cached_scan, cache_scan, log_audit_event, get_audit_logs

# Load environment variables
load_dotenv()

# ReportLab imports for PDF compliance report
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# ---------------------------------------------------------
# Styled ReportLab PDF Compliance Report Generator
# ---------------------------------------------------------
def generate_pdf_report(file_name: str, risk_score: float, risk_level: str, findings: list[dict], recommendations: list[dict]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Title'],
        fontName='Helvetica-Bold', fontSize=24,
        textColor=colors.HexColor("#1e3a8a"), spaceAfter=15
    )
    h1_style = ParagraphStyle(
        'SectionH1', parent=styles['Heading1'],
        fontName='Helvetica-Bold', fontSize=16,
        textColor=colors.HexColor("#1e3a8a"), spaceBefore=15, spaceAfter=10
    )
    body_style = ParagraphStyle(
        'ReportBody', parent=styles['BodyText'],
        fontSize=10, leading=14
    )

    story = []
    story.append(Paragraph("Security Compliance Audit Report", title_style))
    story.append(Spacer(1, 10))

    overview_data = [
        [Paragraph("<b>File Name:</b>", body_style), Paragraph(file_name, body_style)],
        [Paragraph("<b>Overall Risk Score:</b>", body_style), Paragraph(f"{risk_score}/100", body_style)],
        [Paragraph("<b>Risk Level:</b>", body_style), Paragraph(f"<b>{risk_level}</b>", body_style)],
        [Paragraph("<b>Total Findings:</b>", body_style), Paragraph(str(len(findings)), body_style)]
    ]
    t = Table(overview_data, colWidths=[150, 350])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f3f4f6")),
        ('PADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    story.append(Paragraph("Sensitive Data Findings", h1_style))
    findings_data = [["Type", "Matched Value", "Method", "Confidence", "Severity"]]
    for f in findings:
        val_str = str(f["value"])
        masked_val = val_str[:3] + "*" * (len(val_str) - 3) if len(val_str) > 3 else "***"
        findings_data.append([
            f["type"],
            Paragraph(masked_val, body_style),
            f["method"],
            f"{int(f['confidence']*100) if f['confidence'] <= 1.0 else int(f['confidence'])}%",
            f["severity"]
        ])

    ft = Table(findings_data, colWidths=[100, 130, 130, 70, 70])
    ft.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e3a8a")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('PADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#d1d5db")),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f9fafb")]),
    ]))
    story.append(ft)
    story.append(Spacer(1, 20))

    story.append(Paragraph("Actionable Security Remediation Plan", h1_style))
    for idx, rec in enumerate(recommendations):
        story.append(Paragraph(f"<b>{idx+1}. [{rec.get('priority', 'Low').upper()}] {rec.get('action', '')}</b>", body_style))
        story.append(Paragraph(f"<i>Why:</i> {rec.get('reason', '')} (Standard: {rec.get('standard', '')})", body_style))
        story.append(Spacer(1, 10))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


# ---------------------------------------------------------
# Helper: severity CSS class
# ---------------------------------------------------------
def sev_class(severity: str) -> str:
    s = severity.lower()
    if s == "critical": return "sev-critical"
    if s == "high":     return "sev-high"
    if s == "medium":   return "sev-medium"
    return "sev-low"


# ---------------------------------------------------------
# Helper: render section header
# ---------------------------------------------------------
def section_header(icon: str, title: str):
    st.markdown(
        f'<div class="section-header">'
        f'<div class="section-header-icon">{icon}</div>'
        f'<div class="section-header-text">{title}</div>'
        f'</div>',
        unsafe_allow_html=True
    )


# ---------------------------------------------------------
# Page Config
# ---------------------------------------------------------
st.set_page_config(
    page_title="Compliance Assistant · Enterprise",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject CSS
try:
    with open("style.css", "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
except Exception:
    pass

# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div class="sidebar-brand">
      <div class="sidebar-brand-icon">🛡️</div>
      <div class="sidebar-brand-text">
        <div class="sidebar-brand-name">ComplianceAI</div>
        <div class="sidebar-brand-sub">Enterprise Security Suite</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # System status
    st.markdown('<div class="sidebar-section">System Status</div>', unsafe_allow_html=True)
    st.markdown('<span class="status-pill active"><span class="status-dot"></span>All Systems Operational</span>', unsafe_allow_html=True)

    st.markdown('<div class="sidebar-section">Information</div>', unsafe_allow_html=True)


    # About
    st.markdown('<div class="sidebar-section">About</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-size:0.75rem; color:#475569; line-height:1.7; padding:0 0.25rem;">
    Detects <b style="color:#64748B;">PAN · Aadhaar · Credit Cards · API Keys · PII · Business Secrets</b>
    using a 4-stage pipeline: Regex → spaCy NER → Entropy → LLM Verification.
    <br><br>
    Compliance standards: GDPR · PCI DSS · DPDP · ISO 27001
    </div>
    """, unsafe_allow_html=True)
    st.markdown(f"""
    <div style="font-size:0.7rem; color:#334155; margin-top:1.5rem; padding:0 0.25rem;">
    🔗 <a href="https://sensitive-data-detection-compliance-assistant.streamlit.app/" target="_blank" style="color:#38BDF8; text-decoration:none;">Live Demo</a>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------
# Session State
# ---------------------------------------------------------
if "scan_history"      not in st.session_state: st.session_state.scan_history      = {}
if "vector_stores"     not in st.session_state: st.session_state.vector_stores     = {}
if "messages"          not in st.session_state: st.session_state.messages          = {}
if "last_scanned_hash"   not in st.session_state: st.session_state.last_scanned_hash   = None
if "pending_question"   not in st.session_state: st.session_state.pending_question    = None

# ---------------------------------------------------------
# TOP NAVBAR (fixed)
# ---------------------------------------------------------
st.markdown("""
<nav class="top-navbar">
  <!-- Brand / Hamburger -->
  <div class="navbar-brand">
    <button class="navbar-hamburger">☰</button>
    <div class="navbar-brand-icon">🛡️</div>
    <span class="navbar-brand-name">ComplianceAI</span>
    <span class="navbar-brand-tag">ENTERPRISE</span>
  </div>

  <!-- Nav Links: onclick JS clicks the matching Streamlit tab button -->
  <div class="navbar-links">
    <span class="navbar-link" onclick="switchTab(0)">
      <span class="navbar-link-icon">📊</span> Dashboard
    </span>
    <span class="navbar-link" onclick="switchTab(1)">
      <span class="navbar-link-icon">🔍</span> Scanner
    </span>
    <span class="navbar-link" onclick="switchTab(2)">
      <span class="navbar-link-icon">📜</span> Compliance
    </span>
    <span class="navbar-link" onclick="switchTab(3)">
      <span class="navbar-link-icon">🔒</span> Redaction
    </span>
    <span class="navbar-link" onclick="switchTab(4)">
      <span class="navbar-link-icon">💬</span> AI Copilot
    </span>
    <span class="navbar-link" onclick="switchTab(5)">
      <span class="navbar-link-icon">ℹ️</span> About Project
    </span>
    <div class="navbar-divider"></div>
    <span class="navbar-link" onclick="switchTab(6)">
      <span class="navbar-link-icon">📂</span> Audit Logs
    </span>
  </div>

  <!-- Right side -->
  <div class="navbar-right">
    <div class="navbar-status">
      <div class="navbar-status-dot"></div>
      All Systems Online
    </div>
    <span class="navbar-version">v2.0</span>
  </div>
</nav>

<!-- Mobile Navigation Drawer Overlay & Box -->
<div class="mobile-drawer-overlay" id="drawerOverlay"></div>
<div class="mobile-drawer" id="mobileDrawer">
  <div class="mobile-drawer-header">
    <div class="navbar-brand" style="margin: 0;">
      <div class="navbar-brand-icon">🛡️</div>
      <span class="navbar-brand-name" style="display: block !important;">ComplianceAI</span>
    </div>
    <button class="mobile-drawer-close">×</button>
  </div>
  <div class="mobile-drawer-links">
    <span class="drawer-link active">
      <span class="navbar-link-icon">📊</span> Dashboard
    </span>
    <span class="drawer-link">
      <span class="navbar-link-icon">🔍</span> Scanner
    </span>
    <span class="drawer-link">
      <span class="navbar-link-icon">📜</span> Compliance
    </span>
    <span class="drawer-link">
      <span class="navbar-link-icon">🔒</span> Redaction
    </span>
    <span class="drawer-link">
      <span class="navbar-link-icon">💬</span> AI Copilot
    </span>
    <span class="drawer-link">
      <span class="navbar-link-icon">ℹ️</span> About Project
    </span>
    <div class="drawer-divider"></div>
    <span class="drawer-link">
      <span class="navbar-link-icon">📂</span> Audit Logs
    </span>
  </div>
</div>
""", unsafe_allow_html=True)

# Inject working JS via components.html() — this executes in iframe and
# can access window.parent.document to click the Streamlit tab buttons
components.html("""
<script>
(function () {
  function attach() {
    var p     = window.parent.document;
    var links = p.querySelectorAll('.navbar-link');
    var tabs  = p.querySelectorAll('[data-baseweb="tab"]');
    if (!links.length || !tabs.length) return false;

    // Helper to toggle visibility of config & upload controls by hiding all siblings before the tabs block
    function syncTabVisibility(idx) {
      var p = window.parent.document;
      
      var tabs = p.querySelector('[data-testid="stTabs"]');
      if (tabs) {
        var tabsBlock = tabs.closest('.element-container');
        if (tabsBlock) {
          var sib = tabsBlock.previousElementSibling;
          var stopHiding = false;
          while (sib) {
            // Stop hiding if we hit the status pill or configuration columns
            if (sib.querySelector('.status-pill') || 
                sib.querySelector('.sidebar-section') || 
                sib.querySelector('.ent-header')) {
              stopHiding = true;
            }
            
            if (idx === 5) {
              // Hide everything for About Project
              sib.style.display = 'none';
            } else if (idx === 0) {
              // Show everything for Dashboard
              sib.style.display = 'block';
            } else {
              // Other tabs: Hide uploader, uploader header, and run buttons (before stopHiding)
              if (stopHiding) {
                sib.style.display = 'block';
              } else {
                sib.style.display = 'none';
              }
            }
            
            sib = sib.previousElementSibling;
          }
        }
      }
    }

    // Expose drawer toggle functions to parent window context
    window.parent.toggleMobileMenu = function () {
      var drawer = p.getElementById('mobileDrawer');
      var overlay = p.getElementById('drawerOverlay');
      if (drawer && overlay) {
        if (drawer.classList.contains('open')) {
          drawer.classList.remove('open');
          overlay.classList.remove('visible');
        } else {
          drawer.classList.add('open');
          overlay.classList.add('visible');
        }
      }
    };

    // Set initial active state based on active tab
    tabs.forEach(function (tab, i) {
      if (tab.getAttribute('aria-selected') === 'true') {
        syncTabVisibility(i);
        
        // Sync active state in drawer links
        var drLinks = p.querySelectorAll('.drawer-link');
        drLinks.forEach(function (l) { l.classList.remove('active'); });
        if (drLinks[i]) drLinks[i].classList.add('active');
      }
    });

    // Bind desktop link clicks
    links.forEach(function (link, i) {
      // Clone to remove stale handlers
      var fresh = link.cloneNode(true);
      link.parentNode.replaceChild(fresh, link);
      fresh.style.cursor = 'pointer';
      fresh.addEventListener('click', function () {
        var freshTabs = window.parent.document.querySelectorAll('[data-baseweb="tab"]');
        if (freshTabs[i]) freshTabs[i].click();
        
        // Active style
        window.parent.document.querySelectorAll('.navbar-link')
          .forEach(function (l) { l.classList.remove('active'); });
        fresh.classList.add('active');
        
        var drLinks = p.querySelectorAll('.drawer-link');
        drLinks.forEach(function (l) { l.classList.remove('active'); });
        if (drLinks[i]) drLinks[i].classList.add('active');

        syncTabVisibility(i);
      });
    });

    // Bind mobile drawer link clicks
    var drawerLinks = p.querySelectorAll('.drawer-link');
    drawerLinks.forEach(function (link, i) {
      var fresh = link.cloneNode(true);
      link.parentNode.replaceChild(fresh, link);
      fresh.style.cursor = 'pointer';
      fresh.addEventListener('click', function () {
        var freshTabs = window.parent.document.querySelectorAll('[data-baseweb="tab"]');
        if (freshTabs[i]) freshTabs[i].click();
        
        // Sync active style in desktop links
        var dLinks = window.parent.document.querySelectorAll('.navbar-link');
        dLinks.forEach(function (l) { l.classList.remove('active'); });
        if (dLinks[i]) dLinks[i].classList.add('active');

        // Sync active style in drawer links
        var drLinks = p.querySelectorAll('.drawer-link');
        drLinks.forEach(function (l) { l.classList.remove('active'); });
        fresh.classList.add('active');

        syncTabVisibility(i);
        window.parent.toggleMobileMenu();
      });
    });

    // Bind hamburger button click
    var hamburger = p.querySelector('.navbar-hamburger');
    if (hamburger) {
      var freshHamburger = hamburger.cloneNode(true);
      hamburger.parentNode.replaceChild(freshHamburger, hamburger);
      freshHamburger.addEventListener('click', function () {
        window.parent.toggleMobileMenu();
      });
    }

    // Bind close drawer button click
    var closeBtn = p.querySelector('.mobile-drawer-close');
    if (closeBtn) {
      var freshClose = closeBtn.cloneNode(true);
      closeBtn.parentNode.replaceChild(freshClose, closeBtn);
      freshClose.addEventListener('click', function () {
        window.parent.toggleMobileMenu();
      });
    }

    // Bind overlay click
    var overlay = p.getElementById('drawerOverlay');
    if (overlay) {
      var freshOverlay = overlay.cloneNode(true);
      overlay.parentNode.replaceChild(freshOverlay, overlay);
      freshOverlay.addEventListener('click', function () {
        window.parent.toggleMobileMenu();
      });
    }

    // Sync active class when user clicks tabs directly
    tabs.forEach(function (tab, i) {
      tab.addEventListener('click', function () {
        window.parent.document.querySelectorAll('.navbar-link')
          .forEach(function (l) { l.classList.remove('active'); });
        var navLinks = window.parent.document.querySelectorAll('.navbar-link');
        if (navLinks[i]) navLinks[i].classList.add('active');
        
        // Sync drawer links active class
        var drLinks = p.querySelectorAll('.drawer-link');
        drLinks.forEach(function (l) { l.classList.remove('active'); });
        if (drLinks[i]) drLinks[i].classList.add('active');

        syncTabVisibility(i);
      });
    });
    return true;
  }

  // Retry until tabs are rendered
  var n = 0;
  var t = setInterval(function () {
    if (attach() || n++ > 30) clearInterval(t);
  }, 200);
})();
</script>
""", height=0, scrolling=False)

# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------
try:
    with open("header_template.html", "r", encoding="utf-8") as f:
        st.markdown(f.read(), unsafe_allow_html=True)
except Exception:
    pass

# ---------------------------------------------------------
# UPLOAD SECTION
# ---------------------------------------------------------

st.markdown("<div class='config-wrapper'>", unsafe_allow_html=True)
# ── Interactive Audit & Engine Settings (Quick Settings) ──
st.markdown('<div class="sidebar-section" style="margin-top:0.8rem;margin-bottom:0.6rem;color:#475569;font-weight:700;letter-spacing:0.08em;font-size:0.75rem;">⚙️ AUDIT ENGINE &amp; COMPLIANCE CONFIGURATION</div>', unsafe_allow_html=True)

col_eng, col_key, col_depth = st.columns([1.1, 1.4, 1.2])

with col_eng:
    api_provider_choice = st.selectbox(
        "AI Engine / Provider",
        ["Groq (Free)", "HuggingFace", "Gemini", "OpenAI"],
        index=0,
        help="Select the AI/LLM engine for Deep Scan verification and document Q&A."
    )
    if "Groq" in api_provider_choice:
        api_provider = "Groq"
    elif "HuggingFace" in api_provider_choice:
        api_provider = "HuggingFace"
    elif "Gemini" in api_provider_choice:
        api_provider = "Gemini"
    else:
        api_provider = "OpenAI"

with col_key:
    if api_provider == "Groq":
        env_key = os.getenv("GROQ_API_KEY", "")
        key_label = "Groq API Key (Environment Only)"
        placeholder = "✓ Loaded from environment" if env_key else "Disabled (Configure in .env)"
        key_help = "Writing blocked. This key is securely managed via environment configurations only."
        user_key = st.text_input(
            key_label,
            value="",
            type="password",
            placeholder=placeholder,
            help=key_help,
            disabled=True
        )
        api_key = user_key if user_key else env_key
    elif api_provider == "HuggingFace":
        env_key = os.getenv("HF_TOKEN", "")
        key_label = "HuggingFace Token (Environment Only)"
        placeholder = "✓ Loaded from environment" if env_key else "Disabled (Configure in .env)"
        key_help = "Writing blocked. This token is securely managed via environment configurations only."
        user_key = st.text_input(
            key_label,
            value="",
            type="password",
            placeholder=placeholder,
            help=key_help,
            disabled=True
        )
        api_key = user_key if user_key else env_key
    elif api_provider == "Gemini":
        default_key = os.getenv("GEMINI_API_KEY", "")
        key_label = "Gemini API Key"
        placeholder = "AIzaSy_xxxxxxxxxxxxxxxx"
        key_help = "Get key at aistudio.google.com/apikey"
        api_key = st.text_input(
            key_label,
            value=default_key,
            placeholder=placeholder,
            help=key_help
        )
    else:
        default_key = os.getenv("OPENAI_API_KEY", "")
        key_label = "OpenAI API Key"
        placeholder = "sk-xxxxxxxxxxxxxxxx"
        key_help = "Get key at platform.openai.com"
        api_key = st.text_input(
            key_label,
            value=default_key,
            placeholder=placeholder,
            help=key_help
        )



with col_depth:
    scan_depth = st.selectbox(
        "Scan Configuration",
        ["Fast Scan (Regex + spaCy NER)", "Deep Scan (AI-Assisted Hybrid)"],
        index=0,
        help="Deep Scan triggers context verification via AI Engine (requires API Key)."
    )

if api_key:
    status_msg = f"{api_provider} Active ✓ Connected"
    status_class = "active"
else:
    status_msg = f"No API Key for {api_provider} · AI features off"
    status_class = "idle"

st.markdown(f"""
<div style="margin-top:6px; margin-bottom:18px;">
  <span class="status-pill {status_class}">
    <span class="status-dot"></span>
    {status_msg}
  </span>
</div>
""", unsafe_allow_html=True)
st.markdown("</div>", unsafe_allow_html=True)



st.markdown("<div class='upload-wrapper'>", unsafe_allow_html=True)
section_header("📁", "Upload Documents for Compliance Scan")

uploaded_files = st.file_uploader(
    "☁️  Drag & drop your files here  ·  PDF · TXT · CSV  ·  Multiple files supported",
    type=["pdf", "txt", "csv"],
    accept_multiple_files=True,
)
st.markdown("</div>", unsafe_allow_html=True)

# ---------------------------------------------------------
# SCANNING LOGIC  (unchanged backend)
# ---------------------------------------------------------
if uploaded_files:
    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        scan_triggered = st.button("🚀 Execute Security Audit", use_container_width=True)
    with col_info:
        st.markdown(
            f'<div class="alert-box alert-box-info"><span class="alert-box-icon">ℹ️</span>'
            f'{len(uploaded_files)} file(s) ready for scanning · Mode: <b>{scan_depth.split("(")[0].strip()}</b> · Engine: <b>{api_provider}</b></div>',
            unsafe_allow_html=True
        )

    if scan_triggered:
        progress_bar = st.progress(0)
        status_text  = st.empty()

        for idx, file in enumerate(uploaded_files):
            file_bytes = file.read()
            file_hash  = get_file_hash(file_bytes)
            status_text.markdown(
                f'<div class="alert-box alert-box-info"><span class="alert-box-icon">⚙️</span>'
                f'Processing file {idx+1}/{len(uploaded_files)}: <b>{file.name}</b></div>',
                unsafe_allow_html=True
            )
            progress_bar.progress(int(((idx) / len(uploaded_files)) * 100))

            # Check Cache
            cached = get_cached_scan(file_hash)
            if cached:
                st.session_state.scan_history[file_hash] = cached
                if file_hash not in st.session_state.vector_stores:
                    st.session_state.vector_stores[file_hash] = DocVectorStore(cached["text_content"])
                continue

            # Fresh Scan
            start_time = time.perf_counter()

            try:
                if file.name.lower().endswith(".pdf"):
                    text_content, pages_data = parse_pdf(file_bytes)
                elif file.name.lower().endswith(".csv"):
                    text_content = parse_csv(file_bytes)
                    pages_data = [{"page_num": 1, "text": text_content, "width": 0, "height": 0}]
                else:
                    text_content = parse_txt(file_bytes)
                    pages_data = [{"page_num": 1, "text": text_content, "width": 0, "height": 0}]
            except Exception as e:
                st.markdown(
                    f'<div class="alert-box alert-box-danger"><span class="alert-box-icon">❌</span>Failed parsing <b>{file.name}</b>: {str(e)}</div>',
                    unsafe_allow_html=True
                )
                continue

            regex_findings   = run_regex_and_entropy_scan(text_content)
            ner_findings     = run_spacy_ner_scan(text_content, regex_findings)
            combined_findings = regex_findings + ner_findings

            if "Deep Scan" in scan_depth and api_key:
                final_findings = run_llm_hybrid_scan(text_content, combined_findings, api_key, api_provider)
            else:
                final_findings = combined_findings

            risk_score, risk_level, reason_summary = calculate_risk_metrics(final_findings)
            cache_scan(file_hash, file.name, text_content, final_findings, risk_score, risk_level, file_bytes)
            st.session_state.vector_stores[file_hash] = DocVectorStore(text_content)
            st.session_state.scan_history[file_hash] = {
                "file_name":    file.name,
                "text_content": text_content,
                "findings":     final_findings,
                "risk_score":   risk_score,
                "risk_level":   risk_level,
                "raw_bytes":    file_bytes,
                "pages_data":   pages_data,
                "scan_time":    round(time.perf_counter() - start_time, 2),
            }

            # Track last scanned file so the UI auto-selects it
            st.session_state.last_scanned_hash = file_hash

            scan_duration = int((time.perf_counter() - start_time) * 1000)
            log_audit_event(
                action="SCAN_DOCUMENT", file_name=file.name, file_hash=file_hash,
                risk_score=risk_score, risk_level=risk_level, duration_ms=scan_duration
            )

        progress_bar.progress(100)
        status_text.empty()
        st.toast("🛡️ Compliance Audit Complete!", icon="✅")
        time.sleep(0.8)

# ---------------------------------------------------------
# RESULTS  —  Tabs ALWAYS rendered so navbar JS can find them.
# ---------------------------------------------------------

# Comparison matrix + doc selector (only when scans exist)
active_hash = None
active_doc  = None
doc_text    = ""

if st.session_state.scan_history:
    section_header("📊", "Multi-Document Compliance Matrix")

    comparison_data = []
    for f_hash, data in st.session_state.scan_history.items():
        rl = data["risk_level"]
        critical_count = sum(1 for f in data["findings"] if f.get("severity") == "Critical")
        comparison_data.append({
            "📄 File Name":  data["file_name"],
            "⚠️ Risk Score": f"{data['risk_score']}/100",
            "🔴 Risk Level": rl,
            "🔍 Findings":   len(data["findings"]),
            "🚨 Critical":   critical_count,
            "🔑 Hash":       f_hash[:10] + "…",
        })
    st.dataframe(pd.DataFrame(comparison_data), use_container_width=True, hide_index=True)

    section_header("🔍", "Select Document for Deep Dive Analysis")
    _options     = [data["file_name"] for data in st.session_state.scan_history.values()]
    _hashes      = list(st.session_state.scan_history.keys())
    _default_idx = 0
    if st.session_state.last_scanned_hash and st.session_state.last_scanned_hash in _hashes:
        _default_idx = _hashes.index(st.session_state.last_scanned_hash)

    selected_file_name = st.selectbox(
        "Active Document", options=_options, index=_default_idx, label_visibility="collapsed"
    )
    active_hash = next(
        (h for h, d in st.session_state.scan_history.items() if d["file_name"] == selected_file_name),
        None
    )
    if not active_hash and st.session_state.scan_history:
        active_hash = list(st.session_state.scan_history.keys())[0]
        
    active_doc = st.session_state.scan_history[active_hash]
    doc_text   = active_doc["text_content"]


def _no_scan_state(icon="🛡️", title="No Document Scanned Yet",
                   sub="Upload a document above and click <b>Execute Security Audit</b>."):
    st.markdown(f"""
    <div class="empty-state" style="padding:60px 20px;">
      <span class="empty-state-icon">{icon}</span>
      <div class="empty-state-title">{title}</div>
      <div class="empty-state-sub">{sub}</div>
    </div>""", unsafe_allow_html=True)


# Always-rendered tabs
tab_dashboard, tab_scanner, tab_compliance, tab_redact, tab_qa, tab_about, tab_audits = st.tabs([
    "📊 Dashboard", "🔍 Scanner", "📜 Compliance",
    "🔒 Redaction & Export", "💬 AI Copilot", "ℹ️ About Project", "📂 Audit Logs"
])

# ── TAB 1: DASHBOARD ────────────────────────────────
with tab_dashboard:
    if not active_doc:
        _no_scan_state("📊", "Dashboard Awaiting Data",
                       "Scan a document to see risk scores, metrics, and compliance charts.")
    else:
        findings         = active_doc["findings"]
        risk_score       = active_doc["risk_score"]
        risk_level       = active_doc["risk_level"]
        critical_cnt     = sum(1 for f in findings if f.get("severity") == "Critical")
        high_cnt         = sum(1 for f in findings if f.get("severity") == "High")
        scan_time_val    = active_doc.get("scan_time", "—")
        compliance_score = max(0, 100 - int(risk_score))

        c1, c2, c3, c4, c5, c6 = st.columns(6)

        def metric_card(col, icon, value, label, delta_label="", delta_cls="delta-info"):
            with col:
                dh = f'<div class="metric-card-delta {delta_cls}">{delta_label}</div>' if delta_label else ""
                st.markdown(f'<div class="metric-card">{dh}<span class="metric-card-icon">{icon}</span>'
                            f'<div class="metric-card-value">{value}</div>'
                            f'<div class="metric-card-label">{label}</div></div>', unsafe_allow_html=True)

        rl_cls = ("delta-danger" if risk_level == "Critical" else
                  "delta-warn"  if risk_level == "High"     else
                  "delta-success" if risk_level == "Low"    else "delta-info")
        metric_card(c1, "🎯", risk_score,           "Risk Score",       risk_level, rl_cls)
        metric_card(c2, "🔍", len(findings),        "Findings",         f"+{len(findings)}", "delta-warn" if findings else "delta-success")
        metric_card(c3, "🚨", critical_cnt,         "Critical",         "Critical" if critical_cnt else "None", "delta-danger" if critical_cnt else "delta-success")
        metric_card(c4, "⚡", high_cnt,             "High Severity",    f"{high_cnt} High", "delta-warn" if high_cnt else "delta-success")
        metric_card(c5, "✅", f"{compliance_score}%","Compliance Score","Pass" if compliance_score >= 70 else "Fail", "delta-success" if compliance_score >= 70 else "delta-danger")
        metric_card(c6, "⏱️", f"{scan_time_val}s", "Scan Time",        api_provider, "delta-info")

        st.markdown("<br>", unsafe_allow_html=True)
        col_g, col_p, col_b = st.columns(3)

        with col_g:
            gc = "#EF4444" if risk_score >= 70 else "#F59E0B" if risk_score >= 30 else "#10B981"
            fig_g = go.Figure(go.Indicator(
                mode="gauge+number+delta", value=risk_score,
                delta={"reference": 50, "increasing": {"color": "#EF4444"}, "decreasing": {"color": "#10B981"}},
                number={"suffix": "/100", "font": {"size": 32, "color": "#F8FAFC", "family": "Outfit"}},
                domain={"x": [0,1], "y": [0,1]},
                gauge={"axis": {"range": [0,100], "tickwidth":1, "tickcolor":"#334155", "tickfont":{"color":"#64748B","size":10}},
                       "bar": {"color": gc, "thickness": 0.22}, "bgcolor": "rgba(0,0,0,0)", "borderwidth": 0,
                       "steps": [{"range":[0,30],"color":"rgba(16,185,129,0.1)"},
                                  {"range":[30,70],"color":"rgba(245,158,11,0.1)"},
                                  {"range":[70,100],"color":"rgba(239,68,68,0.1)"}],
                       "threshold": {"line":{"color":gc,"width":3},"thickness":0.75,"value":risk_score}}
            ))
            fig_g.update_layout(title={"text":"Overall Risk Score","font":{"size":13,"color":"#94A3B8","family":"Inter"},"x":0.5},
                                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                font={"color":"#F8FAFC","family":"Inter"}, height=260, margin=dict(t=40,b=10,l=20,r=20))
            st.plotly_chart(fig_g, use_container_width=True)

        with col_p:
            if findings:
                fc = {}
                for f in findings: fc[f["type"]] = fc.get(f["type"],0)+1
                fig_p = px.pie(pd.DataFrame([{"Type":k,"Count":v} for k,v in fc.items()]),
                               names="Type", values="Count", hole=0.55,
                               color_discrete_sequence=["#2563EB","#38BDF8","#10B981","#F59E0B","#EF4444","#8B5CF6","#EC4899","#14B8A6"])
                fig_p.update_traces(textfont_size=11, marker=dict(line=dict(color="#0F172A",width=2)))
                fig_p.update_layout(title={"text":"Sensitive Data Distribution","font":{"size":13,"color":"#94A3B8","family":"Inter"},"x":0.5},
                                    paper_bgcolor="rgba(0,0,0,0)", font={"color":"#F8FAFC","family":"Inter"},
                                    height=260, margin=dict(t=40,b=10,l=10,r=10),
                                    legend=dict(font=dict(size=10,color="#94A3B8"),bgcolor="rgba(0,0,0,0)"))
                st.plotly_chart(fig_p, use_container_width=True)
            else:
                st.markdown('<div class="empty-state" style="padding:40px 20px;"><span class="empty-state-icon">✅</span><div class="empty-state-title">No Findings</div></div>', unsafe_allow_html=True)

        with col_b:
            if findings:
                sc = {"Critical":0,"High":0,"Medium":0,"Low":0}
                for f in findings: sc[f.get("severity","Low")] = sc.get(f.get("severity","Low"),0)+1
                fig_b = go.Figure(go.Bar(y=list(sc.keys()), x=list(sc.values()), orientation="h",
                                         marker_color=["#EF4444","#F59E0B","#FBBF24","#10B981"], marker_line_width=0,
                                         text=list(sc.values()), textposition="inside",
                                         textfont=dict(color="#F8FAFC",size=11,family="Outfit")))
                fig_b.update_layout(title={"text":"Findings by Severity","font":{"size":13,"color":"#94A3B8","family":"Inter"},"x":0.5},
                                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                    font={"color":"#F8FAFC","family":"Inter"}, height=260, margin=dict(t=40,b=10,l=10,r=20),
                                    yaxis=dict(gridcolor="rgba(255,255,255,0.04)",tickfont=dict(size=11)),
                                    xaxis=dict(gridcolor="rgba(255,255,255,0.04)",tickfont=dict(size=10)), bargap=0.3)
                st.plotly_chart(fig_b, use_container_width=True)

        section_header("💬", "Risk Assessment Details")
        _, _, reason_summary = calculate_risk_metrics(active_doc["findings"])
        alert_cls = {"Critical":"alert-box-danger","High":"alert-box-warn","Medium":"alert-box-warn","Low":"alert-box-success"}.get(risk_level,"alert-box-info")
        icon_map  = {"Critical":"🚨","High":"⚠️","Medium":"⚡","Low":"✅"}
        st.markdown(f'<div class="alert-box {alert_cls}"><span class="alert-box-icon">{icon_map.get(risk_level,"ℹ️")}</span>'
                    f'<div><b>Risk Level: {risk_level}</b> — Score {risk_score}/100<br>'
                    f'<span style="font-size:0.82rem;">{reason_summary.replace(chr(10)," · ")}</span></div></div>',
                    unsafe_allow_html=True)

# ── TAB 2: SCANNER ──────────────────────────────────
with tab_scanner:
    if not active_doc:
        _no_scan_state("🔍", "Scanner Awaiting Document",
                       "Scan a document to view its text with sensitive data highlighted.")
    else:
        col_l, col_r = st.columns([3, 2])
        with col_l:
            section_header("📄", "Document Viewer")
            ca, cb = st.columns(2)
            with ca: show_highlights = st.checkbox("Highlight Sensitive Data", value=True)
            with cb: search_query    = st.text_input("Search", placeholder="Type to search…", label_visibility="collapsed")

            highlighted_html = generate_html_highlighted_text(doc_text, active_doc["findings"]) if show_highlights else doc_text.replace("\n","<br>")

            if search_query:
                patt = re.compile(re.escape(search_query), re.IGNORECASE)
                mtch = list(patt.finditer(highlighted_html))
                if mtch:
                    st.markdown(f'<div class="alert-box alert-box-success"><span class="alert-box-icon">🔍</span>Found <b>{len(mtch)}</b> matches</div>', unsafe_allow_html=True)
                    highlighted_html = patt.sub(lambda m: f'<span class="search-match">{m.group()}</span>', highlighted_html)
                else:
                    st.markdown('<div class="alert-box alert-box-warn"><span class="alert-box-icon">⚠️</span>No matches found</div>', unsafe_allow_html=True)

            st.markdown(f'<div style="background:#111827;padding:20px;border-radius:10px;max-height:520px;overflow-y:scroll;border:1px solid rgba(255,255,255,0.07);line-height:1.7;font-size:0.875rem;color:#CBD5E1;">{highlighted_html}</div>', unsafe_allow_html=True)

        with col_r:
            section_header("🔎", "Detection Explainability")
            fnd = active_doc["findings"]
            if not fnd:
                st.markdown('<div class="empty-state" style="padding:48px 20px;"><span class="empty-state-icon">✅</span><div class="empty-state-title">Clean Document</div></div>', unsafe_allow_html=True)
            else:
                crit_f = sum(1 for f in fnd if f.get("severity")=="Critical")
                st.markdown(f'<div class="alert-box alert-box-{"danger" if crit_f else "info"}" style="margin-bottom:12px;"><span class="alert-box-icon">{"🚨" if crit_f else "ℹ️"}</span><b>{len(fnd)}</b> findings · <b>{crit_f}</b> Critical</div>', unsafe_allow_html=True)
                for f in fnd:
                    cp = int(f["confidence"]*100) if f["confidence"]<=1.0 else int(f["confidence"])
                    sv = f.get("severity","Low")
                    sc_css = sev_class(sv)
                    sv_col = SEVERITY_COLORS.get(sv,"#eeeeee")
                    st.markdown(f'<div class="finding-card" style="border-left:4px solid {sv_col};">'
                                f'<div class="finding-card-type">{f["type"]}<span class="sev-badge {sc_css}" style="margin-left:8px;">{sv}</span></div>'
                                f'<div class="finding-card-value">{str(f["value"])[:60]}{"…" if len(str(f["value"]))>60 else ""}</div>'
                                f'<div class="finding-card-meta"><b>Method:</b> {f["method"]}<br><b>Confidence:</b> {cp}%<br><b>Reason:</b> {f["reason"]}</div>'
                                f'</div>', unsafe_allow_html=True)

# ── TAB 3: COMPLIANCE ───────────────────────────────
with tab_compliance:
    if not active_doc:
        _no_scan_state("📜", "Compliance Report Awaiting Data",
                       "Scan a document to see GDPR, PCI DSS, and DPDP violations.")
    else:
        violations = map_findings_to_standards(active_doc["findings"])
        cs1, cs2   = st.columns(2)
        with cs1:
            section_header("🇪🇺", "GDPR / DPDP India")
            pvs = list({v["value"]:v for v in violations["GDPR"]+violations["DPDP (India)"]}.values())
            if pvs:
                st.markdown(f'<div class="alert-box alert-box-danger"><span class="alert-box-icon">🚨</span><b>{len(pvs)} Personal Data Leaks</b></div>', unsafe_allow_html=True)
                for v in pvs:
                    cf = int(v["confidence"]*100) if v["confidence"]<=1.0 else int(v["confidence"])
                    st.markdown(f'<div class="violation-GDPR"><b>{v["type"]}:</b> {v["value"][:30]}… <span style="float:right;color:#38BDF8;font-size:0.75rem;">{cf}% conf</span></div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="alert-box alert-box-success"><span class="alert-box-icon">✅</span><b>Compliant</b> with GDPR &amp; DPDP</div>', unsafe_allow_html=True)
        with cs2:
            section_header("💳", "PCI DSS")
            fvs = violations["PCI DSS"]
            if fvs:
                st.markdown(f'<div class="alert-box alert-box-danger"><span class="alert-box-icon">🚨</span><b>{len(fvs)} Financial Exposure Items</b></div>', unsafe_allow_html=True)
                for v in fvs:
                    cf = int(v["confidence"]*100) if v["confidence"]<=1.0 else int(v["confidence"])
                    st.markdown(f'<div class="violation-PCIDSS"><b>{v["type"]}:</b> {v["value"][:30]}… <span style="float:right;color:#F87171;font-size:0.75rem;">{cf}% conf</span></div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="alert-box alert-box-success"><span class="alert-box-icon">✅</span><b>Compliant</b> with PCI DSS</div>', unsafe_allow_html=True)

        section_header("🛡️", "AI-Powered Remediation Plan")
        with st.spinner("Generating priority-ordered remediations…"):
            recs = generate_ai_recommendations(active_doc["findings"], api_key, api_provider)
        if not recs:
            st.markdown('<div class="empty-state" style="padding:48px 20px;"><span class="empty-state-icon">✅</span><div class="empty-state-title">No Actions Required</div></div>', unsafe_allow_html=True)
        else:
            for r in recs:
                prio = r.get("priority","Low")
                pc_map = {"Critical":("#EF4444","sev-critical"),"High":("#F59E0B","sev-high"),"Medium":("#FBBF24","sev-medium"),"Low":("#10B981","sev-low")}
                pc, ps = pc_map.get(prio,("#38BDF8","delta-info"))
                st.markdown(f'<div class="dashboard-card" style="border-left:4px solid {pc};">'
                            f'<span class="sev-badge {ps}">{prio}</span>'
                            f'<div style="font-weight:700;font-size:0.95rem;color:#F8FAFC;margin-top:8px;">{r.get("action","")}</div>'
                            f'<div style="font-size:0.84rem;color:#CBD5E1;margin-top:5px;">{r.get("reason","")}</div>'
                            f'<div style="font-size:0.75rem;color:#64748B;margin-top:8px;">📋 Standard: <b style="color:#94A3B8;">{r.get("standard","")}</b></div>'
                            f'</div>', unsafe_allow_html=True)

# ── TAB 4: REDACTION & EXPORT ───────────────────────
with tab_redact:
    if not active_doc:
        _no_scan_state("🔒", "Redaction Tools Awaiting Document",
                       "Scan a document to redact sensitive data and export compliance artifacts.")
    else:
        doc_text_html   = doc_text.replace("\n","<br>")
        masked_txt      = mask_text_content(doc_text, active_doc["findings"])
        masked_txt_html = masked_txt.replace("\n","<br>")
        ro, rm = st.columns(2)
        with ro:
            section_header("📄","Original Document")
            st.markdown(f'<div style="background:#111827;padding:18px;border-radius:10px;max-height:420px;overflow-y:scroll;border:1px solid rgba(255,255,255,0.07);line-height:1.6;font-size:0.85rem;color:#CBD5E1;">{doc_text_html}</div>', unsafe_allow_html=True)
        with rm:
            section_header("🔒","Redacted Preview")
            st.markdown(f'<div style="background:#0F172A;padding:18px;border-radius:10px;max-height:420px;overflow-y:scroll;border:1px solid rgba(239,68,68,0.2);line-height:1.6;font-size:0.85rem;color:#CBD5E1;font-family:monospace;">{masked_txt_html}</div>', unsafe_allow_html=True)

        section_header("📥","Export Security Artifacts")
        st.markdown('<div class="alert-box alert-box-info" style="margin-bottom:16px;"><span class="alert-box-icon">💡</span>All exports are security-hardened. Redacted PDFs use coordinate-precise black-block redaction.</div>', unsafe_allow_html=True)
        b1,b2,b3,b4,b5 = st.columns(5)
        with b1: st.download_button("📝 Redacted Text", data=masked_txt, file_name=f"redacted_{active_doc['file_name']}", mime="text/plain", use_container_width=True)
        with b2:
            if active_doc["file_name"].lower().endswith(".pdf"):
                st.download_button("🔒 Redacted PDF", data=redact_binary_pdf(active_doc["raw_bytes"],active_doc["findings"]), file_name=f"secure_redacted_{active_doc['file_name']}", mime="application/pdf", use_container_width=True)
            else: st.button("🔒 Redacted PDF", disabled=True, use_container_width=True)
        with b3:
            if active_doc["file_name"].lower().endswith(".pdf"):
                st.download_button("🟡 Highlighted PDF", data=highlight_binary_pdf(active_doc["raw_bytes"],active_doc["findings"]), file_name=f"highlighted_{active_doc['file_name']}", mime="application/pdf", use_container_width=True)
            else: st.button("🟡 Highlighted PDF", disabled=True, use_container_width=True)
        with b4:
            _recs_exp = generate_ai_recommendations(active_doc["findings"], api_key, api_provider)
            _pdf_rep  = generate_pdf_report(active_doc["file_name"], active_doc["risk_score"], active_doc["risk_level"], active_doc["findings"], _recs_exp)
            st.download_button("📊 Compliance PDF", data=_pdf_rep, file_name=f"Compliance_Report_{active_doc['file_name']}.pdf", mime="application/pdf", use_container_width=True)
        with b5:
            import json
            _fjson = json.dumps([{k:v for k,v in f.items() if k!="bbox"} for f in active_doc["findings"]], indent=2, default=str)
            st.download_button("{ } JSON Findings", data=_fjson, file_name=f"findings_{active_doc['file_name']}.json", mime="application/json", use_container_width=True)

# ── TAB 5: AI COPILOT ───────────────────────────────
with tab_qa:
    if not active_doc:
        _no_scan_state("💬", "AI Copilot Awaiting Document",
                       "Scan a document to start asking compliance questions using RAG-powered AI.")
    else:
        st.markdown('<div class="chat-container"><div class="chat-header"><div class="chat-header-avatar">🤖</div><div><div class="chat-header-name">Compliance AI Copilot</div><div class="chat-header-status">● Online · RAG-powered · Document-aware</div></div></div></div>', unsafe_allow_html=True)

        section_header("💡","Suggested Questions")
        sq_cols = st.columns(3)
        suggested = ["Summarize the compliance risks in this document","What PAN or Aadhaar numbers were found?",
                     "Explain the GDPR violations detected","List all API keys or credentials found",
                     "What are the top remediation priorities?","Is this document PCI DSS compliant?"]
        for i, sq in enumerate(suggested):
            with sq_cols[i%3]:
                if st.button(f"💬 {sq}", key=f"sq_{i}", use_container_width=True):
                    st.session_state.pending_question = sq

        section_header("💬","Chat History")
        if active_hash not in st.session_state.messages:
            st.session_state.messages[active_hash] = []

        if st.session_state.pending_question:
            _pq = st.session_state.pending_question
            st.session_state.pending_question = None
            st.session_state.messages[active_hash].append({"role":"user","content":_pq})
            if active_hash not in st.session_state.vector_stores:
                st.session_state.vector_stores[active_hash] = DocVectorStore(active_doc["text_content"])
            with st.spinner("AI Copilot is analysing…"):
                _r = ask_compliance_copilot(query=_pq, vector_store=st.session_state.vector_stores[active_hash],
                                            chat_history=st.session_state.messages[active_hash], api_key=api_key, provider=api_provider)
            st.session_state.messages[active_hash].append({"role":"assistant","content":_r})

        if not st.session_state.messages[active_hash]:
            st.markdown('<div class="empty-state" style="padding:40px 20px;"><span class="empty-state-icon">💬</span><div class="empty-state-title">Start a Conversation</div><div class="empty-state-sub">Ask about compliance risks, data exposures, or remediation advice.</div></div>', unsafe_allow_html=True)

        for msg in st.session_state.messages[active_hash]:
            with st.chat_message(msg["role"]): st.write(msg["content"])

        c_chat, c_clear = st.columns([5,1])
        with c_chat:  user_query = st.chat_input("Ask about the document…")
        with c_clear:
            if st.button("🗑️ Clear", use_container_width=True):
                st.session_state.messages[active_hash] = []
                st.rerun()

        if user_query:
            with st.chat_message("user"): st.write(user_query)
            st.session_state.messages[active_hash].append({"role":"user","content":user_query})
            if active_hash not in st.session_state.vector_stores:
                st.session_state.vector_stores[active_hash] = DocVectorStore(active_doc["text_content"])
            with st.spinner("AI Copilot is reviewing document index…"):
                response = ask_compliance_copilot(query=user_query, vector_store=st.session_state.vector_stores[active_hash],
                                                  chat_history=st.session_state.messages[active_hash], api_key=api_key, provider=api_provider)
            with st.chat_message("assistant"): st.write(response)
            st.session_state.messages[active_hash].append({"role":"assistant","content":response})


# ── TAB 6: ABOUT PROJECT ────────────────────────────
with tab_about:
    section_header("ℹ️", "About Sensitive Data Detection & Compliance Suite")
    
    st.markdown("""
    <div style="background:rgba(30,41,59,0.4); padding:24px; border-radius:12px; border:1px solid rgba(255,255,255,0.06); line-height:1.75; color:#CBD5E1;">
      <h3 style="font-family:'Outfit',sans-serif; color:#F8FAFC; margin-top:0;">🛡️ Project Vision</h3>
      ComplianceAI is an enterprise-grade security and regulatory auditing assistant. It enables security teams, risk assessors, and developers to upload unstructured text, CSV, and PDF documents, identify sensitive personal data (PII) or corporate credentials, perform permanent black-block coordinate redaction, map risks to global standards, and converse with the document using context-aware AI.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Grid of Features
    f1, f2 = st.columns(2)
    with f1:
        st.markdown("""
        <div class="dashboard-card" style="height:100%; border-left:3px solid var(--primary);">
          <div style="font-size:1.2rem; margin-bottom:8px;">🔍 <b>Multi-Stage Detection Engine</b></div>
          Fuses structural regex engines, Luhn algorithms (credit cards), and local <b>spaCy NER</b> models with context-aware LLMs to accurately isolate vulnerabilities.
        </div>
        """, unsafe_allow_html=True)
    with f2:
        st.markdown("""
        <div class="dashboard-card" style="height:100%; border-left:3px solid var(--success);">
          <div style="font-size:1.2rem; margin-bottom:8px;">🔒  <b>Coordinate-Precise Redaction</b></div>
          Permanently burns black redaction boxes onto binary PDFs at exact coordinates using PyMuPDF, protecting corporate data before export.
        </div>
        """, unsafe_allow_html=True)
        
    f3, f4 = st.columns(2)
    with f3:
        st.markdown("""
        <div class="dashboard-card" style="height:100%; border-left:3px solid var(--accent);">
          <div style="font-size:1.2rem; margin-bottom:8px;">📜 <b>Regulatory Compliance Maps</b></div>
          Automatically categories exposures and links findings to regulatory clauses of <b>GDPR</b> (Europe), <b>PCI DSS</b> (Finance), and the <b>DPDP Act</b> (India).
        </div>
        """, unsafe_allow_html=True)
    with f4:
        st.markdown("""
        <div class="dashboard-card" style="height:100%; border-left:3px solid var(--warning);">
          <div style="font-size:1.2rem; margin-bottom:8px;">💬 <b>RAG Document Copilot</b></div>
          Employs Sentence Transformers and local <b>FAISS</b> vector indexes to execute context-bounded Q&A without leaking text to external models.
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    
    # Architecture Overview
    section_header("🏛️", "Architecture Pipeline Flowchart")
    st.markdown("""
    <div style="background:#111827; padding:20px; border-radius:10px; border:1px solid rgba(255,255,255,0.06); font-family:monospace; font-size:0.8rem; overflow-x:auto; color:#94A3B8;">
    [Uploaded Files: PDF/TXT/CSV] ➔ [Document Parsers] ➔ (OCR Fallback via Tesseract & PyMuPDF Pixmaps)<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;➔ [Multi-Stage Scan Pipeline]<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1. Regex Patterns (Aadhaar, PAN, CC, Emails)<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2. spaCy NER (Persons, Organizations, Locations)<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3. Entropy Engine (Passwords, Secrets, API Keys)<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4. AI Hybrid Verification (FPR minimization)<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;➔ [Risk Assessor & Compliance Mapping]<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;➔ [Redaction Engine] &amp; [FAISS vector indexing]<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;➔ [Interactive Audit Logs & PDF Reports Export]
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)

    # Math details
    section_header("🧠", "AI/ML Technical Specifications")
    
    math_col1, math_col2 = st.columns(2)
    with math_col1:
        st.markdown("##### 1. Logarithmic Weighted Risk Score Formulation")
        st.write("To prevent score inflation from repetitive exposures (e.g. 100 emails in one file), overall document risk is computed logarithmically:")
        st.latex(r"Risk = \min\left(100, \sum_{k \in \text{Categories}} W_k \cdot \overline{C_k} \cdot \log_{2}(N_k + 1)\right)")
        st.markdown("""
        * $W_k$ represents severity weights (Critical=25, High=15, Medium=5, Low=2).
        * $\overline{C_k}$ represents the average scan confidence for category $k$.
        * $N_k$ represents the frequency count of matching findings.
        """)
        
    with math_col2:
        st.markdown("##### 2. Confidence & Similarity Matching")
        st.write("Fusing pattern signals with context nearby is modeled as:")
        st.latex(r"Confidence = w_{pat} \cdot S_{pat} + w_{val} \cdot S_{val} + w_{ctx} \cdot S_{ctx}")
        st.write("For vector similarity search in the RAG pipeline, we normalized vectors and execute cosine similarity checks inside FAISS:")
        st.latex(r"\text{Cosine Similarity}(u, v) = \frac{u \cdot v}{\|u\| \|v\|}")
        
    st.markdown("<br>", unsafe_allow_html=True)

    # Tech Stack
    section_header("💻", "Technologies & Frameworks")
    t1, t2, t3 = st.columns(3)
    with t1:
        st.markdown("""
        <b>Frontend & UI:</b>
        - Streamlit Dashboard Framework
        - Plotly (Dynamic charts & risk dials)
        - Custom CSS styling system
        """, unsafe_allow_html=True)
    with t2:
        st.markdown("""
        <b>NLP & Document Parsing:</b>
        - spaCy (NER Pipeline)
        - PyMuPDF / pdfplumber (PDF extraction)
        - Tesseract OCR (Image scan parser)
        """, unsafe_allow_html=True)
    with t3:
        st.markdown("""
        <b>AI & Search Index:</b>
        - FAISS (Cosine Similarity vector store)
        - Sentence Transformers (`all-MiniLM-L6-v2`)
        - Groq, OpenAI, Gemini, & HF models
        """, unsafe_allow_html=True)

# ── TAB 7: AUDIT LOGS  (always functional) ──────────
with tab_audits:
    section_header("📂","System Compliance Audit Logs")
    st.markdown('<div class="alert-box alert-box-info" style="margin-bottom:16px;"><span class="alert-box-icon">🔒</span>Audit logs are cryptographically secured. No raw PII stored — only file hashes, risk metadata, and timestamps.</div>', unsafe_allow_html=True)
    logs = get_audit_logs()
    if logs:
        st.dataframe(pd.DataFrame(logs), use_container_width=True, hide_index=True)
        st.download_button("⬇️ Export Audit Logs (JSON)", data="\n".join(str(l) for l in logs), file_name="compliance_audit_logs.txt", mime="text/plain")
    else:
        st.markdown('<div class="empty-state" style="padding:64px 20px;"><span class="empty-state-icon">📂</span><div class="empty-state-title">No Audit Logs Yet</div><div class="empty-state-sub">Upload and scan a document to generate audit trail entries.</div></div>', unsafe_allow_html=True)



# ---------------------------------------------------------
# FOOTER (fixed at bottom)
# ---------------------------------------------------------
st.markdown("""
<footer class="ent-footer">
  <!-- Left: copyright -->
  <div class="footer-copy">
    <span>© 2025</span>
    <b>ComplianceAI</b>
    <span>·</span>
    <span>Made with <span class="footer-heart">♥</span> for Data Security</span>
  </div>

  <!-- Center: standards -->
  <div class="footer-badges">
    <span class="footer-badge active-badge">GDPR</span>
    <span class="footer-badge active-badge">PCI DSS</span>
    <span class="footer-badge active-badge">DPDP</span>
    <span class="footer-badge">ISO 27001</span>
    <span class="footer-badge">HIPAA</span>
    <span class="footer-badge">SOC 2</span>
  </div>

  <!-- Right: links + live -->
  <div class="footer-right">
    <a class="footer-link" href="https://sensitive-data-detection-compliance-assistant.streamlit.app/" target="_blank">🔗 Live Demo</a>
    <a class="footer-link" href="https://github.com/iamkanhaiyakumar/Compliance-Assistant" target="_blank">GitHub</a>
    <div class="footer-live">
      <div class="footer-live-dot"></div>
      Live
    </div>
  </div>
</footer>
""", unsafe_allow_html=True)
