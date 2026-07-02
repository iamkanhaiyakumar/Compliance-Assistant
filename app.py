import streamlit as st
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
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.HexColor("#1e3a8a"),
        spaceAfter=15
    )
    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=colors.HexColor("#1e3a8a"),
        spaceBefore=15,
        spaceAfter=10
    )
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['BodyText'],
        fontSize=10,
        leading=14
    )
    
    story = []
    
    # Title
    story.append(Paragraph("Security Compliance Audit Report", title_style))
    story.append(Spacer(1, 10))
    
    # Overview Table
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
    
    # Findings Section
    story.append(Paragraph("Sensitive Data Findings", h1_style))
    findings_data = [["Type", "Matched Value", "Method", "Confidence", "Severity"]]
    
    for f in findings:
        val_str = str(f["value"])
        # Obfuscate matched values in PDF report to preserve confidentiality
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
    
    # Recommendations Section
    story.append(Paragraph("Actionable Security Remediation Plan", h1_style))
    for idx, rec in enumerate(recommendations):
        story.append(Paragraph(f"<b>{idx+1}. [{rec.get('priority', 'Low').upper()}] {rec.get('action', '')}</b>", body_style))
        story.append(Paragraph(f"<i>Why:</i> {rec.get('reason', '')} (Standard: {rec.get('standard', '')})", body_style))
        story.append(Spacer(1, 10))
        
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

# ---------------------------------------------------------
# Page Configurations & CSS Styling
# ---------------------------------------------------------
st.set_page_config(
    page_title="Compliance Assistant",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load Premium CSS Styles from file
try:
    with open("style.css", "r", encoding="utf-8") as f:
        css_content = f.read()
    st.markdown(f"<style>{css_content}</style>", unsafe_allow_html=True)
except Exception as e:
    st.warning("Failed to load external CSS styling file.")

# ---------------------------------------------------------
# Sidebar Configuration
# ---------------------------------------------------------
st.sidebar.image("https://img.icons8.com/nolan/96/shield.png", width=60)
st.sidebar.title("Compliance Assistant")
st.sidebar.caption("AI-Powered Sensitive Data Detection & Audit Suite")

st.sidebar.subheader("🔒 Key Configurations")
use_paid = st.sidebar.toggle(
    "Use Paid Models (Gemini/OpenAI)", 
    value=False, 
    help="Enable this to override the default free Groq scanner with a paid API key."
)

if use_paid:
    api_provider = st.sidebar.selectbox("Paid LLM Provider", ["Gemini", "OpenAI"])
    default_key = os.getenv("GEMINI_API_KEY") if api_provider == "Gemini" else os.getenv("OPENAI_API_KEY")
    api_key = st.sidebar.text_input(
        f"{api_provider} API Key",
        value=default_key or "",
        type="password",
        help="Used for context-aware validation, recommendations, and Document QA Chat."
    )
else:
    api_provider = "Groq"
    # Load Groq key from environment
    groq_env_key = os.getenv("GROQ_API_KEY")
    
    if groq_env_key:
        api_key = groq_env_key
        st.sidebar.success("⚡ Running on Free & Fast Groq Engine (Key loaded from env)")
    else:
        api_key = st.sidebar.text_input(
            "Groq API Key (Paste here if not in .env)",
            value="",
            type="password",
            help="Get your free key from console.groq.com"
        )
        if api_key:
            st.sidebar.success("⚡ Running on Free & Fast Groq Engine")
        else:
            st.sidebar.info("💡 Get a free API key at console.groq.com to enable AI features, or toggle to Paid Models.")

scan_depth = st.sidebar.radio(
    "Scan Depth Mode",
    ["Fast Scan (Regex + spaCy NER)", "Deep Scan (AI-Assisted Hybrid)"],
    help="Deep Scan invokes the LLM to verify findings, detect custom employee IDs, and confidential business secrets."
)

# Session Scanned History tracking
if "scan_history" not in st.session_state:
    st.session_state.scan_history = {}
if "vector_stores" not in st.session_state:
    st.session_state.vector_stores = {}
if "messages" not in st.session_state:
    st.session_state.messages = {}

# Load Premium Header Banner from HTML file
try:
    with open("header_template.html", "r", encoding="utf-8") as f:
        header_html = f.read()
    st.markdown(header_html, unsafe_allow_html=True)
except Exception as e:
    pass

# ---------------------------------------------------------
# Document Upload Form
# ---------------------------------------------------------
st.subheader("📁 Upload Files for Compliance Scan")
uploaded_files = st.file_uploader(
    "Drag & drop documents here (Supported: PDF, TXT, CSV)",
    type=["pdf", "txt", "csv"],
    accept_multiple_files=True
)

# ---------------------------------------------------------
# Background Multi-File Scanning Logic
# ---------------------------------------------------------
if uploaded_files:
    # Process scan triggers
    scan_triggered = st.button("🚀 Execute Security Audit")
    
    if scan_triggered:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for idx, file in enumerate(uploaded_files):
            file_bytes = file.read()
            file_hash = get_file_hash(file_bytes)
            
            status_text.text(f"Auditing file {idx+1}/{len(uploaded_files)}: '{file.name}'...")
            progress_bar.progress(int(((idx) / len(uploaded_files)) * 100))
            
            # Check Cache
            cached = get_cached_scan(file_hash)
            if cached:
                st.session_state.scan_history[file_hash] = cached
                # Instantiate RAG vector store for the session
                if file_hash not in st.session_state.vector_stores:
                    st.session_state.vector_stores[file_hash] = DocVectorStore(cached["text_content"])
                continue
                
            # Perform Fresh Scan
            start_time = time.perf_counter()
            
            # Parse File
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
                st.error(f"Failed parsing file '{file.name}': {str(e)}")
                continue
                
            # Step 1: Regex & Entropy Scan
            regex_findings = run_regex_and_entropy_scan(text_content)
            
            # Step 2: spaCy NER Scan
            ner_findings = run_spacy_ner_scan(text_content, regex_findings)
            combined_findings = regex_findings + ner_findings
            
            # Step 3: LLM Hybrid Scanner
            if "Deep Scan" in scan_depth and api_key:
                final_findings = run_llm_hybrid_scan(text_content, combined_findings, api_key, api_provider)
            else:
                final_findings = combined_findings
                
            # Calculate Risk Scores
            risk_score, risk_level, reason_summary = calculate_risk_metrics(final_findings)
            
            # Persist to Cache Database
            cache_scan(file_hash, file.name, text_content, final_findings, risk_score, risk_level, file_bytes)
            
            # Create session store
            st.session_state.vector_stores[file_hash] = DocVectorStore(text_content)
            
            # Record Session History
            st.session_state.scan_history[file_hash] = {
                "file_name": file.name,
                "text_content": text_content,
                "findings": final_findings,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "raw_bytes": file_bytes,
                "pages_data": pages_data
            }
            
            # Write Secure Log
            scan_duration = int((time.perf_counter() - start_time) * 1000)
            log_audit_event(
                action="SCAN_DOCUMENT",
                file_name=file.name,
                file_hash=file_hash,
                risk_score=risk_score,
                risk_level=risk_level,
                duration_ms=scan_duration
            )
            
        progress_bar.progress(100)
        status_text.text("Security audit completed for all uploaded files!")
        st.toast("Compliance Audit Complete!", icon="🛡️")
        time.sleep(1)
        status_text.empty()

# ---------------------------------------------------------
# Multi-File Comparison Table
# ---------------------------------------------------------
if st.session_state.scan_history:
    st.markdown("### 📊 Multi-Document Compliance Matrix")
    comparison_data = []
    
    for f_hash, data in st.session_state.scan_history.items():
        comparison_data.append({
            "File Hash": f_hash[:10] + "...",
            "File Name": data["file_name"],
            "Risk Score": data["risk_score"],
            "Risk Level": data["risk_level"],
            "Total Findings": len(data["findings"])
        })
        
    df_compare = pd.DataFrame(comparison_data)
    st.dataframe(df_compare, use_container_width=True, hide_index=True)
    
    # Selection of Active Document to display detailed reports
    st.markdown("### 🔍 Select Document for Deep Dive Analysis")
    selected_file_name = st.selectbox(
        "Choose file to analyze details:",
        options=[data["file_name"] for data in st.session_state.scan_history.values()]
    )
    
    # Locate selected document hash
    active_hash = next(
        h for h, data in st.session_state.scan_history.items() 
        if data["file_name"] == selected_file_name
    )
    active_doc = st.session_state.scan_history[active_hash]
    
    # -----------------------------------------------------
    # Detailed Tabs Layout
    # -----------------------------------------------------
    tab_dashboard, tab_scanner, tab_compliance, tab_redact, tab_qa, tab_audits = st.tabs([
        "📊 Dashboard Overview", 
        "🔍 Interactive Scanner", 
        "📜 Compliance & Action Plan", 
        "🔒 Redaction & Export", 
        "💬 AI Copilot Chat",
        "📂 Secure Audit Logs"
    ])
    
    # -----------------------------------------------------
    # Tab 1: Dashboard Overview
    # -----------------------------------------------------
    with tab_dashboard:
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        
        # Metric Cards
        with col_m1:
            st.markdown(
                f'<div class="dashboard-card"><div class="metric-value">{active_doc["risk_score"]}/100</div><div class="metric-label">Risk Score</div></div>',
                unsafe_allow_html=True
            )
        with col_m2:
            st.markdown(
                f'<div class="dashboard-card"><div class="metric-value">{active_doc["risk_level"]}</div><div class="metric-label">Risk Level</div></div>',
                unsafe_allow_html=True
            )
        with col_m3:
            st.markdown(
                f'<div class="dashboard-card"><div class="metric-value">{len(active_doc["findings"])}</div><div class="metric-label">Sensitive Items</div></div>',
                unsafe_allow_html=True
            )
        with col_m4:
            word_count = len(active_doc["text_content"].split())
            st.markdown(
                f'<div class="dashboard-card"><div class="metric-value">{word_count}</div><div class="metric-label">Word Count</div></div>',
                unsafe_allow_html=True
            )
            
        col_chart1, col_chart2 = st.columns([1, 1])
        
        # Risk gauge chart
        with col_chart1:
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=active_doc["risk_score"],
                domain={'x': [0, 1], 'y': [0, 1]},
                gauge={
                    'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "#475569"},
                    'bar': {'color': "#3b82f6"},
                    'bgcolor': "rgba(0,0,0,0)",
                    'borderwidth': 1.5,
                    'bordercolor': "#475569",
                    'steps': [
                        {'range': [0, 30], 'color': 'rgba(34, 197, 94, 0.25)'},
                        {'range': [30, 70], 'color': 'rgba(234, 179, 8, 0.25)'},
                        {'range': [70, 100], 'color': 'rgba(239, 68, 68, 0.25)'}
                    ]
                }
            ))
            fig_gauge.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': "#f8fafc", 'family': "Inter"},
                height=250,
                margin=dict(t=20, b=10, l=20, r=20)
            )
            st.plotly_chart(fig_gauge, use_container_width=True)
            
        # Findings Pie Chart
        with col_chart2:
            if active_doc["findings"]:
                finding_counts = {}
                for f in active_doc["findings"]:
                    finding_counts[f["type"]] = finding_counts.get(f["type"], 0) + 1
                    
                df_pie = pd.DataFrame([
                    {"Type": k, "Count": v} for k, v in finding_counts.items()
                ])
                fig_pie = px.pie(
                    df_pie, 
                    names="Type", 
                    values="Count", 
                    hole=0.4,
                    color_discrete_sequence=px.colors.qualitative.Safe
                )
                fig_pie.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    font={'color': "#f8fafc", 'family': "Inter"},
                    height=250,
                    margin=dict(t=20, b=10, l=10, r=10),
                    showlegend=True
                )
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.info("No charts to display - document is clean.")
                
        # Risk Reason Summary Explainer
        st.markdown("### 💬 Risk Assessment Details")
        st.info(active_doc["risk_level"])
        _, _, reason_summary = calculate_risk_metrics(active_doc["findings"])
        st.markdown(reason_summary.replace("\n", "<br>"), unsafe_allow_html=True)
        
    # -----------------------------------------------------
    # Tab 2: Interactive Scanner
    # -----------------------------------------------------
    with tab_scanner:
        col_scan_left, col_scan_right = st.columns([2, 1])
        
        with col_scan_left:
            st.markdown("### 📄 Document Text Viewer")
            show_highlights = st.checkbox("Highlight Sensitive Information", value=True)
            
            # Simple substring advanced search feature
            search_query = st.text_input("🔍 Search within Document:", "")
            
            doc_text = active_doc["text_content"]
            
            if show_highlights:
                highlighted_html = generate_html_highlighted_text(doc_text, active_doc["findings"])
            else:
                highlighted_html = doc_text.replace("\n", "<br>")
                
            # Perform advanced search highlighting
            if search_query:
                # Compile regex search pattern
                pattern = re.compile(re.escape(search_query), re.IGNORECASE)
                matches = list(pattern.finditer(highlighted_html))
                if matches:
                    st.success(f"Found {len(matches)} matches for '{search_query}'.")
                    # Wrap query matches with highlights
                    highlighted_html = pattern.sub(
                        lambda m: f'<span class="search-match">{m.group()}</span>',
                        highlighted_html
                    )
                else:
                    st.warning("No matches found.")
                    
            st.markdown(
                f'<div style="background-color: #1a1f2c; padding: 20px; border-radius: 8px; max-height: 500px; overflow-y: scroll; border: 1px solid #2d3748; line-height: 1.6; font-size: 0.95rem; color: #cbd5e1;">{highlighted_html}</div>',
                unsafe_allow_html=True
            )
            
        with col_scan_right:
            st.markdown("### 🔎 Detection Explainability")
            if not active_doc["findings"]:
                st.success("Clean document! No sensitive findings to report.")
            else:
                for idx, f in enumerate(active_doc["findings"]):
                    conf_pct = int(f["confidence"] * 100) if f["confidence"] <= 1.0 else int(f["confidence"])
                    severity_color = SEVERITY_COLORS.get(f.get("severity", "Low"), "#eeeeee")
                    
                    st.markdown(f"""
                        <div class="dashboard-card" style="border-left: 5px solid {severity_color}; margin-bottom: 10px;">
                            <div style="font-weight: 700; color: #f8fafc; font-size: 1.05rem;">{f['type']}</div>
                            <div style="font-family: monospace; font-size: 0.9rem; color: #94a3b8; background-color: rgba(0,0,0,0.2); padding: 4px; border-radius: 4px; margin: 4px 0;">{f['value']}</div>
                            <div style="font-size: 0.85rem; color: #cbd5e1; margin-top: 5px;">
                                <b>Method:</b> {f['method']}<br>
                                <b>Confidence:</b> {conf_pct}%<br>
                                <b>Reason:</b> {f['reason']}<br>
                                <b>Severity:</b> <span style="color: {severity_color}; font-weight: bold;">{f.get('severity', 'Low')}</span>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    
    # -----------------------------------------------------
    # Tab 3: Compliance & Action Plan
    # -----------------------------------------------------
    with tab_compliance:
        st.markdown("### 📋 Regulatory Standards Violations")
        violations = map_findings_to_standards(active_doc["findings"])
        
        col_std1, col_std2 = st.columns(2)
        with col_std1:
            st.markdown("#### 🇪🇺 GDPR / 🇮🇳 DPDP violations")
            personal_data_violations = violations["GDPR"] + violations["DPDP (India)"]
            # Deduplicate items
            personal_data_violations = {v["value"]: v for v in personal_data_violations}.values()
            
            if personal_data_violations:
                st.error(f"🚨 {len(personal_data_violations)} Personal Data leaks detected!")
                for v in personal_data_violations:
                    st.markdown(f'<div class="violation-GDPR"><b>{v["type"]}:</b> {v["value"][:25]}... (Confidence: {int(v["confidence"]*100)}%)</div>', unsafe_allow_html=True)
            else:
                st.success("✅ Compliant with GDPR & DPDP standards.")
                
        with col_std2:
            st.markdown("#### 💳 PCI DSS violations")
            financial_violations = violations["PCI DSS"]
            if financial_violations:
                st.error(f"🚨 {len(financial_violations)} Financial exposure items detected!")
                for v in financial_violations:
                    st.markdown(f'<div class="violation-PCIDSS"><b>{v["type"]}:</b> {v["value"][:25]}... (Confidence: {int(v["confidence"]*100)}%)</div>', unsafe_allow_html=True)
            else:
                st.success("✅ Compliant with PCI DSS regulations.")
                
        st.markdown("---")
        st.markdown("### 🛡️ Actions & Remediation Plan (Priority-wise)")
        
        # Load AI recommendations
        with st.spinner("Generating prioritized remediations..."):
            recs = generate_ai_recommendations(active_doc["findings"], api_key, api_provider)
            
        for r in recs:
            prio = r.get("priority", "Low")
            badge_color = "#ef4444" if prio == "Critical" else "#f97316" if prio == "High" else "#eab308" if prio == "Medium" else "#3b82f6"
            
            st.markdown(f"""
                <div class="dashboard-card" style="border-left: 4px solid {badge_color};">
                    <span style="background-color: {badge_color}; color: black; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 0.75rem; text-transform: uppercase;">
                        {prio}
                    </span>
                    <div style="font-weight: 700; font-size: 1.1rem; margin-top: 5px; color: #f8fafc;">{r.get('action', '')}</div>
                    <div style="font-size: 0.95rem; color: #cbd5e1; margin-top: 4px;">{r.get('reason', '')}</div>
                    <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 6px;"><b>Violated standard:</b> {r.get('standard', '')}</div>
                </div>
            """, unsafe_allow_html=True)
            
    # -----------------------------------------------------
    # Tab 4: Redaction & Export
    # -----------------------------------------------------
    with tab_redact:
        col_red_orig, col_red_masked = st.columns(2)
        
        # Pre-compute HTML replaced texts to avoid f-string backslash limits in Python < 3.12
        doc_text_html = doc_text.replace("\n", "<br>")
        masked_txt = mask_text_content(doc_text, active_doc["findings"])
        masked_txt_html = masked_txt.replace("\n", "<br>")
        
        with col_red_orig:
            st.markdown("#### Original Document View")
            st.markdown(
                f'<div style="background-color: #1a1f2c; padding: 18px; border-radius: 8px; max-height: 400px; overflow-y: scroll; border: 1px solid #2d3748; line-height: 1.5; font-size: 0.9rem;">{doc_text_html}</div>',
                unsafe_allow_html=True
            )
            
        with col_red_masked:
            st.markdown("#### Masked Document Preview")
            st.markdown(
                f'<div style="background-color: #1e1e1e; padding: 18px; border-radius: 8px; max-height: 400px; overflow-y: scroll; border: 1px solid #ff4d4d; line-height: 1.5; font-size: 0.9rem; font-family: monospace;">{masked_txt_html}</div>',
                unsafe_allow_html=True
            )
            
        st.markdown("---")
        st.markdown("### 📥 Download Security Artifacts")
        
        col_btn1, col_btn2, col_btn3, col_btn4 = st.columns(4)
        
        # 1. Download Redacted Document (TXT/CSV)
        with col_btn1:
            st.download_button(
                "⬇️ Download Redacted Text",
                data=masked_txt,
                file_name=f"redacted_{active_doc['file_name']}",
                mime="text/plain"
            )
            
        # 2. Download Redacted PDF (Black Blocks)
        with col_btn2:
            if active_doc["file_name"].lower().endswith(".pdf"):
                raw_bytes = active_doc["raw_bytes"]
                redacted_pdf_bytes = redact_binary_pdf(raw_bytes, active_doc["findings"])
                st.download_button(
                    "⬇️ Download Redacted PDF",
                    data=redacted_pdf_bytes,
                    file_name=f"secure_redacted_{active_doc['file_name']}",
                    mime="application/pdf"
                )
            else:
                st.button("⬇️ Download Redacted PDF", disabled=True, help="Only available for PDF file uploads.")
                
        # 3. Download Highlighted PDF
        with col_btn3:
            if active_doc["file_name"].lower().endswith(".pdf"):
                raw_bytes = active_doc["raw_bytes"]
                highlighted_pdf_bytes = highlight_binary_pdf(raw_bytes, active_doc["findings"])
                st.download_button(
                    "⬇️ Download Highlighted PDF",
                    data=highlighted_pdf_bytes,
                    file_name=f"highlighted_{active_doc['file_name']}",
                    mime="application/pdf"
                )
            else:
                st.button("⬇️ Download Highlighted PDF", disabled=True, help="Only available for PDF file uploads.")
                
        # 4. Download ReportLab Compliance PDF Report
        with col_btn4:
            pdf_report_bytes = generate_pdf_report(
                active_doc["file_name"],
                active_doc["risk_score"],
                active_doc["risk_level"],
                active_doc["findings"],
                recs
            )
            st.download_button(
                "🏆 Download Compliance Report (PDF)",
                data=pdf_report_bytes,
                file_name=f"Compliance_Report_{active_doc['file_name']}.pdf",
                mime="application/pdf"
            )
            
    # -----------------------------------------------------
    # Tab 5: AI Compliance Copilot Chat
    # -----------------------------------------------------
    with tab_qa:
        st.markdown("### 💬 AI Compliance Copilot (RAG Document QA)")
        st.caption("Ask questions like 'What PAN numbers exist?', 'Explain the GDPR compliance issues here', or 'Summarize the secrets found'")
        
        # Get session messages for active document
        if active_hash not in st.session_state.messages:
            st.session_state.messages[active_hash] = []
            
        # Display chat history
        for msg in st.session_state.messages[active_hash]:
            with st.chat_message(msg["role"]):
                st.write(msg["content"])
                
        # Chat input box
        user_query = st.chat_input("Ask a question about the document:")
        if user_query:
            # Display user message
            with st.chat_message("user"):
                st.write(user_query)
            st.session_state.messages[active_hash].append({"role": "user", "content": user_query})
            
            # Lazy initialize vector store if missing from session state
            if active_hash not in st.session_state.vector_stores:
                st.session_state.vector_stores[active_hash] = DocVectorStore(active_doc["text_content"])
            
            # Run QA retrieval & answer generation
            with st.spinner("AI Copilot is reviewing document index..."):
                response = ask_compliance_copilot(
                    query=user_query,
                    vector_store=st.session_state.vector_stores[active_hash],
                    chat_history=st.session_state.messages[active_hash],
                    api_key=api_key,
                    provider=api_provider
                )
                
            # Display assistant response
            with st.chat_message("assistant"):
                st.write(response)
            st.session_state.messages[active_hash].append({"role": "assistant", "content": response})

    # -----------------------------------------------------
    # Tab 6: Audit Logs & Administrative Panel
    # -----------------------------------------------------
    with tab_audits:
        st.markdown("### 📂 System Compliance Audit Logs")
        st.caption("Administrative log displaying scanning activities, risk metrics, and timestamps without exposing raw values.")
        
        logs = get_audit_logs()
        if logs:
            df_logs = pd.DataFrame(logs)
            st.dataframe(df_logs, use_container_width=True)
            
            # Download logs
            log_str = "\n".join(str(log) for log in logs)
            st.download_button(
                "⬇️ Export JSON Audit Logs",
                data=log_str,
                file_name="compliance_audit_logs.txt",
                mime="text/plain"
            )
        else:
            st.info("No compliance audit logs recorded yet in this session.")
else:
    # Upload Prompt when no files uploaded
    st.info("👋 Welcome! Please upload documents in the form above and click 'Execute Security Audit' to start.")
