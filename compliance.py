import math
import json
import google.generativeai as genai
from openai import OpenAI
import requests

# ---------------------------------------------------------
# Risk Metrics Calculation
# ---------------------------------------------------------
SEVERITY_WEIGHTS = {
    "Aadhaar": 15,
    "PAN": 15,
    "Credit Card": 25,
    "Email": 2,
    "Phone": 5,
    "IFSC": 15,
    "API Key": 25,
    "Password": 25,
    "Employee ID": 5,
    "Confidential Business Information": 15,
    "Person Name": 5,
    "Organization": 5,
    "Location": 2
}

COMPLIANCE_MAPS = {
    "Aadhaar": ["GDPR", "DPDP (India)"],
    "PAN": ["GDPR", "DPDP (India)"],
    "Credit Card": ["PCI DSS"],
    "Email": ["GDPR", "DPDP (India)"],
    "Phone": ["GDPR", "DPDP (India)"],
    "IFSC": ["PCI DSS"],
    "API Key": ["ISO 27001", "NIST CSF"],
    "Password": ["ISO 27001", "NIST CSF"],
    "Employee ID": ["GDPR", "DPDP (India)"],
    "Confidential Business Information": ["ISO 27001", "NIST CSF"],
    "Person Name": ["GDPR", "DPDP (India)"],
    "Organization": ["ISO 27001"],
    "Location": ["GDPR"]
}

def calculate_risk_metrics(findings: list[dict]) -> tuple[float, str, str]:
    """
    Calculates overall document Risk Score (0-100) using a logarithmic frequency scale
    to prevent repetitive items from inflating scores artificially.
    """
    if not findings:
        return 0.0, "Low Risk", "No sensitive data was detected in this document."
        
    # Group findings by type
    grouped = {}
    for f in findings:
        t = f["type"]
        if t not in grouped:
            grouped[t] = []
        grouped[t].append(f)
        
    total_score = 0.0
    reason_lines = []
    
    for t_type, items in grouped.items():
        w_k = SEVERITY_WEIGHTS.get(t_type, 5)
        n_k = len(items)
        # Average confidence score (between 0.0 and 1.0)
        avg_c_k = sum(f.get("confidence", 0.8) for f in items) / n_k
        if avg_c_k > 1.0: # handle percentage check
            avg_c_k /= 100.0 if avg_c_k > 1.0 else 1.0
            
        # Logarithmic scaling term: log2(n + 1)
        sub_score = w_k * avg_c_k * math.log2(n_k + 1)
        total_score += sub_score
        
        # Build explanation statement
        sev_label = "Critical" if w_k >= 25 else "High" if w_k >= 15 else "Medium" if w_k >= 5 else "Low"
        reason_lines.append(f"• {n_k}x {t_type} ({sev_label} Severity)")
        
    risk_score = min(100.0, round(total_score, 1))
    
    # Classify Risk Level
    if risk_score <= 30:
        level = "Low"
    elif risk_score <= 70:
        level = "Medium"
    else:
        level = "High"
        
    reason_summary = "Risk triggered by:\n" + "\n".join(reason_lines)
    return risk_score, level, reason_summary

# ---------------------------------------------------------
# Regulatory Mapping
# ---------------------------------------------------------
def map_findings_to_standards(findings: list[dict]) -> dict:
    """Maps findings to key compliance regulations."""
    violations = {
        "GDPR": [],
        "DPDP (India)": [],
        "PCI DSS": [],
        "ISO 27001": [],
        "NIST CSF": []
    }
    
    for f in findings:
        standards = COMPLIANCE_MAPS.get(f["type"], [])
        for std in standards:
            if std in violations:
                violations[std].append(f)
                
    return violations

# ---------------------------------------------------------
# Dynamic AI Recommendations
# ---------------------------------------------------------
def generate_ai_recommendations(findings: list[dict], api_key: str, provider: str = "Gemini") -> list[dict]:
    """Generates structured, dynamic recommendations from LLM, with local fallback."""
    if not findings:
        return [{
            "priority": "Low",
            "action": "Maintain monitoring",
            "reason": "No immediate risks were detected.",
            "standard": "N/A"
        }]
        
    # Group findings to send a clean summary to the LLM
    summary_map = {}
    for f in findings:
        summary_map[f["type"]] = summary_map.get(f["type"], 0) + 1
        
    summary_str = ", ".join(f"{count}x {t_type}" for t_type, count in summary_map.items())
    
    # Static fallback recommendations
    static_recs = []
    priorities = {"Critical": [], "High": [], "Medium": [], "Low": []}
    
    for t_type, count in summary_map.items():
        weight = SEVERITY_WEIGHTS.get(t_type, 5)
        prio = "Critical" if weight >= 25 else "High" if weight >= 15 else "Medium" if weight >= 5 else "Low"
        standards = ", ".join(COMPLIANCE_MAPS.get(t_type, ["Internal Security"]))
        
        static_recs.append({
            "priority": prio,
            "action": f"Remediate {t_type} instances",
            "reason": f"Detected {count} instances of {t_type}. {RECOMMENDATION_MAP_REASON(t_type)}",
            "standard": standards
        })
        
    # Sort recommendations by priority (Critical > High > Medium > Low)
    static_recs.sort(key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}[x["priority"]])
    
    if not api_key:
        return static_recs
        
    # Ask LLM for dynamic, context-specific remediations
    prompt = f"""
    You are an enterprise risk officer. We scanned a document and detected the following sensitive items: {summary_str}.
    
    Generate custom, priority-wise security remediation recommendations. Return a valid JSON list.
    Each item must contain:
    - "priority": (Critical, High, Medium, Low)
    - "action": (Specific action to be taken, e.g., "Rotate Git API tokens and invalidate local configs")
    - "reason": (Detailed reason describing why this action is required in context of the findings)
    - "standard": (The primary compliance standard violated: GDPR, PCI DSS, DPDP, ISO 27001, NIST)
    
    Ensure you return ONLY the raw JSON list of objects (do not include markdown syntax like ```json ... ```).
    """
    
    try:
        if provider == "Gemini":
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(prompt)
            output = response.text
        elif provider == "OpenAI":
            client = OpenAI(api_key=api_key)
            completion = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a secure, JSON-only returning compliance planner."},
                    {"role": "user", "content": prompt}
                ]
            )
            output = completion.choices[0].message.content
        elif provider == "Groq":
            client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
            completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a secure, JSON-only returning compliance planner."},
                    {"role": "user", "content": prompt}
                ]
            )
            output = completion.choices[0].message.content
        elif provider == "Hugging Face":
            headers = {"Authorization": f"Bearer {api_key}"}
            api_url = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3"
            payload = {
                "inputs": f"<s>[INST] {prompt} [/INST]",
                "parameters": {"max_new_tokens": 1024, "return_full_text": False}
            }
            response = requests.post(api_url, headers=headers, json=payload)
            res_json = response.json()
            if isinstance(res_json, list):
                output = res_json[0].get("generated_text", "")
            else:
                output = res_json.get("generated_text", "")
            
        # Parse JSON
        clean_str = output.strip()
        if clean_str.startswith("```json"):
            clean_str = clean_str[7:]
        if clean_str.endswith("```"):
            clean_str = clean_str[:-3]
        clean_str = clean_str.strip()
        
        dynamic_recs = json.loads(clean_str)
        # Sort by priority
        dynamic_recs.sort(key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x.get("priority", "Low"), 3))
        return dynamic_recs
    except Exception:
        # Fall back to static recommendation on error
        return static_recs

def RECOMMENDATION_MAP_REASON(t_type: str) -> str:
    recs = {
        "Aadhaar": "Exposing Aadhaar numbers violates Indian DPDP regulations and leads to identity theft.",
        "PAN": "PAN card numbers in plain text violate Indian income tax compliance policies.",
        "Credit Card": "Credit cards stored in plaintext represent immediate financial liability and violate PCI DSS Requirements.",
        "Email": "Exposed email lists can trigger spam, phishing campaigns, and GDPR data breaches.",
        "Phone": "Exposing phone numbers violates DPDP/GDPR personal privacy regulations.",
        "IFSC": "Routing details combined with names present bank account compromise risks.",
        "API Key": "Exposed developer tokens can lead to severe service abuse and system breach.",
        "Password": "Plaintext passwords provide unauthorized lateral system access.",
        "Employee ID": "Internal corporate IDs can be combined with other factors to compromise employee profiles.",
        "Confidential Business Information": "Corporate strategy leakage compromises competitive advantage and violates ISO 27001.",
        "Person Name": "Names represent direct Personally Identifiable Information under GDPR.",
        "Organization": "Exposing key partner relationships can compromise vendor NDA terms.",
        "Location": "Geographical address coordinates present profiling risks under personal privacy acts."
    }
    return recs.get(t_type, "Exposing sensitive values compromises data privacy.")
