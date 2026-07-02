import re
import math
import os
import json
import google.generativeai as genai
from openai import OpenAI
import spacy
import requests

# ---------------------------------------------------------
# Self-healing spaCy model loading
# ---------------------------------------------------------
def load_spacy_nlp():
    try:
        return spacy.load("en_core_web_sm")
    except OSError:
        try:
            from spacy.cli import download
            download("en_core_web_sm")
            return spacy.load("en_core_web_sm")
        except Exception:
            return None

# Load NLP model globally or lazily
nlp = load_spacy_nlp()

# ---------------------------------------------------------
# Luhn Algorithm Check for Credit Cards
# ---------------------------------------------------------
def check_luhn(card_num_str: str) -> bool:
    """Verifies a card number using Luhn checksum."""
    digits = [int(c) for c in card_num_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # Luhn algorithm formula
    checksum = sum(digits[-1::-2]) + sum([sum(divmod(2 * d, 10)) for d in digits[-2::-2]])
    return checksum % 10 == 0

# ---------------------------------------------------------
# Entropy Calculation for API Keys/Credentials
# ---------------------------------------------------------
def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    for count in (text.count(c) for c in set(text)):
        p = count / len(text)
        entropy -= p * math.log2(p)
    return entropy

# ---------------------------------------------------------
# Multi-Stage Detection Pipeline
# ---------------------------------------------------------

# Basic pattern compilations
RE_AADHAAR = re.compile(r'\b[2-9]\d{3}\s\d{4}\s\d{4}\b|\b[2-9]\d{11}\b')
RE_PAN = re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b')
RE_EMAIL = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
RE_PHONE = re.compile(r'\b(?:\+?91|0)?[6-9]\d{9}\b')
RE_IFSC = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')
RE_CREDIT_CARD = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
RE_API_KEY_PREFIX = re.compile(r'\b(?:sk-proj-|AIzaSy|gsk_)[a-zA-Z0-9_-]{12,60}\b')
# Candidate tokens for high-entropy secrets (alphanumeric/special, length 16-64)
RE_SECRET_TOKEN = re.compile(r'\b[a-zA-Z0-9+/=_-]{16,64}\b')

# Framework and Severity maps
SEVERITY_MAP = {
    "Aadhaar": "High",
    "PAN": "High",
    "Credit Card": "Critical",
    "Email": "Low",
    "Phone": "Medium",
    "IFSC": "High",
    "API Key": "Critical",
    "Password": "Critical",
    "Employee ID": "Medium",
    "Confidential Business Information": "High",
    "Person Name": "Medium",
    "Organization": "Medium",
    "Location": "Low"
}

RECOMMENDATION_MAP = {
    "Aadhaar": "Mask Aadhaar numbers using redacting filters before storage.",
    "PAN": "Tokenise or mask PAN numbers; restrict access to authorized personnel.",
    "Credit Card": "Encrypt cards using PCI DSS standards or remove plaintext CC numbers.",
    "Email": "Ensure standard email access controls are configured.",
    "Phone": "Restrict plain-text display of phone numbers to avoid phishing risks.",
    "IFSC": "Encrypt or mask banking codes in general reports.",
    "API Key": "Rotate keys immediately, remove from repository commits, and inject via env.",
    "Password": "Use secure credential managers; never store plaintext passwords.",
    "Employee ID": "Implement column-level encryption or role-based access for IDs.",
    "Confidential Business Information": "Encrypt documents, restrict access, and enforce confidentiality agreements.",
    "Person Name": "Anonymise or redact names to comply with GDPR/DPDP personal data guidelines.",
    "Organization": "Restrict exposure of vendor or corporate partnership information.",
    "Location": "Anonymise geographical indicators if profiling risks exist."
}

def check_context(text: str, start_pos: int, keywords: list[str], window: int = 60) -> bool:
    """Checks if keywords are in a window around a match index to increase confidence."""
    sub_start = max(0, start_pos - window)
    sub_end = min(len(text), start_pos + window)
    context_text = text[sub_start:sub_end].lower()
    return any(kw in context_text for kw in keywords)

def run_regex_and_entropy_scan(text: str) -> list[dict]:
    findings = []
    
    # 1. Aadhaar
    for m in RE_AADHAAR.finditer(text):
        val = m.group()
        start, end = m.start(), m.end()
        # Context score
        has_ctx = check_context(text, start, ["aadhaar", "uidai", "aadhar", "government id"])
        confidence = 0.95 if has_ctx else 0.80
        findings.append({
            "type": "Aadhaar",
            "value": val,
            "start": start,
            "end": end,
            "method": "Regex",
            "confidence": confidence,
            "reason": f"Matches standard Aadhaar pattern {'with' if has_ctx else 'without'} local context terms.",
            "severity": SEVERITY_MAP["Aadhaar"],
            "recommendation": RECOMMENDATION_MAP["Aadhaar"]
        })
        
    # 2. PAN
    for m in RE_PAN.finditer(text):
        val = m.group()
        start, end = m.start(), m.end()
        has_ctx = check_context(text, start, ["pan", "tax", "permanent account number", "income tax"])
        confidence = 0.99 if has_ctx else 0.85
        findings.append({
            "type": "PAN",
            "value": val,
            "start": start,
            "end": end,
            "method": "Regex",
            "confidence": confidence,
            "reason": f"Matches Indian PAN pattern {'with' if has_ctx else 'without'} local context terms.",
            "severity": SEVERITY_MAP["PAN"],
            "recommendation": RECOMMENDATION_MAP["PAN"]
        })
        
    # 3. Credit Card
    for m in RE_CREDIT_CARD.finditer(text):
        val = m.group().replace(" ", "").replace("-", "")
        # Run Luhn validation to suppress false positives
        if check_luhn(val):
            start, end = m.start(), m.end()
            has_ctx = check_context(text, start, ["card", "credit", "debit", "visa", "mastercard", "amex", "cvv"])
            confidence = 1.0 if has_ctx else 0.90
            findings.append({
                "type": "Credit Card",
                "value": m.group(), # preserve original format
                "start": start,
                "end": end,
                "method": "Regex + Luhn Validator",
                "confidence": confidence,
                "reason": f"Matches credit card format and passed Luhn validation checksum {'with' if has_ctx else 'without'} context keywords.",
                "severity": SEVERITY_MAP["Credit Card"],
                "recommendation": RECOMMENDATION_MAP["Credit Card"]
            })
            
    # 4. Email
    for m in RE_EMAIL.finditer(text):
        val = m.group()
        start, end = m.start(), m.end()
        findings.append({
            "type": "Email",
            "value": val,
            "start": start,
            "end": end,
            "method": "Regex",
            "confidence": 1.0,
            "reason": "Matches internet standard RFC 5322 email syntax.",
            "severity": SEVERITY_MAP["Email"],
            "recommendation": RECOMMENDATION_MAP["Email"]
        })
        
    # 5. Phone
    for m in RE_PHONE.finditer(text):
        val = m.group()
        start, end = m.start(), m.end()
        has_ctx = check_context(text, start, ["phone", "mobile", "tel", "contact", "call"])
        confidence = 0.90 if has_ctx else 0.70
        findings.append({
            "type": "Phone",
            "value": val,
            "start": start,
            "end": end,
            "method": "Regex",
            "confidence": confidence,
            "reason": f"Matches common contact number structures {'with' if has_ctx else 'without'} local context terms.",
            "severity": SEVERITY_MAP["Phone"],
            "recommendation": RECOMMENDATION_MAP["Phone"]
        })
        
    # 6. IFSC
    for m in RE_IFSC.finditer(text):
        val = m.group()
        start, end = m.start(), m.end()
        has_ctx = check_context(text, start, ["ifsc", "bank", "branch", "neft", "rtgs", "account"])
        confidence = 0.99 if has_ctx else 0.85
        findings.append({
            "type": "IFSC",
            "value": val,
            "start": start,
            "end": end,
            "method": "Regex",
            "confidence": confidence,
            "reason": f"Matches bank branch routing code (IFSC) standard syntax {'with' if has_ctx else 'without'} local context terms.",
            "severity": SEVERITY_MAP["IFSC"],
            "recommendation": RECOMMENDATION_MAP["IFSC"]
        })
        
    # 7. Credential Prefix Matches (API Keys)
    for m in RE_API_KEY_PREFIX.finditer(text):
        val = m.group()
        start, end = m.start(), m.end()
        findings.append({
            "type": "API Key",
            "value": val,
            "start": start,
            "end": end,
            "method": "Regex",
            "confidence": 0.99,
            "reason": "Matches known API token signature pattern (OpenAI, Gemini, or Cohere prefixes).",
            "severity": SEVERITY_MAP["API Key"],
            "recommendation": RECOMMENDATION_MAP["API Key"]
        })
        
    # 8. Entropy Checks for API keys / Secrets
    for m in RE_SECRET_TOKEN.finditer(text):
        val = m.group()
        # Skip if already captured by prefix, PAN, CC, etc.
        if any(f["start"] <= m.start() and m.end() <= f["end"] for f in findings):
            continue
            
        entropy = calculate_entropy(val)
        # Threshold for high entropy (e.g. passwords, hash, secret)
        # Random base64 typically has entropy > 4.5. Numbers/hex > 3.5.
        if entropy > 3.8:
            start, end = m.start(), m.end()
            has_ctx = check_context(text, start, ["api", "key", "password", "secret", "token", "auth", "pwd"])
            confidence = 0.90 if has_ctx else 0.70
            findings.append({
                "type": "API Key" if has_ctx else "Password",
                "value": val,
                "start": start,
                "end": end,
                "method": "Entropy Scanner",
                "confidence": confidence,
                "reason": f"Detected high Shannon entropy string ({entropy:.2f} bits) in the range.",
                "severity": "Critical",
                "recommendation": RECOMMENDATION_MAP["API Key"] if has_ctx else RECOMMENDATION_MAP["Password"]
            })
            
    return findings

# ---------------------------------------------------------
# spaCy NER Scanner
# ---------------------------------------------------------
def run_spacy_ner_scan(text: str, existing_findings: list[dict]) -> list[dict]:
    """Uses spaCy to detect Person, Org, and Location entities."""
    if not nlp:
        return []
        
    findings = []
    doc = nlp(text)
    
    for ent in doc.ents:
        # Ignore if this text overlaps with any existing regex findings
        if any(f["start"] <= ent.start_char and ent.end_char <= f["end"] for f in existing_findings):
            continue
            
        # Map spaCy entity labels to our dashboard categories
        t_type = None
        if ent.label_ == "PERSON":
            t_type = "Person Name"
        elif ent.label_ == "ORG":
            t_type = "Organization"
        elif ent.label_ in ["GPE", "LOC"]:
            t_type = "Location"
            
        if t_type:
            # Basic validation
            # Ensure name contains letters and has some reasonable structure
            val = ent.text.strip()
            if len(val) < 2 or not any(c.isalpha() for c in val):
                continue
                
            # Confidence booster from context
            has_ctx = False
            if t_type == "Person Name":
                has_ctx = check_context(text, ent.start_char, ["employee", "name", "manager", "director", "user"])
                
            confidence = 0.85 if has_ctx else 0.70
            
            findings.append({
                "type": t_type,
                "value": val,
                "start": ent.start_char,
                "end": ent.end_char,
                "method": "spaCy NER",
                "confidence": confidence,
                "reason": f"Identified entity as {ent.label_} via spaCy NER model.",
                "severity": SEVERITY_MAP[t_type],
                "recommendation": RECOMMENDATION_MAP[t_type]
            })
            
    return findings

# ---------------------------------------------------------
# LLM Validation & Detection Engine
# ---------------------------------------------------------
def run_llm_hybrid_scan(text: str, regex_spacy_findings: list[dict], api_key: str, provider: str = "Gemini") -> list[dict]:
    """
    Runs an LLM scan to:
    1. Extract Confidential Business Information and custom Employee IDs.
    2. Confirm or invalidate regex/spaCy findings (Stage 2 Verification).
    """
    if not api_key:
        return regex_spacy_findings
        
    # Prepare findings for prompt verification
    findings_to_verify = [
        {"type": f["type"], "value": f["value"], "method": f["method"]}
        for f in regex_spacy_findings if f["type"] in ["Aadhaar", "PAN", "Credit Card", "API Key", "Password"]
    ]
    
    # We only send a snippet or summary of the text if it is extremely large,
    # but for typical test documents (12 pages), we can take the first 10,000 words.
    truncated_text = text[:40000] # roughly 8,000 to 10,000 words
    
    prompt = f"""
    You are an expert security compliance auditor. Analyze the following document text and perform two actions:
    1. Scan the text to identify:
       - "Confidential Business Information": intellectual property, trade secrets, merger discussions, strategic corporate plans.
       - "Employee IDs": formatted corporate identifiers (e.g. EMP-0921, ID_982).
    2. Verify the list of candidate sensitive findings detected by regex/heuristics to see if they are indeed true positives (not fake dates, template numbers, or formatting artifacts).
    
    Candidates to verify: {json.dumps(findings_to_verify)}
    
    Document Text:
    ---
    {truncated_text}
    ---
    
    Return a valid JSON list of items containing:
    - "type": (Aadhaar, PAN, Credit Card, API Key, Password, Employee ID, Confidential Business Information, Person Name, Organization, Location)
    - "value": (The exact string matched in the text)
    - "verified": (true or false - indicating if the candidate was verified as a true sensitive value, or if a newly detected item is genuine)
    - "confidence": (0.0 to 1.0 based on context analysis)
    - "reason": (A short explanation of why it was verified or detected)
    
    Respond ONLY with the raw JSON array (do not include markdown code block formatting like ```json ... ```, just the plain JSON array).
    """
    
    llm_output = ""
    try:
        if provider == "Gemini":
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(prompt)
            llm_output = response.text
        elif provider == "OpenAI":
            client = OpenAI(api_key=api_key)
            chat_completion = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a secure, JSON-only returning compliance parser."},
                    {"role": "user", "content": prompt}
                ]
            )
            llm_output = chat_completion.choices[0].message.content
        elif provider == "Groq":
            client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
            chat_completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a secure, JSON-only returning compliance parser."},
                    {"role": "user", "content": prompt}
                ]
            )
            llm_output = chat_completion.choices[0].message.content
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
                llm_output = res_json[0].get("generated_text", "")
            else:
                llm_output = res_json.get("generated_text", "")
    except Exception as e:
        # Fall back to regex/spacy without verification if LLM fails
        return regex_spacy_findings

    # Parse JSON
    try:
        # Clean markdown wrappers if returned
        clean_json_str = llm_output.strip()
        if clean_json_str.startswith("```json"):
            clean_json_str = clean_json_str[7:]
        if clean_json_str.endswith("```"):
            clean_json_str = clean_json_str[:-3]
        clean_json_str = clean_json_str.strip()
        
        llm_findings = json.loads(clean_json_str)
    except Exception:
        # Fallback to unverified if parsing fails
        return regex_spacy_findings
        
    # Map LLM results back to findings
    verified_findings = []
    
    # 1. Update/Filter existing findings based on LLM verification
    for f in regex_spacy_findings:
        # If it wasn't subject to LLM verification, keep it
        if f["type"] not in ["Aadhaar", "PAN", "Credit Card", "API Key", "Password"]:
            verified_findings.append(f)
            continue
            
        # Check if LLM verified it
        match_in_llm = next(
            (item for item in llm_findings 
             if item.get("value") == f["value"] and item.get("type") == f["type"]),
            None
        )
        if match_in_llm:
            if match_in_llm.get("verified", True):
                # Update confidence and reason based on LLM verification
                f["confidence"] = float(match_in_llm.get("confidence", f["confidence"]))
                f["reason"] = f"Verified by LLM: {match_in_llm.get('reason', f['reason'])}"
                f["method"] = f"{f['method']} + LLM Verification"
                verified_findings.append(f)
        else:
            # If LLM didn't flag it as false, keep it with original values
            verified_findings.append(f)
            
    # 2. Add new items found by the LLM (like Confidential Business Info, Employee IDs)
    for item in llm_findings:
        if item.get("type") in ["Confidential Business Information", "Employee ID"] and item.get("verified", True):
            val = item.get("value")
            if not val:
                continue
            # Search character position in original text to set bounds
            pos = text.find(val)
            if pos != -1:
                start = pos
                end = pos + len(val)
            else:
                start = 0
                end = 0
                
            t_type = item.get("type")
            verified_findings.append({
                "type": t_type,
                "value": val,
                "start": start,
                "end": end,
                "method": "Gemini/OpenAI LLM",
                "confidence": float(item.get("confidence", 0.85)),
                "reason": item.get("reason", "Identified by context-aware AI scanning."),
                "severity": SEVERITY_MAP[t_type],
                "recommendation": RECOMMENDATION_MAP[t_type]
            })
            
    return verified_findings
