import os
from parsers import parse_txt, parse_csv, parse_pdf
from detector import run_regex_and_entropy_scan, run_spacy_ner_scan
from compliance import calculate_risk_metrics, map_findings_to_standards

def test_text_scanning():
    print("=== Testing TXT scanning on test_pii.txt ===")
    file_path = os.path.join("test_files", "test_pii.txt")
    with open(file_path, "rb") as f:
        file_bytes = f.read()
        
    text = parse_txt(file_bytes)
    regex_findings = run_regex_and_entropy_scan(text)
    ner_findings = run_spacy_ner_scan(text, regex_findings)
    findings = regex_findings + ner_findings
    
    print(f"Total findings: {len(findings)}")
    for f in findings:
        print(f"Type: {f['type']}, Value: {f['value']}, Confidence: {f['confidence']:.2f}, Severity: {f['severity']}")
        
    risk_score, risk_level, reason = calculate_risk_metrics(findings)
    print(f"Risk Score: {risk_score}/100, Level: {risk_level}")
    print(reason)
    print("============================================\n")

def test_csv_scanning():
    print("=== Testing CSV scanning on test_compliance.csv ===")
    file_path = os.path.join("test_files", "test_compliance.csv")
    with open(file_path, "rb") as f:
        file_bytes = f.read()
        
    text = parse_csv(file_bytes)
    regex_findings = run_regex_and_entropy_scan(text)
    findings = regex_findings  # Skip NER for structured tables
    
    print(f"Total findings: {len(findings)}")
    for f in findings:
        print(f"Type: {f['type']}, Value: {f['value']}, Confidence: {f['confidence']:.2f}, Severity: {f['severity']}")
        
    risk_score, risk_level, reason = calculate_risk_metrics(findings)
    print(f"Risk Score: {risk_score}/100, Level: {risk_level}")
    print(reason)
    print("============================================\n")

def test_pdf_scanning():
    print("=== Testing PDF scanning on test_corporate.pdf ===")
    file_path = os.path.join("test_files", "test_corporate.pdf")
    with open(file_path, "rb") as f:
        file_bytes = f.read()
        
    text, pages = parse_pdf(file_bytes)
    regex_findings = run_regex_and_entropy_scan(text)
    ner_findings = run_spacy_ner_scan(text, regex_findings)
    findings = regex_findings + ner_findings
    
    print(f"Total findings: {len(findings)}")
    for f in findings:
        print(f"Type: {f['type']}, Value: {f['value']}, Confidence: {f['confidence']:.2f}, Severity: {f['severity']}")
        
    risk_score, risk_level, reason = calculate_risk_metrics(findings)
    print(f"Risk Score: {risk_score}/100, Level: {risk_level}")
    print(reason)
    print("============================================\n")

if __name__ == "__main__":
    test_text_scanning()
    test_csv_scanning()
    test_pdf_scanning()
