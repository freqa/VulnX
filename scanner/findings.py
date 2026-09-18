findings = []
severity_scoring = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1
}
risk_score = 0

critical_count = 0
high_count = 0
medium_count = 0
low_count = 0

def add_finding(name, severity, evidence, recommendation):
    global risk_score, critical_count, high_count, medium_count, low_count

    finding = {
        "name": name,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation
    }

    findings.append(finding)

    risk_score += severity_scoring[severity]
    if severity == "Critical":
     critical_count += 1
    elif severity == "High":
        high_count += 1
    elif severity == "Medium":
        medium_count += 1
    elif severity == "Low":
        low_count += 1