OEM Vulnerability Scraper 🚨
'''text

A Python-based cybersecurity tool that scrapes and reports Critical and High Severity vulnerabilities published on OEM (Original Equipment Manufacturer) websites like Cisco and Siemens.

---

## 🔍 Features

- Scrapes real-time vulnerability data from:
  - [Cisco Security Advisories](https://tools.cisco.com/security/center/publicationListing.x)
  - [Siemens CERT Portal](https://cert-portal.siemens.com/productcert/html/ssa-publication.html)
- Filters only `CRITICAL` and `HIGH` severity CVEs.
- Generates a clean email-friendly vulnerability report.
- Sends the report via email to configured recipients.
- Automatically falls back to mock data for offline/demo use.

---

## 🛠 Requirements

- Python 3.7+
- Install dependencies:
🚀 Starting OEM Vulnerability Scraper...

🔍 Scanning Cisco Security Advisories...
🔍 Scanning Siemens Security Advisories...
⚠️ No live vulnerabilities found. Using mock data for demo.

=== VULNERABILITY REPORT ===

🚨 Critical/High Severity Vulnerabilities Detected

Scan Time: 2025-04-04 15:42
==================================================

[CRITICAL] Cisco IOS XE Software
• CVE-ID: CVE-2024-20356
• Published: 2024-03-05
• Advisory: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-snmp-rce-MdT4vB6H

[HIGH] Siemens SCALANCE XC-200
• CVE-ID: CVE-2024-18392
• Published: 2024-02-27
• Advisory: https://cert-portal.siemens.com/productcert/html/ssa-347795.html

✅ Email alert sent successfully!

```bash
pip install requests beautifulsoup4
