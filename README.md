OEM Vulnerability Scraper 🚨
'''text

A Python-based cybersecurity tool that scrapes and reports **Critical** and **High Severity** vulnerabilities published on OEM (Original Equipment Manufacturer) websites like **Cisco** and **Siemens**.

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

```bash
pip install requests beautifulsoup4
