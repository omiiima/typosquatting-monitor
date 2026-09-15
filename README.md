# typosquatting_monitor

## Description

`typosquatting_monitor` is a tool for monitoring typosquatted variants of a domain you have authority over. It automatically generates spelling variants of a target domain, checks their availability, and detects potentially malicious domains using indicators such as DNS, HTTP/S, SSL certificates, and VirusTotal.

## Project structure

```
.
├── main.py             # Main entry point
├── name_generator.py   # Generates typo variants of the domain (dnstwist)
├── scanner.py           # Scanning functions: DNS, HTTP/S, SSL, HTML title, VirusTotal, score calculation
├── reporter.py          # CSV report generation
├── requirements.txt
├── output/               # Directory where CSV reports are saved
└── README.md             # Documentation
```

## How it works

1. **Generating typo variants**

   The user provides a target domain, e.g. `apple.com`.
   The program automatically generates spelling variants using:
   - dnstwist (CLI or Python API)

2. **Scanning variants**

   For each generated domain, the scanner collects:
   - DNS: existence, `A`, `MX`, `NS` records
   - HTTP/HTTPS: response code, final URL
   - HTML title: to detect suspicious keywords (`login`, `verify`, `secure`, `update`, `account`)
   - SSL certificate info: issuer and subject
   - **TLS verification status**: whether the certificate passes standard verification — a failed/self-signed certificate is treated as a suspicious signal rather than silently bypassed
   - VirusTotal: malicious count, suspicious count, and reputation

3. **Score calculation**

   Each domain receives a score based on:
   - **DNS resolves**: 2 points
   - **HTTP/HTTPS responds**: 3 points
   - **TLS certificate verification fails**: 3 points
   - **Suspicious SSL certificate issuer**: 1–2 points
   - **VirusTotal**: malicious × 5 + suspicious × 2
   - **HTML title contains suspicious keywords**: 3 points per keyword

   Domains with a high score are considered potentially dangerous.

4. **Reporting and alerts**

   - Results are saved to a CSV file: `<domain>_typosquatting_report.csv`
   - An email alert system notifies when certain domains exceed the average score

## Installation

1. Create a Python 3.12 environment:

```bash
python -m venv tsm
source tsm/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Configure the VirusTotal API key:

```bash
export VT_API_KEY="your_api_key"
```

4. Configure alert email credentials (never hardcoded — loaded from environment variables):

```bash
export ALERT_EMAIL="your_alert_email@example.com"
export ALERT_EMAIL_PASSWORD="your_app_password"
```

## Usage

1. Generate and scan a domain:

```bash
python main.py
# => Enter the domain to monitor, e.g. apple.com
```

2. Check the reports:

   Results are saved in the `output/` folder.
   The CSV contains all variants along with DNS, HTTP/S, SSL, VirusTotal info, and the score.

## Conclusion

This tool performs proactive typosquatting monitoring: it generates potentially typosquatted domains, checks whether they exist and host a live webpage, computes a risk score, and alerts the team about the most suspicious domains. It currently requires manual execution, but it allows threats to be anticipated before they impact users — fulfilling the goal of proactive monitoring.