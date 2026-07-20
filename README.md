# Custom Web Security Testing Framework

A modular, CLI-based web application security testing framework built for the
ITSOLERA PVT LTD Offensive Security internship (Task 2). It automates
detection of common web vulnerability classes against **intentionally
vulnerable applications**, and produces professional HTML/JSON reports.

> **Authorized use only.** Only run this tool against systems you own or are
> explicitly authorized to test — e.g. DVWA, OWASP Juice Shop, bWAPP,
> WebGoat, Mutillidae, `http://testphp.vulnweb.com`, `http://demo.testfire.net`.
> The author and ITSOLERA PVT LTD accept no responsibility for misuse.

## Features

- **5 independent scanning modules** (headers, auth, xss, sqli, disclosure)
- Run one module, several, or all (`--module all`)
- **HTML and JSON reporting** with severity, evidence, remediation, and an
  overall computed risk rating
- **Multi-threading** — run modules concurrently with `--threads`
- **Progress bar** (tqdm) during module execution
- **Colored terminal output** for readability
- **Custom User-Agent**, **cookie support**, **custom request headers**
- **Proxy support** (e.g. route traffic through Burp Suite)
- **Timeout handling** with graceful failure (no crashes on dead targets)
- **YAML configuration file** support for reusable scan profiles

## Project Structure

```
custom_websecurity_testing_tool/
├── custom_websecurity_testing_tool.py            # CLI entry point
├── modules/
│   ├── headers.py          # Module 1 - Security Headers Analyzer
│   ├── auth.py              # Module 2 - Authentication Assessment
│   ├── xss.py                # Module 3 - Reflected XSS Testing
│   ├── sqli.py               # Module 4 - SQL Injection Testing
│   └── disclosure.py         # Module 5 - Information Disclosure
├── utils/
│   ├── http_client.py       # Shared HTTP wrapper (timeout/proxy/headers)
│   ├── report.py            # JSON/HTML report generation
|   ├── api_discovery.py
|   ├── cors_misconfig.py
│   ├── jwt_detection.py
│   ├── mock_bonus_server.py
│   ├── mock_echo_server.py
│   ├── session_auth.py    
│   └── logger.py            # Colored console output
├── reports/                  # Generated reports land here
├── config.example.yaml       # Example config file
├── requirements.txt
└── README.md
```

## Installation

```bash
git clone <your-repo-url>
cd custom_websecurity_testing_tool
pip install -r requirements.txt
```

## Usage

```bash
python custom_websecurity_testing_tool.py --target http://testphp.vulnweb.com --module headers
python custom_websecurity_testing_tool.py --target http://demo.testfire.net --module all --output html
python custom_websecurity_testing_tool.py --target http://testphp.vulnweb.com --module xss,sqli --threads 3
```

### CLI Options

| Flag | Description |
|---|---|
| `--target` | Target base URL (required) |
| `--module` | `headers`, `auth`, `xss`, `sqli`, `disclosure`, comma-separated list, or `all` (default) |
| `--output` | `html`, `json`, or `both` (default) |
| `--report-name` | Base filename for the report (no extension) |
| `--threads` | Number of modules to run concurrently (default: 1) |
| `--timeout` | Per-request timeout in seconds (default: 10) |
| `--user-agent` | Custom User-Agent string |
| `--cookies` | Cookie string, e.g. `"session=abc123; role=user"` |
| `--header` | Extra header `"Key: Value"` (repeatable) |
| `--proxy` | Proxy URL, e.g. `http://127.0.0.1:8080` (Burp Suite) |
| `--no-verify-ssl` | Disable TLS certificate verification |
| `--config` | Path to a YAML config file (see `config.example.yaml`) |
| `--login-path` | Login endpoint URL for the auth module |
| `--time-based-sqli` | Enable optional (slower) time-based SQLi checks |

### Example: full scan with a Burp proxy and custom UA

```bash
python custom_websecurity_testing_tool.py --target http://demo.testfire.net \
  --module all --threads 3 \
  --proxy http://127.0.0.1:8080 \
  --user-agent "InternshipScanner/1.0" \
  --output both --report-name demo_testfire_scan
```

## Modules

1. **Security Headers Analyzer** — checks for `Content-Security-Policy`,
   `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
   `Strict-Transport-Security`, `Permissions-Policy`, plus `Server` /
   `X-Powered-By` banner disclosure.
2. **Authentication Assessment** — session cookie attribute analysis
   (`Secure`/`HttpOnly`/`SameSite`), username-enumeration signal detection via
   response differences, and account-lockout detection using a small number
   of clearly-fake credential attempts (no real brute forcing).
3. **XSS Testing** — tests GET and POST parameters with safe canary payloads
   and flags unencoded reflection as a finding.
4. **SQL Injection Testing** — error-based (SQL error signatures),
   boolean-based (response-length differential), and optional time-based
   (`SLEEP`) detection using non-destructive payloads only.
5. **Information Disclosure** — probes for `robots.txt`, `sitemap.xml`,
   `.git/HEAD`, `.env`, backup files, `phpinfo.php`, directory listing, and
   other commonly exposed resources.

## Reporting

Every scan produces a `reports/<name>.json` and/or `reports/<name>.html`
file containing: target URL, scan date, modules executed, all findings
(title, severity, evidence, remediation), and a computed **overall risk
rating** (`INFORMATIONAL` → `CRITICAL`) based on the severity mix of
findings. A sample report is included at `reports/sample_report.html` /
`reports/sample_report.json`.

## Configuration File

Instead of passing every flag on the command line, create a YAML config
(see `config.example.yaml`) and pass it with `--config config.yaml`. CLI
flags always take precedence over config file values.

## Disclaimer

This tool is provided for educational purposes and authorized security
testing only, as part of the ITSOLERA PVT LTD Offensive Security internship.
Do not use it against systems you do not own or do not have explicit written
permission to test.
