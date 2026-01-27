# Web Application Security Scanner 🔒

A lightweight, professional-grade web application security scanner focused on OWASP Top 10 vulnerabilities. This tool performs automated security assessments to identify common misconfigurations and vulnerabilities in web applications.

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is for **AUTHORIZED TESTING ONLY**. Use this tool only on:
- Web applications you own
- Applications you have explicit written permission to test
- Your own development/staging environments
- Educational/learning environments
- Authorized penetration testing engagements

Unauthorized security testing is illegal in many jurisdictions and may result in criminal charges. The authors are not responsible for misuse of this tool.

## ✨ Features

This scanner detects:

1. **Missing HTTP Security Headers**
   - Strict-Transport-Security (HSTS)
   - X-Content-Type-Options
   - X-Frame-Options
   - Content-Security-Policy (CSP)
   - Referrer-Policy
   - And more...

2. **Open Directories / Sensitive Files**
   - Configuration files (.env, config.php, etc.)
   - Backup files (backup.sql, dump.sql, etc.)
   - Common directories (admin/, backup/, logs/, etc.)
   - Version control files (.git/, .svn/, etc.)

3. **Open Redirect Vulnerability**
   - Tests common redirect parameters
   - Detects external redirects
   - Identifies unsafe redirect implementations

4. **Basic Reflected XSS**
   - Tests multiple XSS payloads
   - Detects reflection in response
   - Identifies vulnerable parameters

5. **Server Information Disclosure**
   - Server header analysis
   - X-Powered-By header detection
   - Technology stack identification

## 🏗️ Architecture

```
Input URL
   |
   v
Request Handler
   |
   +-- Header Analyzer
   +-- Endpoint Scanner
   +-- Payload Tester
   |
   v
Result Aggregator
   |
   v
CLI / JSON Report / Web Interface
```

### Components

- **Request Handler**: Manages all HTTP requests with configurable options
- **Header Analyzer**: Analyzes HTTP security headers
- **Endpoint Scanner**: Scans for exposed files and directories
- **Payload Tester**: Tests for XSS and open redirect vulnerabilities
- **Result Aggregator**: Collects and formats all scan results

## 📋 Requirements

- Python 3.8.1 or higher
- Poetry (for package management)

## 🚀 Installation

### Using Poetry (Recommended)

1. Install Poetry if you haven't already:
```bash
curl -sSL https://install.python-poetry.org | python3 -
```

2. Clone or download this repository:
```bash
git clone <repository-url>
cd eth
```

3. Install dependencies using Poetry:
```bash
poetry install
```

4. Activate the virtual environment:
```bash
poetry shell
```

### Alternative: Direct Installation

If you prefer not to use Poetry:
```bash
pip install requests urllib3 fastapi uvicorn pydantic
```

## 📖 Usage

### Web Interface (FastAPI)

Start the web server:
```bash
poetry run uvicorn web_scanner.api:app --reload --host 0.0.0.0 --port 8000
```

Or use the convenience script:
```bash
poetry run python -m web_scanner.server
```

Then open your browser to: `http://localhost:8000`

The web interface provides:
- ✅ Easy-to-use scan form
- ✅ Real-time scan status updates
- ✅ Beautiful report visualization
- ✅ Interactive vulnerability cards

### Command Line Interface

```bash
# Full security scan
poetry run python -m web_scanner -u https://example.com

# Scan with JSON output
poetry run python -m web_scanner -u https://example.com -o results.json

# Verbose output
poetry run python -m web_scanner -u https://example.com -v
```

### Advanced Usage

```bash
# Scan only specific components
poetry run python -m web_scanner -u https://example.com --no-xss --no-redirect

# Custom timeout
poetry run python -m web_scanner -u https://example.com -t 15

# Verify SSL certificates
poetry run python -m web_scanner -u https://example.com --verify-ssl

# Scan only headers and endpoints
poetry run python -m web_scanner -u https://example.com --no-xss --no-redirect
```

## 📝 Command-Line Options

```
-u, --url          Target URL to scan (required)
-o, --output       Output JSON file path
-t, --timeout      Request timeout in seconds (default: 10)
--verify-ssl       Verify SSL certificates (default: False)
-v, --verbose      Verbose output
--no-headers       Skip security header analysis
--no-endpoints     Skip endpoint scanning
--no-xss           Skip XSS testing
--no-redirect      Skip open redirect testing
-h, --help         Show help message
```

## 🌐 Web Interface API Endpoints

### POST `/api/scan`
Start a new security scan.

**Request Body:**
```json
{
  "url": "https://example.com",
  "scan_headers": true,
  "scan_endpoints": true,
  "scan_xss": true,
  "scan_redirect": true,
  "timeout": 10,
  "verify_ssl": false
}
```

**Response:**
```json
{
  "scan_id": "uuid-here",
  "status": "started"
}
```

### GET `/api/status/{scan_id}`
Get scan status.

**Response:**
```json
{
  "scan_id": "uuid-here",
  "status": "running",
  "progress": "Scanning for exposed endpoints...",
  "created_at": "2026-01-27T10:58:16",
  "completed_at": null
}
```

### GET `/api/results/{scan_id}`
Get scan results (only available when scan is completed).

**Response:**
```json
{
  "scan_info": { ... },
  "summary": { ... },
  "header_analysis": { ... },
  "endpoint_scan": { ... },
  "xss_test": { ... },
  "redirect_test": { ... }
}
```

### GET `/api/scans`
List all scans.

## 📊 Output

### Web Interface

The web interface provides:
- Real-time status updates with progress bar
- Beautiful vulnerability cards with severity indicators
- Statistics dashboard
- Detailed vulnerability listings
- Color-coded severity levels

### Console Report

The scanner provides a detailed console report including:
- Overall risk assessment
- Vulnerability count by severity
- Detailed findings for each test category
- Recommendations

### JSON Export

Export detailed results to JSON for further analysis:

```json
{
  "scan_info": {
    "target_url": "https://example.com",
    "scan_timestamp": "2026-01-26T10:30:00",
    "scanner_version": "1.0"
  },
  "summary": {
    "total_vulnerabilities": 5,
    "high_severity": 2,
    "medium_severity": 2,
    "low_severity": 1,
    "overall_risk": "High"
  },
  "header_analysis": { ... },
  "endpoint_scan": { ... },
  "xss_test": { ... },
  "redirect_test": { ... }
}
```

## 🎯 Example Scans

### 1. Quick Security Check (CLI)
```bash
poetry run python -m web_scanner -u https://your-app.com
```

### 2. Comprehensive Assessment (Web Interface)
1. Start the server: `poetry run uvicorn web_scanner.api:app --reload`
2. Open `http://localhost:8000`
3. Enter URL and click "Start Scan"
4. View real-time progress and results

### 3. Header Analysis Only
```bash
poetry run python -m web_scanner -u https://your-app.com --no-endpoints --no-xss --no-redirect
```

## 🔍 What Gets Tested

### Security Headers
- ✅ Strict-Transport-Security
- ✅ X-Content-Type-Options
- ✅ X-Frame-Options
- ✅ Content-Security-Policy
- ✅ Referrer-Policy
- ✅ Permissions-Policy
- ✅ X-XSS-Protection (deprecated but checked)

### Sensitive Files & Directories
- Configuration files (.env, config.php, web.config)
- Backup files (backup.sql, dump.sql)
- Admin panels (admin/, phpmyadmin/)
- Version control (.git/, .svn/)
- Log files (logs/, log/)
- Test files (test.php, phpinfo.php)

### XSS Payloads
- `<script>alert("XSS")</script>`
- `<img src=x onerror=alert("XSS")>`
- `<svg onload=alert("XSS")>`
- And more variations...

### Redirect Parameters
- redirect, redirect_to, redirect_uri
- return, return_to, return_url
- next, goto, target, destination
- And more...

## 🛡️ Security Considerations

- Always obtain proper authorization before scanning
- Be aware of rate limiting and DDoS protection
- Use appropriate timeouts to avoid hanging requests
- Consider the legal implications in your jurisdiction
- Respect robots.txt and terms of service
- Use responsibly and ethically

## 🐛 Troubleshooting

**Issue**: Connection timeout errors
- **Solution**: Increase timeout with `-t` option, check network connectivity

**Issue**: SSL certificate errors
- **Solution**: Use `--verify-ssl` flag or ensure certificates are valid

**Issue**: No vulnerabilities found
- **Solution**: This is good! The application may be secure, or try verbose mode for details

**Issue**: False positives
- **Solution**: Review findings manually, some detections may need verification

**Issue**: Web interface not loading
- **Solution**: Ensure port 8000 is available, check firewall settings

## 📚 Educational Purpose

This tool is excellent for:
- Learning web application security
- Understanding OWASP Top 10 vulnerabilities
- Security awareness training
- Preparing for security certifications
- Security research and education

## 🔧 Technical Details

- **Language**: Python 3.8.1+
- **Package Manager**: Poetry
- **Dependencies**: requests, urllib3, fastapi, uvicorn, pydantic
- **Architecture**: Modular design with separate components
- **Threading**: Single-threaded (sequential requests)
- **Output**: Console + JSON export + Web Interface
- **Project Structure**: Proper Python package structure

## 🤝 Contributing

Ideas for improvements:
- Add SQL injection testing
- Implement CSRF detection
- Add authentication bypass testing
- Improve XSS detection accuracy
- Add more security header checks
- Implement rate limiting
- Add WebSocket support for real-time updates
- Add database storage for scan history

## 📄 License

This tool is provided for educational and authorized security testing purposes only.

## 🙏 Acknowledgments

Built following OWASP guidelines and best practices for web application security testing.

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally!** 🛡️
