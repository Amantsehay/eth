"""
Web Security Scanner
Main scanner class that orchestrates all components.
"""

from urllib.parse import urlparse
from .request_handler import RequestHandler
from .header_analyzer import HeaderAnalyzer
from .endpoint_scanner import EndpointScanner
from .payload_tester import PayloadTester
from .result_aggregator import ResultAggregator


class WebSecurityScanner:
    """Main scanner class that orchestrates all components."""
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False, verbose: bool = False, silent: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.silent = silent
        self.request_handler = RequestHandler(timeout=timeout, verify_ssl=verify_ssl)
        self.header_analyzer = HeaderAnalyzer(self.request_handler)
        self.endpoint_scanner = EndpointScanner(self.request_handler)
        self.payload_tester = PayloadTester(self.request_handler)
        self.result_aggregator = ResultAggregator()
    
    def scan(self, url: str, scan_headers: bool = True, scan_endpoints: bool = True,
             scan_xss: bool = True, scan_redirect: bool = True, scan_sqli: bool = True):
        """Perform comprehensive security scan."""
        
        # Validate URL
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            print(f"[-] Invalid URL: {url}")
            print("[!] URL must include scheme (http:// or https://)")
            return False
        
        # Ensure URL has scheme
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
        
        if not self.silent:
            print(f"""
╔══════════════════════════════════════════════════════════╗
║     Web Application Security Scanner v1.0                ║
║     OWASP Top 10 - Basic Security Assessment            ║
╚══════════════════════════════════════════════════════════╝

[*] Target URL: {url}
[*] Starting security scan...
        """)
        
        self.result_aggregator.set_scan_info(url)
        
        try:
            # 1. Header Analysis
            if scan_headers:
                if not self.silent:
                    print("[*] Analyzing security headers...")
                header_results = self.header_analyzer.analyze(url)
                self.result_aggregator.add_header_analysis(header_results)
                if self.verbose and not self.silent:
                    missing = len(header_results.get('missing_headers', []))
                    print(f"    Found {missing} missing security header(s)")
            
            # 2. Endpoint Scanning
            if scan_endpoints:
                if not self.silent:
                    print("[*] Scanning for exposed endpoints and sensitive files...")
                base_url = self.request_handler.get_base_url(url)
                endpoint_results = self.endpoint_scanner.scan(base_url)
                self.result_aggregator.add_endpoint_scan(endpoint_results)
                if self.verbose and not self.silent:
                    found = len(endpoint_results.get('found_endpoints', []))
                    print(f"    Found {found} exposed endpoint(s)")
            
            # 3. XSS Testing
            if scan_xss:
                if not self.silent:
                    print("[*] Testing for reflected XSS vulnerabilities...")
                xss_results = self.payload_tester.test_xss(url)
                self.result_aggregator.add_xss_test(xss_results)
                if self.verbose and not self.silent:
                    vulnerable = len(xss_results.get('vulnerable_parameters', []))
                    print(f"    Tested XSS payloads, found {vulnerable} vulnerable parameter(s)")
            
            # 4. Open Redirect Testing
            if scan_redirect:
                if not self.silent:
                    print("[*] Testing for open redirect vulnerabilities...")
                redirect_results = self.payload_tester.test_open_redirect(url)
                self.result_aggregator.add_redirect_test(redirect_results)
                if self.verbose and not self.silent:
                    vulnerable = len(redirect_results.get('vulnerable_parameters', []))
                    print(f"    Tested redirect payloads, found {vulnerable} vulnerable parameter(s)")

            # 5. SQL Injection Testing (basic, error-based)
            if scan_sqli:
                if not self.silent:
                    print("[*] Testing for SQL injection (basic error-based)...")
                sqli_results = self.payload_tester.test_sqli(url)
                self.result_aggregator.add_sqli_test(sqli_results)
                if self.verbose and not self.silent:
                    vulnerable = len(sqli_results.get('vulnerable_parameters', []))
                    print(f"    Tested SQLi payloads, found {vulnerable} potentially vulnerable parameter(s)")
            
            # Generate summary
            if not self.silent:
                print("\n[*] Generating report...")
            self.result_aggregator.generate_summary()
            
            return True
            
        except KeyboardInterrupt:
            if not self.silent:
                print("\n\n[!] Scan interrupted by user")
            return False
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            if not self.silent:
                print(f"\n[-] Error during scan: {e}")
            if self.verbose and not self.silent:
                import traceback
                traceback.print_exc()
            return False
        finally:
            self.request_handler.close()
    
    def get_results(self):
        """Get scan results."""
        return self.result_aggregator.get_results()
    
    def print_report(self):
        """Print formatted report."""
        self.result_aggregator.print_report()
    
    def export_json(self, filename: str):
        """Export results to JSON."""
        self.result_aggregator.export_json(filename)
