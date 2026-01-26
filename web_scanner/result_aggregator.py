"""
Result Aggregator Module
Aggregates and formats scan results.
"""

from typing import Dict
import json
from datetime import datetime


class ResultAggregator:
    """Aggregates scan results and generates reports."""
    
    def __init__(self):
        self.results = {
            'scan_info': {},
            'header_analysis': {},
            'endpoint_scan': {},
            'xss_test': {},
            'redirect_test': {},
            'summary': {}
        }
    
    def add_header_analysis(self, analysis: Dict):
        """Add header analysis results."""
        self.results['header_analysis'] = analysis
    
    def add_endpoint_scan(self, scan: Dict):
        """Add endpoint scan results."""
        self.results['endpoint_scan'] = scan
    
    def add_xss_test(self, test: Dict):
        """Add XSS test results."""
        self.results['xss_test'] = test
    
    def add_redirect_test(self, test: Dict):
        """Add redirect test results."""
        self.results['redirect_test'] = test
    
    def set_scan_info(self, url: str, timestamp: str = None):
        """Set scan information."""
        self.results['scan_info'] = {
            'target_url': url,
            'scan_timestamp': timestamp or datetime.now().isoformat(),
            'scanner_version': '1.0'
        }
    
    def generate_summary(self) -> Dict:
        """Generate summary of all findings."""
        all_vulnerabilities = []
        
        # Collect all vulnerabilities
        if 'vulnerabilities' in self.results['header_analysis']:
            all_vulnerabilities.extend(self.results['header_analysis']['vulnerabilities'])
        
        if 'vulnerabilities' in self.results['endpoint_scan']:
            all_vulnerabilities.extend(self.results['endpoint_scan']['vulnerabilities'])
        
        if 'vulnerabilities' in self.results['xss_test']:
            all_vulnerabilities.extend(self.results['xss_test']['vulnerabilities'])
        
        if 'vulnerabilities' in self.results['redirect_test']:
            all_vulnerabilities.extend(self.results['redirect_test']['vulnerabilities'])
        
        # Count by severity
        high_count = sum(1 for v in all_vulnerabilities if v.get('severity') == 'high')
        medium_count = sum(1 for v in all_vulnerabilities if v.get('severity') == 'medium')
        low_count = sum(1 for v in all_vulnerabilities if v.get('severity') == 'low')
        
        # Count by type
        vulnerability_types = {}
        for v in all_vulnerabilities:
            vuln_type = v.get('type', 'Unknown')
            vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
        
        # Determine overall risk
        if high_count > 0:
            overall_risk = 'High'
        elif medium_count > 0:
            overall_risk = 'Medium'
        elif low_count > 0:
            overall_risk = 'Low'
        else:
            overall_risk = 'None'
        
        self.results['summary'] = {
            'total_vulnerabilities': len(all_vulnerabilities),
            'high_severity': high_count,
            'medium_severity': medium_count,
            'low_severity': low_count,
            'overall_risk': overall_risk,
            'vulnerability_types': vulnerability_types,
            'all_vulnerabilities': all_vulnerabilities
        }
        
        return self.results['summary']
    
    def get_results(self) -> Dict:
        """Get all aggregated results."""
        return self.results
    
    def export_json(self, filename: str):
        """Export results to JSON file."""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
    
    def print_report(self):
        """Print formatted report to console."""
        summary = self.results.get('summary', {})
        
        print("\n" + "="*70)
        print("WEB APPLICATION SECURITY SCAN REPORT")
        print("="*70)
        print(f"\nTarget: {self.results['scan_info'].get('target_url', 'N/A')}")
        print(f"Scan Time: {self.results['scan_info'].get('scan_timestamp', 'N/A')}")
        print(f"\nOverall Risk: {summary.get('overall_risk', 'Unknown')}")
        print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"  - High: {summary.get('high_severity', 0)}")
        print(f"  - Medium: {summary.get('medium_severity', 0)}")
        print(f"  - Low: {summary.get('low_severity', 0)}")
        
        # Header Analysis
        header_analysis = self.results.get('header_analysis', {})
        if header_analysis:
            print("\n" + "-"*70)
            print("SECURITY HEADERS ANALYSIS")
            print("-"*70)
            missing = header_analysis.get('missing_headers', [])
            if missing:
                print(f"\n[!] Missing {len(missing)} security header(s):")
                for header in missing:
                    print(f"    - {header['name']}: {header['description']}")
            else:
                print("\n[+] All required security headers are present")
            
            present = header_analysis.get('present_headers', [])
            if present:
                print(f"\n[+] Found {len(present)} security header(s)")
        
        # Endpoint Scan
        endpoint_scan = self.results.get('endpoint_scan', {})
        if endpoint_scan:
            found = endpoint_scan.get('found_endpoints', [])
            if found:
                print("\n" + "-"*70)
                print("ENDPOINT SCAN")
                print("-"*70)
                print(f"\n[!] Found {len(found)} exposed endpoint(s):")
                for endpoint in found[:10]:  # Show first 10
                    print(f"    - {endpoint['path']} ({endpoint['status_code']})")
                if len(found) > 10:
                    print(f"    ... and {len(found) - 10} more")
        
        # XSS Test
        xss_test = self.results.get('xss_test', {})
        if xss_test:
            vulnerable = xss_test.get('vulnerable_parameters', [])
            if vulnerable:
                print("\n" + "-"*70)
                print("XSS VULNERABILITY TEST")
                print("-"*70)
                print(f"\n[!] Found XSS vulnerability in {len(vulnerable)} parameter(s):")
                for vuln in vulnerable:
                    print(f"    - Parameter: {vuln['parameter']}")
                    print(f"      Payload: {vuln['payload'][:50]}...")
        
        # Redirect Test
        redirect_test = self.results.get('redirect_test', {})
        if redirect_test:
            vulnerable = redirect_test.get('vulnerable_parameters', [])
            if vulnerable:
                print("\n" + "-"*70)
                print("OPEN REDIRECT TEST")
                print("-"*70)
                print(f"\n[!] Found open redirect vulnerability in {len(vulnerable)} parameter(s):")
                for vuln in vulnerable:
                    print(f"    - Parameter: {vuln['parameter']}")
                    print(f"      Redirects to: {vuln['redirect_location']}")
        
        # All Vulnerabilities
        all_vulns = summary.get('all_vulnerabilities', [])
        if all_vulns:
            print("\n" + "-"*70)
            print("DETAILED VULNERABILITIES")
            print("-"*70)
            for i, vuln in enumerate(all_vulns, 1):
                print(f"\n[{i}] {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'unknown').upper()}")
                print(f"    Description: {vuln.get('description', 'N/A')}")
                if 'url' in vuln:
                    print(f"    URL: {vuln['url']}")
        
        print("\n" + "="*70)
        print("Scan completed. Use JSON export for detailed results.")
        print("="*70 + "\n")
