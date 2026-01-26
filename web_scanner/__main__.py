#!/usr/bin/env python3
"""
CLI Entry Point
Web Application Security Scanner - OWASP Top 10 Basic
"""

import argparse
import sys
from .scanner import WebSecurityScanner


def main():
    parser = argparse.ArgumentParser(
        description='Web Application Security Scanner - OWASP Top 10 Basic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan
  python -m web_scanner -u https://example.com
  
  # Scan with JSON output
  python -m web_scanner -u https://example.com -o results.json
  
  # Scan only headers and endpoints
  python -m web_scanner -u https://example.com --no-xss --no-redirect
  
  # Verbose output
  python -m web_scanner -u https://example.com -v
        """
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL to scan (e.g., https://example.com)')
    parser.add_argument('-o', '--output', help='Output JSON file path')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--verify-ssl', action='store_true',
                       help='Verify SSL certificates (default: False)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--no-headers', action='store_true',
                       help='Skip security header analysis')
    parser.add_argument('--no-endpoints', action='store_true',
                       help='Skip endpoint scanning')
    parser.add_argument('--no-xss', action='store_true',
                       help='Skip XSS testing')
    parser.add_argument('--no-redirect', action='store_true',
                       help='Skip open redirect testing')
    
    args = parser.parse_args()
    
    # Create scanner
    scanner = WebSecurityScanner(
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        verbose=args.verbose
    )
    
    # Perform scan
    success = scanner.scan(
        url=args.url,
        scan_headers=not args.no_headers,
        scan_endpoints=not args.no_endpoints,
        scan_xss=not args.no_xss,
        scan_redirect=not args.no_redirect
    )
    
    if success:
        # Print report
        scanner.print_report()
        
        # Export JSON if requested
        if args.output:
            scanner.export_json(args.output)
            print(f"[+] Results exported to {args.output}")
    
    print("\n[!] Remember: Only scan applications you own or have permission to test!")
    print("[!] Unauthorized scanning may be illegal in your jurisdiction.\n")
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
