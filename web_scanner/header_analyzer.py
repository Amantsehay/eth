"""
Header Analyzer Module
Analyzes HTTP security headers for missing or misconfigured headers.
"""

from typing import Dict
from .request_handler import RequestHandler


class HeaderAnalyzer:
    """Analyzes security headers in HTTP responses."""
    
    # OWASP recommended security headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'required': True,
            'description': 'Prevents protocol downgrade attacks and cookie hijacking',
            'recommended_value': 'max-age=31536000; includeSubDomains'
        },
        'X-Content-Type-Options': {
            'required': True,
            'description': 'Prevents MIME type sniffing',
            'recommended_value': 'nosniff'
        },
        'X-Frame-Options': {
            'required': True,
            'description': 'Prevents clickjacking attacks',
            'recommended_value': 'DENY or SAMEORIGIN'
        },
        'X-XSS-Protection': {
            'required': False,  # Deprecated but still checked
            'description': 'Enables XSS filtering (deprecated in modern browsers)',
            'recommended_value': '1; mode=block'
        },
        'Content-Security-Policy': {
            'required': True,
            'description': 'Prevents XSS, data injection, and other attacks',
            'recommended_value': "default-src 'self'"
        },
        'Referrer-Policy': {
            'required': False,
            'description': 'Controls referrer information sent with requests',
            'recommended_value': 'strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'required': False,
            'description': 'Controls browser features and APIs',
            'recommended_value': 'geolocation=(), microphone=(), camera=()'
        }
    }
    
    def __init__(self, request_handler: RequestHandler):
        self.request_handler = request_handler
    
    def analyze(self, url: str) -> Dict:
        """Analyze security headers for a given URL."""
        results = {
            'url': url,
            'missing_headers': [],
            'present_headers': [],
            'vulnerabilities': [],
            'severity': 'low'
        }
        
        response = self.request_handler.get(url)
        if not response:
            results['vulnerabilities'].append({
                'type': 'Connection Error',
                'description': 'Could not connect to the target URL',
                'severity': 'high'
            })
            results['severity'] = 'high'
            return results
        
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Check each security header
        for header_name, header_info in self.SECURITY_HEADERS.items():
            header_lower = header_name.lower()
            
            if header_lower in response_headers:
                header_value = response_headers[header_lower]
                results['present_headers'].append({
                    'name': header_name,
                    'value': header_value,
                    'recommended': header_info['recommended_value']
                })
                
                # Check if value is properly configured
                if header_name == 'X-Frame-Options' and header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                    results['vulnerabilities'].append({
                        'type': 'Misconfigured Header',
                        'header': header_name,
                        'description': f'{header_name} has weak value: {header_value}',
                        'severity': 'medium'
                    })
            else:
                if header_info['required']:
                    results['missing_headers'].append({
                        'name': header_name,
                        'description': header_info['description'],
                        'recommended_value': header_info['recommended_value']
                    })
                    
                    results['vulnerabilities'].append({
                        'type': 'Missing Security Header',
                        'header': header_name,
                        'description': f'Missing required security header: {header_name}',
                        'severity': 'high' if header_name in ['Strict-Transport-Security', 'Content-Security-Policy'] else 'medium'
                    })
        
        # Determine overall severity
        high_severity = any(v['severity'] == 'high' for v in results['vulnerabilities'])
        medium_severity = any(v['severity'] == 'medium' for v in results['vulnerabilities'])
        
        if high_severity:
            results['severity'] = 'high'
        elif medium_severity:
            results['severity'] = 'medium'
        
        # Check for server information disclosure
        server_header = response_headers.get('server', '')
        if server_header:
            results['server_info'] = server_header
            if any(keyword in server_header.lower() for keyword in ['apache', 'nginx', 'iis', 'tomcat']):
                results['vulnerabilities'].append({
                    'type': 'Server Information Disclosure',
                    'description': f'Server header reveals: {server_header}',
                    'severity': 'low'
                })
        
        x_powered_by = response_headers.get('x-powered-by', '')
        if x_powered_by:
            results['x_powered_by'] = x_powered_by
            results['vulnerabilities'].append({
                'type': 'Server Information Disclosure',
                'description': f'X-Powered-By header reveals: {x_powered_by}',
                'severity': 'low'
            })
        
        return results
