"""
Payload Tester Module
Tests for XSS and open redirect vulnerabilities.
"""

from typing import Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .request_handler import RequestHandler


class PayloadTester:
    """Tests for reflected XSS and open redirect vulnerabilities."""
    
    # XSS payloads for testing
    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "javascript:alert('XSS')",
        '<iframe src="javascript:alert(\'XSS\')">',
        '<body onload=alert("XSS")>',
        '<input onfocus=alert("XSS") autofocus>',
    ]
    
    # Open redirect payloads
    REDIRECT_PAYLOADS = [
        'http://evil.com',
        'https://evil.com',
        '//evil.com',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        '/\\evil.com',
    ]

    # Basic SQL injection payloads (non-destructive)
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1 --",
        "1' OR '1'='1",
        "1' OR 1=1 --",
        "' UNION SELECT NULL--",
        "' UNION SELECT username, password FROM users--",
    ]

    # Common database error message fragments to look for
    SQL_ERROR_PATTERNS = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "pg_query():",
        "sqlstate[",
        "ora-01756",
        "odbc sql server driver",
        "mysql_fetch_array()",
        "native client",
    ]
    
    def __init__(self, request_handler: RequestHandler):
        self.request_handler = request_handler
    
    def test_xss(self, url: str) -> Dict:
        """Test for reflected XSS vulnerability."""
        results = {
            'url': url,
            'vulnerable_parameters': [],
            'vulnerabilities': [],
            'severity': 'low'
        }
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # If no parameters, try common parameter names
            params = {
                'q': ['test'],
                'search': ['test'],
                'query': ['test'],
                'input': ['test'],
                'name': ['test'],
                'user': ['test'],
                'id': ['test']
            }
        
        for param_name in params.keys():
            for payload in self.XSS_PAYLOADS:
                # Create new URL with XSS payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                
                response = self.request_handler.get(test_url)
                if not response:
                    continue
                
                # Check if payload is reflected in response
                response_text = response.text.lower()
                payload_lower = payload.lower()
                
                # Check for reflection (with some normalization)
                if payload_lower in response_text or self._check_reflection(payload, response_text):
                    if param_name not in [v['parameter'] for v in results['vulnerable_parameters']]:
                        results['vulnerable_parameters'].append({
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url
                        })
                        
                        results['vulnerabilities'].append({
                            'type': 'Reflected XSS',
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                            'description': f'Reflected XSS vulnerability found in parameter: {param_name}',
                            'severity': 'high'
                        })
                        results['severity'] = 'high'
                        break  # Found XSS in this parameter, move to next
        
        return results
    
    def test_open_redirect(self, url: str) -> Dict:
        """Test for open redirect vulnerability."""
        results = {
            'url': url,
            'vulnerable_parameters': [],
            'vulnerabilities': [],
            'severity': 'low'
        }
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Common redirect parameter names
        redirect_params = ['redirect', 'redirect_to', 'redirect_uri', 'return', 'return_to', 
                          'return_url', 'url', 'next', 'goto', 'target', 'destination', 'r']
        
        # Add existing parameters
        redirect_params.extend(params.keys())
        redirect_params = list(set(redirect_params))  # Remove duplicates
        
        for param_name in redirect_params:
            for payload in self.REDIRECT_PAYLOADS:
                # Create test URL with redirect payload
                test_params = params.copy() if params else {}
                test_params[param_name] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                
                # Don't follow redirects to check the redirect location
                response = self.request_handler.get(test_url, allow_redirects=False)
                if not response:
                    continue
                
                # Check for redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    # Check if redirect goes to external domain
                    if location and self._is_external_redirect(location, parsed.netloc):
                        if param_name not in [v['parameter'] for v in results['vulnerable_parameters']]:
                            results['vulnerable_parameters'].append({
                                'parameter': param_name,
                                'payload': payload,
                                'redirect_location': location,
                                'url': test_url
                            })
                            
                            results['vulnerabilities'].append({
                                'type': 'Open Redirect',
                                'parameter': param_name,
                                'payload': payload,
                                'redirect_location': location,
                                'url': test_url,
                                'description': f'Open redirect vulnerability found in parameter: {param_name}',
                                'severity': 'medium'
                            })
                            
                            if results['severity'] != 'high':
                                results['severity'] = 'medium'
                            break  # Found redirect in this parameter
        
        return results

    def test_sqli(self, url: str) -> Dict:
        """Test for basic SQL injection vulnerability by error-based detection."""
        results = {
            'url': url,
            'vulnerable_parameters': [],
            'vulnerabilities': [],
            'severity': 'low'
        }

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            # If no parameters, try common parameter names
            params = {
                'id': ['1'],
                'user': ['1'],
                'uid': ['1'],
                'product': ['1'],
            }

        for param_name in params.keys():
            for payload in self.SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))

                response = self.request_handler.get(test_url)
                if not response or not response.text:
                    continue

                text_lower = response.text.lower()
                if any(err in text_lower for err in self.SQL_ERROR_PATTERNS):
                    if param_name not in [v['parameter'] for v in results['vulnerable_parameters']]:
                        results['vulnerable_parameters'].append({
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                        })

                        results['vulnerabilities'].append({
                            'type': 'SQL Injection (error-based)',
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                            'description': f'Potential SQL injection vulnerability in parameter: {param_name} (error message detected)',
                            'severity': 'high',
                        })
                        results['severity'] = 'high'
                        break  # move to next parameter

        return results
    
    def _check_reflection(self, payload: str, response_text: str) -> bool:
        """Check if payload is reflected (with HTML encoding variations)."""
        # Check for common encoding
        encoded_variants = [
            payload.replace('<', '&lt;'),
            payload.replace('>', '&gt;'),
            payload.replace('"', '&quot;'),
            payload.replace("'", '&#x27;'),
            payload.replace('/', '&#x2F;'),
        ]
        
        for variant in encoded_variants:
            if variant.lower() in response_text:
                return True
        
        return False
    
    def _is_external_redirect(self, location: str, original_domain: str) -> bool:
        """Check if redirect location is external."""
        if not location:
            return False
        
        # Parse the location
        if location.startswith('//'):
            return True  # Protocol-relative URL
        
        if location.startswith('http://') or location.startswith('https://'):
            parsed = urlparse(location)
            return parsed.netloc != original_domain
        
        if location.startswith('javascript:') or location.startswith('data:'):
            return True
        
        return False
