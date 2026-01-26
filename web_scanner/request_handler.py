"""
Request Handler Module
Handles all HTTP requests for the security scanner.
"""

import requests
from typing import Dict, Optional
from urllib.parse import urljoin, urlparse
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RequestHandler:
    """Handles HTTP requests with configurable options."""
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False, user_agent: str = None):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        
    def get(self, url: str, params: Dict = None, headers: Dict = None, allow_redirects: bool = True) -> Optional[requests.Response]:
        """Perform GET request."""
        try:
            custom_headers = self.session.headers.copy()
            if headers:
                custom_headers.update(headers)
            
            response = self.session.get(
                url,
                params=params,
                headers=custom_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects
            )
            return response
        except requests.exceptions.RequestException:
            return None
    
    def post(self, url: str, data: Dict = None, json: Dict = None, headers: Dict = None) -> Optional[requests.Response]:
        """Perform POST request."""
        try:
            custom_headers = self.session.headers.copy()
            if headers:
                custom_headers.update(headers)
            
            response = self.session.post(
                url,
                data=data,
                json=json,
                headers=custom_headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            return response
        except requests.exceptions.RequestException:
            return None
    
    def head(self, url: str, headers: Dict = None) -> Optional[requests.Response]:
        """Perform HEAD request."""
        try:
            custom_headers = self.session.headers.copy()
            if headers:
                custom_headers.update(headers)
            
            response = self.session.head(
                url,
                headers=custom_headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            return response
        except requests.exceptions.RequestException:
            return None
    
    def get_base_url(self, url: str) -> str:
        """Extract base URL from full URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def build_url(self, base_url: str, path: str) -> str:
        """Build full URL from base and path."""
        return urljoin(base_url, path)
    
    def close(self):
        """Close the session."""
        self.session.close()
