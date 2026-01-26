"""
Endpoint Scanner Module
Scans for open directories and sensitive files.
"""

from typing import Dict
from .request_handler import RequestHandler


class EndpointScanner:
    """Scans for exposed directories and sensitive files."""
    
    # Common sensitive files and directories
    SENSITIVE_PATHS = [
        # Configuration files
        '.env',
        '.git/config',
        '.gitignore',
        'config.php',
        'config.ini',
        'config.json',
        'web.config',
        '.htaccess',
        'robots.txt',
        
        # Backup files
        'backup.sql',
        'backup.tar.gz',
        'backup.zip',
        'database.sql',
        'dump.sql',
        
        # Common directories
        'admin/',
        'administrator/',
        'phpmyadmin/',
        'wp-admin/',
        'wp-content/',
        'wp-includes/',
        '.git/',
        '.svn/',
        '.hg/',
        'backup/',
        'backups/',
        'old/',
        'test/',
        'tests/',
        'dev/',
        'development/',
        'staging/',
        'tmp/',
        'temp/',
        'logs/',
        'log/',
        
        # Sensitive files
        'phpinfo.php',
        'info.php',
        'test.php',
        'readme.txt',
        'readme.md',
        'LICENSE',
        'CHANGELOG',
        'composer.json',
        'package.json',
        
        # API endpoints
        'api/',
        'api/v1/',
        'api/v2/',
        'graphql',
        'graphiql',
    ]
    
    def __init__(self, request_handler: RequestHandler):
        self.request_handler = request_handler
    
    def scan(self, base_url: str) -> Dict:
        """Scan for sensitive files and directories."""
        results = {
            'base_url': base_url,
            'found_endpoints': [],
            'vulnerabilities': [],
            'severity': 'low'
        }
        
        found_count = 0
        
        for path in self.SENSITIVE_PATHS:
            url = self.request_handler.build_url(base_url, path)
            
            # Try HEAD first (faster)
            response = self.request_handler.head(url)
            
            # If HEAD fails or returns 405, try GET
            if not response or response.status_code == 405:
                response = self.request_handler.get(url)
            
            if response and response.status_code == 200:
                found_count += 1
                endpoint_info = {
                    'path': path,
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content) if hasattr(response, 'content') else 0,
                    'content_type': response.headers.get('Content-Type', 'unknown')
                }
                
                results['found_endpoints'].append(endpoint_info)
                
                # Determine severity
                severity = 'low'
                if any(keyword in path.lower() for keyword in ['.env', 'config', 'backup', 'database', '.git']):
                    severity = 'high'
                elif any(keyword in path.lower() for keyword in ['admin', 'phpmyadmin', 'api']):
                    severity = 'medium'
                
                results['vulnerabilities'].append({
                    'type': 'Exposed Endpoint',
                    'endpoint': path,
                    'url': url,
                    'description': f'Sensitive file/directory found: {path}',
                    'severity': severity
                })
        
        # Update overall severity
        if any(v['severity'] == 'high' for v in results['vulnerabilities']):
            results['severity'] = 'high'
        elif any(v['severity'] == 'medium' for v in results['vulnerabilities']):
            results['severity'] = 'medium'
        elif found_count > 0:
            results['severity'] = 'medium'
        
        return results
