"""
Web Application Security Scanner
OWASP Top 10 - Basic Security Scanner
"""

__version__ = "1.0.0"
__author__ = "Web Security Scanner Team"

from .scanner import WebSecurityScanner
from .request_handler import RequestHandler
from .header_analyzer import HeaderAnalyzer
from .endpoint_scanner import EndpointScanner
from .payload_tester import PayloadTester
from .result_aggregator import ResultAggregator

__all__ = [
    'WebSecurityScanner',
    'RequestHandler',
    'HeaderAnalyzer',
    'EndpointScanner',
    'PayloadTester',
    'ResultAggregator',
]
