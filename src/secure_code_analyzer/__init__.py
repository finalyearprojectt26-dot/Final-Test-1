"""
Secure Code Analyzer

A static application security testing (SAST) tool that analyzes
source code for security vulnerabilities.

Features:
- Regex-based pattern matching
- AST-based analysis for JavaScript, Python, PHP, and Java
- URL fetching for client-side code extraction
- JSON and HTML report generation
- REST API for integration

Usage:
    # As a library
    from secure_code_analyzer.core.scanner import scan_directory
    result = scan_directory("/path/to/source")

    # From command line
    python -m secure_code_analyzer /path/to/source

    # As API server
    python -m secure_code_analyzer --serve
"""

__version__ = '1.0.0'
__author__ = 'Secure Code Analyzer Team'

from .core.scanner import Scanner, ScanConfig, scan_directory
from .core.detectors import VulnerabilityDetector, detect_vulnerabilities
from .core.url_fetcher import URLFetcher, fetch_url_for_scanning
from .core.reporters import ReportGenerator, generate_reports
from .core.severity import SeverityLevel, classify_severity

__all__ = [
    'Scanner',
    'ScanConfig',
    'scan_directory',
    'VulnerabilityDetector',
    'detect_vulnerabilities',
    'URLFetcher',
    'fetch_url_for_scanning',
    'ReportGenerator',
    'generate_reports',
    'SeverityLevel',
    'classify_severity',
]
