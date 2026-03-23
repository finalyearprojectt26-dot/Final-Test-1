#!/usr/bin/env python3
"""
Secure Code Analyzer - CLI and Server Entry Point

This module provides:
1. Command-line interface for scanning files
2. Flask server mode for API access

Usage:
    # Scan a directory
    python -m secure_code_analyzer /path/to/source

    # Scan with output reports
    python -m secure_code_analyzer /path/to/source -o ./reports

    # Start API server
    python -m secure_code_analyzer --serve

    # Start API server on custom port
    python -m secure_code_analyzer --serve --port 8080
"""

import argparse
import sys
import json
import os
from typing import Optional

from .core.scanner import Scanner, ScanConfig
from .core.reporters import generate_reports
from .core.severity import SeverityLevel
from .core.utils import logger


def setup_argparse() -> argparse.ArgumentParser:
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog='secure-code-analyzer',
        description='Static security analysis tool for source code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/source              Scan a directory
  %(prog)s /path/to/file.js             Scan a single file
  %(prog)s /path/to/source -o reports   Scan and save reports
  %(prog)s --serve                      Start API server
  %(prog)s --serve --port 8080          Start on custom port
        """
    )
    
    # Positional argument for scan target
    parser.add_argument(
        'target',
        nargs='?',
        help='Path to file or directory to scan'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output',
        metavar='DIR',
        help='Output directory for reports'
    )
    
    parser.add_argument(
        '-f', '--format',
        choices=['json', 'html', 'both'],
        default='both',
        help='Report format (default: both)'
    )
    
    parser.add_argument(
        '--json-only',
        action='store_true',
        help='Output only JSON to stdout (for integration)'
    )
    
    # Scan options
    parser.add_argument(
        '-r', '--recursive',
        action='store_true',
        default=True,
        help='Scan directories recursively (default: True)'
    )
    
    parser.add_argument(
        '--no-recursive',
        action='store_false',
        dest='recursive',
        help='Disable recursive scanning'
    )
    
    parser.add_argument(
        '-j', '--jobs',
        type=int,
        default=4,
        metavar='N',
        help='Number of parallel workers (default: 4)'
    )
    
    parser.add_argument(
        '--max-file-size',
        type=int,
        default=5*1024*1024,
        metavar='BYTES',
        help='Maximum file size to scan in bytes (default: 5MB)'
    )
    
    parser.add_argument(
        '--exclude',
        action='append',
        metavar='PATTERN',
        help='Glob patterns to exclude (can be repeated)'
    )
    
    # Severity filter
    parser.add_argument(
        '--severity',
        choices=['critical', 'high', 'medium', 'low', 'info'],
        help='Minimum severity to report'
    )
    
    # Server options
    parser.add_argument(
        '--serve',
        action='store_true',
        help='Start the Flask API server'
    )
    
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Server host (default: 127.0.0.1)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Server port (default: 5000)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    # Other options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    return parser


def print_summary(result: dict, verbose: bool = False):
    """Print a human-readable summary of scan results."""
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    
    print(f"\nTarget:        {result['target_path']}")
    print(f"Scan ID:       {result['scan_id']}")
    print(f"Scan Time:     {result['scan_time']}s")
    print(f"Files Scanned: {result['files_scanned']}")
    print(f"Files Skipped: {result['files_skipped']}")
    
    severity_summary = result.get('severity_summary', {})
    by_severity = severity_summary.get('by_severity', {})
    
    print(f"\n{'Severity':<12} {'Count':<8}")
    print("-" * 20)
    
    # Print severity counts with colors if available
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    colors = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[33m',    # Orange
        'low': '\033[94m',       # Blue
        'info': '\033[90m',      # Gray
    }
    reset = '\033[0m'
    
    for sev in severity_order:
        count = by_severity.get(sev, 0)
        if count > 0:
            color = colors.get(sev, '')
            print(f"{color}{sev.upper():<12} {count:<8}{reset}")
        else:
            print(f"{sev.upper():<12} {count:<8}")
    
    total = result.get('total_findings', 0)
    print("-" * 20)
    print(f"{'TOTAL':<12} {total:<8}")
    
    # Print findings details
    if verbose and total > 0:
        print("\n" + "=" * 60)
        print("FINDINGS DETAIL")
        print("=" * 60)
        
        for finding in result.get('findings', []):
            sev = finding.get('severity', 'info').upper()
            color = colors.get(finding.get('severity', 'info'), '')
            
            print(f"\n{color}[{sev}]{reset} {finding.get('rule_name', 'Unknown')}")
            print(f"  File: {finding.get('file_path', 'Unknown')}:{finding.get('line_number', 0)}")
            print(f"  Rule: {finding.get('rule_id', 'Unknown')}")
            print(f"  {finding.get('description', '')}")
            
            if finding.get('remediation'):
                print(f"  Fix: {finding.get('remediation')}")
    
    # Print errors if any
    errors = result.get('errors', [])
    if errors:
        print("\n" + "-" * 60)
        print("ERRORS:")
        for error in errors[:5]:  # Limit to first 5 errors
            print(f"  - {error}")
        if len(errors) > 5:
            print(f"  ... and {len(errors) - 5} more errors")


def filter_by_severity(findings: list, min_severity: str) -> list:
    """Filter findings by minimum severity."""
    severity_order = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3,
        'info': 4
    }
    
    min_level = severity_order.get(min_severity.lower(), 4)
    
    return [
        f for f in findings
        if severity_order.get(f.get('severity', 'info').lower(), 4) <= min_level
    ]


def run_scan(args) -> int:
    """Run a scan based on CLI arguments."""
    if not args.target:
        print("Error: No target specified. Use -h for help.", file=sys.stderr)
        return 1
    
    if not os.path.exists(args.target):
        print(f"Error: Target not found: {args.target}", file=sys.stderr)
        return 1
    
    # Build configuration
    config = ScanConfig(
        recursive=args.recursive,
        parallel_workers=args.jobs,
        max_file_size=args.max_file_size,
        generate_html_report=args.format in ('html', 'both'),
        generate_json_report=args.format in ('json', 'both')
    )
    
    if args.exclude:
        config.exclude_patterns.extend(args.exclude)
    
    # Create scanner and run
    scanner = Scanner(config=config)
    
    if not args.json_only:
        print(f"Scanning: {args.target}")
        print("Please wait...")
    
    result = scanner.scan(args.target, output_dir=args.output)
    result_dict = result.to_dict()
    
    # Filter by severity if specified
    if args.severity:
        result_dict['findings'] = filter_by_severity(
            result_dict['findings'],
            args.severity
        )
        result_dict['total_findings'] = len(result_dict['findings'])
    
    # Output results
    if args.json_only:
        print(json.dumps(result_dict, indent=2))
    else:
        print_summary(result_dict, verbose=args.verbose)
        
        if args.output:
            print(f"\nReports saved to: {args.output}")
    
    # Return exit code based on findings
    by_severity = result_dict.get('severity_summary', {}).get('by_severity', {})
    
    if by_severity.get('critical', 0) > 0:
        return 2  # Critical findings
    elif by_severity.get('high', 0) > 0:
        return 1  # High severity findings
    else:
        return 0  # Success


def run_server(args):
    """Start the Flask API server."""
    from flask import Flask
    from flask_cors import CORS
    from .api.routes import api
    
    app = Flask(__name__)
    
    # Enable CORS for all routes
    CORS(app)
    
    # Configure app
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload
    
    # Register API blueprint
    app.register_blueprint(api, url_prefix='')
    
    # Add a simple index route
    @app.route('/')
    def index():
        return {
            'name': 'Secure Code Analyzer API',
            'version': '1.0.0',
            'endpoints': {
                'POST /scan-file': 'Scan uploaded source files',
                'POST /scan-url': 'Extract and scan code from URL',
                'GET /rules': 'List available security rules',
                'GET /health': 'Health check'
            }
        }
    
    print(f"Starting Secure Code Analyzer API server...")
    print(f"Server: http://{args.host}:{args.port}")
    print(f"Documentation: http://{args.host}:{args.port}/")
    print("\nPress Ctrl+C to stop")
    
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug
    )


def main():
    """Main entry point."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    if args.serve:
        run_server(args)
    elif args.target:
        sys.exit(run_scan(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
