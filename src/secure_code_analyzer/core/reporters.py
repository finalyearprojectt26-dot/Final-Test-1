"""
Report generation module for scan results.
Generates both JSON and HTML reports with consistent formatting
regardless of the scan source (file or URL).
"""

import os
import json
import html
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from .utils import logger


class ReportGenerator:
    """
    Generates vulnerability scan reports in multiple formats.
    
    Supported formats:
    - JSON: Machine-readable format for integration
    - HTML: Human-readable format with styling
    """
    
    def __init__(self):
        self.logger = logger
    
    def generate_json_report(
        self, 
        scan_result: Dict[str, Any], 
        output_path: str
    ) -> str:
        """
        Generate a JSON report from scan results.
        
        Args:
            scan_result: Scan result dictionary
            output_path: Path to save the report
            
        Returns:
            Path to the generated report
        """
        # Add report metadata
        report = {
            "report_generated": datetime.utcnow().isoformat() + "Z",
            "report_format": "json",
            "report_version": "1.0",
            **scan_result
        }
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"JSON report generated: {output_path}")
        return output_path
    
    def generate_html_report(
        self, 
        scan_result: Dict[str, Any], 
        output_path: str
    ) -> str:
        """
        Generate an HTML report from scan results.
        
        Args:
            scan_result: Scan result dictionary
            output_path: Path to save the report
            
        Returns:
            Path to the generated report
        """
        html_content = self._build_html_report(scan_result)
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {output_path}")
        return output_path
    
    def _build_html_report(self, scan_result: Dict[str, Any]) -> str:
        """Build the HTML report content."""
        
        severity_summary = scan_result.get('severity_summary', {})
        by_severity = severity_summary.get('by_severity', {})
        findings = scan_result.get('findings', [])
        
        # Build findings HTML
        findings_html = self._build_findings_html(findings)
        
        # Build the complete HTML document
        html_template = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {html.escape(scan_result.get('scan_id', 'Unknown'))}</title>
    <style>
        :root {{
            --critical-color: #dc2626;
            --high-color: #ea580c;
            --medium-color: #ca8a04;
            --low-color: #2563eb;
            --info-color: #6b7280;
            --bg-color: #f9fafb;
            --card-bg: #ffffff;
            --text-color: #111827;
            --text-secondary: #6b7280;
            --border-color: #e5e7eb;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}
        
        h2 {{
            font-size: 1.5rem;
            margin: 2rem 0 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--border-color);
        }}
        
        .subtitle {{
            color: var(--text-secondary);
            margin-bottom: 2rem;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .summary-card {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        .summary-card h3 {{
            font-size: 0.875rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}
        
        .summary-card .value {{
            font-size: 2rem;
            font-weight: bold;
        }}
        
        .severity-badges {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 2rem;
        }}
        
        .badge {{
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-weight: 600;
            font-size: 0.875rem;
            color: white;
        }}
        
        .badge.critical {{ background-color: var(--critical-color); }}
        .badge.high {{ background-color: var(--high-color); }}
        .badge.medium {{ background-color: var(--medium-color); }}
        .badge.low {{ background-color: var(--low-color); }}
        .badge.info {{ background-color: var(--info-color); }}
        
        .finding {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid var(--info-color);
        }}
        
        .finding.critical {{ border-left-color: var(--critical-color); }}
        .finding.high {{ border-left-color: var(--high-color); }}
        .finding.medium {{ border-left-color: var(--medium-color); }}
        .finding.low {{ border-left-color: var(--low-color); }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }}
        
        .finding-title {{
            font-weight: 600;
            font-size: 1.125rem;
        }}
        
        .finding-meta {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
        }}
        
        .finding-description {{
            margin-bottom: 1rem;
        }}
        
        .code-snippet {{
            background: #1f2937;
            color: #f3f4f6;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
            font-size: 0.875rem;
            margin: 1rem 0;
        }}
        
        .code-line {{
            display: block;
            padding: 0.125rem 0;
        }}
        
        .code-line.highlighted {{
            background: rgba(239, 68, 68, 0.3);
            margin: 0 -1rem;
            padding-left: 1rem;
            padding-right: 1rem;
        }}
        
        .line-number {{
            color: #6b7280;
            user-select: none;
            margin-right: 1rem;
            display: inline-block;
            width: 3rem;
            text-align: right;
        }}
        
        .remediation {{
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 6px;
            padding: 1rem;
            margin-top: 1rem;
        }}
        
        .remediation-title {{
            font-weight: 600;
            color: #166534;
            margin-bottom: 0.5rem;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 3rem;
            color: var(--text-secondary);
        }}
        
        .no-findings svg {{
            width: 64px;
            height: 64px;
            margin-bottom: 1rem;
            color: #22c55e;
        }}
        
        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Scan Report</h1>
        <p class="subtitle">
            Scan ID: {html.escape(scan_result.get('scan_id', 'Unknown'))} | 
            Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        </p>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Target</h3>
                <div class="value" style="font-size: 1rem; word-break: break-all;">
                    {html.escape(scan_result.get('target_path', 'Unknown'))}
                </div>
            </div>
            <div class="summary-card">
                <h3>Files Scanned</h3>
                <div class="value">{scan_result.get('files_scanned', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{scan_result.get('total_findings', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Time</h3>
                <div class="value">{scan_result.get('scan_time', 0)}s</div>
            </div>
        </div>
        
        <div class="severity-badges">
            <span class="badge critical">Critical: {by_severity.get('critical', 0)}</span>
            <span class="badge high">High: {by_severity.get('high', 0)}</span>
            <span class="badge medium">Medium: {by_severity.get('medium', 0)}</span>
            <span class="badge low">Low: {by_severity.get('low', 0)}</span>
            <span class="badge info">Info: {by_severity.get('info', 0)}</span>
        </div>
        
        <h2>Findings</h2>
        
        {findings_html}
        
        <footer>
            <p>Generated by Secure Code Analyzer v1.0</p>
        </footer>
    </div>
</body>
</html>'''
        
        return html_template
    
    def _build_findings_html(self, findings: list) -> str:
        """Build HTML for all findings."""
        if not findings:
            return '''
            <div class="no-findings">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <h3>No Vulnerabilities Found</h3>
                <p>Great job! The scanned code appears to be secure.</p>
            </div>
            '''
        
        findings_html = []
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            
            # Build code snippet HTML
            snippet_html = self._build_snippet_html(finding.get('code_snippet', {}))
            
            # Build remediation section
            remediation = finding.get('remediation', '')
            remediation_html = ''
            if remediation:
                remediation_html = f'''
                <div class="remediation">
                    <div class="remediation-title">Remediation</div>
                    <p>{html.escape(remediation)}</p>
                </div>
                '''
            
            finding_html = f'''
            <div class="finding {severity}">
                <div class="finding-header">
                    <div>
                        <div class="finding-title">{html.escape(finding.get('rule_name', 'Unknown'))}</div>
                        <div class="finding-meta">
                            {html.escape(finding.get('file_path', 'Unknown'))}:{finding.get('line_number', 0)} | 
                            Rule: {html.escape(finding.get('rule_id', 'Unknown'))} |
                            CWE: {html.escape(finding.get('cwe_id', 'N/A') or 'N/A')}
                        </div>
                    </div>
                    <span class="badge {severity}">{severity.upper()}</span>
                </div>
                
                <div class="finding-description">
                    <p>{html.escape(finding.get('description', 'No description available.'))}</p>
                </div>
                
                {snippet_html}
                {remediation_html}
            </div>
            '''
            
            findings_html.append(finding_html)
        
        return '\n'.join(findings_html)
    
    def _build_snippet_html(self, snippet: Dict[str, Any]) -> str:
        """Build HTML for a code snippet."""
        lines = snippet.get('lines', [])
        if not lines:
            return ''
        
        lines_html = []
        for line in lines:
            line_num = line.get('line_number', 0)
            content = html.escape(line.get('content', ''))
            is_highlighted = line.get('is_highlighted', False)
            
            highlight_class = ' highlighted' if is_highlighted else ''
            
            lines_html.append(
                f'<span class="code-line{highlight_class}">'
                f'<span class="line-number">{line_num}</span>{content}</span>'
            )
        
        return f'''
        <div class="code-snippet">
            {''.join(lines_html)}
        </div>
        '''


def generate_reports(
    scan_result: Dict[str, Any],
    output_dir: str,
    formats: Optional[list] = None
) -> Dict[str, str]:
    """
    Generate reports in multiple formats.
    
    Args:
        scan_result: Scan result dictionary
        output_dir: Output directory
        formats: List of formats to generate (default: ['json', 'html'])
        
    Returns:
        Dictionary mapping format to file path
    """
    formats = formats or ['json', 'html']
    generator = ReportGenerator()
    reports = {}
    
    scan_id = scan_result.get('scan_id', 'report')
    
    if 'json' in formats:
        json_path = os.path.join(output_dir, f"{scan_id}.json")
        reports['json'] = generator.generate_json_report(scan_result, json_path)
    
    if 'html' in formats:
        html_path = os.path.join(output_dir, f"{scan_id}.html")
        reports['html'] = generator.generate_html_report(scan_result, html_path)
    
    return reports
