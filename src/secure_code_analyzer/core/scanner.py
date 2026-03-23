"""
Scanner module - orchestrates the scanning pipeline.
This module accepts a directory of source files, coordinates detection,
and aggregates results.

IMPORTANT: This module is input-source agnostic. The same scanning logic
is used regardless of whether files came from local filesystem or URL extraction.
"""

import os
import time
import logging
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import (
    get_all_files,
    get_relative_path,
    calculate_file_hash,
    logger
)
from .detectors import VulnerabilityDetector, Finding
from .severity import get_severity_summary
from .reporters import ReportGenerator


@dataclass
class ScanConfig:
    """Configuration options for scanning."""
    max_file_size: int = 5 * 1024 * 1024  # 5 MB
    max_files: int = 10000
    parallel_workers: int = 4
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=lambda: [
        '**/node_modules/**',
        '**/.git/**',
        '**/vendor/**',
        '**/dist/**',
        '**/build/**',
        '**/*.min.js',
        '**/*.bundle.js'
    ])
    recursive: bool = True
    generate_html_report: bool = True
    generate_json_report: bool = True


@dataclass
class ScanResult:
    """Represents the result of a complete scan."""
    success: bool
    scan_id: str
    target_path: str
    scan_time: float
    total_files: int
    files_scanned: int
    files_skipped: int
    total_findings: int
    findings: List[Dict[str, Any]]
    severity_summary: Dict[str, Any]
    errors: List[str]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "success": self.success,
            "scan_id": self.scan_id,
            "target_path": self.target_path,
            "scan_time": self.scan_time,
            "total_files": self.total_files,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "total_findings": self.total_findings,
            "findings": self.findings,
            "severity_summary": self.severity_summary,
            "errors": self.errors,
            "metadata": self.metadata
        }


class Scanner:
    """
    Main scanner class that orchestrates the vulnerability detection pipeline.
    
    Usage:
        scanner = Scanner()
        result = scanner.scan("/path/to/source")
    """
    
    def __init__(self, config: Optional[ScanConfig] = None):
        """
        Initialize the scanner.
        
        Args:
            config: Optional scan configuration
        """
        self.config = config or ScanConfig()
        self.detector = VulnerabilityDetector()
        self.logger = logging.getLogger('scanner')
        self._progress_callback: Optional[Callable] = None
    
    def set_progress_callback(self, callback: Callable[[int, int, str], None]):
        """
        Set a callback for progress updates.
        
        Args:
            callback: Function called with (current, total, message)
        """
        self._progress_callback = callback
    
    def _report_progress(self, current: int, total: int, message: str):
        """Report scanning progress."""
        if self._progress_callback:
            self._progress_callback(current, total, message)
    
    def _should_skip_file(self, filepath: str) -> bool:
        """
        Check if a file should be skipped based on configuration.
        
        Args:
            filepath: Path to check
            
        Returns:
            True if file should be skipped
        """
        from fnmatch import fnmatch
        
        # Check exclude patterns
        for pattern in self.config.exclude_patterns:
            if fnmatch(filepath, pattern):
                return True
        
        # Check file size
        try:
            size = os.path.getsize(filepath)
            if size > self.config.max_file_size:
                self.logger.debug(f"Skipping large file: {filepath} ({size} bytes)")
                return True
        except OSError:
            return True
        
        # Check include patterns if specified
        if self.config.include_patterns:
            for pattern in self.config.include_patterns:
                if fnmatch(filepath, pattern):
                    return False
            return True
        
        return False
    
    def _scan_file(self, filepath: str, base_dir: str) -> List[Finding]:
        """
        Scan a single file for vulnerabilities.
        
        Args:
            filepath: Absolute path to the file
            base_dir: Base directory for relative path calculation
            
        Returns:
            List of Finding objects
        """
        try:
            findings = self.detector.analyze_file(filepath)
            
            # Convert absolute paths to relative for cleaner output
            for finding in findings:
                finding.file_path = get_relative_path(filepath, base_dir)
            
            return findings
        except Exception as e:
            self.logger.error(f"Error scanning {filepath}: {e}")
            return []
    
    def _generate_scan_id(self) -> str:
        """Generate a unique scan ID."""
        import uuid
        return f"scan_{uuid.uuid4().hex[:12]}"
    
    def scan(
        self, 
        target_path: str,
        output_dir: Optional[str] = None
    ) -> ScanResult:
        """
        Scan a directory or file for security vulnerabilities.
        
        This is the main entry point for scanning. It:
        1. Discovers all source files in the target
        2. Applies security rules to each file
        3. Aggregates and deduplicates findings
        4. Generates reports
        
        Args:
            target_path: Path to directory or file to scan
            output_dir: Optional directory for report output
            
        Returns:
            ScanResult with all findings and metadata
        """
        start_time = time.time()
        scan_id = self._generate_scan_id()
        errors = []
        all_findings = []
        files_scanned = 0
        files_skipped = 0
        
        self.logger.info(f"Starting scan {scan_id} on {target_path}")
        
        # Validate target path
        target = Path(target_path)
        if not target.exists():
            return ScanResult(
                success=False,
                scan_id=scan_id,
                target_path=target_path,
                scan_time=0,
                total_files=0,
                files_scanned=0,
                files_skipped=0,
                total_findings=0,
                findings=[],
                severity_summary={},
                errors=[f"Target path does not exist: {target_path}"],
                metadata={}
            )
        
        # Get list of files to scan
        if target.is_file():
            files = [str(target.absolute())]
            base_dir = str(target.parent)
        else:
            files = get_all_files(
                str(target), 
                recursive=self.config.recursive
            )
            base_dir = str(target)
        
        total_files = len(files)
        self.logger.info(f"Found {total_files} files to scan")
        
        # Apply file limit
        if total_files > self.config.max_files:
            self.logger.warning(
                f"File limit exceeded. Scanning first {self.config.max_files} files."
            )
            files = files[:self.config.max_files]
        
        # Filter files
        files_to_scan = []
        for filepath in files:
            if self._should_skip_file(filepath):
                files_skipped += 1
            else:
                files_to_scan.append(filepath)
        
        self.logger.info(
            f"Scanning {len(files_to_scan)} files "
            f"(skipped {files_skipped})"
        )
        
        # Scan files (with parallel processing)
        self._report_progress(0, len(files_to_scan), "Starting scan...")
        
        if self.config.parallel_workers > 1:
            # Parallel scanning
            with ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
                future_to_file = {
                    executor.submit(self._scan_file, f, base_dir): f 
                    for f in files_to_scan
                }
                
                for i, future in enumerate(as_completed(future_to_file)):
                    filepath = future_to_file[future]
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                        files_scanned += 1
                        self._report_progress(
                            i + 1, 
                            len(files_to_scan),
                            f"Scanned {get_relative_path(filepath, base_dir)}"
                        )
                    except Exception as e:
                        errors.append(f"Error scanning {filepath}: {str(e)}")
        else:
            # Sequential scanning
            for i, filepath in enumerate(files_to_scan):
                try:
                    findings = self._scan_file(filepath, base_dir)
                    all_findings.extend(findings)
                    files_scanned += 1
                    self._report_progress(
                        i + 1,
                        len(files_to_scan),
                        f"Scanned {get_relative_path(filepath, base_dir)}"
                    )
                except Exception as e:
                    errors.append(f"Error scanning {filepath}: {str(e)}")
        
        # Convert findings to dictionaries
        findings_dicts = [f.to_dict() for f in all_findings]
        
        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings_dicts.sort(key=lambda x: severity_order.get(x['severity'], 5))
        
        # Calculate severity summary
        severity_summary = get_severity_summary(findings_dicts)
        
        scan_time = time.time() - start_time
        
        # Create result
        result = ScanResult(
            success=True,
            scan_id=scan_id,
            target_path=target_path,
            scan_time=round(scan_time, 2),
            total_files=total_files,
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            total_findings=len(findings_dicts),
            findings=findings_dicts,
            severity_summary=severity_summary,
            errors=errors,
            metadata={
                "scanner_version": "1.0.0",
                "config": {
                    "parallel_workers": self.config.parallel_workers,
                    "max_file_size": self.config.max_file_size,
                    "recursive": self.config.recursive
                }
            }
        )
        
        # Generate reports if output directory specified
        if output_dir:
            self._generate_reports(result, output_dir)
        
        self.logger.info(
            f"Scan {scan_id} completed in {scan_time:.2f}s. "
            f"Found {len(findings_dicts)} vulnerabilities."
        )
        
        return result
    
    def _generate_reports(self, result: ScanResult, output_dir: str):
        """Generate scan reports."""
        reporter = ReportGenerator()
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            if self.config.generate_json_report:
                json_path = os.path.join(output_dir, f"{result.scan_id}.json")
                reporter.generate_json_report(result.to_dict(), json_path)
                self.logger.info(f"JSON report saved to {json_path}")
            
            if self.config.generate_html_report:
                html_path = os.path.join(output_dir, f"{result.scan_id}.html")
                reporter.generate_html_report(result.to_dict(), html_path)
                self.logger.info(f"HTML report saved to {html_path}")
                
        except Exception as e:
            self.logger.error(f"Failed to generate reports: {e}")


def scan_directory(
    target_path: str,
    output_dir: Optional[str] = None,
    config: Optional[ScanConfig] = None
) -> Dict[str, Any]:
    """
    Convenience function to scan a directory.
    
    Args:
        target_path: Path to scan
        output_dir: Optional output directory for reports
        config: Optional scan configuration
        
    Returns:
        Scan result as dictionary
    """
    scanner = Scanner(config=config)
    result = scanner.scan(target_path, output_dir)
    return result.to_dict()
