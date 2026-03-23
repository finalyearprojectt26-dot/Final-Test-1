"""
Detectors module for applying security rules to source code.
This module loads rules from rules.json and applies both regex-based
and AST-based detection methods.

IMPORTANT: This module is input-source agnostic. It does NOT know
whether the files came from local filesystem or URL extraction.
"""

import os
import re
import json
import subprocess
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict

from .utils import (
    read_file_content,
    get_language_from_extension,
    extract_code_snippet,
    logger
)
from .severity import classify_severity, SeverityLevel


# Path to rules file
RULES_FILE = Path(__file__).parent.parent / 'rules' / 'rules.json'

# Path to AST runners
AST_RUNNERS_DIR = Path(__file__).parent.parent / 'ast_runners'


@dataclass
class Finding:
    """Represents a single security finding."""
    rule_id: str
    rule_name: str
    description: str
    severity: str
    confidence: str
    file_path: str
    line_number: int
    column_number: int
    code_snippet: Dict[str, Any]
    category: str
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    remediation: str
    matched_pattern: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return asdict(self)


class RulesLoader:
    """Handles loading and caching of security rules."""
    
    _instance = None
    _rules = None
    
    def __new__(cls):
        """Singleton pattern for rules loader."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def load_rules(self, rules_path: Optional[str] = None) -> Dict[str, Any]:
        if self._rules is not None and rules_path is None:
            return self._rules

        path = Path(rules_path) if rules_path else RULES_FILE

        try:
            with open(path, 'r', encoding='utf-8') as f:
                self._rules = json.load(f)

            logger.info(f"Loaded {len(self._rules.get('rules', []))} rules from {path}")
            return self._rules

        except FileNotFoundError:
            logger.warning(f"Rules file not found: {path}")
            return self._get_default_rules()

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in rules file: {e}")
            return self._get_default_rules()

    
    def _get_default_rules(self) -> Dict[str, Any]:
        """Return minimal default rules if rules.json is not available."""
        return {
            "version": "1.0.0",
            "rules": []
        }
    
    def get_rules_for_language(self, language: str) -> List[Dict[str, Any]]:
        """Get all rules applicable to a specific language."""
        rules = self.load_rules()
        return [
            rule for rule in rules.get("rules", [])
            if language in rule.get("languages", []) or 
               rule.get("languages") == ["*"]
        ]


class RegexDetector:
    """Applies regex-based detection rules to source code."""
    
    def __init__(self):
        self.rules_loader = RulesLoader()
    
    def detect(
        self, 
        file_path: str, 
        content: str, 
        language: str
    ) -> List[Finding]:
        """
        Apply regex rules to detect vulnerabilities.
        
        Args:
            file_path: Path to the source file
            content: File content
            language: Programming language
            
        Returns:
            List of Finding objects
        """
        findings = []
        rules = self.rules_loader.get_rules_for_language(language)
        
        for rule in rules:
            if rule.get("type") != "regex":
                continue
            
            pattern = rule.get("pattern")
            if not pattern:
                continue
            
            try:
                regex = re.compile(pattern, re.MULTILINE | re.IGNORECASE)
                
                for match in regex.finditer(content):
                    line_number = content[:match.start()].count('\n') + 1
                    column_number = match.start() - content.rfind('\n', 0, match.start())
                    
                    # Extract code snippet
                    snippet = extract_code_snippet(content, line_number)
                    
                    # Classify severity
                    severity_result = classify_severity(
                        rule.get("severity", "info"),
                        rule.get("category", "general")
                    )
                    
                    finding = Finding(
                        rule_id=rule.get("id", "unknown"),
                        rule_name=rule.get("name", "Unknown Rule"),
                        description=rule.get("description", ""),
                        severity=severity_result.level.value,
                        confidence=rule.get("confidence", "medium"),
                        file_path=file_path,
                        line_number=line_number,
                        column_number=column_number,
                        code_snippet=snippet,
                        category=rule.get("category", "general"),
                        cwe_id=rule.get("cwe_id"),
                        owasp_category=rule.get("owasp_category"),
                        remediation=rule.get("remediation", ""),
                        matched_pattern=match.group(0)[:100]  # Truncate long matches
                    )
                    findings.append(finding)
                    
            except re.error as e:
                logger.warning(f"Invalid regex pattern in rule {rule.get('id')}: {e}")
                continue
        
        return findings


class ASTDetector:
    """Applies AST-based detection using external runners."""
    
    # Mapping of languages to their AST runner scripts
    RUNNERS = {
        'javascript': 'js_ast_runner.js',
        'typescript': 'js_ast_runner.js',  # Uses same parser
        'python': 'python_ast_runner.py',
        'php': 'php_ast_runner.js',
        'java': 'java_ast_runner.py',
    }
    
    def __init__(self):
        self.rules_loader = RulesLoader()
    
    def detect(
        self, 
        file_path: str, 
        content: str, 
        language: str
    ) -> List[Finding]:
        """
        Apply AST-based rules to detect vulnerabilities.
        
        Args:
            file_path: Path to the source file
            content: File content
            language: Programming language
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        runner_file = self.RUNNERS.get(language)
        if not runner_file:
            logger.debug(f"No AST runner available for {language}")
            return findings
        
        runner_path = AST_RUNNERS_DIR / runner_file
        if not runner_path.exists():
            logger.warning(f"AST runner not found: {runner_path}")
            return findings
        
        # Get AST rules for this language
        rules = [
            r for r in self.rules_loader.get_rules_for_language(language)
            if r.get("type") == "ast"
        ]
        
        if not rules:
            return findings
        
        try:
            # Determine interpreter
            if runner_file.endswith('.py'):
                interpreter = 'python3'
            elif runner_file.endswith('.js'):
                interpreter = 'node'
            else:
                logger.warning(f"Unknown runner type: {runner_file}")
                return findings
            
            # Prepare input for AST runner
            runner_input = json.dumps({
                "file_path": file_path,
                "content": content,
                "rules": rules
            })
            
            # Execute AST runner
            result = subprocess.run(
                [interpreter, str(runner_path)],
                input=runner_input,
                capture_output=True,
                text=True,
                timeout=30  # 30 second timeout per file
            )
            
            if result.returncode != 0:
                logger.warning(
                    f"AST runner failed for {file_path}: {result.stderr}"
                )
                return findings
            
            # Parse runner output
            try:
                runner_findings = json.loads(result.stdout)
                
                for rf in runner_findings.get("findings", []):
                    # Get the original rule for additional metadata
                    rule = next(
                        (r for r in rules if r.get("id") == rf.get("rule_id")),
                        {}
                    )
                    
                    # Extract code snippet
                    snippet = extract_code_snippet(
                        content, 
                        rf.get("line_number", 1)
                    )
                    
                    # Classify severity
                    severity_result = classify_severity(
                        rf.get("severity", rule.get("severity", "info")),
                        rule.get("category", "general")
                    )
                    
                    finding = Finding(
                        rule_id=rf.get("rule_id", "unknown"),
                        rule_name=rf.get("rule_name", rule.get("name", "Unknown")),
                        description=rf.get("description", rule.get("description", "")),
                        severity=severity_result.level.value,
                        confidence=rf.get("confidence", "high"),
                        file_path=file_path,
                        line_number=rf.get("line_number", 1),
                        column_number=rf.get("column_number", 1),
                        code_snippet=snippet,
                        category=rule.get("category", "general"),
                        cwe_id=rule.get("cwe_id"),
                        owasp_category=rule.get("owasp_category"),
                        remediation=rule.get("remediation", ""),
                        matched_pattern=rf.get("matched_code")
                    )
                    findings.append(finding)
                    
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON from AST runner: {e}")
                
        except subprocess.TimeoutExpired:
            logger.warning(f"AST analysis timed out for {file_path}")
        except Exception as e:
            logger.error(f"AST analysis failed for {file_path}: {e}")
        
        return findings


class VulnerabilityDetector:
    """
    Main detector class that orchestrates all detection methods.
    This class combines regex and AST detection for comprehensive analysis.
    """
    
    def __init__(self):
        self.regex_detector = RegexDetector()
        self.ast_detector = ASTDetector()
    
    def analyze_file(self, file_path: str) -> List[Finding]:
        """
        Analyze a single file for vulnerabilities.
        
        Args:
            file_path: Path to the source file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Read file content
        content = read_file_content(file_path)
        if content is None:
            logger.warning(f"Could not read file: {file_path}")
            return findings
        
        # Determine language
        language = get_language_from_extension(file_path)
        if not language:
            logger.debug(f"Unsupported file type: {file_path}")
            return findings
        
        logger.debug(f"Analyzing {file_path} as {language}")
        
        # Apply regex detection
        regex_findings = self.regex_detector.detect(file_path, content, language)
        findings.extend(regex_findings)
        
        # Apply AST detection
        ast_findings = self.ast_detector.detect(file_path, content, language)
        findings.extend(ast_findings)
        
        # Deduplicate findings (same location and rule)
        findings = self._deduplicate_findings(findings)
        
        return findings
    
    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings at the same location."""
        seen = set()
        unique_findings = []
        
        for finding in findings:
            key = (
                finding.rule_id,
                finding.file_path,
                finding.line_number
            )
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings


def detect_vulnerabilities(file_path: str) -> List[Dict[str, Any]]:
    """
    Convenience function to detect vulnerabilities in a file.
    
    Args:
        file_path: Path to the source file
        
    Returns:
        List of finding dictionaries
    """
    detector = VulnerabilityDetector()
    findings = detector.analyze_file(file_path)
    return [f.to_dict() for f in findings]

