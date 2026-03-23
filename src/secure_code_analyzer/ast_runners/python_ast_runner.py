#!/usr/bin/env python3
"""
Python AST Runner

This script performs AST-based security analysis on Python code.
It receives input via stdin and outputs findings as JSON to stdout.

Input format (JSON via stdin):
{
    "file_path": "path/to/file.py",
    "content": "source code content",
    "rules": [{ rule objects }]
}

Output format (JSON via stdout):
{
    "success": true,
    "findings": [{ finding objects }]
}
"""

import ast
import json
import sys
from typing import List, Dict, Any, Optional


class PythonSecurityAnalyzer(ast.NodeVisitor):
    """
    AST visitor that detects security vulnerabilities in Python code.
    """
    
    def __init__(self, content: str, rules: List[Dict]):
        self.content = content
        self.rules = rules
        self.findings: List[Dict[str, Any]] = []
        self.lines = content.splitlines()
        
        # Dangerous function calls
        self.dangerous_calls = {
            'eval': ('high', 'Code injection via eval()'),
            'exec': ('high', 'Code injection via exec()'),
            'compile': ('medium', 'Dynamic code compilation'),
            '__import__': ('medium', 'Dynamic import'),
        }
        
        # Dangerous module.function patterns
        self.dangerous_module_calls = {
            ('os', 'system'): ('high', 'Command injection via os.system()'),
            ('os', 'popen'): ('high', 'Command injection via os.popen()'),
            ('subprocess', 'call'): ('medium', 'Potential command injection'),
            ('subprocess', 'run'): ('medium', 'Potential command injection'),
            ('subprocess', 'Popen'): ('medium', 'Potential command injection'),
            ('pickle', 'load'): ('high', 'Insecure deserialization'),
            ('pickle', 'loads'): ('high', 'Insecure deserialization'),
            ('yaml', 'load'): ('medium', 'Potentially unsafe YAML loading'),
            ('marshal', 'load'): ('high', 'Insecure deserialization'),
            ('marshal', 'loads'): ('high', 'Insecure deserialization'),
        }
    
    def _get_code_at_line(self, lineno: int) -> str:
        """Get the code at a specific line number."""
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1]
        return ""
    
    def _add_finding(
        self,
        rule_id: str,
        rule_name: str,
        description: str,
        severity: str,
        lineno: int,
        col_offset: int,
        confidence: str = 'medium'
    ):
        """Add a security finding."""
        self.findings.append({
            'rule_id': rule_id,
            'rule_name': rule_name,
            'description': description,
            'severity': severity,
            'confidence': confidence,
            'line_number': lineno,
            'column_number': col_offset,
            'matched_code': self._get_code_at_line(lineno)[:100]
        })
    
    def visit_Call(self, node: ast.Call):
        """Visit function calls to detect dangerous patterns."""
        
        # Check direct function calls (e.g., eval(...))
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.dangerous_calls:
                severity, desc = self.dangerous_calls[func_name]
                self._add_finding(
                    rule_id=f'PY_AST_{func_name.upper()}',
                    rule_name=f'Dangerous function: {func_name}',
                    description=desc,
                    severity=severity,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    confidence='high'
                )
        
        # Check module.function calls (e.g., os.system(...))
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                func_name = node.func.attr
                key = (module_name, func_name)
                
                if key in self.dangerous_module_calls:
                    severity, desc = self.dangerous_module_calls[key]
                    
                    # Check for shell=True in subprocess calls
                    if module_name == 'subprocess':
                        for keyword in node.keywords:
                            if keyword.arg == 'shell':
                                if isinstance(keyword.value, ast.Constant) and keyword.value.value:
                                    severity = 'high'
                                    desc = f'{desc} with shell=True'
                    
                    self._add_finding(
                        rule_id=f'PY_AST_{module_name.upper()}_{func_name.upper()}',
                        rule_name=f'Dangerous call: {module_name}.{func_name}',
                        description=desc,
                        severity=severity,
                        lineno=node.lineno,
                        col_offset=node.col_offset
                    )
        
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import):
        """Check for dangerous imports."""
        dangerous_modules = ['telnetlib', 'ftplib']
        
        for alias in node.names:
            if alias.name in dangerous_modules:
                self._add_finding(
                    rule_id=f'PY_AST_IMPORT_{alias.name.upper()}',
                    rule_name=f'Insecure module import: {alias.name}',
                    description=f'Module {alias.name} uses insecure protocols',
                    severity='low',
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    confidence='medium'
                )
        
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Check for dangerous from ... import statements."""
        if node.module == 'xml.etree.ElementTree':
            # Check if defused alternatives are not used
            self._add_finding(
                rule_id='PY_AST_XML_PARSER',
                rule_name='Potentially unsafe XML parser',
                description='xml.etree.ElementTree may be vulnerable to XXE. Consider using defusedxml.',
                severity='low',
                lineno=node.lineno,
                col_offset=node.col_offset,
                confidence='low'
            )
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        """Check for hardcoded sensitive values."""
        sensitive_names = ['password', 'passwd', 'secret', 'api_key', 'apikey', 'token', 'auth']
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                if any(s in var_name for s in sensitive_names):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 3:  # Ignore empty or very short values
                            self._add_finding(
                                rule_id='PY_AST_HARDCODED_SECRET',
                                rule_name='Hardcoded secret',
                                description=f'Potential hardcoded secret in variable "{target.id}"',
                                severity='high',
                                lineno=node.lineno,
                                col_offset=node.col_offset,
                                confidence='medium'
                            )
        
        self.generic_visit(node)
    
    def visit_Assert(self, node: ast.Assert):
        """Check for assertions that should not be in production code."""
        # Assertions can be stripped with -O flag
        self._add_finding(
            rule_id='PY_AST_ASSERT',
            rule_name='Assert statement found',
            description='Assert statements are removed with python -O. Do not use for security checks.',
            severity='info',
            lineno=node.lineno,
            col_offset=node.col_offset,
            confidence='low'
        )
        
        self.generic_visit(node)
    
    def visit_Try(self, node: ast.Try):
        """Check for bare except clauses."""
        for handler in node.handlers:
            if handler.type is None:
                self._add_finding(
                    rule_id='PY_AST_BARE_EXCEPT',
                    rule_name='Bare except clause',
                    description='Bare except catches all exceptions including SystemExit and KeyboardInterrupt',
                    severity='low',
                    lineno=handler.lineno,
                    col_offset=handler.col_offset,
                    confidence='high'
                )
        
        self.generic_visit(node)
    
    def visit_Compare(self, node: ast.Compare):
        """Check for timing-unsafe comparisons of secrets."""
        # This is a simplified check - real implementation would need data flow analysis
        if isinstance(node.left, ast.Name):
            var_name = node.left.id.lower()
            if 'password' in var_name or 'secret' in var_name or 'token' in var_name:
                if isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
                    self._add_finding(
                        rule_id='PY_AST_TIMING_ATTACK',
                        rule_name='Potential timing attack',
                        description='Use hmac.compare_digest() for constant-time comparison of secrets',
                        severity='medium',
                        lineno=node.lineno,
                        col_offset=node.col_offset,
                        confidence='low'
                    )
        
        self.generic_visit(node)


def analyze_code(file_path: str, content: str, rules: List[Dict]) -> Dict[str, Any]:
    """
    Analyze Python code for security vulnerabilities.
    
    Args:
        file_path: Path to the file being analyzed
        content: Source code content
        rules: List of rule configurations
        
    Returns:
        Analysis result dictionary
    """
    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError as e:
        return {
            'success': False,
            'findings': [],
            'error': f'Syntax error: {str(e)}'
        }
    
    analyzer = PythonSecurityAnalyzer(content, rules)
    analyzer.visit(tree)
    
    return {
        'success': True,
        'findings': analyzer.findings
    }


def main():
    """Main entry point."""
    try:
        # Read input from stdin
        input_data = sys.stdin.read()
        data = json.loads(input_data)
        
        file_path = data.get('file_path', 'unknown.py')
        content = data.get('content', '')
        rules = data.get('rules', [])
        
        result = analyze_code(file_path, content, rules)
        print(json.dumps(result))
        
    except json.JSONDecodeError as e:
        print(json.dumps({
            'success': False,
            'findings': [],
            'error': f'Invalid JSON input: {str(e)}'
        }))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({
            'success': False,
            'findings': [],
            'error': str(e)
        }))
        sys.exit(1)


if __name__ == '__main__':
    main()
