#!/usr/bin/env python3
"""
Java AST Runner

This script performs AST-based security analysis on Java code.
It uses pattern matching and regex analysis as Java AST parsing
requires a full Java parser (like ANTLR or JavaParser).

Input format (JSON via stdin):
{
    "file_path": "path/to/file.java",
    "content": "source code content",
    "rules": [{ rule objects }]
}

Output format (JSON via stdout):
{
    "success": true,
    "findings": [{ finding objects }]
}
"""

import json
import re
import sys
from typing import List, Dict, Any, Tuple


# Dangerous patterns in Java code
DANGEROUS_PATTERNS: List[Tuple[re.Pattern, str, str, str, str]] = [
    # SQL Injection
    (
        re.compile(r'(executeQuery|executeUpdate|execute)\s*\(\s*[^)]*\+', re.IGNORECASE),
        'JAVA_AST_SQL_INJECTION',
        'SQL Injection Risk',
        'SQL query with string concatenation may lead to SQL injection',
        'critical'
    ),
    (
        re.compile(r'Statement\s+\w+\s*=.*createStatement', re.IGNORECASE),
        'JAVA_AST_STATEMENT',
        'Unsafe Statement usage',
        'Use PreparedStatement instead of Statement to prevent SQL injection',
        'medium'
    ),
    
    # Command Injection
    (
        re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(', re.IGNORECASE),
        'JAVA_AST_COMMAND_EXEC',
        'Command Execution',
        'Runtime.exec() may lead to command injection if input is not sanitized',
        'high'
    ),
    (
        re.compile(r'ProcessBuilder\s*\(', re.IGNORECASE),
        'JAVA_AST_PROCESS_BUILDER',
        'Process Builder',
        'ProcessBuilder usage - ensure inputs are properly validated',
        'medium'
    ),
    
    # Deserialization
    (
        re.compile(r'ObjectInputStream\s*\(', re.IGNORECASE),
        'JAVA_AST_DESERIALIZATION',
        'Insecure Deserialization',
        'ObjectInputStream may lead to RCE if deserializing untrusted data',
        'high'
    ),
    (
        re.compile(r'\.readObject\s*\(\s*\)', re.IGNORECASE),
        'JAVA_AST_READ_OBJECT',
        'Object Deserialization',
        'readObject() on untrusted data can lead to remote code execution',
        'high'
    ),
    
    # XXE
    (
        re.compile(r'DocumentBuilderFactory\.newInstance\s*\(\s*\)', re.IGNORECASE),
        'JAVA_AST_XXE',
        'Potential XXE',
        'XML parser may be vulnerable to XXE. Disable external entities.',
        'medium'
    ),
    (
        re.compile(r'SAXParserFactory\.newInstance\s*\(\s*\)', re.IGNORECASE),
        'JAVA_AST_XXE_SAX',
        'Potential XXE (SAX)',
        'SAX parser may be vulnerable to XXE. Disable external entities.',
        'medium'
    ),
    (
        re.compile(r'XMLInputFactory\.newInstance\s*\(\s*\)', re.IGNORECASE),
        'JAVA_AST_XXE_STAX',
        'Potential XXE (StAX)',
        'StAX parser may be vulnerable to XXE. Disable external entities.',
        'medium'
    ),
    
    # Cryptography
    (
        re.compile(r'DES|DESede|RC2|RC4|Blowfish', re.IGNORECASE),
        'JAVA_AST_WEAK_CIPHER',
        'Weak Cipher Algorithm',
        'Using weak cipher algorithm. Use AES-256-GCM instead.',
        'high'
    ),
    (
        re.compile(r'Cipher\.getInstance\s*\(\s*"(DES|ECB)', re.IGNORECASE),
        'JAVA_AST_INSECURE_CIPHER',
        'Insecure Cipher Mode',
        'DES or ECB mode is insecure. Use AES with GCM mode.',
        'high'
    ),
    (
        re.compile(r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1)"', re.IGNORECASE),
        'JAVA_AST_WEAK_HASH',
        'Weak Hash Algorithm',
        'MD5 and SHA-1 are deprecated. Use SHA-256 or stronger.',
        'medium'
    ),
    (
        re.compile(r'new\s+Random\s*\(', re.IGNORECASE),
        'JAVA_AST_INSECURE_RANDOM',
        'Insecure Random',
        'java.util.Random is not cryptographically secure. Use SecureRandom.',
        'medium'
    ),
    
    # Hardcoded Secrets
    (
        re.compile(r'(password|passwd|pwd)\s*=\s*"[^"]+"', re.IGNORECASE),
        'JAVA_AST_HARDCODED_PASSWORD',
        'Hardcoded Password',
        'Password appears to be hardcoded in source code',
        'high'
    ),
    (
        re.compile(r'(secret|apikey|api_key|token)\s*=\s*"[^"]+"', re.IGNORECASE),
        'JAVA_AST_HARDCODED_SECRET',
        'Hardcoded Secret',
        'Secret or API key appears to be hardcoded in source code',
        'high'
    ),
    
    # Path Traversal
    (
        re.compile(r'new\s+File\s*\([^)]*\+', re.IGNORECASE),
        'JAVA_AST_PATH_TRAVERSAL',
        'Potential Path Traversal',
        'File path constructed with concatenation may be vulnerable to path traversal',
        'medium'
    ),
    (
        re.compile(r'new\s+FileInputStream\s*\([^)]*\+', re.IGNORECASE),
        'JAVA_AST_FILE_PATH',
        'Dynamic File Path',
        'FileInputStream with dynamic path - ensure path is validated',
        'medium'
    ),
    
    # LDAP Injection
    (
        re.compile(r'search\s*\([^)]*\+[^)]*\)', re.IGNORECASE),
        'JAVA_AST_LDAP_INJECTION',
        'Potential LDAP Injection',
        'LDAP query with string concatenation may lead to LDAP injection',
        'high'
    ),
    
    # XSS in Servlets
    (
        re.compile(r'getWriter\s*\(\s*\)\s*\.\s*print(ln)?\s*\([^)]*request\.getParameter', re.IGNORECASE),
        'JAVA_AST_XSS',
        'Reflected XSS',
        'Printing request parameter directly may lead to XSS',
        'high'
    ),
    
    # Trust Manager
    (
        re.compile(r'TrustManager|X509TrustManager', re.IGNORECASE),
        'JAVA_AST_TRUST_MANAGER',
        'Custom TrustManager',
        'Custom TrustManager may disable certificate validation',
        'low'
    ),
    (
        re.compile(r'setHostnameVerifier\s*\(', re.IGNORECASE),
        'JAVA_AST_HOSTNAME_VERIFIER',
        'Custom HostnameVerifier',
        'Custom HostnameVerifier may disable hostname verification',
        'low'
    ),
    
    # Logging Sensitive Data
    (
        re.compile(r'(log|logger)\.(debug|info|warn|error)\s*\([^)]*password', re.IGNORECASE),
        'JAVA_AST_LOG_PASSWORD',
        'Logging Sensitive Data',
        'Password may be logged - sensitive data exposure risk',
        'medium'
    ),
]


def analyze_code(file_path: str, content: str, rules: List[Dict]) -> Dict[str, Any]:
    """
    Analyze Java code for security vulnerabilities.
    
    Args:
        file_path: Path to the file being analyzed
        content: Source code content
        rules: List of rule configurations
        
    Returns:
        Analysis result dictionary
    """
    findings = []
    lines = content.splitlines()
    
    for line_num, line in enumerate(lines, start=1):
        for pattern, rule_id, name, description, severity in DANGEROUS_PATTERNS:
            if pattern.search(line):
                findings.append({
                    'rule_id': rule_id,
                    'rule_name': name,
                    'description': description,
                    'severity': severity,
                    'confidence': 'medium',
                    'line_number': line_num,
                    'column_number': 1,
                    'matched_code': line.strip()[:100]
                })
    
    # Check for class-level patterns
    class_patterns = [
        # Serializable without serialVersionUID
        (
            re.compile(r'class\s+\w+[^{]*implements[^{]*Serializable', re.IGNORECASE | re.MULTILINE),
            'JAVA_AST_SERIALIZABLE',
            'Serializable Class',
            'Class implements Serializable - ensure serialVersionUID is defined',
            'info'
        ),
    ]
    
    for pattern, rule_id, name, description, severity in class_patterns:
        for match in pattern.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                'rule_id': rule_id,
                'rule_name': name,
                'description': description,
                'severity': severity,
                'confidence': 'low',
                'line_number': line_num,
                'column_number': 1,
                'matched_code': match.group(0)[:100]
            })
    
    # Deduplicate findings at the same location
    seen = set()
    unique_findings = []
    
    for finding in findings:
        key = (finding['rule_id'], finding['line_number'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    
    return {
        'success': True,
        'findings': unique_findings
    }


def main():
    """Main entry point."""
    try:
        # Read input from stdin
        input_data = sys.stdin.read()
        data = json.loads(input_data)
        
        file_path = data.get('file_path', 'unknown.java')
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
