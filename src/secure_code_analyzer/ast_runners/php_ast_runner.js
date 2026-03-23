#!/usr/bin/env node
/**
 * PHP AST Runner
 * 
 * This script performs AST-based security analysis on PHP code.
 * It uses php-parser for AST generation and analysis.
 * 
 * Input format (JSON via stdin):
 * {
 *   "file_path": "path/to/file.php",
 *   "content": "source code content",
 *   "rules": [{ rule objects }]
 * }
 * 
 * Output format (JSON via stdout):
 * {
 *   "success": true,
 *   "findings": [{ finding objects }]
 * }
 * 
 * Note: This is a placeholder implementation that uses regex-based
 * detection as a fallback when php-parser is not available.
 */

const fs = require('fs');

// Dangerous functions in PHP
const DANGEROUS_FUNCTIONS = {
    // Code execution
    'eval': { severity: 'critical', desc: 'Code injection via eval()' },
    'assert': { severity: 'high', desc: 'Code injection via assert()' },
    'create_function': { severity: 'high', desc: 'Deprecated and dangerous function' },
    'preg_replace': { severity: 'medium', desc: 'Potential code execution with /e modifier' },
    
    // Command execution
    'exec': { severity: 'high', desc: 'Command injection via exec()' },
    'system': { severity: 'high', desc: 'Command injection via system()' },
    'shell_exec': { severity: 'high', desc: 'Command injection via shell_exec()' },
    'passthru': { severity: 'high', desc: 'Command injection via passthru()' },
    'popen': { severity: 'high', desc: 'Command injection via popen()' },
    'proc_open': { severity: 'high', desc: 'Command injection via proc_open()' },
    'pcntl_exec': { severity: 'high', desc: 'Command injection via pcntl_exec()' },
    
    // File operations
    'include': { severity: 'medium', desc: 'Potential file inclusion vulnerability' },
    'include_once': { severity: 'medium', desc: 'Potential file inclusion vulnerability' },
    'require': { severity: 'medium', desc: 'Potential file inclusion vulnerability' },
    'require_once': { severity: 'medium', desc: 'Potential file inclusion vulnerability' },
    
    // Deserialization
    'unserialize': { severity: 'high', desc: 'Insecure deserialization' },
    
    // SQL
    'mysql_query': { severity: 'medium', desc: 'Deprecated MySQL function, potential SQLi' },
    'mysqli_query': { severity: 'low', desc: 'Ensure parameterized queries are used' },
    'pg_query': { severity: 'low', desc: 'Ensure parameterized queries are used' },
};

// Patterns for detecting vulnerabilities
const VULNERABILITY_PATTERNS = [
    {
        pattern: /\beval\s*\(\s*\$/i,
        rule_id: 'PHP_AST_EVAL_VAR',
        name: 'Eval with variable',
        desc: 'eval() called with variable input - high risk of code injection',
        severity: 'critical'
    },
    {
        pattern: /\$_(GET|POST|REQUEST|COOKIE)\s*\[/i,
        rule_id: 'PHP_AST_SUPERGLOBAL',
        name: 'Direct superglobal access',
        desc: 'Direct access to superglobal without sanitization',
        severity: 'low'
    },
    {
        pattern: /(mysql_query|mysqli_query|pg_query)\s*\([^)]*\$_(GET|POST|REQUEST)/i,
        rule_id: 'PHP_AST_SQL_INJECTION',
        name: 'SQL Injection',
        desc: 'SQL query with direct user input - SQL injection vulnerability',
        severity: 'critical'
    },
    {
        pattern: /echo\s+\$_(GET|POST|REQUEST|COOKIE)/i,
        rule_id: 'PHP_AST_XSS',
        name: 'Reflected XSS',
        desc: 'Echoing user input without escaping - XSS vulnerability',
        severity: 'high'
    },
    {
        pattern: /header\s*\(\s*['"]Location:\s*['"]?\s*\.\s*\$/i,
        rule_id: 'PHP_AST_OPEN_REDIRECT',
        name: 'Open Redirect',
        desc: 'Redirect with user-controlled input - open redirect vulnerability',
        severity: 'medium'
    },
    {
        pattern: /file_get_contents\s*\(\s*\$/i,
        rule_id: 'PHP_AST_SSRF',
        name: 'Potential SSRF',
        desc: 'file_get_contents with variable URL - potential SSRF',
        severity: 'high'
    },
    {
        pattern: /md5\s*\(|sha1\s*\(/i,
        rule_id: 'PHP_AST_WEAK_HASH',
        name: 'Weak hashing',
        desc: 'MD5/SHA1 are not suitable for password hashing',
        severity: 'medium'
    },
    {
        pattern: /\$\w+\s*=\s*['"]password['"]/i,
        rule_id: 'PHP_AST_HARDCODED_PASSWORD',
        name: 'Hardcoded password',
        desc: 'Potential hardcoded password detected',
        severity: 'high'
    }
];

/**
 * Analyze PHP code for security vulnerabilities
 */
function analyzeCode(filePath, content, rules) {
    const findings = [];
    const lines = content.split('\n');
    
    // Check each line for dangerous function calls
    lines.forEach((line, index) => {
        const lineNum = index + 1;
        
        // Check for dangerous function calls
        for (const [funcName, info] of Object.entries(DANGEROUS_FUNCTIONS)) {
            const regex = new RegExp(`\\b${funcName}\\s*\\(`, 'gi');
            if (regex.test(line)) {
                findings.push({
                    rule_id: `PHP_AST_${funcName.toUpperCase()}`,
                    rule_name: `Dangerous function: ${funcName}`,
                    description: info.desc,
                    severity: info.severity,
                    confidence: 'medium',
                    line_number: lineNum,
                    column_number: line.indexOf(funcName) + 1,
                    matched_code: line.trim().substring(0, 100)
                });
            }
        }
        
        // Check vulnerability patterns
        for (const vuln of VULNERABILITY_PATTERNS) {
            if (vuln.pattern.test(line)) {
                findings.push({
                    rule_id: vuln.rule_id,
                    rule_name: vuln.name,
                    description: vuln.desc,
                    severity: vuln.severity,
                    confidence: 'medium',
                    line_number: lineNum,
                    column_number: 1,
                    matched_code: line.trim().substring(0, 100)
                });
            }
        }
    });
    
    // Deduplicate findings at the same location
    const uniqueFindings = [];
    const seen = new Set();
    
    for (const finding of findings) {
        const key = `${finding.rule_id}:${finding.line_number}`;
        if (!seen.has(key)) {
            seen.add(key);
            uniqueFindings.push(finding);
        }
    }
    
    return {
        success: true,
        findings: uniqueFindings
    };
}

/**
 * Read input from stdin
 */
async function readStdin() {
    return new Promise((resolve, reject) => {
        let data = '';
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', chunk => data += chunk);
        process.stdin.on('end', () => resolve(data));
        process.stdin.on('error', reject);
    });
}

/**
 * Main entry point
 */
async function main() {
    try {
        const input = await readStdin();
        const { file_path, content, rules } = JSON.parse(input);
        
        const result = analyzeCode(file_path, content, rules || []);
        console.log(JSON.stringify(result));
        
    } catch (e) {
        console.log(JSON.stringify({
            success: false,
            findings: [],
            error: e.message
        }));
        process.exit(1);
    }
}

main();
