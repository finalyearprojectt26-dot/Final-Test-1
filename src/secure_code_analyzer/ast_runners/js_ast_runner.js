#!/usr/bin/env node
/**
 * JavaScript/TypeScript AST Runner
 * 
 * This script performs AST-based security analysis on JavaScript and TypeScript code.
 * It receives input via stdin and outputs findings as JSON to stdout.
 * 
 * Input format (JSON via stdin):
 * {
 *   "file_path": "path/to/file.js",
 *   "content": "source code content",
 *   "rules": [{ rule objects }]
 * }
 * 
 * Output format (JSON via stdout):
 * {
 *   "success": true,
 *   "findings": [{ finding objects }]
 * }
 */

const acorn = require('acorn');
const walk = require('acorn-walk');

/**
 * Parse JavaScript/TypeScript code into AST
 */
function parseCode(content, filePath) {
    const isTypeScript = filePath.endsWith('.ts') || filePath.endsWith('.tsx');
    
    try {
        // Try parsing as ES module first
        return acorn.parse(content, {
            ecmaVersion: 'latest',
            sourceType: 'module',
            locations: true,
            allowHashBang: true,
            allowAwaitOutsideFunction: true,
            allowImportExportEverywhere: true,
            allowReserved: true,
        });
    } catch (e) {
        try {
            // Fall back to script mode
            return acorn.parse(content, {
                ecmaVersion: 'latest',
                sourceType: 'script',
                locations: true,
                allowHashBang: true,
            });
        } catch (e2) {
            return null;
        }
    }
}

/**
 * AST-based detectors for JavaScript security issues
 */
const detectors = {
    /**
     * Detect prototype pollution patterns
     */
    prototypePollution: (ast, content, rule) => {
        const findings = [];
        
        walk.simple(ast, {
            AssignmentExpression(node) {
                // Check for obj[key][key2] = value patterns
                if (node.left.type === 'MemberExpression' && 
                    node.left.object.type === 'MemberExpression' &&
                    node.left.computed && 
                    node.left.object.computed) {
                    
                    findings.push({
                        rule_id: rule.id,
                        rule_name: rule.name,
                        description: 'Potential prototype pollution through nested bracket notation',
                        severity: rule.severity,
                        confidence: 'medium',
                        line_number: node.loc?.start?.line || 1,
                        column_number: node.loc?.start?.column || 1,
                        matched_code: content.substring(node.start, Math.min(node.end, node.start + 100))
                    });
                }
            }
        });
        
        return findings;
    },
    
    /**
     * Detect dangerous function calls
     */
    dangerousFunctions: (ast, content, rule) => {
        const findings = [];
        const dangerousFns = ['eval', 'Function', 'setTimeout', 'setInterval'];
        
        walk.simple(ast, {
            CallExpression(node) {
                let fnName = null;
                
                if (node.callee.type === 'Identifier') {
                    fnName = node.callee.name;
                } else if (node.callee.type === 'MemberExpression' && 
                           node.callee.property.type === 'Identifier') {
                    fnName = node.callee.property.name;
                }
                
                if (fnName && dangerousFns.includes(fnName)) {
                    // Check if argument is a string literal (less dangerous)
                    const isStringArg = node.arguments[0]?.type === 'Literal' && 
                                       typeof node.arguments[0]?.value === 'string';
                    
                    // Only report if argument is not a string literal (potential dynamic code)
                    if (!isStringArg && node.arguments.length > 0) {
                        findings.push({
                            rule_id: rule.id || 'JS_DANGEROUS_FN',
                            rule_name: rule.name || `Dangerous function: ${fnName}`,
                            description: `${fnName}() called with dynamic argument may execute arbitrary code`,
                            severity: fnName === 'eval' ? 'high' : 'medium',
                            confidence: 'medium',
                            line_number: node.loc?.start?.line || 1,
                            column_number: node.loc?.start?.column || 1,
                            matched_code: content.substring(node.start, Math.min(node.end, node.start + 100))
                        });
                    }
                }
            }
        });
        
        return findings;
    },
    
    /**
     * Detect insecure DOM manipulation
     */
    insecureDOM: (ast, content, rule) => {
        const findings = [];
        const dangerousProps = ['innerHTML', 'outerHTML', 'insertAdjacentHTML'];
        
        walk.simple(ast, {
            AssignmentExpression(node) {
                if (node.left.type === 'MemberExpression' &&
                    node.left.property.type === 'Identifier' &&
                    dangerousProps.includes(node.left.property.name)) {
                    
                    // Check if RHS is a simple string literal
                    const isSimpleString = node.right.type === 'Literal' && 
                                          typeof node.right.value === 'string';
                    
                    if (!isSimpleString) {
                        findings.push({
                            rule_id: rule.id || 'JS_XSS',
                            rule_name: rule.name || 'Potential XSS vulnerability',
                            description: `Dynamic assignment to ${node.left.property.name} may lead to XSS`,
                            severity: 'medium',
                            confidence: 'medium',
                            line_number: node.loc?.start?.line || 1,
                            column_number: node.loc?.start?.column || 1,
                            matched_code: content.substring(node.start, Math.min(node.end, node.start + 100))
                        });
                    }
                }
            },
            CallExpression(node) {
                if (node.callee.type === 'MemberExpression' &&
                    node.callee.property.type === 'Identifier' &&
                    node.callee.property.name === 'insertAdjacentHTML') {
                    
                    findings.push({
                        rule_id: rule.id || 'JS_XSS',
                        rule_name: rule.name || 'Potential XSS vulnerability',
                        description: 'insertAdjacentHTML may lead to XSS if content is not sanitized',
                        severity: 'medium',
                        confidence: 'low',
                        line_number: node.loc?.start?.line || 1,
                        column_number: node.loc?.start?.column || 1,
                        matched_code: content.substring(node.start, Math.min(node.end, node.start + 100))
                    });
                }
            }
        });
        
        return findings;
    },
    
    /**
     * Detect postMessage without origin check
     */
    postMessageVulnerability: (ast, content, rule) => {
        const findings = [];
        
        walk.simple(ast, {
            CallExpression(node) {
                if (node.callee.type === 'MemberExpression' &&
                    node.callee.property.type === 'Identifier' &&
                    node.callee.property.name === 'postMessage') {
                    
                    // Check if second argument (origin) is '*'
                    if (node.arguments[1]?.type === 'Literal' &&
                        node.arguments[1]?.value === '*') {
                        findings.push({
                            rule_id: rule.id || 'JS_POSTMESSAGE',
                            rule_name: rule.name || 'Insecure postMessage',
                            description: 'postMessage with "*" origin allows any domain to receive the message',
                            severity: 'medium',
                            confidence: 'high',
                            line_number: node.loc?.start?.line || 1,
                            column_number: node.loc?.start?.column || 1,
                            matched_code: content.substring(node.start, Math.min(node.end, node.start + 100))
                        });
                    }
                }
            }
        });
        
        return findings;
    },
    
    /**
     * Detect hardcoded credentials in code
     */
    hardcodedCredentials: (ast, content, rule) => {
        const findings = [];
        const sensitiveNames = ['password', 'passwd', 'secret', 'apikey', 'api_key', 'token', 'auth'];
        
        walk.simple(ast, {
            VariableDeclarator(node) {
                if (node.id.type === 'Identifier' &&
                    node.init?.type === 'Literal' &&
                    typeof node.init.value === 'string' &&
                    node.init.value.length > 3) {
                    
                    const varName = node.id.name.toLowerCase();
                    if (sensitiveNames.some(s => varName.includes(s))) {
                        findings.push({
                            rule_id: rule.id || 'JS_HARDCODED_CRED',
                            rule_name: rule.name || 'Hardcoded credential',
                            description: `Potential hardcoded credential in variable "${node.id.name}"`,
                            severity: 'high',
                            confidence: 'medium',
                            line_number: node.loc?.start?.line || 1,
                            column_number: node.loc?.start?.column || 1,
                            matched_code: content.substring(node.start, Math.min(node.end, node.start + 100))
                        });
                    }
                }
            },
            Property(node) {
                if (node.key.type === 'Identifier' &&
                    node.value?.type === 'Literal' &&
                    typeof node.value.value === 'string' &&
                    node.value.value.length > 3) {
                    
                    const propName = node.key.name.toLowerCase();
                    if (sensitiveNames.some(s => propName.includes(s))) {
                        findings.push({
                            rule_id: rule.id || 'JS_HARDCODED_CRED',
                            rule_name: rule.name || 'Hardcoded credential',
                            description: `Potential hardcoded credential in property "${node.key.name}"`,
                            severity: 'high',
                            confidence: 'medium',
                            line_number: node.loc?.start?.line || 1,
                            column_number: node.loc?.start?.column || 1,
                            matched_code: content.substring(node.start, Math.min(node.end, node.start + 100))
                        });
                    }
                }
            }
        });
        
        return findings;
    }
};

/**
 * Main analysis function
 */
function analyzeCode(filePath, content, rules) {
    const findings = [];
    
    // Parse the code
    const ast = parseCode(content, filePath);
    if (!ast) {
        return { success: false, findings: [], error: 'Failed to parse code' };
    }
    
    // Run each detector
    for (const [detectorName, detector] of Object.entries(detectors)) {
        try {
            // Find matching rule or use default
            const rule = rules.find(r => r.id?.toLowerCase().includes(detectorName.toLowerCase())) || {
                id: `AST_${detectorName.toUpperCase()}`,
                name: detectorName,
                severity: 'medium'
            };
            
            const detectorFindings = detector(ast, content, rule);
            findings.push(...detectorFindings);
        } catch (e) {
            // Continue with other detectors even if one fails
            console.error(`Detector ${detectorName} failed: ${e.message}`);
        }
    }
    
    return { success: true, findings };
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
