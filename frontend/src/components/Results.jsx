'use client';

/**
 * Enhanced Results Component
 * Displays scan results with advanced filtering, charts, and user-friendly interface
 */

import React, { useState, useMemo, useEffect } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

// Severity colors for charts and UI
const SEVERITY_COLORS = {
  CRITICAL: { chip: "critical", row: "severity-critical", chart: "#ef4444" },
  HIGH: { chip: "high", row: "severity-high", chart: "#f59e0b" },
  MEDIUM: { chip: "medium", row: "severity-medium", chart: "#06b6d4" },
  LOW: { chip: "low", row: "severity-low", chart: "#10b981" },
  INFO: { chip: "info", row: "severity-info", chart: "#94a3b8" },
};

// OWASP Top 10 Vulnerabilities
const OWASP_VULNERABILITIES = [
  {
    name: "A01: Broken Access Control",
    id: "A01",
    color: "#ef4444",
    description: "Restrictions on authenticated users not properly enforced"
  },
  {
    name: "A02: Cryptographic Failures",
    id: "A02",
    color: "#f59e0b",
    description: "Sensitive data exposure due to cryptographic failures"
  },
  {
    name: "A03: Injection",
    id: "A03",
    color: "#dc2626",
    description: "SQL, NoSQL, OS command injection vulnerabilities"
  },
  {
    name: "A04: Insecure Design",
    id: "A04",
    color: "#9333ea",
    description: "Security risks from insecure design patterns"
  },
  {
    name: "A05: Security Misconfiguration",
    id: "A05",
    color: "#0891b2",
    description: "Improperly configured security settings"
  },
  {
    name: "A06: Vulnerable Components",
    id: "A06",
    color: "#059669",
    description: "Using components with known vulnerabilities"
  },
  {
    name: "A07: Authentication Failures",
    id: "A07",
    color: "#7c3aed",
    description: "Broken authentication and session management"
  },
  {
    name: "A08: Software Integrity Failures",
    id: "A08",
    color: "#be185d",
    description: "Code and infrastructure integrity violations"
  },
  {
    name: "A09: Logging & Monitoring Failures",
    id: "A09",
    color: "#b91c1c",
    description: "Insufficient logging and monitoring"
  },
  {
    name: "A10: Server-Side Request Forgery",
    id: "A10",
    color: "#374151",
    description: "SSRF flaws allowing server-side requests"
  }
];

// File extensions mapping
const FILE_EXTENSIONS = {
  PYTHON: [".py"],
  JAVASCRIPT: [".js", ".jsx"],
  PHP: [".php"],
  JAVA: [".java"],
};

/**
 * Severity badge component
 */
const SeverityBadge = ({ severity }) => {
  const sev = severity?.toUpperCase();
  const colorConfig = SEVERITY_COLORS[sev] || SEVERITY_COLORS.INFO;

  return (
    <span style={{
      display: 'inline-block',
      padding: '4px 8px',
      borderRadius: '4px',
      fontSize: '0.75rem',
      fontWeight: '600',
      textTransform: 'uppercase',
      backgroundColor: `rgba(${colorConfig.chart.slice(1).match(/.{2}/g).map(x => parseInt(x, 16)).join(', ')}, 0.2)`,
      color: colorConfig.chart
    }}>
      {sev}
    </span>
  );
};

/**
 * Statistics card component
 */
const StatCard = ({ label, value, color }) => (
  <div
    style={{
      backgroundColor: '#ffffff',
      border: '1px solid #e5e7eb',
      borderRadius: '8px',
      padding: '16px',
      textAlign: 'center',
      minWidth: '100px',
    }}
  >
    <div
      style={{
        fontSize: '28px',
        fontWeight: '700',
        color: color || '#1f2937',
        marginBottom: '4px',
      }}
    >
      {value}
    </div>
    <div
      style={{
        fontSize: '12px',
        color: '#6b7280',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
      }}
    >
      {label}
    </div>
  </div>
);

/**
 * Vulnerability card component
 */
const VulnerabilityCard = ({ vulnerability, isExpanded, onToggle }) => {
  const {
    rule_id,
    rule_name,
    description,
    severity,
    file_path,
    line_number,
    column_number,
    code_snippet,
    remediation,
    cwe_id,
    owasp_category,
  } = vulnerability;

  return (
    <div
      style={{
        backgroundColor: '#ffffff',
        border: '1px solid #e5e7eb',
        borderRadius: '8px',
        marginBottom: '12px',
        overflow: 'hidden',
        transition: 'box-shadow 0.2s ease',
      }}
    >
      {/* Header */}
      <button
        onClick={onToggle}
        style={{
          width: '100%',
          padding: '16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          backgroundColor: 'transparent',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
          <SeverityBadge severity={severity} />
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: '600', color: '#1f2937', marginBottom: '4px' }}>
              {rule_id}
            </div>
            <div style={{ fontSize: '14px', color: '#6b7280' }}>
              {file_path}:{line_number}:{column_number}
            </div>
          </div>
        </div>
        <svg
          style={{
            width: '20px',
            height: '20px',
            color: '#9ca3af',
            transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
            transition: 'transform 0.2s ease',
          }}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Expanded content */}
      {isExpanded && (
        <div style={{ padding: '0 16px 16px', borderTop: '1px solid #e5e7eb' }}>
          {/* Message */}
          <div style={{ marginTop: '16px' }}>
            <h4 style={{ fontSize: '12px', fontWeight: '600', color: '#6b7280', marginBottom: '8px', textTransform: 'uppercase' }}>
              Description
            </h4>
            <p style={{ color: '#374151', lineHeight: '1.5' }}>{description}</p>
          </div>

          {/* Code snippet */}
          {code_snippet && (
            <div style={{ marginTop: '16px' }}>
              <h4 style={{ fontSize: '12px', fontWeight: '600', color: '#6b7280', marginBottom: '8px', textTransform: 'uppercase' }}>
                Code Snippet
              </h4>
              <pre
                style={{
                  backgroundColor: '#1f2937',
                  color: '#f3f4f6',
                  padding: '12px',
                  borderRadius: '6px',
                  fontSize: '13px',
                  fontFamily: 'monospace',
                  overflow: 'auto',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                }}
              >
                {code_snippet?.lines
                  ?.map(line =>
                    line.is_highlighted
                      ? `>> ${line.line_number}: ${line.content}`
                      : `   ${line.line_number}: ${line.content}`
                  )
                  .join('\n')}
              </pre>
            </div>
          )}

          {/* Recommendation */}
          {remediation && (
            <div style={{ marginTop: '16px' }}>
              <h4 style={{ fontSize: '12px', fontWeight: '600', color: '#6b7280', marginBottom: '8px', textTransform: 'uppercase' }}>
                Recommendation
              </h4>
              <p style={{ color: '#374151', lineHeight: '1.5' }}>{remediation}</p>
            </div>
          )}

          {/* Reference IDs */}
          <div style={{ marginTop: '16px', display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
            {cwe_id && (
              <div>
                <span style={{ fontSize: '12px', color: '#6b7280' }}>CWE: </span>
                <a
                  href={`https://cwe.mitre.org/data/definitions/${cwe_id.replace('CWE-', '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ fontSize: '12px', color: '#2563eb', textDecoration: 'none' }}
                >
                  {cwe_id}
                </a>
              </div>
            )}
            {owasp_category && (
              <div>
                <span style={{ fontSize: '12px', color: '#6b7280' }}>OWASP: </span>
                <span style={{ fontSize: '12px', color: '#374151' }}>{owasp_category}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

/**
 * Filter button component
 */
const FilterButton = ({ label, isActive, onClick, count }) => (
  <button
    onClick={onClick}
    style={{
      padding: '8px 16px',
      borderRadius: '6px',
      border: isActive ? '2px solid #2563eb' : '1px solid #e5e7eb',
      backgroundColor: isActive ? '#eff6ff' : '#ffffff',
      color: isActive ? '#2563eb' : '#374151',
      fontWeight: '500',
      fontSize: '14px',
      cursor: 'pointer',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      transition: 'all 0.2s ease',
    }}
  >
    {label}
    {count !== undefined && (
      <span
        style={{
          backgroundColor: isActive ? '#2563eb' : '#e5e7eb',
          color: isActive ? '#ffffff' : '#6b7280',
          padding: '2px 8px',
          borderRadius: '9999px',
          fontSize: '12px',
        }}
      >
        {count}
      </span>
    )}
  </button>
);

/**
 * Main Results component
 */
const Results = ({ results, onClear, activeTab, onTabChange, onScanComplete }) => {
  const [expandedIds, setExpandedIds] = useState(new Set());
  const [theme, setTheme] = useState("dark");
  const [filtersVisible, setFiltersVisible] = useState(true);
  const [activeBar, setActiveBar] = useState(null);
  const [chartAnimated, setChartAnimated] = useState(false);
  const [filters, setFilters] = useState({
    severity: "ALL",
    owasp: "ALL",
    cwe: "ALL",
    fileType: "ALL",
    search: "",
  });
  const vulnerabilities = results?.findings || [];

  // Calculate statistics
  // Filter options computation
  const filterOptions = useMemo(() => {
    const options = {
      severities: new Set(["ALL"]),
      owaspCategories: new Set(["ALL"]),
      cweCategories: new Set(["ALL"]),
      fileTypes: new Set(["ALL"]),
    };

    vulnerabilities.forEach(issue => {
      // Add severity
      options.severities.add(issue.severity?.toUpperCase());

      // Add OWASP categories
      if (issue.owasp_category) {
        const owaspMatch = issue.owasp_category.match(/A\d+/);
        if (owaspMatch && owaspMatch[0]) {
          options.owaspCategories.add(owaspMatch[0]);
        }
      }

      // Add CWE categories
      if (issue.cwe_id) {
        const cweMatch = issue.cwe_id.match(/CWE-\d+/);
        if (cweMatch && cweMatch[0]) {
          options.cweCategories.add(cweMatch[0]);
        }
      }

      // Add file types
      if (issue.file_path) {
        const fileExt = issue.file_path.substring(issue.file_path.lastIndexOf('.'));
        const fileType = Object.entries(FILE_EXTENSIONS).find(([_, exts]) =>
          exts.includes(fileExt)
        );
        if (fileType) {
          options.fileTypes.add(fileType[0]);
        }
      }
    });

    // Convert Sets to Arrays for easier mapping
    return {
      severities: Array.from(options.severities),
      owaspCategories: Array.from(options.owaspCategories),
      cweCategories: Array.from(options.cweCategories),
      fileTypes: Array.from(options.fileTypes),
    };
  }, [vulnerabilities]);

  // Function to get OWASP category name from ID
  const getOwaspName = (id) => {
    const vuln = OWASP_VULNERABILITIES.find(v => v.id === id);
    return vuln ? vuln.name : id;
  };

  // Stats computation
  const stats = useMemo(() => {
    const severityCounts = vulnerabilities.reduce((acc, vuln) => {
      const severity = vuln.severity?.toUpperCase();
      if (severity && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severity)) {
        acc[severity.toLowerCase()] = (acc[severity.toLowerCase()] || 0) + 1;
      }
      return acc;
    }, {});

    return {
      total: results?.total_findings || vulnerabilities.length,
      critical: severityCounts.critical || 0,
      high: severityCounts.high || 0,
      medium: severityCounts.medium || 0,
      low: severityCounts.low || 0,
      info: severityCounts.info || 0,
    };
  }, [results, vulnerabilities]);

  // OWASP counts
  const owaspCounts = useMemo(() => {
    const counts = {};

    OWASP_VULNERABILITIES.forEach(vuln => {
      counts[vuln.id] = 0;
    });

    vulnerabilities.forEach(issue => {
      const owaspMatch = issue.owasp_category?.match(/A\d+/);
      if (owaspMatch && owaspMatch[0]) {
        const owaspId = owaspMatch[0];
        if (counts.hasOwnProperty(owaspId)) {
          counts[owaspId]++;
        }
      }
    });

    return counts;
  }, [vulnerabilities]);

  // OWASP chart data
  const owaspChartData = useMemo(() => {
    return OWASP_VULNERABILITIES.map(vuln => {
      const count = owaspCounts[vuln.id] || 0;
      const percentage = vulnerabilities.length > 0
        ? Math.round((count / vulnerabilities.length) * 100)
        : 0;

      return {
        ...vuln,
        count,
        value: percentage,
      };
    }).filter(item => item.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [owaspCounts, vulnerabilities.length]);

  // Security score calculation
  const securityScore = useMemo(() => {
    return Math.max(0, 100 -
      (stats.critical * 10 +
       stats.high * 5 +
       stats.medium * 2 +
       stats.low * 1));
  }, [stats]);

  const getScoreRange = (score) => {
    if (score >= 90) return "excellent";
    if (score >= 70) return "good";
    if (score >= 50) return "average";
    return "poor";
  };

  // Clear filters function
  const clearFilters = () => {
    setFilters({
      severity: "ALL",
      owasp: "ALL",
      cwe: "ALL",
      fileType: "ALL",
      search: "",
    });
  };

  // Theme toggle
  const toggleTheme = () => {
    setTheme(theme === "dark" ? "light" : "dark");
  };

  // Handle bar click for OWASP chart
  const handleBarClick = (index) => {
    setActiveBar(index === activeBar ? null : index);
  };

  // Filter vulnerabilities
  const filteredVulnerabilities = useMemo(() => {
    if (!vulnerabilities.length) return [];

    let filtered = vulnerabilities.filter((vuln) => {
      // Severity filter
      if (filters.severity !== "ALL" && vuln.severity?.toUpperCase() !== filters.severity) {
        return false;
      }

      // OWASP filter
      if (filters.owasp !== "ALL" && !vuln.owasp_category?.includes(filters.owasp)) {
        return false;
      }

      // CWE filter
      if (filters.cwe !== "ALL" && !vuln.cwe_id?.includes(filters.cwe)) {
        return false;
      }

      // File type filter
      if (filters.fileType !== "ALL") {
        const fileExt = vuln.file_path?.substring(vuln.file_path.lastIndexOf('.'));
        if (!FILE_EXTENSIONS[filters.fileType]?.includes(fileExt)) {
          return false;
        }
      }

      // Search filter
      if (filters.search) {
        const searchTerm = filters.search.toLowerCase();
        const searchableFields = [
          vuln.file_path,
          vuln.description,
          vuln.category,
          vuln.rule_id,
          vuln.detected_by,
          vuln.owasp_category,
          vuln.cwe_id,
          vuln.remediation
        ].join(" ").toLowerCase();

        if (!searchableFields.includes(searchTerm)) {
          return false;
        }
      }

      return true;
    });

    // Sort by severity (CRITICAL, HIGH, MEDIUM, LOW) and then by line numbers
    const severityOrder = {
      CRITICAL: 1,
      HIGH: 2,
      MEDIUM: 3,
      LOW: 4,
      INFO: 5
    };

    return filtered.sort((a, b) => {
      const severityA = a.severity?.toUpperCase();
      const severityB = b.severity?.toUpperCase();

      // First sort by severity
      if (severityOrder[severityA] !== severityOrder[severityB]) {
        return severityOrder[severityA] - severityOrder[severityB];
      }

      // If same severity, sort by line numbers
      const lineA = parseInt(a.line_number) || 0;
      const lineB = parseInt(b.line_number) || 0;

      return lineA - lineB;
    });
  }, [vulnerabilities, filters]);

  // Toggle expanded state
  const toggleExpanded = (id) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Expand/collapse all
  const expandAll = () => {
    setExpandedIds(new Set(filteredVulnerabilities.map((_, i) => i)));
  };

  const collapseAll = () => {
    setExpandedIds(new Set());
  };

  // Theme effect
  useEffect(() => {
    document.body.className = theme;
  }, [theme]);

  // Chart animation effect
  useEffect(() => {
    setTimeout(() => setChartAnimated(true), 1000);
  }, []);

  // Constants for API and configuration
  const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";
  const ENDPOINTS = { SCAN_FILE: "/scan-file", SCAN_URL: "/scan-url" };
  const REQUEST_TIMEOUT = 120000;
  const MAX_FILE_SIZE = 10 * 1024 * 1024;
  const MAX_FILES = 50;
  const SUPPORTED_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".py", ".pyw", ".php", ".phtml", ".java", ".html", ".htm", ".css", ".scss", ".sass", ".json", ".xml", ".yaml", ".yml", ".sql", ".sh", ".bash", ".rb", ".erb", ".go", ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt", ".kts"];

  // API Functions
  const fetchWithErrorHandling = async (url, options = {}) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
    try {
      const response = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(timeoutId);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP error ${response.status}`);
      return data;
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === "AbortError") throw new Error("Request timed out");
      throw error;
    }
  };

  const scanFiles = async (files, onProgress) => {
    const formData = new FormData();
    files.forEach(file => formData.append("files", file));
    if (onProgress) {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.upload.addEventListener("progress", event => {
          if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100));
        });
        xhr.addEventListener("load", () => {
          try {
            const data = JSON.parse(xhr.responseText);
            if (xhr.status >= 200 && xhr.status < 300) resolve(data);
            else reject(new Error(data.error || "Scan failed"));
          } catch { reject(new Error("Invalid response")); }
        });
        xhr.addEventListener("error", () => reject(new Error("Network error")));
        xhr.addEventListener("timeout", () => reject(new Error("Request timed out")));
        xhr.timeout = REQUEST_TIMEOUT;
        xhr.open("POST", `${API_BASE_URL}${ENDPOINTS.SCAN_FILE}`);
        xhr.send(formData);
      });
    }
    return fetchWithErrorHandling(`${API_BASE_URL}${ENDPOINTS.SCAN_FILE}`, { method: "POST", body: formData });
  };

  const scanUrl = async (url) => {
    return fetchWithErrorHandling(`${API_BASE_URL}${ENDPOINTS.SCAN_URL}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
  };

  // FileScan Component
  const FileScan = () => {
    const [files, setFiles] = useState([]);
    const [isDragging, setIsDragging] = useState(false);
    const [isScanning, setIsScanning] = useState(false);
    const [progress, setProgress] = useState(0);
    const [status, setStatus] = useState("");
    const [error, setError] = useState(null);
    const fileInputRef = React.useRef(null);

    const validateFile = (file) => {
      if (file.size > MAX_FILE_SIZE) return `File "${file.name}" exceeds maximum size`;
      const ext = "." + file.name.split(".").pop()?.toLowerCase();
      if (!SUPPORTED_EXTENSIONS.includes(ext)) return `File type "${ext}" is not supported`;
      return null;
    };

    const handleFiles = (newFiles) => {
      setError(null);
      const fileArray = Array.from(newFiles);
      if (files.length + fileArray.length > MAX_FILES) { setError(`Maximum ${MAX_FILES} files allowed`); return; }
      const validFiles = [];
      for (const file of fileArray) {
        const validationError = validateFile(file);
        if (validationError) { setError(validationError); return; }
        if (!files.some((f) => f.name === file.name && f.size === file.size)) validFiles.push(file);
      }
      setFiles((prev) => [...prev, ...validFiles]);
    };

    const handleDragEnter = (e) => { e.preventDefault(); e.stopPropagation(); setIsDragging(true); };
    const handleDragLeave = (e) => { e.preventDefault(); e.stopPropagation(); setIsDragging(false); };
    const handleDragOver = (e) => { e.preventDefault(); e.stopPropagation(); };
    const handleDrop = (e) => { e.preventDefault(); e.stopPropagation(); setIsDragging(false); handleFiles(e.dataTransfer.files); };
    const handleFileInputChange = (e) => { if (e.target.files) handleFiles(e.target.files); e.target.value = ""; };

    const handleScan = async () => {
      if (files.length === 0) { setError("Please select files to scan"); return; }
      setIsScanning(true); setProgress(0); setStatus("Uploading files..."); setError(null);
      try {
        const results = await scanFiles(files, (uploadProgress) => { setProgress(uploadProgress); if (uploadProgress === 100) setStatus("Analyzing code..."); });
        setStatus("Scan complete!"); setProgress(100); onScanComplete(results);
      } catch (err) { setError(err.message); }
      finally { setIsScanning(false); }
    };

    return (
      <div style={{ maxWidth: '600px', margin: '0 auto', padding: '24px' }}>
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '8px', color: theme === 'dark' ? '#e2e8f0' : '#1e293b' }}>
            File Scan
          </h2>
          <p style={{ fontSize: '0.875rem', color: theme === 'dark' ? '#94a3b8' : '#64748b' }}>
            Upload source code files to analyze for security vulnerabilities
          </p>
        </div>
        <div
          onDragEnter={handleDragEnter} onDragLeave={handleDragLeave} onDragOver={handleDragOver} onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          style={{
            border: `2px dashed ${isDragging ? '#2563eb' : theme === 'dark' ? '#475569' : '#e5e7eb'}`,
            borderRadius: '12px',
            padding: '48px',
            textAlign: 'center',
            cursor: 'pointer',
            backgroundColor: isDragging ? (theme === 'dark' ? '#1e293b' : '#eff6ff') : (theme === 'dark' ? '#0f172a' : '#ffffff'),
            transition: 'all 0.2s ease'
          }}
        >
          <input ref={fileInputRef} type="file" multiple onChange={handleFileInputChange} accept={SUPPORTED_EXTENSIONS.join(",")} style={{ display: 'none' }} />
          <div style={{ fontSize: '3rem', marginBottom: '16px' }}>📁</div>
          <p style={{ fontSize: '1.125rem', fontWeight: '600', marginBottom: '8px', color: theme === 'dark' ? '#e2e8f0' : '#1e293b' }}>
            {isDragging ? "Drop files here" : "Drag and drop files here"}
          </p>
          <p style={{ fontSize: '0.875rem', color: theme === 'dark' ? '#94a3b8' : '#64748b' }}>
            or click to browse
          </p>
          <p style={{ fontSize: '0.75rem', color: theme === 'dark' ? '#64748b' : '#94a3b8', marginTop: '12px' }}>
            Supports: JavaScript, Python, PHP, Java, HTML, CSS, and more
          </p>
        </div>
        {files.length > 0 && (
          <div style={{ marginTop: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <span style={{ fontSize: '1.125rem', fontWeight: '600', color: theme === 'dark' ? '#e2e8f0' : '#1e293b' }}>
                Selected Files ({files.length})
              </span>
              <button onClick={() => setFiles([])} style={{
                fontSize: '0.875rem',
                color: theme === 'dark' ? '#94a3b8' : '#64748b',
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                textDecoration: 'underline'
              }}>
                Clear All
              </button>
            </div>
            <div style={{ maxHeight: '240px', overflowY: 'auto' }}>
              {files.map((file, index) => (
                <div key={`${file.name}-${index}`} style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '12px',
                  backgroundColor: theme === 'dark' ? '#1e293b' : '#f8fafc',
                  borderRadius: '8px',
                  marginBottom: '8px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ fontSize: '1.25rem' }}>📄</span>
                    <div>
                      <div style={{ fontSize: '0.875rem', fontWeight: '500', color: theme === 'dark' ? '#e2e8f0' : '#1e293b' }}>
                        {file.name}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: theme === 'dark' ? '#94a3b8' : '#64748b' }}>
                        {(file.size / 1024 / 1024).toFixed(1)} MB
                      </div>
                    </div>
                  </div>
                  <button onClick={() => setFiles((prev) => prev.filter((f) => f !== file))} style={{
                    fontSize: '1.25rem',
                    color: theme === 'dark' ? '#94a3b8' : '#64748b',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer'
                  }}>
                    ×
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
        {isScanning && (
          <div style={{ marginTop: '24px', textAlign: 'center' }}>
            <div style={{ fontSize: '1rem', marginBottom: '8px', color: theme === 'dark' ? '#e2e8f0' : '#1e293b' }}>
              {status}
            </div>
            <div style={{
              width: '100%',
              height: '8px',
              backgroundColor: theme === 'dark' ? '#334155' : '#e2e8f0',
              borderRadius: '4px',
              overflow: 'hidden'
            }}>
              <div style={{
                width: `${progress}%`,
                height: '100%',
                backgroundColor: '#2563eb',
                transition: 'width 0.3s ease'
              }} />
            </div>
          </div>
        )}
        {error && (
          <div style={{
            marginTop: '16px',
            padding: '12px',
            backgroundColor: '#fef2f2',
            border: '1px solid #fecaca',
            borderRadius: '6px',
            color: '#dc2626'
          }}>
            {error}
          </div>
        )}
        <button
          onClick={handleScan}
          disabled={isScanning || files.length === 0}
          style={{
            width: '100%',
            marginTop: '24px',
            padding: '12px',
            backgroundColor: isScanning || files.length === 0 ? '#9ca3af' : '#2563eb',
            color: '#ffffff',
            border: 'none',
            borderRadius: '6px',
            fontSize: '1rem',
            fontWeight: '500',
            cursor: isScanning || files.length === 0 ? 'not-allowed' : 'pointer'
          }}
        >
          {isScanning ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>
    );
  };

  // UrlScan Component
  const UrlScan = () => {
    const [url, setUrl] = useState("");
    const [isScanning, setIsScanning] = useState(false);
    const [error, setError] = useState(null);

    const handleScan = async () => {
      if (!url.trim()) { setError("Please enter a URL"); return; }
      setIsScanning(true); setError(null);
      try {
        const results = await scanUrl(url);
        onScanComplete(results);
      } catch (err) { setError(err.message); }
      finally { setIsScanning(false); }
    };

    return (
      <div style={{ maxWidth: '600px', margin: '0 auto', padding: '24px' }}>
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <h2 style={{ fontSize: '1.5rem', fontWeight: '700', marginBottom: '8px', color: theme === 'dark' ? '#e2e8f0' : '#1e293b' }}>
            URL Scan
          </h2>
          <p style={{ fontSize: '0.875rem', color: theme === 'dark' ? '#94a3b8' : '#64748b' }}>
            Enter a website URL to analyze client-side JavaScript for security vulnerabilities
          </p>
        </div>
        <div style={{
          backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
          borderRadius: '12px',
          padding: '32px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
          border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
        }}>
          <div style={{ marginBottom: '24px' }}>
            <label style={{
              display: 'block',
              fontSize: '0.875rem',
              fontWeight: '500',
              marginBottom: '8px',
              color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
            }}>
              Website URL
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type="text"
                value={url}
                onChange={(e) => { setUrl(e.target.value); setError(null); }}
                placeholder="https://example.com"
                style={{
                  width: '100%',
                  padding: '12px 16px 12px 44px',
                  border: `1px solid ${theme === 'dark' ? '#475569' : '#e2e8f0'}`,
                  borderRadius: '6px',
                  backgroundColor: theme === 'dark' ? '#334155' : '#ffffff',
                  color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                  fontSize: '1rem'
                }}
              />
              <span style={{
                position: 'absolute',
                left: '12px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: theme === 'dark' ? '#94a3b8' : '#64748b',
                fontSize: '1.25rem'
              }}>
                🌐
              </span>
            </div>
          </div>
          {error && (
            <div style={{
              marginBottom: '16px',
              padding: '12px',
              backgroundColor: '#fef2f2',
              border: '1px solid #fecaca',
              borderRadius: '6px',
              color: '#dc2626'
            }}>
              {error}
            </div>
          )}
          <button
            onClick={handleScan}
            disabled={isScanning || !url.trim()}
            style={{
              width: '100%',
              padding: '12px',
              backgroundColor: isScanning || !url.trim() ? '#9ca3af' : '#2563eb',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontSize: '1rem',
              fontWeight: '500',
              cursor: isScanning || !url.trim() ? 'not-allowed' : 'pointer'
            }}
          >
            {isScanning ? 'Scanning...' : 'Start Scan'}
          </button>
        </div>
      </div>
    );
  };

  if (!results) {
    return (
      <div style={{
        minHeight: '100vh',
        backgroundColor: theme === 'dark' ? '#0f172a' : '#f8fafc',
        color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
        padding: '24px'
      }}>
        {/* Header */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '24px',
          padding: '16px 24px',
          backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
          borderRadius: '8px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
          border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
        }}>
          <div>
            <h1 style={{
              fontSize: '1.5rem',
              fontWeight: '700',
              marginBottom: '4px',
              color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
            }}>
              Security Scan Results
            </h1>
            <p style={{
              fontSize: '0.875rem',
              color: theme === 'dark' ? '#94a3b8' : '#64748b'
            }}>
              No scan results available - Start a new scan
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              type="button"
              onClick={toggleTheme}
              style={{
                background: 'none',
                border: 'none',
                color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                fontSize: '1.2rem',
                cursor: 'pointer',
                padding: '8px',
                borderRadius: '4px',
                transition: 'background-color 0.2s'
              }}
              onMouseOver={(e) => e.target.style.backgroundColor = theme === 'dark' ? '#334155' : '#f1f5f9'}
              onMouseOut={(e) => e.target.style.backgroundColor = 'transparent'}
              title={theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"}
            >
              <span>{theme === "dark" ? "☀️" : "🌙"}</span>
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div style={{
          backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
          borderRadius: '8px',
          padding: '16px',
          marginBottom: '24px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
          border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
        }}>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '0' }}>
            <button
              onClick={() => onTabChange('file')}
              style={{
                padding: '12px 24px',
                border: 'none',
                backgroundColor: activeTab === 'file' ? (theme === 'dark' ? '#334155' : '#f1f5f9') : 'transparent',
                color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                fontWeight: activeTab === 'file' ? '600' : '500',
                cursor: 'pointer',
                borderRadius: '6px 0 0 6px',
                transition: 'all 0.2s'
              }}
            >
              📁 File Scan
            </button>
            <button
              onClick={() => onTabChange('url')}
              style={{
                padding: '12px 24px',
                border: 'none',
                backgroundColor: activeTab === 'url' ? (theme === 'dark' ? '#334155' : '#f1f5f9') : 'transparent',
                color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                fontWeight: activeTab === 'url' ? '600' : '500',
                cursor: 'pointer',
                borderRadius: '0 6px 6px 0',
                transition: 'all 0.2s'
              }}
            >
              🌐 URL Scan
            </button>
          </div>
        </div>

        {/* Scan Interface */}
        <div style={{
          backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
          borderRadius: '12px',
          padding: '32px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
          border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
        }}>
          {activeTab === 'file' ? <FileScan /> : <UrlScan />}
        </div>
      </div>
    );
  }

  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: theme === 'dark' ? '#0f172a' : '#f8fafc',
      color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
      padding: '24px'
    }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '24px',
        padding: '16px 24px',
        backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
        borderRadius: '8px',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
        border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
      }}>
        <div>
          <h1 style={{
            fontSize: '1.5rem',
            fontWeight: '700',
            marginBottom: '4px',
            color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
          }}>
            Security Scan Results
          </h1>
          <p style={{
            fontSize: '0.875rem',
            color: theme === 'dark' ? '#94a3b8' : '#64748b'
          }}>
            Analysis complete - {stats.total} vulnerabilities found
          </p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            onClick={toggleTheme}
            style={{
              background: 'none',
              border: 'none',
              color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
              fontSize: '1.2rem',
              cursor: 'pointer',
              padding: '8px',
              borderRadius: '4px',
              transition: 'background-color 0.2s'
            }}
            onMouseOver={(e) => e.target.style.backgroundColor = theme === 'dark' ? '#334155' : '#f1f5f9'}
            onMouseOut={(e) => e.target.style.backgroundColor = 'transparent'}
            title={theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"}
          >
            <span>{theme === "dark" ? "☀️" : "🌙"}</span>
          </button>
          <button
            type="button"
            onClick={onClear}
            style={{
              background: 'none',
              border: 'none',
              color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
              fontSize: '1.2rem',
              cursor: 'pointer',
              padding: '8px',
              borderRadius: '4px',
              transition: 'background-color 0.2s'
            }}
            onMouseOver={(e) => e.target.style.backgroundColor = theme === 'dark' ? '#334155' : '#f1f5f9'}
            onMouseOut={(e) => e.target.style.backgroundColor = 'transparent'}
            title="New Scan"
          >
            <span>🔄</span>
          </button>
        </div>
      </div>

      {/* Dashboard Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
        gap: '24px',
        marginBottom: '24px'
      }}>
        {/* Security Score Card */}
        <div style={{
          backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
          borderRadius: '12px',
          padding: '24px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
          border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
        }}>
          <div style={{ fontSize: '2.5rem', marginBottom: '16px' }}>📊</div>
          <h3 style={{
            fontSize: '1.25rem',
            fontWeight: '600',
            marginBottom: '12px',
            color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
          }}>
            Security Score
          </h3>
          <div style={{ textAlign: 'center', margin: '20px 0' }}>
            <div style={{
              fontSize: '2.5rem',
              fontWeight: '700',
              marginBottom: '4px',
              color: securityScore >= 90 ? '#10b981' :
                     securityScore >= 70 ? '#84cc16' :
                     securityScore >= 50 ? '#f59e0b' : '#ef4444'
            }}>
              {securityScore}%
            </div>
            <div style={{
              fontSize: '0.875rem',
              color: theme === 'dark' ? '#94a3b8' : '#64748b'
            }}>
              Overall Security
            </div>
          </div>
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '16px'
          }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', marginBottom: '4px' }}>🚨</div>
              <div style={{
                fontSize: '1.5rem',
                fontWeight: '600',
                color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
              }}>
                {stats.total}
              </div>
              <div style={{
                fontSize: '0.875rem',
                color: theme === 'dark' ? '#94a3b8' : '#64748b'
              }}>
                Total Issues
              </div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', marginBottom: '4px' }}>📁</div>
              <div style={{
                fontSize: '1.5rem',
                fontWeight: '600',
                color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
              }}>
                {results?.metadata?.files_scanned || 0}
              </div>
              <div style={{
                fontSize: '0.875rem',
                color: theme === 'dark' ? '#94a3b8' : '#64748b'
              }}>
                Files Scanned
              </div>
            </div>
          </div>
        </div>

        {/* Severity Statistics */}
        <div style={{
          backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
          borderRadius: '12px',
          padding: '24px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
          border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
        }}>
          <h3 style={{
            fontSize: '1.25rem',
            fontWeight: '600',
            marginBottom: '20px',
            color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
          }}>
            Severity Breakdown
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            {[
              { name: 'Critical', count: stats.critical, color: SEVERITY_COLORS.CRITICAL.chart, icon: '🚨' },
              { name: 'High', count: stats.high, color: SEVERITY_COLORS.HIGH.chart, icon: '⚠️' },
              { name: 'Medium', count: stats.medium, color: SEVERITY_COLORS.MEDIUM.chart, icon: '⚡' },
              { name: 'Low', count: stats.low, color: SEVERITY_COLORS.LOW.chart, icon: 'ℹ️' }
            ].map(({ name, count, color, icon }) => (
              <div key={name} style={{
                backgroundColor: theme === 'dark' ? '#334155' : '#f8fafc',
                borderRadius: '8px',
                padding: '16px',
                textAlign: 'center',
                border: `1px solid ${color}20`
              }}>
                <div style={{ fontSize: '1.5rem', marginBottom: '8px' }}>{icon}</div>
                <div style={{
                  fontSize: '1.25rem',
                  fontWeight: '700',
                  color: color,
                  marginBottom: '4px'
                }}>
                  {count}
                </div>
                <div style={{
                  fontSize: '0.875rem',
                  fontWeight: '500',
                  color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                  marginBottom: '4px'
                }}>
                  {name}
                </div>
                <div style={{
                  fontSize: '0.75rem',
                  color: theme === 'dark' ? '#94a3b8' : '#64748b'
                }}>
                  {stats.total > 0 ? Math.round((count / stats.total) * 100) : 0}% of total
                </div>
              </div>
            ))}
          </div>
          {stats.total === 0 && (
            <div style={{
              textAlign: 'center',
              padding: '20px',
              color: theme === 'dark' ? '#94a3b8' : '#64748b',
              fontStyle: 'italic'
            }}>
              No vulnerabilities found
            </div>
          )}
        </div>
      </div>

      {/* Charts Section */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(500px, 1fr))',
        gap: '24px',
        marginBottom: '24px'
      }}>
        {/* Severity Distribution Pie Chart */}
        <div style={{
          backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
          borderRadius: '12px',
          padding: '24px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
          border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
        }}>
          <h3 style={{
            fontSize: '1.25rem',
            fontWeight: '600',
            marginBottom: '20px',
            color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
          }}>
            Severity Distribution
          </h3>
          <div style={{
            height: '300px',
            display: 'flex',
            gap: '24px'
          }}>
            <div style={{
              position: 'relative',
              width: '200px',
              height: '200px',
              flexShrink: 0
            }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={Object.entries(stats)
                      .filter(([key, value]) => key !== 'total' && value > 0)
                      .map(([name, value]) => ({ name: name.charAt(0).toUpperCase() + name.slice(1), value }))}
                    dataKey="value"
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={2}
                    startAngle={90}
                    endAngle={-270}
                    animationBegin={0}
                    animationDuration={1000}
                  >
                    {Object.entries(stats)
                      .filter(([key, value]) => key !== 'total' && value > 0)
                      .map(([name], index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={SEVERITY_COLORS[name.toUpperCase()]?.chart || "#94a3b8"}
                          stroke={theme === 'dark' ? "#1e293b" : "#e5e7eb"}
                          strokeWidth={2}
                        />
                      ))}
                  </Pie>
                  <Tooltip
                    formatter={(value, name) => [`${value} issues`, name]}
                    contentStyle={{
                      backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
                      border: theme === 'dark' ? '1px solid #334155' : '1px solid #e5e7eb',
                      borderRadius: '8px',
                      color: theme === 'dark' ? '#ffffff' : '#1e293b',
                      fontSize: '14px',
                      fontWeight: '500'
                    }}
                    itemStyle={{
                      color: theme === 'dark' ? '#ffffff' : '#1e293b'
                    }}
                    labelStyle={{
                      color: theme === 'dark' ? '#f8fafc' : '#1e293b',
                      fontWeight: '600'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>

              <div style={{
                position: 'absolute',
                top: '50%',
                left: '50%',
                transform: 'translate(-50%, -50%)',
                textAlign: 'center'
              }}>
                <div style={{
                  fontSize: '2rem',
                  fontWeight: '700',
                  color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
                }}>
                  {stats.total}
                </div>
                <div style={{
                  fontSize: '0.875rem',
                  color: theme === 'dark' ? '#94a3b8' : '#64748b'
                }}>
                  Total Issues
                </div>
              </div>
            </div>

            <div style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'center',
              gap: '12px'
            }}>
              {Object.entries(stats).map(([name, value]) => {
                if (name === 'total' || value === 0) return null;
                return (
                  <div key={name} style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px'
                  }}>
                    <div style={{
                      width: '12px',
                      height: '12px',
                      borderRadius: '50%',
                      backgroundColor: SEVERITY_COLORS[name.toUpperCase()]?.chart || "#94a3b8",
                      flexShrink: 0
                    }}></div>
                    <div style={{ flex: 1 }}>
                      <div style={{
                        fontSize: '0.875rem',
                        fontWeight: '500',
                        color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
                      }}>
                        {name.charAt(0).toUpperCase() + name.slice(1)}
                      </div>
                      <div style={{
                        fontSize: '0.75rem',
                        color: theme === 'dark' ? '#94a3b8' : '#64748b'
                      }}>
                        {value} issue{value !== 1 ? 's' : ''}
                      </div>
                    </div>
                    <div style={{
                      fontSize: '0.875rem',
                      fontWeight: '600',
                      color: theme === 'dark' ? '#94a3b8' : '#64748b'
                    }}>
                      {stats.total > 0 ? Math.round((value / stats.total) * 100) : 0}%
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* OWASP Top 10 Vulnerabilities */}
        <div style={{
          backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
          borderRadius: '12px',
          padding: '24px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
          border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
        }}>
          <h3 style={{
            fontSize: '1.25rem',
            fontWeight: '600',
            marginBottom: '20px',
            color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
          }}>
            OWASP Top 10 Vulnerabilities
          </h3>
          <div style={{ height: '300px' }}>
            {owaspChartData.length > 0 ? (
              <div style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '12px',
                height: '100%',
                overflowY: 'auto'
              }}>
                {owaspChartData.map((item, index) => {
                  const maxValue = Math.max(...owaspChartData.map(i => i.count), 1);
                  const widthPercentage = chartAnimated ? (item.count / maxValue) * 100 : 0;

                  return (
                    <div
                      key={item.id}
                      onClick={() => handleBarClick(index)}
                      style={{
                        cursor: 'pointer'
                      }}
                    >
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        marginBottom: '4px'
                      }}>
                        <div style={{
                          fontSize: '0.875rem',
                          fontWeight: '500',
                          color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
                        }}>
                          {item.name}
                        </div>
                        <div style={{
                          fontSize: '0.75rem',
                          color: theme === 'dark' ? '#94a3b8' : '#64748b'
                        }}>
                          {item.count} issues ({item.value}%)
                        </div>
                      </div>
                      <div style={{
                        height: '8px',
                        backgroundColor: theme === 'dark' ? '#334155' : '#e2e8f0',
                        borderRadius: '4px',
                        overflow: 'hidden',
                        position: 'relative'
                      }}>
                        <div
                          style={{
                            height: '100%',
                            borderRadius: '4px',
                            position: 'relative',
                            width: `${widthPercentage}%`,
                            backgroundColor: item.color,
                            transition: 'width 0.5s ease',
                            animationDelay: `${index * 0.15}s`
                          }}
                        >
                          <div style={{
                            position: 'absolute',
                            top: 0,
                            left: 0,
                            right: 0,
                            bottom: 0,
                            background: 'linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.2) 50%, transparent 100%)',
                            animation: 'glow 2s infinite'
                          }}></div>
                        </div>
                      </div>
                      {activeBar === index && (
                        <div style={{
                          fontSize: '0.75rem',
                          color: theme === 'dark' ? '#94a3b8' : '#64748b',
                          marginTop: '4px',
                          padding: '8px',
                          backgroundColor: theme === 'dark' ? '#334155' : '#f1f5f9',
                          borderRadius: '4px'
                        }}>
                          {item.description}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: theme === 'dark' ? '#94a3b8' : '#64748b',
                fontStyle: 'italic'
              }}>
                No OWASP vulnerabilities found with current filters
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Filters Section */}
      <div style={{ marginBottom: '24px' }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '16px'
        }}>
          <h3 style={{
            fontSize: '1.25rem',
            fontWeight: '600',
            color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
          }}>
            Filters
          </h3>
          <div>
            <button
              type="button"
              onClick={clearFilters}
              style={{
                background: 'none',
                border: 'none',
                color: theme === 'dark' ? '#94a3b8' : '#64748b',
                cursor: 'pointer',
                marginRight: '10px',
                fontSize: '0.9rem',
                transition: 'color 0.2s'
              }}
              onMouseOver={(e) => e.target.style.color = theme === 'dark' ? '#e2e8f0' : '#1e293b'}
              onMouseOut={(e) => e.target.style.color = theme === 'dark' ? '#94a3b8' : '#64748b'}
            >
              Clear Filters
            </button>
            <button
              type="button"
              onClick={() => setFiltersVisible(!filtersVisible)}
              style={{
                background: 'none',
                border: 'none',
                color: theme === 'dark' ? '#94a3b8' : '#64748b',
                cursor: 'pointer',
                fontSize: '0.9rem',
                padding: '4px 8px',
                borderRadius: '4px',
                transition: 'background-color 0.2s'
              }}
              onMouseOver={(e) => e.target.style.backgroundColor = theme === 'dark' ? '#334155' : '#f1f5f9'}
              onMouseOut={(e) => e.target.style.backgroundColor = 'transparent'}
            >
              {filtersVisible ? "▲" : "▼"}
            </button>
          </div>
        </div>

        {filtersVisible && (
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '16px',
            backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
            padding: '20px',
            borderRadius: '8px',
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
            border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
          }}>
            {/* Severity Filter */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label style={{
                fontSize: '0.875rem',
                fontWeight: '500',
                color: theme === 'dark' ? '#94a3b8' : '#64748b'
              }}>
                Severity
              </label>
              <select
                value={filters.severity}
                onChange={(e) => setFilters({...filters, severity: e.target.value})}
                style={{
                  backgroundColor: theme === 'dark' ? '#334155' : '#f1f5f9',
                  border: theme === 'dark' ? '1px solid #475569' : '1px solid #e2e8f0',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                  fontSize: '0.875rem'
                }}
              >
                {filterOptions.severities.map(severity => (
                  <option key={severity} value={severity}>
                    {severity === "ALL" ? "All Severity" : severity}
                  </option>
                ))}
              </select>
            </div>

            {/* OWASP Filter */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label style={{
                fontSize: '0.875rem',
                fontWeight: '500',
                color: theme === 'dark' ? '#94a3b8' : '#64748b'
              }}>
                OWASP
              </label>
              <select
                value={filters.owasp}
                onChange={(e) => setFilters({...filters, owasp: e.target.value})}
                style={{
                  backgroundColor: theme === 'dark' ? '#334155' : '#f1f5f9',
                  border: theme === 'dark' ? '1px solid #475569' : '1px solid #e2e8f0',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                  fontSize: '0.875rem'
                }}
              >
                {filterOptions.owaspCategories.map(owasp => (
                  <option key={owasp} value={owasp}>
                    {owasp === "ALL" ? "All OWASP" : getOwaspName(owasp)}
                  </option>
                ))}
              </select>
            </div>

            {/* CWE Filter */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label style={{
                fontSize: '0.875rem',
                fontWeight: '500',
                color: theme === 'dark' ? '#94a3b8' : '#64748b'
              }}>
                CWE
              </label>
              <select
                value={filters.cwe}
                onChange={(e) => setFilters({...filters, cwe: e.target.value})}
                style={{
                  backgroundColor: theme === 'dark' ? '#334155' : '#f1f5f9',
                  border: theme === 'dark' ? '1px solid #475569' : '1px solid #e2e8f0',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                  fontSize: '0.875rem'
                }}
              >
                {filterOptions.cweCategories.map(cwe => (
                  <option key={cwe} value={cwe}>
                    {cwe === "ALL" ? "All CWE" : cwe}
                  </option>
                ))}
              </select>
            </div>

            {/* File Type Filter */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label style={{
                fontSize: '0.875rem',
                fontWeight: '500',
                color: theme === 'dark' ? '#94a3b8' : '#64748b'
              }}>
                File Type
              </label>
              <select
                value={filters.fileType}
                onChange={(e) => setFilters({...filters, fileType: e.target.value})}
                style={{
                  backgroundColor: theme === 'dark' ? '#334155' : '#f1f5f9',
                  border: theme === 'dark' ? '1px solid #475569' : '1px solid #e2e8f0',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                  fontSize: '0.875rem'
                }}
              >
                {filterOptions.fileTypes.map(fileType => (
                  <option key={fileType} value={fileType}>
                    {fileType === "ALL" ? "All Files" : fileType}
                  </option>
                ))}
              </select>
            </div>

            {/* Search Filter */}
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
              gridColumn: '1 / -1'
            }}>
              <label style={{
                fontSize: '0.875rem',
                fontWeight: '500',
                color: theme === 'dark' ? '#94a3b8' : '#64748b'
              }}>
                Search
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type="text"
                  placeholder="Search vulnerabilities..."
                  value={filters.search}
                  onChange={(e) => setFilters({...filters, search: e.target.value})}
                  style={{
                    width: '100%',
                    padding: '8px 12px 8px 36px',
                    backgroundColor: theme === 'dark' ? '#334155' : '#f1f5f9',
                    border: theme === 'dark' ? '1px solid #475569' : '1px solid #e2e8f0',
                    borderRadius: '6px',
                    color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                    fontSize: '0.875rem'
                  }}
                />
                <span style={{
                  position: 'absolute',
                  left: '12px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: theme === 'dark' ? '#94a3b8' : '#64748b'
                }}>
                  🔍
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Issues Table */}
      <div style={{ marginBottom: '40px' }}>
        <h3 style={{
          fontSize: '1.25rem',
          fontWeight: '600',
          marginBottom: '16px',
          color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
        }}>
          Security Vulnerabilities ({filteredVulnerabilities.length} issues)
        </h3>
        <div style={{
          backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
          borderRadius: '8px',
          overflow: 'hidden',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
          border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
        }}>
          <table style={{
            width: '100%',
            borderCollapse: 'collapse'
          }}>
            <thead>
              <tr style={{
                backgroundColor: theme === 'dark' ? '#334155' : '#f1f5f9',
                borderColor: theme === 'dark' ? '#475569' : '#e2e8f0'
              }}>
                <th style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  fontSize: '0.875rem',
                  fontWeight: '500',
                  color: theme === 'dark' ? '#94a3b8' : '#64748b',
                  width: '40px'
                }}></th>
                <th style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  fontSize: '0.875rem',
                  fontWeight: '500',
                  color: theme === 'dark' ? '#94a3b8' : '#64748b'
                }}>SEVERITY</th>
                <th style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  fontSize: '0.875rem',
                  fontWeight: '500',
                  color: theme === 'dark' ? '#94a3b8' : '#64748b'
                }}>FILE</th>
                <th style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  fontSize: '0.875rem',
                  fontWeight: '500',
                  color: theme === 'dark' ? '#94a3b8' : '#64748b'
                }}>LINE</th>
                <th style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  fontSize: '0.875rem',
                  fontWeight: '500',
                  color: theme === 'dark' ? '#94a3b8' : '#64748b'
                }}>RULE</th>
              </tr>
            </thead>
            <tbody>
              {filteredVulnerabilities.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: '32px' }}>
                    <div style={{ fontSize: '1rem', color: theme === 'dark' ? '#94a3b8' : '#64748b' }}>
                      No vulnerabilities found with current filters
                    </div>
                  </td>
                </tr>
              ) : (
                filteredVulnerabilities.map((vulnerability, index) => (
                  <React.Fragment key={index}>
                    <tr style={{ borderBottom: theme === 'dark' ? '1px solid #475569' : '1px solid #e2e8f0' }}>
                      <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                        <button
                          onClick={() => toggleExpanded(index)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: theme === 'dark' ? '#94a3b8' : '#64748b',
                            cursor: 'pointer',
                            fontSize: '0.875rem'
                          }}
                        >
                          {expandedIds.has(index) ? '▼' : '▶'}
                        </button>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <SeverityBadge severity={vulnerability.severity} />
                      </td>
                      <td style={{ 
                        padding: '12px 16px', 
                        color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                        fontSize: '0.875rem',
                        fontFamily: 'monospace'
                      }}>
                        {vulnerability.file_path}
                      </td>
                      <td style={{ 
                        padding: '12px 16px', 
                        color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                        fontSize: '0.875rem',
                        fontFamily: 'monospace'
                      }}>
                        {vulnerability.line_number}
                      </td>
                      <td style={{ 
                        padding: '12px 16px', 
                        color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                        fontSize: '0.875rem'
                      }}>
                        {vulnerability.rule_id}
                      </td>
                    </tr>
                    {expandedIds.has(index) && (
                      <tr>
                        <td colSpan="5" style={{ padding: 0 }}>
                          <VulnerabilityCard
                            vulnerability={vulnerability}
                            isExpanded={true}
                            onToggle={() => toggleExpanded(index)}
                          />
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Export and Actions Section */}
      <div style={{
        backgroundColor: theme === 'dark' ? '#1e293b' : '#ffffff',
        borderRadius: '8px',
        padding: '20px',
        marginBottom: '24px',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
        border: theme === 'dark' ? 'none' : '1px solid #e5e7eb'
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div>
            <h3 style={{
              fontSize: '1rem',
              fontWeight: '600',
              marginBottom: '8px',
              color: theme === 'dark' ? '#e2e8f0' : '#1e293b'
            }}>
              Actions
            </h3>
            <p style={{
              fontSize: '0.875rem',
              color: theme === 'dark' ? '#94a3b8' : '#64748b'
            }}>
              Export results or perform additional actions
            </p>
          </div>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={expandAll}
              style={{
                padding: '8px 16px',
                backgroundColor: theme === 'dark' ? '#334155' : '#f1f5f9',
                border: 'none',
                borderRadius: '6px',
                color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                fontSize: '0.875rem',
                fontWeight: '500',
                cursor: 'pointer',
                transition: 'background-color 0.2s'
              }}
              onMouseOver={(e) => e.target.style.backgroundColor = theme === 'dark' ? '#475569' : '#e2e8f0'}
              onMouseOut={(e) => e.target.style.backgroundColor = theme === 'dark' ? '#334155' : '#f1f5f9'}
            >
              Expand All
            </button>
            <button
              onClick={collapseAll}
              style={{
                padding: '8px 16px',
                backgroundColor: theme === 'dark' ? '#334155' : '#f1f5f9',
                border: 'none',
                borderRadius: '6px',
                color: theme === 'dark' ? '#e2e8f0' : '#1e293b',
                fontSize: '0.875rem',
                fontWeight: '500',
                cursor: 'pointer',
                transition: 'background-color 0.2s'
              }}
              onMouseOver={(e) => e.target.style.backgroundColor = theme === 'dark' ? '#475569' : '#e2e8f0'}
              onMouseOut={(e) => e.target.style.backgroundColor = theme === 'dark' ? '#334155' : '#f1f5f9'}
            >
              Collapse All
            </button>
            <button
              onClick={() => {
                const dataStr = JSON.stringify(results, null, 2);
                const dataBlob = new Blob([dataStr], { type: 'application/json' });
                const url = window.URL.createObjectURL(dataBlob);
                const link = document.createElement('a');
                link.href = url;
                link.download = `security-scan-results-${new Date().toISOString().split('T')[0]}.json`;
                link.click();
              }}
              style={{
                padding: '8px 16px',
                backgroundColor: '#2563eb',
                border: 'none',
                borderRadius: '6px',
                color: '#ffffff',
                fontSize: '0.875rem',
                fontWeight: '500',
                cursor: 'pointer',
                transition: 'background-color 0.2s'
              }}
              onMouseOver={(e) => e.target.style.backgroundColor = '#1d4ed8'}
              onMouseOut={(e) => e.target.style.backgroundColor = '#2563eb'}
            >
              Export JSON
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Results;