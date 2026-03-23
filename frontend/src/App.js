'use client';

/**
 * Secure Code Analyzer - Main Application Component
 * 
 * A React-based frontend for the SAST (Static Application Security Testing) tool.
 * Provides two scanning modes: File Upload and URL Scan.
 */

import React, { useState, useCallback } from 'react';
import FileScan from './components/FileScan';
import UrlScan from './components/UrlScan';
import Results from './components/Results';

/**
 * Navigation tab component
 */
const Tab = ({ label, icon, isActive, onClick }) => (
  <button
    onClick={onClick}
    style={{
      padding: '12px 24px',
      backgroundColor: isActive ? '#ffffff' : 'transparent',
      border: 'none',
      borderBottom: isActive ? '2px solid #2563eb' : '2px solid transparent',
      color: isActive ? '#2563eb' : '#6b7280',
      fontWeight: isActive ? '600' : '500',
      fontSize: '14px',
      cursor: 'pointer',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      transition: 'all 0.2s ease',
    }}
  >
    {icon}
    {label}
  </button>
);

/**
 * Header component
 */
const Header = () => (
  <header
    style={{
      backgroundColor: '#1f2937',
      color: '#ffffff',
      padding: '16px 24px',
    }}
  >
    <div
      style={{
        maxWidth: '1200px',
        margin: '0 auto',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <svg
          style={{ width: '32px', height: '32px', color: '#60a5fa' }}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
          />
        </svg>
        <div>
          <h1 style={{ fontSize: '20px', fontWeight: '700', margin: 0 }}>
            Secure Code Analyzer
          </h1>
          <p style={{ fontSize: '12px', color: '#9ca3af', margin: 0 }}>
            Static Application Security Testing
          </p>
        </div>
      </div>
      <a
        href="https://github.com"
        target="_blank"
        rel="noopener noreferrer"
        style={{
          padding: '8px 16px',
          backgroundColor: '#374151',
          color: '#ffffff',
          borderRadius: '6px',
          textDecoration: 'none',
          fontSize: '14px',
          fontWeight: '500',
        }}
      >
        Documentation
      </a>
    </div>
  </header>
);

/**
 * Footer component
 */
const Footer = () => (
  <footer
    style={{
      backgroundColor: '#f9fafb',
      borderTop: '1px solid #e5e7eb',
      padding: '24px',
      textAlign: 'center',
    }}
  >
    <p style={{ fontSize: '14px', color: '#6b7280', margin: 0 }}>
      Secure Code Analyzer - SAST Tool for JavaScript, Python, PHP, and Java
    </p>
    <p style={{ fontSize: '12px', color: '#9ca3af', marginTop: '8px' }}>
      Analyzes source code statically without executing it.
    </p>
  </footer>
);

/**
 * Main App component
 */

/**
 * Normalize backend scan results to frontend-friendly format
 */
const normalizeResults = (raw) => {
  if (!raw) return null;

  return {
    ...raw,


    vulnerabilities: (raw.findings || []).map((f) => ({
      rule_id: f.rule_id,
      severity: f.severity?.toUpperCase(),
      message: f.description,
      file: f.file_path,
      line: f.line_number,
      column: f.column_number,
      code_snippet: f.code_snippet?.code || f.code_snippet,
      recommendation: f.remediation,
      cwe_id: f.cwe_id,
      owasp_category: f.owasp_category,
    })),

    metadata: {
      scan_duration: raw.scan_time,
      files_scanned: raw.files_scanned,
      rules_applied: raw.findings?.length,
      source_url: raw.source_url,
    },
  };
};

function App() {
  const [activeTab, setActiveTab] = useState('file');
  const [results, setResults] = useState(null);

  // Handle scan completion
  const handleScanComplete = useCallback((scanResults) => {
  console.log("RAW BACKEND RESPONSE:", scanResults);
  setResults(scanResults);
}, []);


  // Clear results and start new scan
  const handleClearResults = useCallback(() => {
    setResults(null);
  }, []);

  // File icon SVG
  const fileIcon = (
    <svg
      style={{ width: '16px', height: '16px' }}
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
      />
    </svg>
  );

  // URL icon SVG
  const urlIcon = (
    <svg
      style={{ width: '16px', height: '16px' }}
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"
      />
    </svg>
  );

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: '#f3f4f6',
      }}
    >
      <Header />

      <main style={{ flex: 1 }}>
        {/* Show results if available, otherwise show scan interface */}
        {results ? (
  <Results
    results={normalizeResults(results)}
    onClear={handleClearResults}
  />
) : (

          <>
            {/* Tab navigation */}
            <div
              style={{
                backgroundColor: '#ffffff',
                borderBottom: '1px solid #e5e7eb',
              }}
            >
              <div
                style={{
                  maxWidth: '600px',
                  margin: '0 auto',
                  display: 'flex',
                  justifyContent: 'center',
                }}
              >
                <Tab
                  label="File Scan"
                  icon={fileIcon}
                  isActive={activeTab === 'file'}
                  onClick={() => setActiveTab('file')}
                />
                <Tab
                  label="URL Scan"
                  icon={urlIcon}
                  isActive={activeTab === 'url'}
                  onClick={() => setActiveTab('url')}
                />
              </div>
            </div>

            {/* Scan content */}
            <div style={{ paddingTop: '32px', paddingBottom: '48px' }}>
              {activeTab === 'file' ? (
                <FileScan onScanComplete={handleScanComplete} />
              ) : (
                <UrlScan onScanComplete={handleScanComplete} />
              )}
            </div>
          </>
        )}
      </main>

      <Footer />
    </div>
  );
}

export default App;
