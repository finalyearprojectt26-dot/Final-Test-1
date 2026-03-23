'use client';

/**
 * UrlScan Component
 * Handles URL input and scanning for security vulnerabilities in client-side code
 */

import React, { useState, useCallback } from 'react';
import { scanUrl } from '../services/api';
import { URL_PATTERN } from '../config';

/**
 * Scan progress steps
 */
const SCAN_STEPS = [
  { id: 'fetch', label: 'Fetching page content', icon: '🌐' },
  { id: 'extract', label: 'Extracting JavaScript', icon: '📜' },
  { id: 'analyze', label: 'Analyzing code', icon: '🔍' },
  { id: 'report', label: 'Generating report', icon: '📊' },
];

/**
 * Progress step component
 */
const ProgressStep = ({ step, status }) => {
  const getStatusIcon = () => {
    switch (status) {
      case 'complete':
        return '✓';
      case 'active':
        return '...';
      case 'pending':
      default:
        return step.icon;
    }
  };

  const getStatusColor = () => {
    switch (status) {
      case 'complete':
        return '#16a34a';
      case 'active':
        return '#2563eb';
      case 'pending':
      default:
        return '#9ca3af';
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '12px 16px',
        backgroundColor: status === 'active' ? '#eff6ff' : 'transparent',
        borderRadius: '8px',
        transition: 'all 0.3s ease',
      }}
    >
      <span
        style={{
          width: '32px',
          height: '32px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: '50%',
          backgroundColor: status === 'complete' ? '#dcfce7' : status === 'active' ? '#dbeafe' : '#f3f4f6',
          color: getStatusColor(),
          fontSize: '14px',
          fontWeight: '600',
        }}
      >
        {getStatusIcon()}
      </span>
      <span
        style={{
          color: status === 'pending' ? '#9ca3af' : '#374151',
          fontWeight: status === 'active' ? '500' : '400',
        }}
      >
        {step.label}
      </span>
    </div>
  );
};

/**
 * URL input validation hook
 */
const useUrlValidation = (url) => {
  const isValid = URL_PATTERN.test(url);
  const isEmpty = url.trim() === '';
  
  let error = null;
  if (!isEmpty && !isValid) {
    error = 'Please enter a valid URL (e.g., https://example.com)';
  }
  
  return { isValid, isEmpty, error };
};

/**
 * Main UrlScan component
 */
const UrlScan = ({ onScanComplete }) => {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [currentStep, setCurrentStep] = useState(-1);
  const [error, setError] = useState(null);
  const [touched, setTouched] = useState(false);

  const { isValid, isEmpty, error: validationError } = useUrlValidation(url);

  // Handle URL input change
  const handleUrlChange = useCallback((e) => {
    setUrl(e.target.value);
    setError(null);
  }, []);

  // Handle input blur
  const handleBlur = useCallback(() => {
    setTouched(true);
  }, []);

  // Simulate progress steps
  const simulateProgress = useCallback(() => {
    return new Promise((resolve) => {
      let step = 0;
      const interval = setInterval(() => {
        setCurrentStep(step);
        step++;
        if (step >= SCAN_STEPS.length) {
          clearInterval(interval);
          resolve();
        }
      }, 1500);
    });
  }, []);

  // Start scan
  const handleScan = useCallback(async () => {
    if (!isValid || isEmpty) {
      setTouched(true);
      return;
    }

    setIsScanning(true);
    setCurrentStep(0);
    setError(null);

    try {
      // Start progress simulation
      const progressPromise = simulateProgress();
      
      // Start actual scan
      const results = await scanUrl(url);
      
      // Wait for progress animation to catch up
      await progressPromise;
      
      // Complete
      setCurrentStep(SCAN_STEPS.length);
      setTimeout(() => {
        onScanComplete(results);
      }, 500);
    } catch (err) {
      setError(err.message || 'Failed to scan URL. Please check the URL and try again.');
      setCurrentStep(-1);
    } finally {
      setIsScanning(false);
    }
  }, [url, isValid, isEmpty, simulateProgress, onScanComplete]);

  // Handle form submission
  const handleSubmit = useCallback(
    (e) => {
      e.preventDefault();
      handleScan();
    },
    [handleScan]
  );

  // Get step status
  const getStepStatus = (index) => {
    if (index < currentStep) return 'complete';
    if (index === currentStep) return 'active';
    return 'pending';
  };

  return (
    <div style={{ maxWidth: '600px', margin: '0 auto', padding: '24px' }}>
      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: '32px' }}>
        <h2 style={{ fontSize: '24px', fontWeight: '700', color: '#1f2937', marginBottom: '8px' }}>
          URL Scan
        </h2>
        <p style={{ color: '#6b7280', fontSize: '14px' }}>
          Analyze client-side JavaScript from any website for security vulnerabilities
        </p>
      </div>

      {/* URL input form */}
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: '16px' }}>
          <label
            htmlFor="url-input"
            style={{
              display: 'block',
              fontWeight: '500',
              color: '#374151',
              marginBottom: '8px',
              fontSize: '14px',
            }}
          >
            Website URL
          </label>
          <div style={{ position: 'relative' }}>
            <input
              id="url-input"
              type="text"
              value={url}
              onChange={handleUrlChange}
              onBlur={handleBlur}
              placeholder="https://example.com"
              disabled={isScanning}
              style={{
                width: '100%',
                padding: '14px 16px',
                paddingLeft: '44px',
                border: `2px solid ${
                  touched && validationError ? '#dc2626' : isValid && !isEmpty ? '#16a34a' : '#e5e7eb'
                }`,
                borderRadius: '8px',
                fontSize: '16px',
                outline: 'none',
                transition: 'border-color 0.2s ease',
                backgroundColor: isScanning ? '#f9fafb' : '#ffffff',
              }}
            />
            <svg
              style={{
                position: 'absolute',
                left: '14px',
                top: '50%',
                transform: 'translateY(-50%)',
                width: '20px',
                height: '20px',
                color: '#9ca3af',
              }}
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
          </div>
          {touched && validationError && (
            <p style={{ marginTop: '8px', fontSize: '14px', color: '#dc2626' }}>
              {validationError}
            </p>
          )}
        </div>

        {/* Info box */}
        <div
          style={{
            padding: '16px',
            backgroundColor: '#f0f9ff',
            border: '1px solid #bae6fd',
            borderRadius: '8px',
            marginBottom: '24px',
          }}
        >
          <div style={{ display: 'flex', gap: '12px' }}>
            <svg
              style={{ width: '20px', height: '20px', color: '#0284c7', flexShrink: 0, marginTop: '2px' }}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <div style={{ fontSize: '14px', color: '#0369a1' }}>
              <p style={{ fontWeight: '500', marginBottom: '4px' }}>What gets scanned:</p>
              <ul style={{ margin: 0, paddingLeft: '16px', color: '#0c4a6e' }}>
                <li>Inline JavaScript code</li>
                <li>External JavaScript files</li>
                <li>JavaScript within HTML attributes</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Error message */}
        {error && (
          <div
            style={{
              marginBottom: '16px',
              padding: '12px 16px',
              backgroundColor: '#fef2f2',
              border: '1px solid #fee2e2',
              borderRadius: '8px',
              color: '#dc2626',
              fontSize: '14px',
            }}
          >
            {error}
          </div>
        )}

        {/* Progress steps */}
        {isScanning && (
          <div
            style={{
              marginBottom: '24px',
              padding: '16px',
              backgroundColor: '#f9fafb',
              borderRadius: '12px',
              border: '1px solid #e5e7eb',
            }}
          >
            <h4
              style={{
                fontSize: '14px',
                fontWeight: '600',
                color: '#374151',
                marginBottom: '16px',
              }}
            >
              Scan Progress
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {SCAN_STEPS.map((step, index) => (
                <ProgressStep
                  key={step.id}
                  step={step}
                  status={getStepStatus(index)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Scan button */}
        <button
          type="submit"
          disabled={isScanning || isEmpty}
          style={{
            width: '100%',
            padding: '14px 24px',
            backgroundColor: isScanning || isEmpty ? '#9ca3af' : '#2563eb',
            color: '#ffffff',
            border: 'none',
            borderRadius: '8px',
            fontSize: '16px',
            fontWeight: '600',
            cursor: isScanning || isEmpty ? 'not-allowed' : 'pointer',
            transition: 'background-color 0.2s ease',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
          }}
        >
          {isScanning ? (
            <>
              <svg
                style={{
                  width: '20px',
                  height: '20px',
                  animation: 'spin 1s linear infinite',
                }}
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle
                  style={{ opacity: 0.25 }}
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                />
                <path
                  style={{ opacity: 0.75 }}
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                />
              </svg>
              Scanning...
            </>
          ) : (
            <>
              <svg
                style={{ width: '20px', height: '20px' }}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                />
              </svg>
              Start Scan
            </>
          )}
        </button>
      </form>

      {/* CSS for spinner animation */}
      <style>
        {`
          @keyframes spin {
            from {
              transform: rotate(0deg);
            }
            to {
              transform: rotate(360deg);
            }
          }
        `}
      </style>
    </div>
  );
};

export default UrlScan;
