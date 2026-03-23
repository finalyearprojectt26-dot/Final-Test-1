'use client';

/**
 * FileScan Component
 * Handles file upload and scanning for security vulnerabilities
 */

import React, { useState, useCallback, useRef } from 'react';
import { scanFiles } from '../services/api';
import { MAX_FILE_SIZE, MAX_FILES, SUPPORTED_EXTENSIONS } from '../config';

/**
 * File item component for displaying selected files
 */
const FileItem = ({ file, onRemove }) => {
  const getFileIcon = (filename) => {
    const ext = filename.split('.').pop().toLowerCase();
    const iconMap = {
      js: '📜', jsx: '⚛️', ts: '📘', tsx: '⚛️',
      py: '🐍', php: '🐘', java: '☕',
      html: '🌐', css: '🎨', json: '📋',
      sql: '🗃️', sh: '⚙️', rb: '💎',
    };
    return iconMap[ext] || '📄';
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 16px',
        backgroundColor: '#f9fafb',
        borderRadius: '8px',
        marginBottom: '8px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <span style={{ fontSize: '20px' }}>{getFileIcon(file.name)}</span>
        <div>
          <div style={{ fontWeight: '500', color: '#1f2937', fontSize: '14px' }}>
            {file.name}
          </div>
          <div style={{ fontSize: '12px', color: '#6b7280' }}>
            {formatFileSize(file.size)}
          </div>
        </div>
      </div>
      <button
        onClick={() => onRemove(file)}
        style={{
          padding: '4px 8px',
          backgroundColor: 'transparent',
          border: 'none',
          color: '#9ca3af',
          cursor: 'pointer',
          fontSize: '18px',
          lineHeight: 1,
        }}
        aria-label={`Remove ${file.name}`}
      >
        ×
      </button>
    </div>
  );
};

/**
 * Progress bar component
 */
const ProgressBar = ({ progress, status }) => (
  <div style={{ marginTop: '24px' }}>
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        marginBottom: '8px',
      }}
    >
      <span style={{ fontSize: '14px', color: '#374151', fontWeight: '500' }}>
        {status}
      </span>
      <span style={{ fontSize: '14px', color: '#6b7280' }}>{progress}%</span>
    </div>
    <div
      style={{
        width: '100%',
        height: '8px',
        backgroundColor: '#e5e7eb',
        borderRadius: '9999px',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          width: `${progress}%`,
          height: '100%',
          backgroundColor: '#2563eb',
          borderRadius: '9999px',
          transition: 'width 0.3s ease',
        }}
      />
    </div>
  </div>
);

/**
 * Main FileScan component
 */
const FileScan = ({ onScanComplete }) => {
  const [files, setFiles] = useState([]);
  const [isDragging, setIsDragging] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('');
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  // Validate file
  const validateFile = useCallback((file) => {
    // Check file size
    if (file.size > MAX_FILE_SIZE) {
      return `File "${file.name}" exceeds maximum size of ${MAX_FILE_SIZE / (1024 * 1024)}MB`;
    }

    // Check file extension
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!SUPPORTED_EXTENSIONS.includes(ext)) {
      return `File type "${ext}" is not supported`;
    }

    return null;
  }, []);

  // Handle file selection
  const handleFiles = useCallback(
    (newFiles) => {
      setError(null);
      const fileArray = Array.from(newFiles);

      // Check total file count
      if (files.length + fileArray.length > MAX_FILES) {
        setError(`Maximum ${MAX_FILES} files allowed`);
        return;
      }

      // Validate each file
      const validFiles = [];
      for (const file of fileArray) {
        const validationError = validateFile(file);
        if (validationError) {
          setError(validationError);
          return;
        }
        // Check for duplicates
        if (!files.some((f) => f.name === file.name && f.size === file.size)) {
          validFiles.push(file);
        }
      }

      setFiles((prev) => [...prev, ...validFiles]);
    },
    [files, validateFile]
  );

  // Drag and drop handlers
  const handleDragEnter = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);
      handleFiles(e.dataTransfer.files);
    },
    [handleFiles]
  );

  // File input change handler
  const handleFileInputChange = useCallback(
    (e) => {
      handleFiles(e.target.files);
      // Reset input value to allow re-selecting same files
      e.target.value = '';
    },
    [handleFiles]
  );

  // Remove file
  const handleRemoveFile = useCallback((fileToRemove) => {
    setFiles((prev) => prev.filter((f) => f !== fileToRemove));
  }, []);

  // Clear all files
  const handleClearFiles = useCallback(() => {
    setFiles([]);
    setError(null);
  }, []);

  // Start scan
  const handleScan = useCallback(async () => {
    if (files.length === 0) {
      setError('Please select files to scan');
      return;
    }

    setIsScanning(true);
    setProgress(0);
    setStatus('Uploading files...');
    setError(null);

    try {
      const results = await scanFiles(files, (uploadProgress) => {
        setProgress(uploadProgress);
        if (uploadProgress === 100) {
          setStatus('Analyzing code...');
        }
      });

      setStatus('Scan complete!');
      setProgress(100);
      console.log("SCAN API RESPONSE:", results);
      onScanComplete(results);
    } catch (err) {
      setError(err.message || 'Scan failed. Please try again.');
    } finally {
      setIsScanning(false);
    }
  }, [files, onScanComplete]);

  return (
    <div style={{ maxWidth: '600px', margin: '0 auto', padding: '24px' }}>
      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: '32px' }}>
        <h2 style={{ fontSize: '24px', fontWeight: '700', color: '#1f2937', marginBottom: '8px' }}>
          File Scan
        </h2>
        <p style={{ color: '#6b7280', fontSize: '14px' }}>
          Upload source code files to analyze for security vulnerabilities
        </p>
      </div>

      {/* Drop zone */}
      <div
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        style={{
          border: `2px dashed ${isDragging ? '#2563eb' : '#e5e7eb'}`,
          borderRadius: '12px',
          padding: '48px 24px',
          textAlign: 'center',
          backgroundColor: isDragging ? '#eff6ff' : '#f9fafb',
          cursor: 'pointer',
          transition: 'all 0.2s ease',
        }}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          onChange={handleFileInputChange}
          accept={SUPPORTED_EXTENSIONS.join(',')}
          style={{ display: 'none' }}
        />
        <svg
          style={{
            width: '48px',
            height: '48px',
            color: isDragging ? '#2563eb' : '#9ca3af',
            margin: '0 auto 16px',
          }}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
          />
        </svg>
        <p style={{ fontWeight: '500', color: '#374151', marginBottom: '4px' }}>
          {isDragging ? 'Drop files here' : 'Drag and drop files here'}
        </p>
        <p style={{ fontSize: '14px', color: '#6b7280' }}>
          or click to browse
        </p>
        <p style={{ fontSize: '12px', color: '#9ca3af', marginTop: '12px' }}>
          Supports: JavaScript, Python, PHP, Java, HTML, CSS, and more
        </p>
      </div>

      {/* Selected files list */}
      {files.length > 0 && (
        <div style={{ marginTop: '24px' }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '12px',
            }}
          >
            <span style={{ fontWeight: '600', color: '#374151' }}>
              Selected Files ({files.length})
            </span>
            <button
              onClick={handleClearFiles}
              style={{
                padding: '4px 12px',
                backgroundColor: 'transparent',
                border: 'none',
                color: '#dc2626',
                fontSize: '14px',
                cursor: 'pointer',
              }}
            >
              Clear All
            </button>
          </div>
          <div style={{ maxHeight: '240px', overflowY: 'auto' }}>
            {files.map((file, index) => (
              <FileItem
                key={`${file.name}-${index}`}
                file={file}
                onRemove={handleRemoveFile}
              />
            ))}
          </div>
        </div>
      )}

      {/* Error message */}
      {error && (
        <div
          style={{
            marginTop: '16px',
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

      {/* Progress bar */}
      {isScanning && <ProgressBar progress={progress} status={status} />}

      {/* Scan button */}
      <button
        onClick={handleScan}
        disabled={isScanning || files.length === 0}
        style={{
          width: '100%',
          marginTop: '24px',
          padding: '14px 24px',
          backgroundColor: isScanning || files.length === 0 ? '#9ca3af' : '#2563eb',
          color: '#ffffff',
          border: 'none',
          borderRadius: '8px',
          fontSize: '16px',
          fontWeight: '600',
          cursor: isScanning || files.length === 0 ? 'not-allowed' : 'pointer',
          transition: 'background-color 0.2s ease',
        }}
      >
        {isScanning ? 'Scanning...' : 'Start Scan'}
      </button>
    </div>
  );
};

export default FileScan;
