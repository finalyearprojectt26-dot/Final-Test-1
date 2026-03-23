/**
 * Frontend Configuration
 * Contains all configurable settings for the React application
 */

// API Configuration
export const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

// API Endpoints
export const ENDPOINTS = {
  SCAN_FILE: '/scan-file',
  SCAN_URL: '/scan-url',
  HEALTH: '/health',
  SUPPORTED_TYPES: '/supported-types',
};

// Request Configuration
export const REQUEST_TIMEOUT = 120000; // 2 minutes for large scans

// File Upload Configuration
export const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
export const MAX_FILES = 50;
export const SUPPORTED_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx',
  '.py', '.pyw',
  '.php', '.phtml',
  '.java',
  '.html', '.htm',
  '.css', '.scss', '.sass',
  '.json', '.xml', '.yaml', '.yml',
  '.sql',
  '.sh', '.bash',
  '.rb', '.erb',
  '.go',
  '.c', '.cpp', '.h', '.hpp',
  '.cs',
  '.swift',
  '.kt', '.kts',
];

// Severity Configuration
export const SEVERITY_LEVELS = {
  CRITICAL: {
    label: 'Critical',
    color: '#dc2626',
    bgColor: '#fef2f2',
    priority: 1,
  },
  HIGH: {
    label: 'High',
    color: '#ea580c',
    bgColor: '#fff7ed',
    priority: 2,
  },
  MEDIUM: {
    label: 'Medium',
    color: '#ca8a04',
    bgColor: '#fefce8',
    priority: 3,
  },
  LOW: {
    label: 'Low',
    color: '#16a34a',
    bgColor: '#f0fdf4',
    priority: 4,
  },
  INFO: {
    label: 'Info',
    color: '#2563eb',
    bgColor: '#eff6ff',
    priority: 5,
  },
};

// UI Configuration
export const ANIMATION_DURATION = 300;
export const DEBOUNCE_DELAY = 300;

// Validation Patterns
export const URL_PATTERN = /^https?:\/\/[^\s/$.?#].[^\s]*$/i;

// Default scan options
export const DEFAULT_SCAN_OPTIONS = {
  includeInfoLevel: false,
  generateHtmlReport: true,
  maxDepth: 5,
};
