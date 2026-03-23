/**
 * API Service Module
 * Handles all communication with the Flask backend API
 */

import { API_BASE_URL, ENDPOINTS, REQUEST_TIMEOUT } from '../config';

/**
 * Custom error class for API errors
 */
class ApiError extends Error {
  constructor(message, status, data = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

/**
 * Creates an AbortController with timeout
 * @param {number} timeout - Timeout in milliseconds
 * @returns {AbortController}
 */
const createTimeoutController = (timeout = REQUEST_TIMEOUT) => {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), timeout);
  return controller;
};

/**
 * Generic fetch wrapper with error handling
 * @param {string} url - The URL to fetch
 * @param {object} options - Fetch options
 * @returns {Promise<object>} - Response data
 */
const fetchWithErrorHandling = async (url, options = {}) => {
  const controller = createTimeoutController();
  
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new ApiError(
        data.error || `HTTP error ${response.status}`,
        response.status,
        data
      );
    }
    
    return data;
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new ApiError('Request timed out', 408);
    }
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(
      error.message || 'Network error occurred',
      0
    );
  }
};

/**
 * Scan uploaded files for security vulnerabilities
 * @param {FileList|File[]} files - Files to scan
 * @param {function} onProgress - Progress callback (optional)
 * @returns {Promise<object>} - Scan results
 */
export const scanFiles = async (files, onProgress = null) => {
  const formData = new FormData();
  
  // Append all files to the form data
  Array.from(files).forEach((file) => {
    formData.append('files', file);
  });
  
  // Use XMLHttpRequest for progress tracking if callback provided
  if (onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      
      xhr.upload.addEventListener('progress', (event) => {
        if (event.lengthComputable) {
          const percentComplete = Math.round((event.loaded / event.total) * 100);
          onProgress(percentComplete);
        }
      });
      
      xhr.addEventListener('load', () => {
        try {
          const data = JSON.parse(xhr.responseText);
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve(data);
          } else {
            reject(new ApiError(data.error || 'Scan failed', xhr.status, data));
          }
        } catch (e) {
          reject(new ApiError('Invalid response from server', xhr.status));
        }
      });
      
      xhr.addEventListener('error', () => {
        reject(new ApiError('Network error occurred', 0));
      });
      
      xhr.addEventListener('timeout', () => {
        reject(new ApiError('Request timed out', 408));
      });
      
      xhr.timeout = REQUEST_TIMEOUT;
      xhr.open('POST', `${API_BASE_URL}${ENDPOINTS.SCAN_FILE}`);
      xhr.send(formData);
    });
  }
  
  // Standard fetch for simple requests
  return fetchWithErrorHandling(`${API_BASE_URL}${ENDPOINTS.SCAN_FILE}`, {
    method: 'POST',
    body: formData,
  });
};

/**
 * Scan a URL for security vulnerabilities
 * @param {string} url - The URL to scan
 * @returns {Promise<object>} - Scan results
 */
export const scanUrl = async (url) => {
  return fetchWithErrorHandling(`${API_BASE_URL}${ENDPOINTS.SCAN_URL}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url }),
  });
};

/**
 * Check API health status
 * @returns {Promise<object>} - Health status
 */
export const checkHealth = async () => {
  return fetchWithErrorHandling(`${API_BASE_URL}${ENDPOINTS.HEALTH}`, {
    method: 'GET',
  });
};

/**
 * Get list of supported file types
 * @returns {Promise<object>} - Supported file types
 */
export const getSupportedTypes = async () => {
  return fetchWithErrorHandling(`${API_BASE_URL}${ENDPOINTS.SUPPORTED_TYPES}`, {
    method: 'GET',
  });
};

export { ApiError };
