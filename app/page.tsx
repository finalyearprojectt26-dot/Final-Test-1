"use client";

/**
 * Secure Code Analyzer - Main Application Page
 *
 * A Next.js page that renders the SAST (Static Application Security Testing) tool.
 * Provides two scanning modes: File Upload and URL Scan.
 */

import React, { useState, useCallback } from "react";
import Results from "../frontend/src/components/Results.jsx";

// Configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";

const ENDPOINTS = {
  SCAN_FILE: "/scan-file",
  SCAN_URL: "/scan-url",
};

const REQUEST_TIMEOUT = 120000;

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_FILES = 50;
const SUPPORTED_EXTENSIONS = [
  ".js", ".jsx", ".ts", ".tsx",
  ".py", ".pyw",
  ".php", ".phtml",
  ".java",
  ".html", ".htm",
  ".css", ".scss", ".sass",
  ".json", ".xml", ".yaml", ".yml",
  ".sql",
  ".sh", ".bash",
  ".rb", ".erb",
  ".go",
  ".c", ".cpp", ".h", ".hpp",
  ".cs",
  ".swift",
  ".kt", ".kts",
];

const SEVERITY_LEVELS: Record<string, { label: string; color: string; bgColor: string; priority: number }> = {
  CRITICAL: { label: "Critical", color: "#dc2626", bgColor: "#fef2f2", priority: 1 },
  HIGH: { label: "High", color: "#ea580c", bgColor: "#fff7ed", priority: 2 },
  MEDIUM: { label: "Medium", color: "#ca8a04", bgColor: "#fefce8", priority: 3 },
  LOW: { label: "Low", color: "#16a34a", bgColor: "#f0fdf4", priority: 4 },
  INFO: { label: "Info", color: "#2563eb", bgColor: "#eff6ff", priority: 5 },
};

const URL_PATTERN = /^https?:\/\/[^\s/$.?#].[^\s]*$/i;

// Types
interface Vulnerability {
  rule_id: string;
  rule_name: string;
  description: string;
  severity: string;
  file_path: string;
  line_number: number;
  column_number: number;
  code_snippet?: any;
  remediation?: string;
  cwe_id?: string;
  owasp_category?: string;
}

interface ScanMetadata {
  scan_duration?: number;
  files_scanned?: number;
  rules_applied?: number;
  source_url?: string;
}

interface ScanResults {
  findings: Vulnerability[];
  metadata?: ScanMetadata;
}

// API Functions
class ApiError extends Error {
  status: number;
  data: unknown;
  constructor(message: string, status: number, data: unknown = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

const fetchWithErrorHandling = async (url: string, options: RequestInit = {}) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
  
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timeoutId);
    const data = await response.json();
    
    if (!response.ok) {
      throw new ApiError(data.error || `HTTP error ${response.status}`, response.status, data);
    }
    return data;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === "AbortError") {
      throw new ApiError("Request timed out", 408);
    }
    if (error instanceof ApiError) throw error;
    throw new ApiError(error instanceof Error ? error.message : "Network error", 0);
  }
};

const scanFiles = async (files: File[], onProgress?: (progress: number) => void): Promise<ScanResults> => {
  const formData = new FormData();
  files.forEach((file) => formData.append("files", file));

  if (onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.upload.addEventListener("progress", (event) => {
        if (event.lengthComputable) {
          onProgress(Math.round((event.loaded / event.total) * 100));
        }
      });
      xhr.addEventListener("load", () => {
        try {
          const data = JSON.parse(xhr.responseText);
          if (xhr.status >= 200 && xhr.status < 300) resolve(data);
          else reject(new ApiError(data.error || "Scan failed", xhr.status, data));
        } catch {
          reject(new ApiError("Invalid response", xhr.status));
        }
      });
      xhr.addEventListener("error", () => reject(new ApiError("Network error", 0)));
      xhr.addEventListener("timeout", () => reject(new ApiError("Request timed out", 408)));
      xhr.timeout = REQUEST_TIMEOUT;
      xhr.open("POST", `${API_BASE_URL}${ENDPOINTS.SCAN_FILE}`);
      xhr.send(formData);
    });
  }
  return fetchWithErrorHandling(`${API_BASE_URL}${ENDPOINTS.SCAN_FILE}`, { method: "POST", body: formData });
};

const scanUrl = async (url: string): Promise<ScanResults> => {
  return fetchWithErrorHandling(`${API_BASE_URL}${ENDPOINTS.SCAN_URL}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
};

// Components
const SeverityBadge = ({ severity }: { severity: string }) => {
  const config = SEVERITY_LEVELS[severity] || SEVERITY_LEVELS.INFO;
  return (
    <span
      className="px-3 py-1 rounded-full text-xs font-semibold uppercase tracking-wide"
      style={{ backgroundColor: config.bgColor, color: config.color }}
    >
      {config.label}
    </span>
  );
};

const StatCard = ({ label, value, color }: { label: string; value: number; color?: string }) => (
  <div className="bg-card border border-border rounded-lg p-4 text-center min-w-[100px]">
    <div className="text-2xl font-bold mb-1" style={{ color: color || "inherit" }}>{value}</div>
    <div className="text-xs text-muted-foreground uppercase tracking-wide">{label}</div>
  </div>
);

const VulnerabilityCard = ({ vulnerability, isExpanded, onToggle }: { vulnerability: Vulnerability; isExpanded: boolean; onToggle: () => void }) => {
  const { rule_id, rule_name, description, severity, file_path, line_number, column_number, code_snippet, remediation, cwe_id, owasp_category } = vulnerability;

  return (
    <div className="bg-card border border-border rounded-lg mb-3 overflow-hidden">
      <button onClick={onToggle} className="w-full p-4 flex items-center justify-between text-left hover:bg-muted/50 transition-colors">
        <div className="flex items-center gap-3 flex-1">
          <SeverityBadge severity={severity} />
          <div className="flex-1">
            <div className="font-semibold text-foreground mb-1">{rule_name || rule_id}</div>
            <div className="text-sm text-muted-foreground">{file_path}:{line_number}:{column_number}</div>
          </div>
        </div>
        <svg className={`w-5 h-5 text-muted-foreground transition-transform ${isExpanded ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {isExpanded && (
        <div className="px-4 pb-4 border-t border-border">
          <div className="mt-4">
            <h4 className="text-xs font-semibold text-muted-foreground mb-2 uppercase">Description</h4>
            <p className="text-foreground leading-relaxed">{description}</p>
          </div>
          {code_snippet && (
            <div className="mt-4">
              <h4 className="text-xs font-semibold text-muted-foreground mb-2 uppercase">Code Snippet</h4>
              <pre className="bg-primary text-primary-foreground p-3 rounded-md text-sm font-mono overflow-auto whitespace-pre-wrap break-words">
                {typeof code_snippet === 'object' && code_snippet.lines
                  ? code_snippet.lines.map((line: any) => `${line.line_number}: ${line.content}`).join('\n')
                  : typeof code_snippet === 'string'
                  ? code_snippet
                  : JSON.stringify(code_snippet, null, 2)
                }
              </pre>
            </div>
          )}
          {remediation && (
            <div className="mt-4">
              <h4 className="text-xs font-semibold text-muted-foreground mb-2 uppercase">Recommendation</h4>
              <p className="text-foreground leading-relaxed">{remediation}</p>
            </div>
          )}
          <div className="mt-4 flex gap-4 flex-wrap">
            {cwe_id && (
              <div>
                <span className="text-xs text-muted-foreground">CWE: </span>
                <a href={`https://cwe.mitre.org/data/definitions/${cwe_id.replace("CWE-", "")}.html`} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline">{cwe_id}</a>
              </div>
            )}
            {owasp_category && (
              <div>
                <span className="text-xs text-muted-foreground">OWASP: </span>
                <span className="text-xs text-foreground">{owasp_category}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

const FilterButton = ({ label, isActive, onClick, count }: { label: string; isActive: boolean; onClick: () => void; count?: number }) => (
  <button
    onClick={onClick}
    className={`px-4 py-2 rounded-md font-medium text-sm flex items-center gap-2 transition-colors ${
      isActive ? "border-2 border-primary bg-primary/10 text-primary" : "border border-border bg-card text-foreground hover:bg-muted"
    }`}
  >
    {label}
    {count !== undefined && (
      <span className={`px-2 py-0.5 rounded-full text-xs ${isActive ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"}`}>{count}</span>
    )}
  </button>
);



const FileItem = ({ file, onRemove }: { file: File; onRemove: (file: File) => void }) => {
  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="flex items-center justify-between p-3 bg-muted rounded-lg mb-2">
      <div className="flex items-center gap-3">
        <span className="text-xl">📄</span>
        <div>
          <div className="font-medium text-foreground text-sm">{file.name}</div>
          <div className="text-xs text-muted-foreground">{formatFileSize(file.size)}</div>
        </div>
      </div>
      <button onClick={() => onRemove(file)} className="text-muted-foreground hover:text-destructive text-lg leading-none" aria-label={`Remove ${file.name}`}>×</button>
    </div>
  );
};

const ProgressBar = ({ progress, status }: { progress: number; status: string }) => (
  <div className="mt-6">
    <div className="flex justify-between mb-2">
      <span className="text-sm font-medium text-foreground">{status}</span>
      <span className="text-sm text-muted-foreground">{progress}%</span>
    </div>
    <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
      <div className="h-full bg-primary rounded-full transition-all duration-300" style={{ width: `${progress}%` }} />
    </div>
  </div>
);

const FileScan = ({ onScanComplete }: { onScanComplete: (results: ScanResults) => void }) => {
  const [files, setFiles] = useState<File[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState("");
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const validateFile = useCallback((file: File) => {
    if (file.size > MAX_FILE_SIZE) return `File "${file.name}" exceeds maximum size`;
    const ext = "." + file.name.split(".").pop()?.toLowerCase();
    if (!SUPPORTED_EXTENSIONS.includes(ext)) return `File type "${ext}" is not supported`;
    return null;
  }, []);

  const handleFiles = useCallback((newFiles: FileList | File[]) => {
    setError(null);
    const fileArray = Array.from(newFiles);
    if (files.length + fileArray.length > MAX_FILES) { setError(`Maximum ${MAX_FILES} files allowed`); return; }
    const validFiles: File[] = [];
    for (const file of fileArray) {
      const validationError = validateFile(file);
      if (validationError) { setError(validationError); return; }
      if (!files.some((f) => f.name === file.name && f.size === file.size)) validFiles.push(file);
    }
    setFiles((prev) => [...prev, ...validFiles]);
  }, [files, validateFile]);

  const handleDragEnter = useCallback((e: React.DragEvent) => { e.preventDefault(); e.stopPropagation(); setIsDragging(true); }, []);
  const handleDragLeave = useCallback((e: React.DragEvent) => { e.preventDefault(); e.stopPropagation(); setIsDragging(false); }, []);
  const handleDragOver = useCallback((e: React.DragEvent) => { e.preventDefault(); e.stopPropagation(); }, []);
  const handleDrop = useCallback((e: React.DragEvent) => { e.preventDefault(); e.stopPropagation(); setIsDragging(false); handleFiles(e.dataTransfer.files); }, [handleFiles]);
  const handleFileInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => { if (e.target.files) handleFiles(e.target.files); e.target.value = ""; }, [handleFiles]);

  const handleScan = useCallback(async () => {
    if (files.length === 0) { setError("Please select files to scan"); return; }
    setIsScanning(true); setProgress(0); setStatus("Uploading files..."); setError(null);
    try {
      const results = await scanFiles(files, (uploadProgress) => { setProgress(uploadProgress); if (uploadProgress === 100) setStatus("Analyzing code..."); });
      setStatus("Scan complete!"); setProgress(100); onScanComplete(results);
    } catch (err) { setError(err instanceof Error ? err.message : "Scan failed"); }
    finally { setIsScanning(false); }
  }, [files, onScanComplete]);

  return (
    <div className="max-w-[600px] mx-auto p-6">
      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold text-foreground mb-2">File Scan</h2>
        <p className="text-muted-foreground text-sm">Upload source code files to analyze for security vulnerabilities</p>
      </div>
      <div
        onDragEnter={handleDragEnter} onDragLeave={handleDragLeave} onDragOver={handleDragOver} onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-colors ${isDragging ? "border-primary bg-primary/5" : "border-border bg-muted/50 hover:border-primary/50"}`}
      >
        <input ref={fileInputRef} type="file" multiple onChange={handleFileInputChange} accept={SUPPORTED_EXTENSIONS.join(",")} className="hidden" />
        <svg className={`w-12 h-12 mx-auto mb-4 ${isDragging ? "text-primary" : "text-muted-foreground"}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" /></svg>
        <p className="font-medium text-foreground mb-1">{isDragging ? "Drop files here" : "Drag and drop files here"}</p>
        <p className="text-sm text-muted-foreground">or click to browse</p>
        <p className="text-xs text-muted-foreground mt-3">Supports: JavaScript, Python, PHP, Java, HTML, CSS, and more</p>
      </div>
      {files.length > 0 && (
        <div className="mt-6">
          <div className="flex justify-between items-center mb-3">
            <span className="font-semibold text-foreground">Selected Files ({files.length})</span>
            <button onClick={() => setFiles([])} className="text-sm text-destructive hover:underline">Clear All</button>
          </div>
          <div className="max-h-60 overflow-y-auto">{files.map((file, index) => <FileItem key={`${file.name}-${index}`} file={file} onRemove={(f) => setFiles((prev) => prev.filter((x) => x !== f))} />)}</div>
        </div>
      )}
      {error && <div className="mt-4 p-3 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive text-sm">{error}</div>}
      {isScanning && <ProgressBar progress={progress} status={status} />}
      <button onClick={handleScan} disabled={isScanning || files.length === 0} className={`w-full mt-6 py-3.5 px-6 rounded-lg text-base font-semibold transition-colors ${isScanning || files.length === 0 ? "bg-muted text-muted-foreground cursor-not-allowed" : "bg-primary text-primary-foreground hover:bg-primary/90"}`}>
        {isScanning ? "Scanning..." : "Start Scan"}
      </button>
    </div>
  );
};

const SCAN_STEPS = [
  { id: "fetch", label: "Fetching page content" },
  { id: "extract", label: "Extracting JavaScript" },
  { id: "analyze", label: "Analyzing code" },
  { id: "report", label: "Generating report" },
];

const ProgressStep = ({ step, status }: { step: { id: string; label: string }; status: "complete" | "active" | "pending" }) => (
  <div className={`flex items-center gap-3 p-3 rounded-lg transition-colors ${status === "active" ? "bg-primary/10" : ""}`}>
    <span className={`w-8 h-8 flex items-center justify-center rounded-full text-sm font-semibold ${status === "complete" ? "bg-green-100 text-green-600" : status === "active" ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"}`}>
      {status === "complete" ? "✓" : status === "active" ? "..." : "○"}
    </span>
    <span className={status === "pending" ? "text-muted-foreground" : "text-foreground"}>{step.label}</span>
  </div>
);

const UrlScan = ({ onScanComplete }: { onScanComplete: (results: ScanResults) => void }) => {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [currentStep, setCurrentStep] = useState(-1);
  const [error, setError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);

  const isValid = URL_PATTERN.test(url);
  const isEmpty = url.trim() === "";
  const validationError = !isEmpty && !isValid ? "Please enter a valid URL (e.g., https://example.com)" : null;

  const handleScan = useCallback(async () => {
    if (!isValid || isEmpty) { setTouched(true); return; }
    setIsScanning(true); setCurrentStep(0); setError(null);
    try {
      const progressPromise = new Promise<void>((resolve) => {
        let step = 0;
        const interval = setInterval(() => { setCurrentStep(step); step++; if (step >= SCAN_STEPS.length) { clearInterval(interval); resolve(); } }, 1500);
      });
      const results = await scanUrl(url);
      await progressPromise;
      setCurrentStep(SCAN_STEPS.length);
      setTimeout(() => onScanComplete(results), 500);
    } catch (err) { setError(err instanceof Error ? err.message : "Failed to scan URL"); setCurrentStep(-1); }
    finally { setIsScanning(false); }
  }, [url, isValid, isEmpty, onScanComplete]);

  const getStepStatus = (index: number): "complete" | "active" | "pending" => {
    if (index < currentStep) return "complete";
    if (index === currentStep) return "active";
    return "pending";
  };

  return (
    <div className="max-w-[600px] mx-auto p-6">
      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold text-foreground mb-2">URL Scan</h2>
        <p className="text-muted-foreground text-sm">Analyze client-side JavaScript from any website for security vulnerabilities</p>
      </div>
      <form onSubmit={(e) => { e.preventDefault(); handleScan(); }}>
        <div className="mb-4">
          <label htmlFor="url-input" className="block font-medium text-foreground mb-2 text-sm">Website URL</label>
          <div className="relative">
            <input id="url-input" type="text" value={url} onChange={(e) => { setUrl(e.target.value); setError(null); }} onBlur={() => setTouched(true)} placeholder="https://example.com" disabled={isScanning}
              className={`w-full py-3.5 px-4 pl-11 border-2 rounded-lg text-base outline-none transition-colors ${touched && validationError ? "border-destructive" : isValid && !isEmpty ? "border-green-500" : "border-border"} ${isScanning ? "bg-muted" : "bg-background"}`}
            />
            <svg className="absolute left-3.5 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>
          </div>
          {touched && validationError && <p className="mt-2 text-sm text-destructive">{validationError}</p>}
        </div>
        <div className="p-4 bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-900 rounded-lg mb-6">
          <div className="flex gap-3">
            <svg className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            <div className="text-sm text-blue-800 dark:text-blue-200">
              <p className="font-medium mb-1">What gets scanned:</p>
              <ul className="list-disc list-inside text-blue-700 dark:text-blue-300"><li>Inline JavaScript code</li><li>External JavaScript files</li><li>JavaScript within HTML attributes</li></ul>
            </div>
          </div>
        </div>
        {error && <div className="mb-4 p-3 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive text-sm">{error}</div>}
        {isScanning && (
          <div className="mb-6 p-4 bg-muted rounded-xl border border-border">
            <h4 className="text-sm font-semibold text-foreground mb-4">Scan Progress</h4>
            <div className="flex flex-col gap-1">{SCAN_STEPS.map((step, index) => <ProgressStep key={step.id} step={step} status={getStepStatus(index)} />)}</div>
          </div>
        )}
        <button type="submit" disabled={isScanning || isEmpty} className={`w-full py-3.5 px-6 rounded-lg text-base font-semibold flex items-center justify-center gap-2 transition-colors ${isScanning || isEmpty ? "bg-muted text-muted-foreground cursor-not-allowed" : "bg-primary text-primary-foreground hover:bg-primary/90"}`}>
          {isScanning ? (
            <><svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>Scanning...</>
          ) : (
            <><svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>Start Scan</>
          )}
        </button>
      </form>
    </div>
  );
};

const Tab = ({ label, icon, isActive, onClick }: { label: string; icon: React.ReactNode; isActive: boolean; onClick: () => void }) => (
  <button onClick={onClick} className={`px-6 py-3 flex items-center gap-2 text-sm font-medium border-b-2 transition-colors ${isActive ? "border-primary text-primary bg-background" : "border-transparent text-muted-foreground hover:text-foreground"}`}>
    {icon}
    {label}
  </button>
);

const Header = () => (
  <header className="bg-primary text-primary-foreground py-4 px-6">
    <div className="max-w-[1200px] mx-auto flex items-center justify-between">
      <div className="flex items-center gap-3">
        <svg className="w-8 h-8 text-blue-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
        <div>
          <h1 className="text-xl font-bold">Secure Code Analyzer</h1>
          <p className="text-xs opacity-80">Static Application Security Testing</p>
        </div>
      </div>
      <a href="https://github.com" target="_blank" rel="noopener noreferrer" className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors">Documentation</a>
    </div>
  </header>
);

const Footer = () => (
  <footer className="bg-muted border-t border-border py-6 text-center">
    <p className="text-sm text-muted-foreground">Secure Code Analyzer - SAST Tool for JavaScript, Python, PHP, and Java</p>
    <p className="text-xs text-muted-foreground mt-2">Analyzes source code statically without executing it.</p>
  </footer>
);

export default function Page() {
  const [activeTab, setActiveTab] = useState("file");
  const [results, setResults] = useState<ScanResults | null>(null);

  const handleScanComplete = useCallback((scanResults: ScanResults) => setResults(scanResults), []);
  const handleClearResults = useCallback(() => setResults(null), []);

  const fileIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>;
  const urlIcon = <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>;

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <main className="flex-1">
        <Results
          results={results}
          onClear={handleClearResults}
          activeTab={activeTab}
          onTabChange={setActiveTab}
          onScanComplete={handleScanComplete}
        />
      </main>
      <Footer />
    </div>
  );
}
