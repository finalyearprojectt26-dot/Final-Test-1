"""
URL Fetcher module for extracting client-side source code from live URLs.
This module fetches HTML content, extracts inline scripts, and downloads
external JavaScript files for static analysis.

IMPORTANT: This is NOT a crawler or fuzzer. It only fetches publicly
accessible client-side source code from a single URL.
"""

import os
import re
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from pathlib import Path
import requests
from bs4 import BeautifulSoup

from .utils import (
    create_temp_directory,
    sanitize_filename,
    logger
)

# Configuration constants
DEFAULT_TIMEOUT = 30  # seconds
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_EXTERNAL_SCRIPTS = 50  # Maximum external scripts to fetch
ALLOWED_SCHEMES = {'http', 'https'}

# User agent for requests
USER_AGENT = (
    'Mozilla/5.0 (compatible; SecureCodeAnalyzer/1.0; '
    '+https://github.com/secure-code-analyzer)'
)


class URLFetchError(Exception):
    """Custom exception for URL fetching errors."""
    pass


class URLFetcher:
    """
    Fetches and extracts client-side source code from a URL.
    
    This class:
    1. Fetches the HTML content of the target URL
    2. Extracts inline <script> JavaScript code
    3. Resolves and downloads external JavaScript files
    4. Stores all extracted code in a temporary directory
    5. Returns the directory path for scanning
    """
    
    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        max_file_size: int = MAX_FILE_SIZE,
        max_external_scripts: int = MAX_EXTERNAL_SCRIPTS,
        verify_ssl: bool = True
    ):
        """
        Initialize the URL fetcher.
        
        Args:
            timeout: Request timeout in seconds
            max_file_size: Maximum file size to download (bytes)
            max_external_scripts: Maximum number of external scripts to fetch
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.max_file_size = max_file_size
        self.max_external_scripts = max_external_scripts
        self.verify_ssl = verify_ssl
        self.session = self._create_session()
        self.logger = logging.getLogger('url_fetcher')
    
    def _create_session(self) -> requests.Session:
        """Create a configured requests session."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        return session
    
    def _validate_url(self, url: str) -> Tuple[bool, str]:
        """
        Validate that a URL is allowed for fetching.
        
        Args:
            url: URL to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)
            
            if not parsed.scheme:
                return False, "URL must include a scheme (http:// or https://)"
            
            if parsed.scheme not in ALLOWED_SCHEMES:
                return False, f"URL scheme must be one of: {ALLOWED_SCHEMES}"
            
            if not parsed.netloc:
                return False, "URL must include a domain"
            
            # Block localhost and private IPs for security
            hostname = parsed.hostname or ''
            if hostname in ('localhost', '127.0.0.1', '0.0.0.0'):
                return False, "Cannot fetch from localhost"
            
            # Block private IP ranges
            if self._is_private_ip(hostname):
                return False, "Cannot fetch from private IP addresses"
            
            return True, ""
            
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"
    
    def _is_private_ip(self, hostname: str) -> bool:
        """Check if a hostname resolves to a private IP."""
        import socket
        try:
            ip = socket.gethostbyname(hostname)
            parts = [int(p) for p in ip.split('.')]
            
            # Check private ranges
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
                
            return False
        except socket.gaierror:
            return False
    
    def _fetch_content(self, url: str) -> str:
        """
        Fetch content from a URL with proper error handling.
        
        Args:
            url: URL to fetch
            
        Returns:
            Response content as string
            
        Raises:
            URLFetchError: If fetching fails
        """
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                stream=True
            )
            response.raise_for_status()
            
            # Check content length
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > self.max_file_size:
                raise URLFetchError(
                    f"Content too large: {content_length} bytes "
                    f"(max: {self.max_file_size})"
                )
            
            # Read content with size limit
            content = b''
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > self.max_file_size:
                    raise URLFetchError(
                        f"Content exceeded size limit of {self.max_file_size} bytes"
                    )
            
            return content.decode('utf-8', errors='ignore')
            
        except requests.exceptions.Timeout:
            raise URLFetchError(f"Request timed out after {self.timeout} seconds")
        except requests.exceptions.SSLError as e:
            raise URLFetchError(f"SSL error: {str(e)}")
        except requests.exceptions.ConnectionError as e:
            raise URLFetchError(f"Connection error: {str(e)}")
        except requests.exceptions.HTTPError as e:
            raise URLFetchError(f"HTTP error: {str(e)}")
        except Exception as e:
            raise URLFetchError(f"Failed to fetch URL: {str(e)}")
    
    def _extract_scripts_from_html(
        self, 
        html_content: str, 
        base_url: str
    ) -> Tuple[List[str], List[str]]:
        """
        Extract inline scripts and external script URLs from HTML.
        
        Args:
            html_content: HTML content to parse
            base_url: Base URL for resolving relative paths
            
        Returns:
            Tuple of (inline_scripts, external_script_urls)
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        inline_scripts = []
        external_urls = []
        
        for script in soup.find_all('script'):
            src = script.get('src')
            
            if src:
                # External script
                absolute_url = urljoin(base_url, src)
                
                # Only fetch JavaScript files
                if self._is_javascript_url(absolute_url):
                    external_urls.append(absolute_url)
            else:
                # Inline script
                script_content = script.string
                if script_content and script_content.strip():
                    inline_scripts.append(script_content)
        
        return inline_scripts, external_urls
    
    def _is_javascript_url(self, url: str) -> bool:
        """Check if a URL points to a JavaScript file."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Check extension
        if path.endswith(('.js', '.mjs', '.jsx')):
            return True
        
        # Some CDNs don't use extensions
        if 'javascript' in path or 'js' in path:
            return True
        
        return True  # Assume it's JS if from a script tag
    
    def _save_script(
        self, 
        content: str, 
        filename: str, 
        output_dir: str
    ) -> str:
        """
        Save script content to a file.
        
        Args:
            content: Script content
            filename: Desired filename
            output_dir: Output directory
            
        Returns:
            Path to saved file
        """
        safe_filename = sanitize_filename(filename)
        filepath = os.path.join(output_dir, safe_filename)
        
        # Handle duplicate filenames
        counter = 1
        base, ext = os.path.splitext(filepath)
        while os.path.exists(filepath):
            filepath = f"{base}_{counter}{ext}"
            counter += 1
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return filepath
    
    def fetch(self, url: str) -> Dict[str, any]:
        """
        Fetch and extract all client-side source code from a URL.

        This is the main entry point. It:
        1. Validates the URL
        2. Fetches the HTML from the provided URL
        3. Extracts inline <script> JavaScript
        4. Downloads external JavaScript files
        5. Saves everything to a temp directory

        Args:
            url: Target URL to analyze

        Returns:
            Dictionary with:
            - success: bool
            - directory: str (path to temp directory with extracted files)
            - files: list of extracted file paths
            - metadata: dict with fetch statistics
            - error: str (if success is False)
        """
        result = {
            "success": False,
            "directory": None,
            "files": [],
            "metadata": {
                "url": url,
                "inline_scripts": 0,
                "external_scripts": 0,
                "total_size": 0
            },
            "error": None
        }

        # Validate URL
        is_valid, error_msg = self._validate_url(url)
        if not is_valid:
            result["error"] = error_msg
            return result

        try:
            # Create temp directory
            temp_dir = create_temp_directory(prefix='url_scan_')
            result["directory"] = temp_dir

            self.logger.info(f"Fetching URL: {url}")

            # Fetch HTML
            html_content = self._fetch_content(url)

            # Save the HTML file
            html_path = self._save_script(html_content, 'index.html', temp_dir)
            result["files"].append(html_path)

            # Extract scripts
            inline_scripts, external_urls = self._extract_scripts_from_html(
                html_content, url
            )

            self.logger.info(
                f"Found {len(inline_scripts)} inline scripts and "
                f"{len(external_urls)} external scripts"
            )

            # Save inline scripts
            for i, script in enumerate(inline_scripts):
                filename = f"inline_script_{i + 1}.js"
                filepath = self._save_script(script, filename, temp_dir)
                result["files"].append(filepath)
                result["metadata"]["inline_scripts"] += 1
                result["metadata"]["total_size"] += len(script)

            # Fetch and save external scripts (with limit)
            external_urls = external_urls[:self.max_external_scripts]

            for ext_url in external_urls:
                try:
                    self.logger.debug(f"Fetching external script: {ext_url}")
                    script_content = self._fetch_content(ext_url)

                    # Generate filename from URL
                    parsed = urlparse(ext_url)
                    filename = os.path.basename(parsed.path) or 'external_script.js'
                    if not filename.endswith('.js'):
                        filename += '.js'

                    filepath = self._save_script(script_content, filename, temp_dir)
                    result["files"].append(filepath)
                    result["metadata"]["external_scripts"] += 1
                    result["metadata"]["total_size"] += len(script_content)

                except URLFetchError as e:
                    self.logger.warning(f"Failed to fetch {ext_url}: {e}")
                    continue

            result["success"] = True
            self.logger.info(
                f"Successfully extracted {len(result['files'])} files "
                f"to {temp_dir}"
            )

        except URLFetchError as e:
            result["error"] = str(e)
            self.logger.error(f"URL fetch failed: {e}")

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            self.logger.exception("Unexpected error during URL fetch")

        return result


def fetch_url_for_scanning(url: str) -> str:
    """
    Convenience function to fetch a URL and return the temp directory path.
    
    This function is used by the scanner to get a directory of extracted
    source files that can be passed to the standard scanning pipeline.
    
    Args:
        url: Target URL to analyze
        
    Returns:
        Path to temporary directory containing extracted source files
        
    Raises:
        URLFetchError: If fetching or extraction fails
    """
    fetcher = URLFetcher()
    result = fetcher.fetch(url)
    
    if not result["success"]:
        raise URLFetchError(result["error"])
    
    return result["directory"]
