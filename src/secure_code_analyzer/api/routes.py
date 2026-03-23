"""
Flask API routes for the Secure Code Analyzer.
Provides REST endpoints for scanning files and URLs.

Endpoints:
- POST /scan-file: Scan uploaded source files
- POST /scan-url: Extract and scan client-side code from a URL
- GET /health: Health check endpoint
"""

import os
import tempfile
import shutil
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename

from ..core.scanner import Scanner, ScanConfig
from ..core.url_fetcher import URLFetcher, URLFetchError
from ..core.utils import cleanup_temp_directory, logger


# Create blueprint
api = Blueprint('api', __name__)


# Allowed file extensions for upload
ALLOWED_EXTENSIONS = {
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.py',
    '.php', '.phtml',
    '.java',
    '.html', '.htm',
    '.css'
}


def allowed_file(filename: str) -> bool:
    """Check if a file has an allowed extension."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


@api.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint.
    
    Returns:
        JSON with status information
    """
    return jsonify({
        'status': 'healthy',
        'service': 'secure-code-analyzer',
        'version': '1.0.0'
    })


@api.route('/scan-file', methods=['POST'])
def scan_file():
    """
    Scan uploaded source files for security vulnerabilities.
    
    Request:
        - Content-Type: multipart/form-data
        - files: One or more source code files
        - config (optional): JSON string with scan configuration
    
    Response:
        - JSON with scan results
    
    Example:
        curl -X POST -F "files=@mycode.js" http://localhost:5000/scan-file
    """
    # Check if files were uploaded
    if 'files' not in request.files:
        return jsonify({
            'success': False,
            'error': 'No files provided. Use "files" field to upload source code.'
        }), 400
    
    files = request.files.getlist('files')
    
    if not files or all(f.filename == '' for f in files):
        return jsonify({
            'success': False,
            'error': 'No files selected for upload.'
        }), 400
    
    # Create temporary directory for uploaded files
    temp_dir = tempfile.mkdtemp(prefix='file_scan_')
    
    try:
        uploaded_files = []
        rejected_files = []
        
        # Save uploaded files
        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                
                if allowed_file(filename):
                    filepath = os.path.join(temp_dir, filename)
                    file.save(filepath)
                    uploaded_files.append(filename)
                else:
                    rejected_files.append(filename)
        
        if not uploaded_files:
            return jsonify({
                'success': False,
                'error': 'No valid source files uploaded.',
                'rejected_files': rejected_files,
                'allowed_extensions': list(ALLOWED_EXTENSIONS)
            }), 400
        
        # Parse optional configuration
        config = ScanConfig()
        if 'config' in request.form:
            try:
                import json
                config_data = json.loads(request.form['config'])
                
                if 'parallel_workers' in config_data:
                    config.parallel_workers = int(config_data['parallel_workers'])
                if 'max_file_size' in config_data:
                    config.max_file_size = int(config_data['max_file_size'])
                    
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Invalid config provided: {e}")
        
        # Run the scan
        scanner = Scanner(config=config)
        result = scanner.scan(temp_dir)
        
        # Add metadata about the upload
        result_dict = result.to_dict()
        result_dict['uploaded_files'] = uploaded_files
        result_dict['rejected_files'] = rejected_files
        result_dict['scan_type'] = 'file'
        
        return jsonify(result_dict)
        
    except Exception as e:
        logger.exception("Error during file scan")
        return jsonify({
            'success': False,
            'error': f'Scan failed: {str(e)}'
        }), 500
        
    finally:
        # Cleanup temporary directory
        cleanup_temp_directory(temp_dir)


@api.route('/scan-url', methods=['POST'])
def scan_url():
    """
    Extract and scan client-side source code from a URL.
    
    This endpoint:
    1. Fetches the HTML from the provided URL
    2. Extracts inline <script> JavaScript
    3. Downloads external JavaScript files
    4. Runs static analysis on all extracted code
    
    Request:
        - Content-Type: application/json
        - Body: { "url": "https://example.com", "config": {...} }
    
    Response:
        - JSON with scan results
    
    Example:
        curl -X POST -H "Content-Type: application/json" \
             -d '{"url": "https://example.com"}' \
             http://localhost:5000/scan-url
    """
    # Validate request
    if not request.is_json:
        return jsonify({
            'success': False,
            'error': 'Request must be JSON. Set Content-Type: application/json'
        }), 400
    
    data = request.get_json()
    
    if 'url' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing required field: url'
        }), 400
    
    url = data['url']
    
    # Basic URL validation
    if not url.startswith(('http://', 'https://')):
        return jsonify({
            'success': False,
            'error': 'URL must start with http:// or https://'
        }), 400
    
    temp_dir = None
    
    try:
        # Fetch URL content
        fetcher = URLFetcher(
            timeout=data.get('timeout', 30),
            max_external_scripts=data.get('max_scripts', 50)
        )
        
        fetch_result = fetcher.fetch(url)
        
        if not fetch_result['success']:
            return jsonify({
                'success': False,
                'error': f"Failed to fetch URL: {fetch_result['error']}",
                'scan_type': 'url'
            }), 400
        
        temp_dir = fetch_result['directory']
        
        # Parse optional scan configuration
        config = ScanConfig()
        if 'config' in data:
            config_data = data['config']
            
            if 'parallel_workers' in config_data:
                config.parallel_workers = int(config_data['parallel_workers'])
            if 'max_file_size' in config_data:
                config.max_file_size = int(config_data['max_file_size'])
        
        # Run the scan on extracted files
        scanner = Scanner(config=config)
        result = scanner.scan(temp_dir)
        
        # Add URL-specific metadata
        result_dict = result.to_dict()
        result_dict['scan_type'] = 'url'
        result_dict['source_url'] = url
        result_dict['fetch_metadata'] = fetch_result['metadata']
        result_dict['extracted_files'] = [
            os.path.basename(f) for f in fetch_result['files']
        ]
        
        # Update target_path to show the URL instead of temp directory
        result_dict['target_path'] = url
        
        return jsonify(result_dict)
        
    except URLFetchError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'scan_type': 'url'
        }), 400
        
    except Exception as e:
        logger.exception("Error during URL scan")
        return jsonify({
            'success': False,
            'error': f'Scan failed: {str(e)}',
            'scan_type': 'url'
        }), 500
        
    finally:
        # Cleanup temporary directory
        if temp_dir:
            cleanup_temp_directory(temp_dir)


@api.route('/rules', methods=['GET'])
def get_rules():
    """
    Get information about available security rules.
    
    Returns:
        JSON with rules metadata
    """
    from ..core.detectors import RulesLoader
    
    try:
        loader = RulesLoader()
        rules = loader.load_rules()
        
        # Summarize rules by category
        categories = {}
        for rule in rules.get('rules', []):
            category = rule.get('category', 'other')
            if category not in categories:
                categories[category] = {
                    'count': 0,
                    'rules': []
                }
            categories[category]['count'] += 1
            categories[category]['rules'].append({
                'id': rule.get('id'),
                'name': rule.get('name'),
                'severity': rule.get('severity'),
                'languages': rule.get('languages', [])
            })
        
        return jsonify({
            'version': rules.get('version', '1.0.0'),
            'total_rules': len(rules.get('rules', [])),
            'categories': categories
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to load rules: {str(e)}'
        }), 500


@api.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error."""
    return jsonify({
        'success': False,
        'error': 'File too large. Maximum size is 16MB.'
    }), 413


@api.errorhandler(500)
def internal_server_error(error):
    """Handle internal server errors."""
    return jsonify({
        'success': False,
        'error': 'Internal server error occurred.'
    }), 500
