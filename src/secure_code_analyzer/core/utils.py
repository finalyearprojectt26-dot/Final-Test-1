"""
Utility functions for the Secure Code Analyzer.
Provides helper functions for file operations, logging, and common tasks.
"""

import os
import hashlib
import logging
import tempfile
import shutil
from typing import List, Dict, Any, Optional
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('secure_code_analyzer')


# Supported file extensions for each language
SUPPORTED_EXTENSIONS = {
    'javascript': ['.js', '.jsx', '.mjs', '.cjs'],
    'typescript': ['.ts', '.tsx'],
    'python': ['.py'],
    'php': ['.php', '.phtml'],
    'java': ['.java'],
    'html': ['.html', '.htm'],
    'css': ['.css'],
}

# Reverse mapping: extension to language
EXTENSION_TO_LANGUAGE = {}
for lang, exts in SUPPORTED_EXTENSIONS.items():
    for ext in exts:
        EXTENSION_TO_LANGUAGE[ext] = lang


def get_file_extension(filepath: str) -> str:
    """Extract the file extension from a filepath."""
    return Path(filepath).suffix.lower()


def get_language_from_extension(filepath: str) -> Optional[str]:
    """Determine the programming language based on file extension."""
    ext = get_file_extension(filepath)
    return EXTENSION_TO_LANGUAGE.get(ext)


def is_supported_file(filepath: str) -> bool:
    """Check if a file is supported for scanning based on its extension."""
    ext = get_file_extension(filepath)
    return ext in EXTENSION_TO_LANGUAGE


def get_all_files(directory: str, recursive: bool = True) -> List[str]:
    """
    Get all supported source files from a directory.
    
    Args:
        directory: Path to the directory to scan
        recursive: Whether to scan subdirectories
        
    Returns:
        List of absolute file paths
    """
    files = []
    directory = Path(directory)
    
    if not directory.exists():
        logger.warning(f"Directory does not exist: {directory}")
        return files
    
    if recursive:
        for filepath in directory.rglob('*'):
            if filepath.is_file() and is_supported_file(str(filepath)):
                files.append(str(filepath.absolute()))
    else:
        for filepath in directory.iterdir():
            if filepath.is_file() and is_supported_file(str(filepath)):
                files.append(str(filepath.absolute()))
    
    return files


def read_file_content(filepath: str, encoding: str = 'utf-8') -> Optional[str]:
    """
    Safely read file content with error handling.
    
    Args:
        filepath: Path to the file
        encoding: File encoding (default: utf-8)
        
    Returns:
        File content as string, or None if reading failed
    """
    try:
        with open(filepath, 'r', encoding=encoding, errors='ignore') as f:
            return f.read()
    except (IOError, OSError) as e:
        logger.error(f"Failed to read file {filepath}: {e}")
        return None


def calculate_file_hash(filepath: str) -> Optional[str]:
    """Calculate SHA-256 hash of a file."""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (IOError, OSError) as e:
        logger.error(f"Failed to hash file {filepath}: {e}")
        return None


def create_temp_directory(prefix: str = 'secure_analyzer_') -> str:
    """
    Create a temporary directory for storing fetched files.
    
    Args:
        prefix: Prefix for the temp directory name
        
    Returns:
        Path to the created temporary directory
    """
    return tempfile.mkdtemp(prefix=prefix)


def cleanup_temp_directory(directory: str) -> bool:
    """
    Safely remove a temporary directory and its contents.
    
    Args:
        directory: Path to the directory to remove
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if os.path.exists(directory) and os.path.isdir(directory):
            shutil.rmtree(directory)
            return True
        return False
    except (IOError, OSError) as e:
        logger.error(f"Failed to cleanup directory {directory}: {e}")
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent directory traversal and invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename safe for filesystem operations
    """
    # Remove directory traversal attempts
    filename = os.path.basename(filename)
    
    # Replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Ensure filename is not empty
    if not filename:
        filename = 'unnamed_file'
    
    return filename


def truncate_string(s: str, max_length: int = 100, suffix: str = '...') -> str:
    """Truncate a string to a maximum length with suffix."""
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def normalize_path(path: str) -> str:
    """Normalize a file path for consistent comparison."""
    return str(Path(path).resolve())


def get_relative_path(filepath: str, base_dir: str) -> str:
    """Get the relative path of a file from a base directory."""
    try:
        return str(Path(filepath).relative_to(base_dir))
    except ValueError:
        return filepath


def format_line_number(line_num: int, total_lines: int) -> str:
    """Format a line number with appropriate padding."""
    width = len(str(total_lines))
    return str(line_num).rjust(width)


def extract_code_snippet(
    content: str,
    line_number: int,
    context_lines: int = 3
) -> Dict[str, Any]:
    """
    Extract a code snippet around a specific line number.
    
    Args:
        content: Full file content
        line_number: Target line number (1-indexed)
        context_lines: Number of lines to include before and after
        
    Returns:
        Dictionary with snippet info including lines and highlighting
    """
    lines = content.splitlines()
    total_lines = len(lines)
    
    # Adjust line_number to 0-indexed
    idx = line_number - 1
    
    # Calculate range
    start = max(0, idx - context_lines)
    end = min(total_lines, idx + context_lines + 1)
    
    snippet_lines = []
    for i in range(start, end):
        snippet_lines.append({
            'line_number': i + 1,
            'content': lines[i] if i < len(lines) else '',
            'is_highlighted': i == idx
        })
    
    return {
        'lines': snippet_lines,
        'start_line': start + 1,
        'end_line': end,
        'target_line': line_number
    }
