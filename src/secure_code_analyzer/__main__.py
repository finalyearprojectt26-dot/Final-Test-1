"""
Entry point for running the package as a module.

Usage:
    python -m secure_code_analyzer /path/to/scan
    python -m secure_code_analyzer --serve
"""

from .cli import main

if __name__ == '__main__':
    main()
