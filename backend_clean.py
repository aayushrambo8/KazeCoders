"""Clean compatibility wrapper for the modular detector.

Use this file if `backend.py` is corrupted. It re-exports the same
symbols and provides the CLI entrypoint used previously.
"""
from runner import run_detection, main_cli
from extractor import extract_http_requests
from normalizer import normalize_url
from detector import detect_attack

__all__ = [
    'extract_http_requests',
    'normalize_url',
    'detect_attack',
    'run_detection',
]


if __name__ == '__main__':
    main_cli()
