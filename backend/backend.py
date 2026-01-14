"""Compatibility wrapper for the modular detector.

This module re-exports the core functions from the smaller modules so
existing imports continue to work while implementation lives in
`extractor.py`, `normalizer.py`, `detector.py`, and `runner.py`.
"""
from backend import run_detection, main_cli, extract_http_requests, normalize_url, detect_attack

__all__ = [
    'extract_http_requests',
    'normalize_url',
    'detect_attack',
    'run_detection',
]


if __name__ == '__main__':
    main_cli()

