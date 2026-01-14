"""Small top-level runner to preserve CLI compatibility.

Usage: `python run_detector.py <pcap|ipdr-file>`
It delegates to the `backend` package runner.
"""
from backend.runner import main_cli


if __name__ == '__main__':
    main_cli()
