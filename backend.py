"""
Simple PCAP HTTP URL attack detector.

Requirements:
- pyshark
- pandas

This file provides beginner-friendly functions to extract HTTP requests
from a PCAP file, normalize URLs, and detect common URL-based attacks
using rule-based signatures (no ML).
"""
import sys
import re
import logging
from urllib.parse import urlparse, urlunparse, unquote_plus
import posixpath

try:
	import pyshark
except Exception as e:  # pragma: no cover - informative for missing deps
	raise ImportError(
		"pyshark is required. Install with `pip install pyshark`\n" + str(e)
	)

import pandas as pd

logging.basicConfig(level=logging.INFO)


def extract_http_requests(pcap_file):
	"""Extract HTTP requests from a PCAP file using pyshark.

	Yields dictionaries with keys: src_ip, method, url (raw, not normalized).
	"""
	capture = pyshark.FileCapture(pcap_file, display_filter='http.request', keep_packets=False)
	try:
		for pkt in capture:
			try:
				# prefer IPv4 then IPv6
				src_ip = getattr(pkt.ip, 'src', None) or getattr(pkt.ipv6, 'src', None)
			except Exception:
				src_ip = 'UNKNOWN'

			# HTTP fields
			method = getattr(pkt.http, 'request_method', '')
			host = getattr(pkt.http, 'host', '')
			uri = getattr(pkt.http, 'request_uri', '')

			# Construct full URL when possible
			if uri and uri.startswith('http'):
				full_url = uri
			else:
				if host:
					full_url = f'http://{host}{uri}'
				else:
					full_url = uri or ''

			# Decode common URL-encoding in the raw captured URL
			try:
				full_url = unquote_plus(full_url)
			except Exception:
				pass

			yield {'src_ip': src_ip, 'method': method, 'url': full_url}
	finally:
		capture.close()


def normalize_url(url):
	"""Normalize a URL for analysis.

	- Strips surrounding whitespace
	- Percent-decodes path and query
	- Lowercases scheme and host
	- Collapses dot-segments in the path
	"""
	if not url:
		return url

	url = url.strip()
	# Ensure parser has a scheme when only host/path is present
	parsed = urlparse(url, scheme='http')

	scheme = (parsed.scheme or 'http').lower()
	netloc = (parsed.netloc or '').lower()
	# Remove default www. prefix for more consistent matching
	if netloc.startswith('www.'):
		netloc = netloc[4:]

	# Decode and normalize path
	path = unquote_plus(parsed.path or '')
	# Collapse ../ and ./ segments
	try:
		path = posixpath.normpath(path)
	except Exception:
		pass
	# If original path ended with a slash, preserve it
	if parsed.path.endswith('/') and not path.endswith('/'):
		path = path + '/'

	query = unquote_plus(parsed.query or '')

	normalized = urlunparse((scheme, netloc, path, '', query, ''))
	return normalized


def detect_attack(url):
	"""Detect and classify attack types based on URL content.

	Returns a tuple: (attack_type, malicious)
	attack_type is one of: 'SQL Injection', 'XSS', 'Command Injection',
	'Directory Traversal', 'SSRF', or 'None'.
	"""
	if not url:
		return ('None', False)

	u = url.lower()

	# SQL Injection signatures
	sqli_patterns = [r"union\s+select", r"'\s*or\s*'1'='1'", r"--\s*$", r";\s*drop\s+table"]
	for p in sqli_patterns:
		if re.search(p, u):
			return ('SQL Injection', True)

	# Cross Site Scripting (XSS)
	xss_patterns = [r"<script", r"javascript:", r"onerror=", r"%3cscript%3e"]
	for p in xss_patterns:
		if p in u:
			return ('Cross Site Scripting (XSS)', True)

	# Command Injection
	cmd_patterns = [r";", r"\|", r"&&", r"\bwhoami\b", r"\bls\b", r"\bcat\b"]
	for p in cmd_patterns:
		if re.search(p, u):
			return ('Command Injection', True)

	# Directory Traversal
	if "../" in u or "%2e%2e" in u or "%2e/%2e" in u:
		return ('Directory Traversal', True)

	# Server Side Request Forgery (SSRF)
	ssrf_indicators = ['127.0.0.1', 'localhost', '169.254.169.254']
	for indicator in ssrf_indicators:
		if indicator in u:
			return ('SSRF', True)

	return ('None', False)


def run_detection(pcap_file):
	"""Run detection over a PCAP file and return a pandas DataFrame.

	Columns: src_ip, method, url, attack_type, malicious
	"""
	rows = []
	for req in extract_http_requests(pcap_file):
		src = req.get('src_ip', 'UNKNOWN')
		method = req.get('method', '')
		raw_url = req.get('url', '')

		norm = normalize_url(raw_url)
		attack_type, malicious = detect_attack(norm)

		rows.append({
			'src_ip': src,
			'method': method,
			'url': norm,
			'attack_type': attack_type,
			'malicious': malicious,
		})

	df = pd.DataFrame(rows, columns=['src_ip', 'method', 'url', 'attack_type', 'malicious'])
	return df


if __name__ == '__main__':
	if len(sys.argv) > 1:
		pcap = sys.argv[1]
	else:
		print('Usage: python backend.py <pcap-file>')
		print('No PCAP provided; exiting.')
		sys.exit(1)

	print(f'Running detection on: {pcap}')
	df = run_detection(pcap)
	# Print the first few rows for quick inspection
	print(df.head())

