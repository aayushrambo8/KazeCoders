"""Rule-based URL attack detection."""
import re


def detect_attack(url):
    """Detect simple URL-based attacks and classify them.

    Returns (attack_type, malicious)
    """
    if not url:
        return ('None', False)

    u = url.lower()

    sqli_patterns = [r"union\s+select", r"'\s*or\s*'1'='1'", r"--\s*$", r";\s*drop\s+table"]
    for p in sqli_patterns:
        if re.search(p, u):
            return ('SQL Injection', True)

    xss_patterns = [r"<script", r"javascript:", r"onerror=", r"%3cscript%3e"]
    for p in xss_patterns:
        if p in u:
            return ('Cross Site Scripting (XSS)', True)

    cmd_patterns = [r";", r"\|", r"&&", r"\bwhoami\b", r"\bls\b", r"\bcat\b"]
    for p in cmd_patterns:
        if re.search(p, u):
            return ('Command Injection', True)

    if "../" in u or "%2e%2e" in u or "%2e/%2e" in u:
        return ('Directory Traversal', True)

    ssrf_indicators = ['127.0.0.1', 'localhost', '169.254.169.254']
    for indicator in ssrf_indicators:
        if indicator in u:
            return ('SSRF', True)

    return ('None', False)
