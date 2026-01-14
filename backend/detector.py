"""
Rule-based URL attack detection.
Backward-compatible with previous versions.
"""

import re
from urllib.parse import urlparse, parse_qs


def detect_attack(url):
    """
    Detect simple URL-based attacks and classify them.

    Returns:
        (attack_type, malicious)
    """
    if not url:
        return ('None', False)
    u = url.lower()

# SQL Injection (existing + extended)
    sqli_patterns = [
        r"union\s+select",
        r"'\s*or\s*'1'='1'",
        r"--",
        r";\s*(drop|insert|update|delete)\b",
        r"\bselect\b.*\bfrom\b"
    ]
    for p in sqli_patterns:
        if re.search(p, u):
            return ('SQL Injection', True)

# Cross Site Scripting (XSS)
    xss_patterns = [
        "<script",
        "</script>",
        "javascript:",
        "onerror=",
        "onload=",
        "<img",
        "<svg"
    ]
    for p in xss_patterns:
        if p in u:
            return ('Cross Site Scripting (XSS)', True)

# Command Injection (tightened)
    cmd_patterns = [
        r";\s*(ls|whoami|cat|id|pwd)",
        r"\|\s*(ls|whoami|cat|id|pwd)",
        r"&&\s*(ls|whoami|cat|id|pwd)"
    ]
    for p in cmd_patterns:
        if re.search(p, u):
            return ('Command Injection', True)

# Directory Traversal
    if (
        "../" in u or
        "..\\" in u or
        re.search(r"%2e%2e(%2f|/)", u)
    ):
        return ('Directory Traversal', True)

# Local / Remote File Inclusion
    lfi_rfi_patterns = [
        "/etc/passwd",
        "boot.ini",
        "windows/system32",
        "file=",
        "php://",
        "expect://",
        "input://"
    ]
    for p in lfi_rfi_patterns:
        if p in u:
            return ('LFI / RFI', True)

# Server-Side Request Forgery (SSRF)
    ssrf_indicators = [
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "169.254.169.254",
        "metadata.google.internal"
    ]
    for indicator in ssrf_indicators:
        if indicator in u:
            return ('SSRF', True)

# HTTP Parameter Pollution
    parsed = urlparse(u)
    params = parse_qs(parsed.query)
    for values in params.values():
        if len(values) > 1:
            return ('HTTP Parameter Pollution', True)

# XML External Entity (XXE)
    if "<!doctype" in u and "system" in u:
        return ('XXE', True)

# Credential Stuffing
    if (("login" in u or "signin" in u) and("password=" in u or "pwd=" in u)):
        return ('Credential Stuffing', True)

# Web Shell Access
    webshell_patterns = [".php?cmd=",".jsp?cmd=","shell.php","cmd="]
    for p in webshell_patterns:
        if p in u:
            return ('Web Shell Access', True)

# URL Spoofing
    if parsed.netloc.count('.') >= 4:
        return ('URL Spoofing', True)
    return ('None', False)