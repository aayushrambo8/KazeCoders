"""HTTP extraction helpers using pyshark.

Provides `extract_http_requests(pcap_file)` which yields dicts with
`src_ip`, `method`, and `url` for each HTTP request found.
"""
from urllib.parse import unquote_plus

try:
    import pyshark
except Exception as e:  # pragma: no cover - informative for missing deps
    raise ImportError(
        "pyshark is required. Install with `pip install pyshark`\n" + str(e)
    )


def extract_http_requests(pcap_file):
    """Yield HTTP request info dictionaries from a PCAP file.

    Each yielded dict contains: `src_ip`, `method`, `url` (raw, decoded).
    """
    capture = pyshark.FileCapture(pcap_file, display_filter='http.request', keep_packets=False)
    try:
        for pkt in capture:
            try:
                src_ip = getattr(pkt.ip, 'src', None) or getattr(pkt.ipv6, 'src', None)
            except Exception:
                src_ip = 'UNKNOWN'

            method = getattr(pkt.http, 'request_method', '')
            host = getattr(pkt.http, 'host', '')
            uri = getattr(pkt.http, 'request_uri', '')

            if uri and uri.startswith('http'):
                full_url = uri
            else:
                if host:
                    full_url = f'http://{host}{uri}'
                else:
                    full_url = uri or ''

            try:
                full_url = unquote_plus(full_url)
            except Exception:
                pass

            yield {'src_ip': src_ip, 'method': method, 'url': full_url}
    finally:
        capture.close()
