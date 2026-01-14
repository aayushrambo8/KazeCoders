"""HTTP extraction helpers using pyshark.

Provides `extract_http_requests(pcap_file)` which yields dicts with
`src_ip`, `method`, and `url` for each HTTP request found.
"""
from urllib.parse import unquote_plus
import asyncio
import os

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
    # Ensure an asyncio event loop exists (pyshark uses asyncio internals).
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    # Attempt to create a FileCapture; if tshark isn't found, provide a clearer error.
    try:
        from pyshark.tshark.tshark import TSharkNotFoundException
    except Exception:
        TSharkNotFoundException = None

    # If tshark isn't on PATH, try common install locations (including D: on Windows).
    possible_tshark = [
        r"D:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for p in possible_tshark:
        if os.path.exists(p):
            try:
                # Set pyshark's tshark path directly so FileCapture can find it.
                setattr(pyshark.tshark.tshark, 'tshark_path', p)
            except Exception:
                pass
            break

    try:
        capture = pyshark.FileCapture(pcap_file, display_filter='http.request', keep_packets=False)
    except Exception as e:
        # If pyshark signals tshark missing, surface a friendly message.
        if TSharkNotFoundException is not None and isinstance(e, TSharkNotFoundException):
            raise RuntimeError(
                "TShark (the tshark binary from Wireshark) was not found.\n"
                "Install Wireshark or add the directory containing 'tshark' to your PATH.\n"
                "On Windows you can verify with: where tshark\n"
                f"If Wireshark is installed in a non-standard location (e.g. D:\\Program Files),\n"
                f"set the PATH or update this script to point to: {p}\n"
                f"Original error: {e}"
            ) from e
        raise
    try:
        for pkt in capture:
            try:
                src_ip = getattr(pkt.ip, 'src', None) or getattr(pkt.ipv6, 'src', None)
            except Exception:
                src_ip = 'UNKNOWN'

            # Some packets may not have an HTTP layer (e.g., TCP, FTP); guard access.
            http_layer = getattr(pkt, 'http', None)
            if http_layer is None:
                method = ''
                host = ''
                uri = ''
            else:
                method = getattr(http_layer, 'request_method', '')
                host = getattr(http_layer, 'host', '')
                uri = getattr(http_layer, 'request_uri', '')

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
