"""URL normalization utilities."""
from urllib.parse import urlparse, urlunparse, unquote_plus
import posixpath


def normalize_url(url):
    """Normalize a URL for deterministic analysis.

    Steps:
    - strip whitespace
    - ensure scheme
    - lowercase scheme and host
    - percent-decode path and query
    - collapse dot-segments in paths
    """
    if not url:
        return url

    url = url.strip()
    parsed = urlparse(url, scheme='http')

    scheme = (parsed.scheme or 'http').lower()
    netloc = (parsed.netloc or '').lower()
    if netloc.startswith('www.'):
        netloc = netloc[4:]

    path = unquote_plus(parsed.path or '')
    try:
        path = posixpath.normpath(path)
    except Exception:
        pass
    if parsed.path.endswith('/') and not path.endswith('/'):
        path = path + '/'

    query = unquote_plus(parsed.query or '')
    normalized = urlunparse((scheme, netloc, path, '', query, ''))
    return normalized
