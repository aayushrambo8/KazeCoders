"""Run the detection pipeline and return results as a pandas DataFrame."""
import pandas as pd
from extractor import extract_http_requests
from normalizer import normalize_url
from detector import detect_attack


def run_detection(pcap_file):
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


def main_cli():
    import sys

    if len(sys.argv) > 1:
        pcap = sys.argv[1]
    else:
        print('Usage: python backend.py <pcap-file>')
        sys.exit(1)

    print(f'Running detection on: {pcap}')
    df = run_detection(pcap)
    print(df.head())


if __name__ == '__main__':
    main_cli()
