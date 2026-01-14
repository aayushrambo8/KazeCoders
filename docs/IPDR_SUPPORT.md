IPDR Support
===========

This project can read Cisco-style `.ipdr` capture files directly when `tshark` (the Wireshark CLI) supports the `ipdr` input format on your system.

Requirements
- `tshark` (part of Wireshark) installed and available on `PATH`, or installed in a common location (the code also checks `D:\Program Files\Wireshark` on Windows).
- Python dependencies from `requirements.txt` (e.g. `pyshark`, `pandas`).

Behavior
- The extractor will attempt to open `.ipdr` files by passing the `-F ipdr` format flag to `tshark` via `pyshark`.
- If `tshark` does not support IPDR input on your platform, you'll see an error — in that case use a PCAP input or ensure your `tshark` build supports the format.

Usage
```
python -m run_detector example.ipdr
```

Troubleshooting
- Verify `tshark` is installed and reachable:
  - Windows: `where tshark`
  - macOS/Linux: `which tshark`
- Confirm `tshark` can read the file directly:
```
tshark -r example.ipdr -V | head 
```
- If `tshark` cannot read IPDR files on your system, consider converting to pcap with a `tshark` build that supports IPDR, or provide PCAP inputs instead.

Notes
- The extractor focuses on extracting HTTP requests. If your IPDR contains other protocols of interest (FTP, DNS, etc.), consider extending the extractor to parse those layers.
