# Quicmap
a quic port scanner

    Service fingerprinting through HTTP/3 headers

    Protocol validation (QUIC vs HTTP/3)

    Banner grabbing for service identification

    Error differentiation (network errors vs protocol errors)

    JSON output for programmatic processing

Usage:
# Basic scan with color output
python quic_scanner.py example.com -p 443,8443 -s example.com

# Full scan with verbose output and JSON export
python quic_scanner.py example.com -p 1-65535 -t 5 -v -o results.json

# Quick scan with text output
python quic_scanner.py 192.168.1.1 -p 80-443 -f txt -o scan_results.txt

# Dependencies:

pip install aioquic colorama

Notes:

    The scanner now differentiates between QUIC services and HTTP/3 services

    HTTP/3 detection includes basic banner grabbing from server headers

    Timeout values should be adjusted based on network conditions

    Some enterprise-grade QUIC implementations might require additional protocol handling

    For maximum effectiveness, combine with UDP port scan results (QUIC runs over UDP)

