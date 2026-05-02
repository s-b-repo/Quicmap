# Quicmap

A QUIC / HTTP/3 port scanner.

- ALPN-based protocol detection (HTTP/3 vs generic QUIC)
- HTTP/3 banner grabbing via `:authority` GET request and full response-header capture
- Generic-QUIC banner attempt on a fresh bidi stream
- Closed-vs-error classification (no-handshake-response, idle timeout, OS errors)
- JSON or plain-text output for downstream tooling

## Install

    pip install aioquic colorama

Requires Python 3.11+ (uses `asyncio.timeout`).

## Usage

    # Basic scan with colour output
    python qmap.py example.com -p 443,8443 -s example.com

    # Verbose multi-port scan with JSON export
    python qmap.py example.com -p 1-1000 -t 5 -v -o results.json

    # Plain-text output
    python qmap.py 192.168.1.1 -p 80-443 -f txt -o scan_results.txt

    # Scan everything (slow, expect lots of false-closed)
    python qmap.py example.com --scan-all-ports -t 3 -c 200

## Flags

| Flag | Description |
| --- | --- |
| `host` | Target hostname or IP |
| `-p, --ports` | Ports / ranges to scan (default `443`) |
| `--scan-all-ports` | Shortcut for `1-65535` |
| `-s, --server-name` | SNI to send (defaults to `host`) |
| `-t, --timeout` | Per-port handshake/banner timeout in seconds (default `3.0`) |
| `-c, --concurrency` | Parallel scan tasks (default `100`) |
| `-o, --output` | Write results to file |
| `-f, --format` | `json` or `txt` (inferred from `-o` extension) |
| `-v, --verbose` | Show closed/error ports and full H3 headers |

## Notes

- Certificate verification is disabled — this is a recon tool, not a TLS validator.
- Pair with a UDP port scan: QUIC rides over UDP, and many filtered ports look "closed" here even when they are silently dropped.
- Idle/handshake timeouts are noisy on the open internet; bump `-t` for high-latency targets.

