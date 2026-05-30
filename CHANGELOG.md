# Changelog

## v1.3.0 - 2026-05-03

### Fixed
- **Scanner no longer crashes against any host.** The previous version called `aioquic.asyncio.connect()` with `server_name=` and `timeout=` kwargs that the library does not accept (`TypeError: connect() got an unexpected keyword argument 'server_name'`). SNI is now set on `QuicConfiguration(server_name=...)` and the per-port budget is enforced with `asyncio.timeout()`.
- **Replaced calls to non-existent `QuicConnectionProtocol` attributes.** `protocol.next_event()`, `protocol.quic`, `protocol.alpn_protocol`, `protocol.configuration`, `protocol.get_next_available_stream_id()`, and `protocol.send_stream_data()` do not exist in aioquic 1.x — they live on the underlying `QuicConnection` (accessible as `protocol._quic`). The scanner now subclasses `QuicConnectionProtocol` and overrides `quic_event_received`, which is the supported pattern.
- **Handshake now actually starts.** Calling `connect(..., wait_connected=False)` skipped the initial flight transmit, so handshakes never began. Switched to `wait_connected=True` and bound the entire connect+handshake+banner phase with `asyncio.timeout(timeout * 2 + 5)`.
- **Closed-port reporting no longer prints empty error messages.** Bare `ConnectionError` from aioquic now renders as `connection error: no QUIC handshake response`.

### Changed
- **Event handling rewritten as event-driven instead of polling.** Per-stream `asyncio.Future` waiters are populated by `quic_event_received` for both H3 `HeadersReceived` and raw `StreamDataReceived` paths. Removes the busy `while not stream_ended: await next_event()` loop that depended on missing API.
- **HTTP/3 banner fetch now sets `end_stream=True` on the request headers.** Previously the request was followed by a separate empty-data send; the H3 layer expects the end-of-stream flag on `send_headers()`.
- **Generic-QUIC banner attempt opens its own bidi stream** and uses the protocol's `transmit()` helper instead of poking `send_stream_data` on a non-existent attribute.
- **Closed/error classification expanded.** Distinguishes `ConnectionRefusedError`, `ConnectionError` (peer dropped during handshake), `asyncio.TimeoutError`, and selected `OSError` errnos (`ECONNREFUSED`, `EHOSTUNREACH`, etc.).
- **Suppressed cosmetic asyncio warning.** Installed a loop exception handler that swallows `Future exception was never retrieved` for `ConnectionError` — these come from aioquic's internal `_connected_waiter` losing the race against our outer timeout and are not actionable.
- **README rewritten** to reflect actual flag set and the Python 3.11+ requirement (`asyncio.timeout`).

### Verified against
- `www.google.com:443` — H3, server `gws`
- `cloudflare-quic.com:443` — H3, server `cloudflare`
- `www.facebook.com:443` — H3, full headers including `x-fb-debug`
- Range scans (e.g. `440-445`) correctly report a single open port
- Closed local ports (`127.0.0.1:9999`) report `connection timeout`
- JSON and TXT output formats both render
