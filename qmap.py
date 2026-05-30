import argparse
import asyncio
import json
import os
import ssl
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    ProtocolNegotiated,
    QuicEvent,
    StreamDataReceived,
    StreamReset,
)
from colorama import Fore, Style, init

init(autoreset=True)


class Protocol(Enum):
    HTTP3 = "HTTP/3"
    QUIC = "QUIC"


def parse_ports(ports_arg: str) -> List[int]:
    ports: List[int] = []
    for part in ports_arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = map(int, part.split("-", 1))
            except ValueError:
                print(f"{Fore.YELLOW}Warning: invalid range '{part}', skipping.{Style.RESET_ALL}")
                continue
            if not (0 < start <= end < 65536):
                print(f"{Fore.YELLOW}Warning: out-of-range '{part}', skipping.{Style.RESET_ALL}")
                continue
            ports.extend(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                print(f"{Fore.YELLOW}Warning: invalid port '{part}', skipping.{Style.RESET_ALL}")
                continue
            if not (0 < port < 65536):
                print(f"{Fore.YELLOW}Warning: out-of-range port '{part}', skipping.{Style.RESET_ALL}")
                continue
            ports.append(port)
    return sorted(set(ports))


class ScanResult:
    def __init__(self, port: int):
        self.port = port
        self.status: str = "closed"
        self.protocol: Optional[str] = None
        self.service: Optional[str] = None
        self.version: Optional[str] = None
        self.banner: Optional[str] = None
        self.error: Optional[str] = None
        self.full_headers: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "status": self.status,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "error": self.error,
            "full_headers": self.full_headers,
        }


class QuicScannerProtocol(QuicConnectionProtocol):
    """QuicConnectionProtocol that captures ALPN, H3 headers, and raw stream data."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._loop = asyncio.get_event_loop()
        self._alpn: Optional[str] = None
        self._h3: Optional[H3Connection] = None
        self._terminated: Optional[ConnectionTerminated] = None

        # Per-stream waiters for H3 headers
        self._h3_header_waiters: Dict[int, asyncio.Future[List[tuple]]] = {}
        # Per-stream collected data (raw bytes) and end-of-stream waiter
        self._stream_data: Dict[int, bytearray] = {}
        self._stream_end_waiters: Dict[int, asyncio.Future[bytes]] = {}

    @property
    def alpn(self) -> Optional[str]:
        return self._alpn

    @property
    def terminated(self) -> Optional[ConnectionTerminated]:
        return self._terminated

    @staticmethod
    def _silently_consume(fut: "asyncio.Future") -> None:
        # Prevent "Future exception was never retrieved" warnings when nobody
        # is awaiting a waiter we had to fail.
        fut.add_done_callback(lambda f: f.exception())

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._alpn = event.alpn_protocol
            if event.alpn_protocol in H3_ALPN:
                self._h3 = H3Connection(self._quic)
            return

        if isinstance(event, ConnectionTerminated):
            self._terminated = event
            for fut in self._h3_header_waiters.values():
                if not fut.done():
                    fut.set_exception(ConnectionError("connection terminated"))
                    self._silently_consume(fut)
            for sid, fut in self._stream_end_waiters.items():
                if not fut.done():
                    fut.set_result(bytes(self._stream_data.get(sid, b"")))
            return

        if isinstance(event, StreamReset):
            fut = self._stream_end_waiters.get(event.stream_id)
            if fut is not None and not fut.done():
                fut.set_result(bytes(self._stream_data.get(event.stream_id, b"")))
            hfut = self._h3_header_waiters.get(event.stream_id)
            if hfut is not None and not hfut.done():
                hfut.set_exception(ConnectionError(f"stream reset: {event.error_code}"))
            return

        # H3 path: feed event into the H3Connection
        if self._h3 is not None:
            for h3_event in self._h3.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    fut = self._h3_header_waiters.get(h3_event.stream_id)
                    if fut is not None and not fut.done():
                        fut.set_result(h3_event.headers)
                # We ignore body data for H3 banner purposes; we only need headers.

        # Always also collect raw stream data (for generic QUIC banner mode).
        if isinstance(event, StreamDataReceived):
            buf = self._stream_data.setdefault(event.stream_id, bytearray())
            buf.extend(event.data)
            if event.end_stream:
                fut = self._stream_end_waiters.get(event.stream_id)
                if fut is not None and not fut.done():
                    fut.set_result(bytes(buf))

    # ------------------ Helpers used by scanner -------------------

    async def fetch_http3_banner(self, authority: str, timeout: float) -> Dict[str, Any]:
        if self._h3 is None:
            raise RuntimeError("HTTP/3 connection not established (no H3 ALPN).")
        stream_id = self._quic.get_next_available_stream_id()
        waiter: asyncio.Future[List[tuple]] = self._loop.create_future()
        self._h3_header_waiters[stream_id] = waiter

        self._h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", b"/"),
                (b"user-agent", b"Quicmap/1.3"),
            ],
            end_stream=True,
        )
        self.transmit()

        try:
            headers = await asyncio.wait_for(waiter, timeout=timeout)
        finally:
            self._h3_header_waiters.pop(stream_id, None)

        headers_dict: Dict[str, str] = {}
        for k, v in headers:
            try:
                headers_dict[k.decode("ascii", errors="replace")] = v.decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                continue

        return {
            "service": Protocol.HTTP3.value,
            "headers": headers_dict,
            "version": headers_dict.get("server") or "UnknownServer",
        }

    async def fetch_generic_banner(self, timeout: float) -> Dict[str, Any]:
        # Open a new bidi stream and send a probe; many non-H3 services won't reply
        # to arbitrary bytes, but some (e.g. plain text protocols tunneled over QUIC)
        # may emit a banner.
        stream_id = self._quic.get_next_available_stream_id()
        waiter: asyncio.Future[bytes] = self._loop.create_future()
        self._stream_end_waiters[stream_id] = waiter
        self._stream_data[stream_id] = bytearray()

        try:
            self._quic.send_stream_data(stream_id, b"GET / HTTP/1.0\r\n\r\n", end_stream=True)
            self.transmit()
        except Exception as exc:
            self._stream_end_waiters.pop(stream_id, None)
            self._stream_data.pop(stream_id, None)
            return {"banner": None, "error": f"failed to send probe: {exc}"}

        try:
            data = await asyncio.wait_for(waiter, timeout=timeout)
            note = None
        except asyncio.TimeoutError:
            data = bytes(self._stream_data.get(stream_id, b""))
            note = "timeout (partial data)" if data else None
            if not data:
                return {"banner": None, "error": "timeout waiting for banner"}
        finally:
            self._stream_end_waiters.pop(stream_id, None)
            self._stream_data.pop(stream_id, None)

        text = data.decode("utf-8", errors="replace").strip()
        if len(text) > 256:
            text = text[:256] + "..."
        result: Dict[str, Any] = {"banner": text or None}
        if note:
            result["note"] = note
        return result


async def check_quic_port(host: str, port: int, server_name: str, timeout: float) -> ScanResult:
    result = ScanResult(port)

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        server_name=server_name,
        verify_mode=ssl.CERT_NONE,
        idle_timeout=max(timeout + 5.0, 10.0),
    )

    try:
        # asyncio.timeout bounds the entire connect+handshake+banner phase.
        # aioquic.connect() itself awaits the handshake when wait_connected=True,
        # but does not honour any per-call timeout, so we enforce one here.
        async with asyncio.timeout(timeout * 2 + 5):
            async with connect(
                host=host,
                port=port,
                configuration=configuration,
                create_protocol=QuicScannerProtocol,
                wait_connected=True,
            ) as protocol:
                assert isinstance(protocol, QuicScannerProtocol)
                result.status = "open"
                alpn = protocol.alpn
                result.protocol = alpn or "QUIC (no ALPN)"

                if alpn in H3_ALPN:
                    result.service = Protocol.HTTP3.value
                    try:
                        info = await protocol.fetch_http3_banner(server_name, timeout)
                        result.version = info.get("version")
                        result.full_headers = info.get("headers")
                        if result.version and result.version != "UnknownServer":
                            result.banner = f"Server: {result.version}"
                        else:
                            result.banner = "HTTP/3 (no Server header)"
                    except Exception as exc:
                        result.error = f"HTTP/3 banner fetch failed: {type(exc).__name__}: {exc}"
                        result.banner = f"HTTP/3 (banner error: {type(exc).__name__})"
                else:
                    result.service = Protocol.QUIC.value
                    try:
                        info = await protocol.fetch_generic_banner(timeout)
                        if info.get("banner"):
                            result.banner = info["banner"]
                        else:
                            result.banner = f"Generic QUIC (ALPN: {result.protocol})"
                        for key in ("error", "note"):
                            if info.get(key):
                                tag = "BannerInfo" if key == "note" else "BannerErr"
                                result.error = (
                                    (result.error + "; " if result.error else "")
                                    + f"{tag}: {info[key]}"
                                )
                    except Exception as exc:
                        result.error = f"Generic banner failed: {type(exc).__name__}: {exc}"
                        result.banner = f"Generic QUIC (banner error: {type(exc).__name__})"
    except (asyncio.TimeoutError, TimeoutError):
        if result.status == "closed":
            result.error = "connection timeout"
    except ConnectionRefusedError:
        result.status = "closed"
        result.error = "connection refused"
    except ConnectionError as exc:
        # aioquic raises bare ConnectionError when the peer closes during handshake.
        result.status = "closed"
        msg = str(exc) or "no QUIC handshake response"
        result.error = f"connection error: {msg}"
    except OSError as exc:
        if exc.errno in {111, 113, 61, 64, 65}:
            result.status = "closed"
        else:
            result.status = "error"
        msg = os.strerror(exc.errno) if exc.errno else str(exc)
        result.error = f"OS error: {msg} (errno {exc.errno})"
    except Exception as exc:
        result.status = "error"
        result.error = f"{type(exc).__name__}: {exc}"

    return result


async def scan_ports_async(
    host: str,
    ports: List[int],
    server_name: str,
    timeout: float,
    concurrency: int,
) -> List[ScanResult]:
    sem = asyncio.Semaphore(concurrency)

    async def _one(port: int) -> ScanResult:
        async with sem:
            return await check_quic_port(host, port, server_name, timeout)

    tasks = [asyncio.create_task(_one(p)) for p in ports]
    results: List[ScanResult] = []
    try:
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        raise

    for port, item in zip(ports, gathered):
        if isinstance(item, ScanResult):
            results.append(item)
        else:
            err = ScanResult(port)
            err.status = "error"
            err.error = f"unhandled: {type(item).__name__}: {item}"
            results.append(err)
    return results


def print_results(results: List[ScanResult], verbose: bool = False) -> None:
    open_found = False
    for r in sorted(results, key=lambda x: x.port):
        if r.status == "open":
            open_found = True
            parts = [
                f"Port {r.port}",
                f"Status: {r.status}",
            ]
            if r.protocol:
                parts.append(f"Protocol: {r.protocol}")
            if r.service:
                parts.append(f"Service: {r.service}")
            if r.banner:
                parts.append(f"Banner: {r.banner}")
            print(f"{Fore.GREEN}{Style.BRIGHT}{' | '.join(parts)}{Style.RESET_ALL}")

            if verbose and r.full_headers:
                print(f"{Fore.CYAN}  Full H3 Headers:{Style.RESET_ALL}")
                for k, v in r.full_headers.items():
                    print(f"{Fore.CYAN}    {k}: {v}{Style.RESET_ALL}")
            if r.error:
                print(f"{Fore.YELLOW}  Note: {r.error}{Style.RESET_ALL}")
        elif verbose:
            if r.status == "closed":
                print(
                    f"{Fore.LIGHTBLACK_EX}Port {r.port}: closed ({r.error or 'no response'}){Style.RESET_ALL}"
                )
            else:
                print(f"{Fore.RED}Port {r.port}: error - {r.error or 'unknown'}{Style.RESET_ALL}")

    if not open_found:
        suffix = "" if verbose else " (use -v for closed/error details)"
        print(f"{Fore.YELLOW}No open QUIC/HTTP3 ports found{suffix}.{Style.RESET_ALL}")


def save_results(results: List[ScanResult], file_format: str, filename: str) -> None:
    if not results:
        print(f"{Fore.YELLOW}No results to save.{Style.RESET_ALL}")
        return

    if not filename:
        filename = f"quic_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_format}"
    else:
        base, ext = os.path.splitext(filename)
        if ext.lower() != f".{file_format.lower()}":
            filename = f"{base}.{file_format}"

    payload = [r.to_dict() for r in results]
    try:
        with open(filename, "w", encoding="utf-8") as f:
            if file_format == "json":
                json.dump(payload, f, indent=2, ensure_ascii=False)
            elif file_format == "txt":
                for item in payload:
                    f.write(f"Port {item['port']}:\n")
                    f.write(f"  Status: {item['status']}\n")
                    for k in ("protocol", "service", "version", "banner", "error"):
                        if item.get(k):
                            f.write(f"  {k.capitalize()}: {item[k]}\n")
                    if item.get("full_headers"):
                        f.write("  Full H3 Headers:\n")
                        for hk, hv in item["full_headers"].items():
                            f.write(f"    {hk}: {hv}\n")
                    f.write("\n")
            else:
                print(f"{Fore.RED}Unsupported format '{file_format}'.{Style.RESET_ALL}")
                return
        print(f"{Fore.GREEN}Results saved to {filename}{Style.RESET_ALL}")
    except OSError as exc:
        print(f"{Fore.RED}Error saving to {filename}: {exc}{Style.RESET_ALL}")


def _quiet_loop_exception_handler(loop, context):
    # aioquic's QuicConnectionProtocol sets ConnectionError on its internal
    # _connected_waiter when the peer drops; if our outer timeout fires first
    # the asyncio loop logs a noisy "Future exception was never retrieved".
    # These are benign for a port scanner that races handshakes — silence them.
    exc = context.get("exception")
    if isinstance(exc, ConnectionError) and "never retrieved" in context.get("message", ""):
        return
    loop.default_exception_handler(context)


async def amain() -> None:
    parser = argparse.ArgumentParser(
        description="Quicmap - QUIC/HTTP3 port scanner with banner grabbing",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("host", help="Target hostname or IP address")
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p",
        "--ports",
        default="443",
        help="Ports to scan, e.g. 80,443 or 1-1000 (default: 443)",
    )
    port_group.add_argument(
        "--scan-all-ports",
        action="store_true",
        help="Scan ports 1-65535. Overrides -p/--ports.",
    )
    parser.add_argument(
        "-s", "--server-name", help="SNI to send (defaults to host)."
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=3.0, help="Per-port timeout (s) (default: 3.0)"
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=100, help="Concurrent tasks (default: 100)"
    )
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "txt"],
        help="Output format (defaults inferred from -o extension, else json)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show closed/error ports and full H3 headers"
    )
    args = parser.parse_args()

    asyncio.get_running_loop().set_exception_handler(_quiet_loop_exception_handler)

    if args.scan_all_ports:
        ports = list(range(1, 65536))
        print(f"{Fore.YELLOW}Info: scanning all ports 1-65535.{Style.RESET_ALL}")
    else:
        ports = parse_ports(args.ports)

    if not ports:
        print(f"{Fore.RED}No valid ports specified. Exiting.{Style.RESET_ALL}")
        return

    sni = args.server_name or args.host
    print(
        f"{Fore.CYAN}Starting QUIC/HTTP3 scan on {Style.BRIGHT}{args.host}{Style.NORMAL}"
        f" (SNI: {sni}) for {len(ports)} port(s)...{Style.RESET_ALL}"
    )
    if args.verbose:
        print(
            f"{Fore.CYAN}Timeout: {args.timeout}s | Concurrency: {args.concurrency}{Style.RESET_ALL}"
        )

    results: List[ScanResult] = []
    try:
        results = await scan_ports_async(args.host, ports, sni, args.timeout, args.concurrency)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrupted by user.{Style.RESET_ALL}")
    except Exception as exc:
        print(f"\n{Fore.RED}Unexpected error: {type(exc).__name__}: {exc}{Style.RESET_ALL}")
        if args.verbose:
            import traceback

            traceback.print_exc()

    if results:
        print_results(results, args.verbose)
        if args.output:
            fmt = args.format
            if not fmt:
                _, ext = os.path.splitext(args.output)
                fmt = "txt" if ext.lower() == ".txt" else "json"
            save_results(results, fmt, args.output)


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
