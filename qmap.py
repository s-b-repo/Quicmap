import asyncio
import ssl
from enum import Enum
from typing import Optional, Dict
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
import argparse
import json
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class ScanResult:
    def __init__(self, port: int):
        self.port = port
        self.status: str = "closed"
        self.protocol: Optional[str] = None
        self.service: Optional[str] = None
        self.version: Optional[str] = None
        self.banner: Optional[str] = None
        self.error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "status": self.status,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "error": self.error
        }

class Protocol(Enum):
    HTTP3 = "HTTP/3"
    QUIC = "QUIC"

async def fetch_http3_banner(quic_connection, timeout: float) -> Dict:
    """Attempt to retrieve HTTP/3 server headers"""
    try:
        h3_connection = H3Connection(quic_connection)
        stream_id = quic_connection.get_next_available_stream_id()
        
        # Send a HEAD request to get headers
        h3_connection.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"HEAD"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/"),
                (b"user-agent", b"QUIC-Scanner/1.0"),
            ],
        )
        quic_connection.send_stream_data(stream_id, b"", end_stream=True)

        # Wait for response
        start_time = asyncio.get_event_loop().time()
        while True:
            event = await asyncio.wait_for(quic_connection.next_event(), timeout=timeout)
            if isinstance(event, HeadersReceived):
                return {
                    "service": Protocol.HTTP3.value,
                    "headers": {k.decode(): v.decode() for (k, v) in event.headers}
                }
            if (asyncio.get_event_loop().time() - start_time) > timeout:
                raise asyncio.TimeoutError()
    except Exception as e:
        raise

async def check_quic_port(host: str, port: int, server_name: str, timeout: float) -> ScanResult:
    result = ScanResult(port)
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.verify_mode = ssl.CERT_NONE
    configuration.idle_timeout = timeout

    try:
        async with connect(
            host=host,
            port=port,
            configuration=configuration,
            server_name=server_name,
        ) as connection:
            result.status = "open"
            result.protocol = connection._quic.alpn_protocol or "unknown"

            # Detect HTTP/3 service
            if connection._quic.alpn_protocol in H3_ALPN:
                try:
                    http_info = await asyncio.wait_for(
                        fetch_http3_banner(connection, timeout/2),
                        timeout=timeout/2
                    )
                    result.service = http_info["service"]
                    headers = http_info["headers"]
                    result.version = headers.get("server", "Unknown")
                    if "server" in headers:
                        result.banner = f"{headers['server']} ({result.protocol})"
                except Exception as e:
                    result.error = f"HTTP3 detection failed: {str(e)}"
            else:
                result.service = Protocol.QUIC.value
                result.banner = f"QUIC service ({result.protocol})"

    except Exception as e:
        result.error = str(e)
        result.status = "error"

    return result

async def scan_ports(host: str, ports: list, server_name: str, timeout: float) -> list:
    tasks = [check_quic_port(host, port, server_name, timeout) for port in ports]
    return await asyncio.gather(*tasks)

def print_results(results: list[ScanResult], verbose: bool = False):
    for result in results:
        if result.status == "open":
            color = Fore.GREEN
            details = [
                f"Port {result.port}",
                f"Service: {result.service}",
                f"Version: {result.version}" if result.version else "",
                f"Banner: {result.banner}" if result.banner else ""
            ]
            print(f"{color}{Style.BRIGHT}{' | '.join(filter(None, details))}")
            if verbose and result.error:
                print(f"{Fore.YELLOW}  Error: {result.error}")
        elif result.status == "error" and verbose:
            print(f"{Fore.RED}Port {result.port}: Error - {result.error}")

def save_results(results: list[ScanResult], format: str = "json", filename: str = None):
    if not filename:
        filename = f"quic_scan_{datetime.now().strftime('%Y%m%d%H%M%S')}.{format}"
    
    data = [result.to_dict() for result in results]
    
    if format == "json":
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
    elif format == "txt":
        with open(filename, "w") as f:
            for item in data:
                f.write(f"Port {item['port']}: {item['status']}\n")
                if item['status'] == "open":
                    f.write(f"  Service: {item['service']}\n")
                    f.write(f"  Version: {item.get('version', 'Unknown')}\n")
    print(f"Results saved to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced QUIC Port Scanner")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", default="1-1000",
                       help="Port range (e.g., 80,443 or 1-1000)")
    parser.add_argument("-s", "--server-name", 
                       help="Server name indication (SNI) for TLS handshake")
    parser.add_argument("-t", "--timeout", type=float, default=3.0,
                       help="Connection timeout per port")
    parser.add_argument("-o", "--output", 
                       help="Output file name (supports .json or .txt)")
    parser.add_argument("-f", "--format", choices=["json", "txt"], default="json",
                       help="Output file format")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Show verbose output")

    args = parser.parse_args()
    ports = parse_ports(args.ports)  # Reuse previous parse_ports function

    print(f"{Fore.CYAN}Scanning {args.host} (QUIC) on {len(ports)} ports...{Style.RESET_ALL}")
    
    loop = asyncio.new_event_loop()
    results = loop.run_until_complete(
        scan_ports(args.host, ports, args.server_name or args.host, args.timeout)
    )

    print_results(results, args.verbose)
    
    if args.output:
        save_results(results, args.format, args.output)
