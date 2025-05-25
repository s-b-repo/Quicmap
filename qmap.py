import asyncio
import ssl
from enum import Enum
from typing import Optional, Dict, List, Any
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived, H3Event
from aioquic.quic.events import StreamDataReceived # For generic banner grabbing
import argparse
import json
from datetime import datetime
from colorama import Fore, Style, init
import os # For os.strerror

# Initialize colorama
init(autoreset=True)

def parse_ports(ports_arg: str) -> List[int]:
    """Parse port range argument"""
    ports = []
    for part in ports_arg.split(','):
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 0 < start <= end < 65536: # Valid port range
                    ports.extend(range(start, end + 1))
                else:
                    print(f"{Fore.YELLOW}Warning: Invalid port range '{part}'. Skipping.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.YELLOW}Warning: Invalid format in port range '{part}'. Skipping.{Style.RESET_ALL}")
        else:
            try:
                port_num = int(part)
                if 0 < port_num < 65536: # Valid port number
                    ports.append(port_num)
                else:
                    print(f"{Fore.YELLOW}Warning: Invalid port number '{part}'. Skipping.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.YELLOW}Warning: Invalid port format '{part}'. Skipping.{Style.RESET_ALL}")
    return sorted(list(set(ports)))  # Remove duplicates and sort

class ScanResult:
    def __init__(self, port: int):
        self.port = port
        self.status: str = "closed"  # Default status
        self.protocol: Optional[str] = None
        self.service: Optional[str] = None
        self.version: Optional[str] = None # Primarily for HTTP/3 server header
        self.banner: Optional[str] = None # For H3 server or generic QUIC banner
        self.error: Optional[str] = None
        self.full_headers: Optional[Dict[str, str]] = None # For verbose H3 details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "status": self.status,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "error": self.error,
            "full_headers": self.full_headers
        }

class Protocol(Enum):
    HTTP3 = "HTTP/3"
    QUIC = "QUIC"

async def fetch_http3_banner(
    quic_connection: Any, # Actually aioquic.asyncio.QuicConnection
    timeout: float
) -> Dict[str, Any]:
    """Attempt to retrieve HTTP/3 server headers."""
    h3_connection = H3Connection(quic_connection.quic) # Use the core QUIC connection
    stream_id = quic_connection.get_next_available_stream_id()

    authority = quic_connection.configuration.server_name
    if not authority:
        raise ValueError("Server name (authority) not available in QUIC configuration for HTTP/3 request.")

    headers_to_send = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", authority.encode()),
        (b":path", b"/"),
        (b"user-agent", b"QUIC-Scanner/1.2"), # Updated version
    ]

    h3_connection.send_headers(stream_id=stream_id, headers=headers_to_send)
    quic_connection.send_stream_data(stream_id, b"", end_stream=True)

    received_headers_list: Optional[List[tuple[bytes, bytes]]] = None # Renamed for clarity
    stream_ended_flags = {"headers": False, "data": False}
    
    loop = asyncio.get_running_loop()
    start_time = loop.time()

    try:
        while not (stream_ended_flags["headers"] and stream_ended_flags["data"]):
            elapsed_time = loop.time() - start_time
            remaining_time = timeout - elapsed_time
            if remaining_time <= 0:
                raise asyncio.TimeoutError("Timeout while waiting for HTTP/3 response events.")

            quic_event = await asyncio.wait_for(quic_connection.next_event(), timeout=remaining_time)

            if quic_event is None:
                if not received_headers_list:
                    raise ConnectionAbortedError("QUIC connection closed before any H3 headers were received.")
                break 

            for h3_event in h3_connection.handle_event(quic_event):
                if h3_event.stream_id == stream_id:
                    if isinstance(h3_event, HeadersReceived):
                        received_headers_list = h3_event.headers
                        stream_ended_flags["headers"] = True 
                        if h3_event.stream_ended:
                           stream_ended_flags["data"] = True 
                    elif isinstance(h3_event, DataReceived):
                        if h3_event.stream_ended:
                            stream_ended_flags["data"] = True
                    
                    if received_headers_list and stream_ended_flags["headers"] and stream_ended_flags["data"]:
                        break 
            
            if received_headers_list and stream_ended_flags["headers"] and stream_ended_flags["data"]:
                break 

        if received_headers_list is None:
            raise EOFError("No HTTP/3 headers received from the server for the stream.")

        headers_dict = {k.decode(errors='replace'): v.decode(errors='replace') for (k, v) in received_headers_list}
        server_header = headers_dict.get('server', None)

        return {
            "service": Protocol.HTTP3.value,
            "headers": headers_dict,
            "version": server_header if server_header else "UnknownServer",
        }
    except Exception as e:
        raise 

async def fetch_generic_quic_banner(
    quic_connection: Any, # aioquic.asyncio.QuicConnection
    timeout: float
) -> Dict[str, Any]:
    """Attempt to retrieve a generic banner from a QUIC service by sending a probe."""
    stream_id = quic_connection.get_next_available_stream_id()
    
    # Common probe that might elicit a response from various services.
    # Other options: b"\r\n", b"VERSION\r\n", b"STATUS\r\n"
    probe_data = b"GET / HTTP/1.0\r\n\r\n" 

    try:
        quic_connection.send_stream_data(stream_id, probe_data, end_stream=True)
    except Exception as e: # Handle potential errors during send, e.g., if connection is closing
        return {"banner": None, "error": f"Failed to send probe: {e}"}


    banner_bytes = bytearray()
    stream_ended_flag = False # Renamed for clarity
    
    loop = asyncio.get_running_loop()
    start_time = loop.time()
    decoded_banner = None # Initialize

    try:
        while not stream_ended_flag:
            elapsed_time = loop.time() - start_time
            remaining_time = timeout - elapsed_time
            if remaining_time <= 0:
                # If we got some data before timeout, use it. Otherwise, raise timeout.
                if banner_bytes:
                    break 
                raise asyncio.TimeoutError("Timeout while waiting for generic QUIC banner data.")

            event = await asyncio.wait_for(quic_connection.next_event(), timeout=remaining_time)

            if event is None: # Connection closed
                break 
            
            if isinstance(event, StreamDataReceived) and event.stream_id == stream_id:
                banner_bytes.extend(event.data)
                if event.end_stream:
                    stream_ended_flag = True
            # Could also handle StreamReset if needed
            # elif isinstance(event, StreamReset) and event.stream_id == stream_id:
            #    stream_ended_flag = True
            #    # Optionally log stream reset as an error/note for the banner
        
        if banner_bytes:
            try:
                # Try decoding as UTF-8, replace errors. ASCII is a subset of UTF-8.
                decoded_banner = banner_bytes.decode('utf-8', errors='replace')
                # Limit banner length for display/storage
                max_banner_len = 256 # Increased slightly
                if len(decoded_banner) > max_banner_len:
                    decoded_banner = decoded_banner[:max_banner_len].strip() + "..."
                else:
                    decoded_banner = decoded_banner.strip() # Remove leading/trailing whitespace
            except Exception: # Broad catch for any decoding issue
                decoded_banner = f"[Binary data, {len(banner_bytes)} bytes]"
        
        return {"banner": decoded_banner if decoded_banner else None}

    except asyncio.TimeoutError:
        if banner_bytes: # Partial data received before timeout
            try:
                decoded_banner = banner_bytes.decode('utf-8', errors='replace').strip()
                max_banner_len = 256
                if len(decoded_banner) > max_banner_len:
                    decoded_banner = decoded_banner[:max_banner_len].strip() + "..."
                return {"banner": decoded_banner, "note": "Partial data due to timeout"}
            except Exception:
                 return {"banner": f"[Partial binary data, {len(banner_bytes)} bytes]", "note": "Partial data due to timeout"}
        return {"banner": None, "error": "Timeout waiting for banner"} # No data at all
    except Exception as e:
        return {"banner": None, "error": f"Error during banner grab: {type(e).__name__} - {str(e)}"}


async def check_quic_port(host: str, port: int, server_name_to_use: str, timeout: float) -> ScanResult:
    result = ScanResult(port)
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN 
    )
    configuration.verify_mode = ssl.CERT_NONE 
    configuration.idle_timeout = int(timeout + 10) # Increased QUIC idle timeout

    try:
        async with connect(
            host=host,
            port=port,
            configuration=configuration,
            server_name=server_name_to_use, 
            local_port=0, 
            wait_connected=True, 
            timeout=timeout 
        ) as connection: 
            result.status = "open"
            result.protocol = connection.alpn_protocol or "QUIC (no ALPN)"

            if connection.alpn_protocol in H3_ALPN:
                result.service = Protocol.HTTP3.value
                try:
                    http_info = await asyncio.wait_for(
                        fetch_http3_banner(connection, timeout),
                        timeout=timeout
                    )
                    result.version = http_info.get("version", "Unknown")
                    # For H3, banner is typically the server software from headers
                    result.banner = f"Server: {result.version}" 
                    result.full_headers = http_info.get("headers")
                except Exception as e:
                    result.error = (result.error + "; " if result.error else "") + \
                                   f"HTTP/3 banner fetch failed: {type(e).__name__} - {str(e)}"
                    # Fallback banner if H3 header fetch fails but ALPN was H3
                    result.banner = f"HTTP/3 (ALPN: {result.protocol}, Banner Error: {type(e).__name__})"
            else: # Generic QUIC or other QUIC-based protocol (non-H3)
                result.service = Protocol.QUIC.value
                try:
                    generic_banner_info = await asyncio.wait_for(
                        fetch_generic_quic_banner(connection, timeout),
                        timeout=timeout 
                    )
                    
                    if generic_banner_info.get("banner"):
                        result.banner = generic_banner_info["banner"]
                    else:
                        result.banner = f"Generic QUIC (ALPN: {result.protocol})" # Default if no banner data
                    
                    if generic_banner_info.get("error"):
                         result.error = (result.error + "; " if result.error else "") + \
                                       f"BannerInfo: {generic_banner_info['error']}"
                    if generic_banner_info.get("note"):
                         result.error = (result.error + "; " if result.error else "") + \
                                       f"BannerInfo: {generic_banner_info['note']}"


                except Exception as e:
                    result.error = (result.error + "; " if result.error else "") + \
                                   f"Generic QUIC banner attempt failed: {type(e).__name__} - {str(e)}"
                    result.banner = f"Generic QUIC (ALPN: {result.protocol}, Banner Error: {type(e).__name__})"
                
                # Refine banner message if no specific ALPN and no banner data
                if result.protocol == "QUIC (no ALPN)" and not (result.banner and result.banner.strip() and not result.banner.startswith("Generic QUIC")):
                    result.banner = "Generic QUIC (No ALPN, No specific banner)"


    except ConnectionRefusedError:
        result.status = "closed"
        result.error = "Connection refused"
    except asyncio.TimeoutError:
        result.status = "closed" 
        result.error = "Connection timeout"
    except OSError as e:
        if e.errno in [111, 113, 61]: # ECONNREFUSED, EHOSTUNREACH, also 61 for macos conn refused
            result.status = "closed"
        else:
            result.status = "error"
        result.error = f"OS Error: {os.strerror(e.errno)} (errno {e.errno})"
    except Exception as e:
        result.status = "error"
        result.error = f"General connection error: {type(e).__name__} - {str(e)}"

    return result

async def scan_ports_async(host: str, ports_to_scan: List[int], server_name: str, timeout: float, concurrency: int) -> List[ScanResult]:
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []

    async def _task_wrapper(port_num: int):
        async with semaphore:
            return await check_quic_port(host, port_num, server_name, timeout)

    for port in ports_to_scan:
        tasks.append(_task_wrapper(port))
        
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    final_results = []
    for i, res_or_exc in enumerate(results):
        if isinstance(res_or_exc, Exception):
            port_val = ports_to_scan[i] # Get original port for error reporting
            err_result = ScanResult(port_val)
            err_result.status = "error"
            err_result.error = f"Unhandled scanner exception for port {port_val}: {type(res_or_exc).__name__} - {str(res_or_exc)}"
            final_results.append(err_result)
        elif res_or_exc is not None: # Ensure it's a ScanResult instance
            final_results.append(res_or_exc)
    return final_results


def print_results(results: List[ScanResult], verbose: bool = False):
    open_ports_found = False
    for result in results:
        if result.status == "open":
            open_ports_found = True
            color = Fore.GREEN
            # Construct details, ensuring banner is distinct
            banner_display = ""
            if result.service == Protocol.HTTP3.value and result.full_headers:
                server_from_header = result.full_headers.get('server', result.version) # Prefer full header's server
                banner_display = f"H3 Server: {server_from_header}" if server_from_header else "H3 Service (No Server Header)"
            elif result.banner: # Generic QUIC banner or H3 fallback
                banner_display = f"Banner: {result.banner}"

            details = [
                f"Port {result.port}",
                f"Status: {result.status}",
                f"Protocol: {result.protocol}" if result.protocol else "",
                f"Service: {result.service}" if result.service else "",
            ]
            if result.service == Protocol.HTTP3.value and result.version and result.version != "UnknownServer" and not result.full_headers:
                 # Only show version if it's distinct and not part of a full H3 server banner already
                details.append(f"Version: {result.version}")

            if banner_display:
                details.append(banner_display)
            
            print(f"{color}{Style.BRIGHT}{' | '.join(filter(None, details))}{Style.RESET_ALL}")

            if verbose and result.full_headers:
                print(f"{Fore.CYAN}  Full H3 Headers:{Style.RESET_ALL}")
                for k, v_h in result.full_headers.items(): # Renamed v to v_h
                    print(f"{Fore.CYAN}    {k}: {v_h}{Style.RESET_ALL}")
            
            if result.error: 
                print(f"{Fore.YELLOW}  Note: {result.error}{Style.RESET_ALL}")

        elif verbose: 
            if result.status == "closed":
                print(f"{Fore.LIGHTBLACK_EX}Port {result.port}: Closed ({result.error or 'No response'}){Style.RESET_ALL}")
            elif result.status == "error":
                print(f"{Fore.RED}Port {result.port}: Error - {result.error or 'Unknown error'}{Style.RESET_ALL}")
    
    if not open_ports_found and not verbose : # If not verbose, and no open ports, explicitly say so.
        print(f"{Fore.YELLOW}No open QUIC/HTTP3 ports found (run with -v for details on closed/error ports).{Style.RESET_ALL}")
    elif not open_ports_found and verbose: # If verbose, and still no open ports
        print(f"{Fore.YELLOW}No open QUIC/HTTP3 ports found.{Style.RESET_ALL}")


def save_results(results: List[ScanResult], file_format: str = "json", filename: str = ""):
    if not results:
        print(f"{Fore.YELLOW}No results to save.{Style.RESET_ALL}")
        return

    actual_filename = filename
    if not actual_filename:
        actual_filename = f"quic_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_format}"
    
    if not actual_filename.lower().endswith(f".{file_format}"):
        # Ensure the filename includes the format extension if not already present.
        base, ext = os.path.splitext(actual_filename)
        if ext.lower() != f".{file_format.lower()}": # if extension is different or missing
             actual_filename = f"{base}.{file_format}"


    data_to_save = [result.to_dict() for result in results]

    try:
        with open(actual_filename, "w", encoding='utf-8') as f: # Added encoding
            if file_format == "json":
                json.dump(data_to_save, f, indent=2, ensure_ascii=False) # ensure_ascii=False for better unicode
            elif file_format == "txt":
                for item in data_to_save:
                    f.write(f"Port {item['port']}:\n")
                    f.write(f"  Status: {item['status']}\n")
                    if item.get('protocol'):
                        f.write(f"  Protocol: {item['protocol']}\n")
                    if item.get('service'):
                        f.write(f"  Service: {item['service']}\n")
                    if item.get('version') and item['service'] == Protocol.HTTP3.value : # Version more relevant for H3
                        f.write(f"  H3 Version/Server: {item['version']}\n")
                    if item.get('banner'):
                        f.write(f"  Banner: {item['banner']}\n")
                    if item.get('error'):
                        f.write(f"  Error: {item['error']}\n")
                    if item.get('full_headers'):
                        f.write(f"  Full H3 Headers:\n")
                        for k_h, v_h in item['full_headers'].items(): # Renamed k,v
                             f.write(f"    {k_h}: {v_h}\n")
                    f.write("\n")
            else:
                print(f"{Fore.RED}Error: Unsupported save format '{file_format}'.{Style.RESET_ALL}")
                return
        print(f"{Fore.GREEN}Results saved to {actual_filename}{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}Error saving results to {actual_filename}: {e}{Style.RESET_ALL}")


async def amain():
    parser = argparse.ArgumentParser(
        description="Advanced QUIC/HTTP3 Port Scanner with Banner Grabbing",
        formatter_class=argparse.RawTextHelpFormatter 
    )
    parser.add_argument("host", help="Target hostname or IP address")
    
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p", "--ports", default="443",
        help="Ports to scan. Examples:\n"
             "  80,443 (specific ports)\n"
             "  1-1000 (a range)\n"
             "  Default: 443"
    )
    port_group.add_argument(
        "--scan-all-ports", action="store_true",
        help="Scan all ports from 1 to 65535. Overrides -p/--ports."
    )
    
    parser.add_argument(
        "-s", "--server-name",
        help="Server Name Indication (SNI) for TLS handshake.\n"
             "Defaults to the target host if not provided."
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=3.0,
        help="Connection and operation timeout per port (seconds).\nDefault: 3.0"
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=100,
        help="Number of concurrent scanning tasks.\nDefault: 100"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file name. Format (json/txt) can be inferred\n"
             "from extension or set with --format.\n"
             "Example: scan_results.json or scan_results.txt"
    )
    parser.add_argument(
        "-f", "--format", choices=["json", "txt"],
        help="Output file format. Overrides inference from filename extension.\n"
             "If -o is used without an extension, defaults to json."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show verbose output, including closed/error ports and full H3 headers."
    )

    args = parser.parse_args()

    ports_to_scan: List[int]
    if args.scan_all_ports:
        ports_to_scan = list(range(1, 65536))
        print(f"{Fore.YELLOW}Info: --scan-all-ports active. Scanning ports 1-65535.{Style.RESET_ALL}")
    else:
        ports_to_scan = parse_ports(args.ports)
    
    if not ports_to_scan:
        print(f"{Fore.RED}No valid ports specified for scanning. Exiting.{Style.RESET_ALL}")
        return

    sni_host = args.server_name if args.server_name else args.host

    print(f"{Fore.CYAN}Starting QUIC/HTTP3 scan on {Style.BRIGHT}{args.host}{Style.NORMAL} (SNI: {sni_host}) for {len(ports_to_scan)} port(s)...{Style.RESET_ALL}")
    if args.verbose:
        if not args.scan_all_ports: # Don't print all 65k ports
            print(f"{Fore.CYAN}Ports: {', '.join(map(str, ports_to_scan))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Timeout per port: {args.timeout}s, Concurrency: {args.concurrency}{Style.RESET_ALL}")


    results: List[ScanResult] = []
    try:
        results = await scan_ports_async(args.host, ports_to_scan, sni_host, args.timeout, args.concurrency)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}An unexpected error occurred: {type(e).__name__} - {e}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc() # Print full traceback if verbose
    
    if results:
        print_results(results, args.verbose)
        if args.output:
            output_format_to_use = args.format # User's explicit choice
            if not output_format_to_use: # If format not explicitly set
                _, ext = os.path.splitext(args.output)
                if ext.lower() == ".txt":
                    output_format_to_use = "txt"
                else: # Default to json if extension is .json or missing/unknown
                    output_format_to_use = "json"
            
            save_results(results, output_format_to_use, args.output)
    elif not isinstance(results, list): 
         print(f"{Fore.RED}Scan did not return valid results.{Style.RESET_ALL}")


if __name__ == "__main__":
    # For Windows, selector event loop might be needed for aioquic in some cases,
    # though default ProactorEventLoop usually works. For other OS, default is fine.
    # if os.name == 'nt':
    #    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(amain())
