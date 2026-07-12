"""
NullByte Tool - Network Scanner
Wraps python-nmap to perform comprehensive port/service/version scanning.
Results are returned via a callback for real-time UI updates.
"""

import nmap
import platform
import socket
import threading
from typing import Callable, Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class ServiceInfo:
    """Represents a discovered open port / service."""
    host:        str
    port:        int
    protocol:    str
    state:       str
    service:     str
    product:     str        # e.g. "OpenSSH"
    version:     str        # e.g. "8.9p1"
    extra_info:  str
    cpe:         str        # Common Platform Enumeration string
    script_out:  Dict[str, str] = field(default_factory=dict)

    @property
    def display_version(self) -> str:
        parts = [self.product, self.version, self.extra_info]
        return " ".join(p for p in parts if p).strip() or "Unknown"

    @property
    def search_query(self) -> str:
        """Query string for CVE lookup."""
        if self.product and self.version:
            return f"{self.product} {self.version}"
        if self.product:
            return self.product
        return self.service


@dataclass
class ScanResult:
    """Full result for one target host."""
    host:          str
    hostname:      str
    state:         str        # "up" / "down"
    os_guess:      str
    services:      List[ServiceInfo] = field(default_factory=list)
    raw_output:    str = ""


class Scanner:
    """
    Nmap-based network scanner.

    Usage:
        scanner = Scanner()
        scanner.scan(
            target="192.168.1.1",
            port_mode="top1000",   # "top1000" | "all" | "custom"
            custom_ports="22,80,443",
            on_host=callback,
            on_done=done_callback
        )
    """

    PORT_MODES = {
        "top1000": "--top-ports 1000",
        "all":     "-p 1-65535",
        "custom":  "",   # filled in dynamically
    }

    def __init__(self):
        self._nm = nmap.PortScanner()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ─────────────────────────────────────────────────────────────── public ──

    def scan(
        self,
        targets: List[str],
        port_mode: str = "top1000",
        custom_ports: str = "",
        on_host: Optional[Callable[[ScanResult], None]] = None,
        on_progress: Optional[Callable[[str], None]] = None,
        on_done: Optional[Callable[[List[ScanResult]], None]] = None,
    ) -> None:
        """
        Start a scan in a background thread.
        Callbacks are called from the worker thread — UI code must marshal
        to the main thread via root.after().
        """
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            args=(targets, port_mode, custom_ports, on_host, on_progress, on_done),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Request cancellation of the running scan."""
        self._stop_event.set()

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ─────────────────────────────────────────────────────────────── private ─

    def _build_args(self, port_mode: str, custom_ports: str) -> str:
        """Build nmap argument string."""
        base_args = "-sV --version-intensity 7 -T4 -O --osscan-guess"

        if port_mode == "top1000":
            port_arg = "--top-ports 1000"
        elif port_mode == "all":
            port_arg = "-p 1-65535"
        elif port_mode == "custom" and custom_ports:
            # Sanitize: allow only digits, commas, hyphens
            import re
            safe = re.sub(r"[^0-9,\-]", "", custom_ports)
            port_arg = f"-p {safe}" if safe else "--top-ports 1000"
        else:
            port_arg = "--top-ports 1000"

        # Try to enable script scanning for extra info
        script_arg = "--script=banner,http-title,ftp-anon,ssh-hostkey"

        return f"{base_args} {port_arg} {script_arg}"

    def _run(
        self,
        targets: List[str],
        port_mode: str,
        custom_ports: str,
        on_host,
        on_progress,
        on_done,
    ) -> None:
        results: List[ScanResult] = []
        args = self._build_args(port_mode, custom_ports)

        for target in targets:
            if self._stop_event.is_set():
                break

            if on_progress:
                on_progress(f"Scanning {target} ...")

            try:
                result = self._scan_single(target, args, on_progress)
                results.append(result)
                if on_host:
                    on_host(result)
            except Exception as exc:
                # Return an empty "down" result so the UI can show the error
                err_result = ScanResult(
                    host=target,
                    hostname="",
                    state="error",
                    os_guess="",
                    raw_output=str(exc),
                )
                results.append(err_result)
                if on_host:
                    on_host(err_result)

        if on_done:
            on_done(results)

    def _scan_single(self, target: str, args: str, on_progress) -> ScanResult:
        """Scan one host and return a ScanResult."""
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments=args)

        if not nm.all_hosts():
            # Host did not respond
            try:
                hostname = socket.gethostbyaddr(target)[0]
            except Exception:
                hostname = ""
            return ScanResult(host=target, hostname=hostname, state="down", os_guess="")

        host = nm.all_hosts()[0]
        host_data = nm[host]

        # ── Hostname ──────────────────────────────────────────────────────────
        hostnames = host_data.get("hostnames", [])
        hostname = hostnames[0]["name"] if hostnames else ""

        # ── State ─────────────────────────────────────────────────────────────
        state = host_data.get("status", {}).get("state", "unknown")

        # ── OS guess ──────────────────────────────────────────────────────────
        os_matches = host_data.get("osmatch", [])
        os_guess = os_matches[0]["name"] if os_matches else ""

        # ── Services ──────────────────────────────────────────────────────────
        services: List[ServiceInfo] = []
        for proto in ("tcp", "udp"):
            if proto not in host_data:
                continue
            for port_num, port_data in host_data[proto].items():
                if port_data.get("state") not in ("open", "open|filtered"):
                    continue

                svc_data = port_data
                cpe_list = svc_data.get("cpe", "")
                if isinstance(cpe_list, list):
                    cpe = cpe_list[0] if cpe_list else ""
                else:
                    cpe = cpe_list

                script_out = {}
                for sc_name, sc_output in svc_data.get("script", {}).items():
                    script_out[sc_name] = str(sc_output)

                svc = ServiceInfo(
                    host=host,
                    port=int(port_num),
                    protocol=proto,
                    state=svc_data.get("state", "open"),
                    service=svc_data.get("name", ""),
                    product=svc_data.get("product", ""),
                    version=svc_data.get("version", ""),
                    extra_info=svc_data.get("extrainfo", ""),
                    cpe=cpe,
                    script_out=script_out,
                )
                services.append(svc)

        # Sort by port number
        services.sort(key=lambda s: s.port)

        return ScanResult(
            host=host,
            hostname=hostname,
            state=state,
            os_guess=os_guess,
            services=services,
            raw_output=nm.get_nmap_last_output() or "",
        )


def resolve_hostname(target: str) -> str:
    """Resolve a hostname/domain to IP. Returns original if fails."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target
