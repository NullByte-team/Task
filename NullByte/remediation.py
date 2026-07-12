"""
NullByte Tool - Remediation Engine
Performs real upgrade / shutdown actions on discovered services.

For LOCAL targets: executes package manager and service control commands.
For REMOTE targets: reports that SSH is required and provides instructions.
"""

import platform
import subprocess
import socket
import shutil
import threading
from typing import Optional, Callable
from dataclasses import dataclass

# Service name → common package name mappings (nmap product name → pkg name)
_SERVICE_PKG_MAP = {
    "openssh":          {"apt": "openssh-server", "yum": "openssh-server",
                         "brew": "openssh",       "choco": "openssh",
                         "winget": "Microsoft.OpenSSH.Beta", "sc": "sshd"},
    "apache":           {"apt": "apache2",         "yum": "httpd",
                         "brew": "httpd",          "choco": "apache-httpd",
                         "winget": "Apache.ApacheHTTPServer", "sc": "Apache2.4"},
    "apache httpd":     {"apt": "apache2",         "yum": "httpd",
                         "brew": "httpd",          "choco": "apache-httpd",
                         "winget": "Apache.ApacheHTTPServer", "sc": "Apache2.4"},
    "nginx":            {"apt": "nginx",           "yum": "nginx",
                         "brew": "nginx",          "choco": "nginx",
                         "winget": "nginx.nginx",  "sc": "nginx"},
    "mysql":            {"apt": "mysql-server",    "yum": "mysql-server",
                         "brew": "mysql",          "choco": "mysql",
                         "winget": "Oracle.MySQL", "sc": "MySQL80"},
    "mariadb":          {"apt": "mariadb-server",  "yum": "mariadb-server",
                         "brew": "mariadb",        "choco": "mariadb",
                         "winget": "MariaDB.Server", "sc": "MariaDB"},
    "postgresql":       {"apt": "postgresql",      "yum": "postgresql-server",
                         "brew": "postgresql",     "choco": "postgresql",
                         "winget": "PostgreSQL.PostgreSQL", "sc": "postgresql"},
    "ftp":              {"apt": "vsftpd",           "yum": "vsftpd",
                         "brew": "",               "choco": "filezilla",
                         "winget": "", "sc": "ftpsvc"},
    "vsftpd":           {"apt": "vsftpd",           "yum": "vsftpd",
                         "brew": "",               "choco": "",
                         "winget": "", "sc": "ftpsvc"},
    "proftpd":          {"apt": "proftpd",          "yum": "proftpd",
                         "brew": "proftpd",        "choco": "",
                         "winget": "", "sc": ""},
    "smtp":             {"apt": "postfix",          "yum": "postfix",
                         "brew": "postfix",        "choco": "",
                         "winget": "", "sc": "SMTPSVC"},
    "postfix":          {"apt": "postfix",          "yum": "postfix",
                         "brew": "postfix",        "choco": "",
                         "winget": "", "sc": "SMTPSVC"},
    "telnet":           {"apt": "telnetd",          "yum": "telnet-server",
                         "brew": "",               "choco": "telnet",
                         "winget": "", "sc": "TlntSvr"},
    "samba":            {"apt": "samba",            "yum": "samba",
                         "brew": "samba",          "choco": "",
                         "winget": "", "sc": "lanmanserver"},
    "redis":            {"apt": "redis-server",     "yum": "redis",
                         "brew": "redis",          "choco": "redis",
                         "winget": "Redis.Redis",  "sc": "Redis"},
    "mongodb":          {"apt": "mongodb",          "yum": "mongodb",
                         "brew": "mongodb-community","choco": "mongodb",
                         "winget": "MongoDB.Server","sc": "MongoDB"},
    "iis":              {"apt": "",                 "yum": "",
                         "brew": "",               "choco": "",
                         "winget": "", "sc": "W3SVC"},
    "rdp":              {"apt": "",                 "yum": "",
                         "brew": "",               "choco": "",
                         "winget": "", "sc": "TermService"},
}


@dataclass
class RemediationResult:
    success: bool
    action:  str   # "upgrade" | "shutdown" | "restart"
    message: str
    details: str = ""


class RemediationEngine:
    """Handles upgrade and shutdown of services."""

    def __init__(self):
        self._os   = platform.system().lower()   # "windows" | "linux" | "darwin"
        self._pkgm = self._detect_package_manager()

    # ─────────────────────────────────────────────── public ──

    def is_local(self, host: str) -> bool:
        """Check if a host resolves to the local machine."""
        try:
            local_ips = {
                "127.0.0.1", "::1",
                socket.gethostbyname(socket.gethostname()),
            }
            return host in local_ips or host.lower() in ("localhost", "127.0.0.1")
        except Exception:
            return False

    def upgrade_service(
        self,
        host: str,
        service_name: str,
        product: str,
        on_output: Optional[Callable[[str], None]] = None,
    ) -> RemediationResult:
        """Upgrade a service to its latest patched version."""
        if not self.is_local(host):
            return RemediationResult(
                success=False,
                action="upgrade",
                message="Remote host — SSH access required",
                details=(
                    f"To upgrade {product or service_name} on {host}, SSH into the machine "
                    f"and run the appropriate package manager command.\n\n"
                    f"  Linux (apt):  sudo apt-get install --only-upgrade -y {self._get_pkg(service_name, 'apt')}\n"
                    f"  Linux (yum):  sudo yum update -y {self._get_pkg(service_name, 'yum')}\n"
                    f"  Windows:      winget upgrade --id {self._get_pkg(service_name, 'winget')} --silent"
                ),
            )

        pkg = self._get_pkg(service_name, self._pkgm)
        if not pkg:
            pkg = (product or service_name).lower().replace(" ", "-")

        if on_output:
            on_output(f"[*] Upgrading {pkg} using {self._pkgm} ...")

        try:
            cmd = self._build_upgrade_cmd(pkg)
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            output = (result.stdout + result.stderr).strip()

            if on_output:
                on_output(output or "[*] Upgrade completed")

            if result.returncode == 0:
                return RemediationResult(
                    success=True,
                    action="upgrade",
                    message=f"✅ {pkg} upgraded successfully.",
                    details=output,
                )
            else:
                return RemediationResult(
                    success=False,
                    action="upgrade",
                    message=f"❌ Upgrade failed (exit code {result.returncode})",
                    details=output,
                )
        except FileNotFoundError:
            return RemediationResult(
                success=False, action="upgrade",
                message=f"❌ Package manager '{self._pkgm}' not found",
                details="Please install a supported package manager.",
            )
        except subprocess.TimeoutExpired:
            return RemediationResult(
                success=False, action="upgrade",
                message="❌ Upgrade timed out (>120 s)",
                details="The operation took too long. Try manually.",
            )

    def shutdown_service(
        self,
        host: str,
        service_name: str,
        product: str,
        on_output: Optional[Callable[[str], None]] = None,
    ) -> RemediationResult:
        """Stop a service and disable it from auto-start."""
        if not self.is_local(host):
            return RemediationResult(
                success=False,
                action="shutdown",
                message="Remote host — SSH access required",
                details=(
                    f"To stop {product or service_name} on {host}:\n\n"
                    f"  Linux:    sudo systemctl stop {service_name} && sudo systemctl disable {service_name}\n"
                    f"  Windows:  sc stop \"{self._get_pkg(service_name, 'sc')}\" && sc config \"{service_name}\" start=disabled"
                ),
            )

        svc_sc = self._get_pkg(service_name, "sc") or service_name

        if on_output:
            on_output(f"[*] Stopping service: {svc_sc} ...")

        try:
            if self._os == "windows":
                r1 = subprocess.run(["sc", "stop", svc_sc],  capture_output=True, text=True, timeout=30)
                r2 = subprocess.run(["sc", "config", svc_sc, "start=disabled"], capture_output=True, text=True, timeout=10)
                out = (r1.stdout + r1.stderr + r2.stdout + r2.stderr).strip()
                success = r1.returncode == 0
            else:
                r1 = subprocess.run(["systemctl", "stop",    service_name], capture_output=True, text=True, timeout=30)
                r2 = subprocess.run(["systemctl", "disable", service_name], capture_output=True, text=True, timeout=10)
                out = (r1.stdout + r1.stderr + r2.stdout + r2.stderr).strip()
                success = r1.returncode in (0, 5)   # 5 = already stopped

            if on_output:
                on_output(out or "[*] Service stopped")

            if success:
                return RemediationResult(
                    success=True, action="shutdown",
                    message=f"🛑 {svc_sc} stopped and disabled.",
                    details=out,
                )
            else:
                return RemediationResult(
                    success=False, action="shutdown",
                    message=f"❌ Could not stop {svc_sc}",
                    details=out,
                )
        except FileNotFoundError as e:
            return RemediationResult(
                success=False, action="shutdown",
                message="❌ Service control command not found",
                details=str(e),
            )

    def restart_service(
        self,
        host: str,
        service_name: str,
        on_output: Optional[Callable[[str], None]] = None,
    ) -> RemediationResult:
        """Re-enable and restart a previously stopped service."""
        if not self.is_local(host):
            return RemediationResult(
                success=False, action="restart",
                message="Remote host — SSH access required",
                details=""
            )

        svc_sc = self._get_pkg(service_name, "sc") or service_name
        if on_output:
            on_output(f"[*] Restarting service: {svc_sc} ...")

        try:
            if self._os == "windows":
                r1 = subprocess.run(["sc", "config", svc_sc, "start=auto"], capture_output=True, text=True, timeout=10)
                r2 = subprocess.run(["sc", "start",  svc_sc],               capture_output=True, text=True, timeout=30)
                out = (r1.stdout + r1.stderr + r2.stdout + r2.stderr).strip()
                success = r2.returncode in (0, 1056)  # 1056 = already running
            else:
                r1 = subprocess.run(["systemctl", "enable",  service_name], capture_output=True, text=True, timeout=10)
                r2 = subprocess.run(["systemctl", "restart", service_name], capture_output=True, text=True, timeout=30)
                out = (r1.stdout + r1.stderr + r2.stdout + r2.stderr).strip()
                success = r2.returncode == 0

            if on_output:
                on_output(out or "[*] Done")

            if success:
                return RemediationResult(
                    success=True, action="restart",
                    message=f"▶️  {svc_sc} restarted and re-enabled.",
                    details=out,
                )
            else:
                return RemediationResult(
                    success=False, action="restart",
                    message=f"❌ Could not restart {svc_sc}",
                    details=out,
                )
        except FileNotFoundError as e:
            return RemediationResult(
                success=False, action="restart",
                message="❌ Service control command not found",
                details=str(e),
            )

    # ─────────────────────────────────────────────── private ──

    def _detect_package_manager(self) -> str:
        if self._os == "windows":
            if shutil.which("winget"):  return "winget"
            if shutil.which("choco"):   return "choco"
            return "winget"
        if self._os == "darwin":
            return "brew"
        # Linux — try common ones
        for pm in ("apt-get", "apt", "dnf", "yum", "zypper", "pacman"):
            if shutil.which(pm):
                return pm.replace("-get", "")   # normalize "apt-get" → "apt"
        return "apt"

    def _get_pkg(self, service_name: str, manager: str) -> str:
        """Look up the package name for a given service and manager."""
        key = service_name.lower()
        for svc_key, pkgs in _SERVICE_PKG_MAP.items():
            if svc_key in key or key in svc_key:
                return pkgs.get(manager, "") or ""
        return ""

    def _build_upgrade_cmd(self, pkg: str) -> list:
        """Build the upgrade command list for the current OS."""
        pm = self._pkgm
        if pm == "apt":
            return ["apt-get", "install", "--only-upgrade", "-y", pkg]
        if pm == "apt-get":
            return ["apt-get", "install", "--only-upgrade", "-y", pkg]
        if pm == "yum":
            return ["yum", "update", "-y", pkg]
        if pm == "dnf":
            return ["dnf", "upgrade", "-y", pkg]
        if pm == "brew":
            return ["brew", "upgrade", pkg]
        if pm == "choco":
            return ["choco", "upgrade", pkg, "-y"]
        if pm == "winget":
            return ["winget", "upgrade", "--id", pkg, "--silent", "--accept-package-agreements", "--accept-source-agreements"]
        if pm == "pacman":
            return ["pacman", "-Syu", "--noconfirm", pkg]
        return ["echo", f"No known upgrade command for {pm}"]
