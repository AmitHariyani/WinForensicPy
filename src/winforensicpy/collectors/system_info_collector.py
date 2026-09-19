"""
Windows system information collector.

Collects basic host information for forensic documentation.
"""

import platform
import socket
import getpass


class SystemInfoCollector:
    """Collect basic Windows host information."""

    def get_name(self) -> str:
        """Return the name of this collector."""
        return "Windows System Information Collector"

    def collect(self) -> dict:
        """
        Collect basic Windows system information.

        Returns
        -------
        dict
            System information collected from the host.
        """

        return {
            "hostname": socket.gethostname(),
            "username": getpass.getuser(),
            "operating_system": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
        }