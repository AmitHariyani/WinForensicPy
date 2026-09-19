"""
Windows network connection forensic collector.

Collects active TCP network connections and their
associated process IDs from the Windows host.
"""

import socket

import psutil


class NetworkCollector:
    """Collect active network connections."""

    def get_name(self) -> str:
        """Return the name of this collector."""
        return "Windows Network Connection Collector"

    def collect(self) -> list[dict]:
        """
        Collect active network connections.

        Returns
        -------
        list[dict]
            Active network connection records.
        """

        results = []

        connections = psutil.net_connections(
            kind="inet"
        )

        for connection in connections:

            local_address = self._format_address(
                connection.laddr
            )

            remote_address = self._format_address(
                connection.raddr
            )

            protocol = (
                "TCP"
                if connection.type == socket.SOCK_STREAM
                else "UDP"
            )

            results.append(
                {
                    "protocol": protocol,
                    "local_address": local_address,
                    "remote_address": remote_address,
                    "status": connection.status,
                    "process_id": connection.pid,
                }
            )

        return results

    @staticmethod
    def _format_address(address) -> str:
        """
        Convert a psutil address object into a string.

        Parameters
        ----------
        address : tuple or object
            Network address information.

        Returns
        -------
        str
            Formatted IP address and port.
        """

        if not address:
            return ""

        try:
            return f"{address.ip}:{address.port}"
        except AttributeError:
            return str(address)