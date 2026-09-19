"""
Windows process information forensic collector.

Collects running process information from the
Windows host.
"""

import psutil


class ProcessCollector:
    """Collect running process information."""

    def get_name(self) -> str:
        """Return the name of this collector."""
        return "Windows Process Information Collector"

    def collect(self) -> list[dict]:
        """
        Collect information about running processes.

        Returns
        -------
        list[dict]
            Running process records.
        """

        results = []

        for process in psutil.process_iter(
            [
                "pid",
                "ppid",
                "name",
                "username",
                "exe",
                "cmdline",
                "status",
                "create_time",
            ]
        ):

            try:
                information = process.info

                results.append(
                    {
                        "process_id": information.get("pid"),
                        "parent_process_id": information.get("ppid"),
                        "name": information.get("name"),
                        "username": information.get("username"),
                        "executable": information.get("exe"),
                        "command_line": information.get("cmdline"),
                        "status": information.get("status"),
                        "create_time": information.get("create_time"),
                    }
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                continue

        return results