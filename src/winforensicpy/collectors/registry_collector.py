"""
Windows Registry Collector.

This module provides functionality for collecting
forensic information from the Windows Registry.
"""

import winreg


class RegistryCollector:
    """Collect forensic artifacts from the Windows Registry."""

    def __init__(self):
        """Initialize the Registry collector."""
        self.local_machine = winreg.HKEY_LOCAL_MACHINE
        self.current_user = winreg.HKEY_CURRENT_USER

    def get_name(self) -> str:
        """Return the name of this collector."""
        return "Windows Registry Collector"

    def collect_run_keys(self) -> list[dict]:
        """
        Collect Windows Registry Run Key entries.

        Returns
        -------
        list[dict]
            A list containing Registry Run Key information.
        """

        run_key_paths = [
            (
                "HKEY_LOCAL_MACHINE",
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
            ),
            (
                "HKEY_CURRENT_USER",
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
            ),
        ]

        results = []

        for hive_name, hive, key_path in run_key_paths:

            try:
                with winreg.OpenKey(hive, key_path) as key:

                    value_count = winreg.QueryInfoKey(key)[1]

                    for index in range(value_count):
                        value_name, value_data, value_type = (
                            winreg.EnumValue(key, index)
                        )

                        results.append(
                            {
                                "hive": hive_name,
                                "key_path": key_path,
                                "value_name": value_name,
                                "value_data": value_data,
                                "value_type": value_type,
                            }
                        )

            except FileNotFoundError:
                # The Registry key may not exist on every Windows system.
                continue

            except PermissionError:
                # Access may be restricted depending on the system.
                continue

        return results