"""
USB device forensic collector.

Collects USB mass-storage device information
from the Windows Registry.
"""

import winreg


class USBCollector:
    """Collect USB storage device information."""

    def get_name(self) -> str:
        """Return the name of this collector."""
        return "Windows USB Storage Collector"

    def collect(self) -> list[dict]:
        """
        Collect USB storage device information.

        Returns
        -------
        list[dict]
            USB storage device records.
        """

        registry_path = (
            r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        )

        results = []

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                registry_path
            ) as usb_key:

                device_count = winreg.QueryInfoKey(usb_key)[0]

                for device_index in range(device_count):

                    device_name = winreg.EnumKey(
                        usb_key,
                        device_index
                    )

                    device_path = (
                        f"{registry_path}\\{device_name}"
                    )

                    try:
                        with winreg.OpenKey(
                            winreg.HKEY_LOCAL_MACHINE,
                            device_path
                        ) as device_key:

                            instance_count = (
                                winreg.QueryInfoKey(device_key)[0]
                            )

                            for instance_index in range(
                                instance_count
                            ):

                                instance_name = winreg.EnumKey(
                                    device_key,
                                    instance_index
                                )

                                instance_path = (
                                    f"{device_path}\\"
                                    f"{instance_name}"
                                )

                                instance_values = {}

                                try:
                                    with winreg.OpenKey(
                                        winreg.HKEY_LOCAL_MACHINE,
                                        instance_path
                                    ) as instance_key:

                                        value_count = (
                                            winreg.QueryInfoKey(
                                                instance_key
                                            )[1]
                                        )

                                        for value_index in range(
                                            value_count
                                        ):

                                            value_name, value_data, _ = (
                                                winreg.EnumValue(
                                                    instance_key,
                                                    value_index
                                                )
                                            )

                                            instance_values[
                                                value_name
                                            ] = value_data

                                except (
                                    FileNotFoundError,
                                    PermissionError
                                ):
                                    pass

                                results.append(
                                    {
                                        "device_name": device_name,
                                        "instance_name": instance_name,
                                        "registry_path": instance_path,
                                        "registry_values": instance_values,
                                    }
                                )

                    except (
                        FileNotFoundError,
                        PermissionError
                    ):
                        continue

        except (
            FileNotFoundError,
            PermissionError
        ):
            return results

        return results