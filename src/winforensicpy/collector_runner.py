"""
Central collector runner for WinForensicPy.

Provides a standardized workflow for executing
forensic artifact collectors.
"""

from pathlib import Path

from winforensicpy.collectors.registry_collector import (
    RegistryCollector,
)
from winforensicpy.collectors.system_info_collector import (
    SystemInfoCollector,
)
from winforensicpy.collectors.usb_collector import (
    USBCollector,
)
from winforensicpy.collectors.security_event_collector import (
    SecurityEventCollector,
)
from winforensicpy.collectors.powershell_event_collector import (
    PowerShellEventCollector,
)
from winforensicpy.collectors.network_collector import (
    NetworkCollector,
)
from winforensicpy.collectors.process_collector import (
    ProcessCollector,
)
from winforensicpy.collectors.chrome_history_collector import (
    ChromeHistoryCollector,
)

from winforensicpy.output.evidence_manager import (
    save_evidence,
)


class CollectorRunner:
    """Execute WinForensicPy forensic collectors."""

    def __init__(self, output_directory: str = "evidence_output"):
        """
        Initialize the collector runner.

        Parameters
        ----------
        output_directory : str
            Directory where evidence files are stored.
        """

        self.output_directory = Path(
            output_directory
        )

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    def run_registry(self) -> dict:
        """Collect Registry Run Key evidence."""

        collector = RegistryCollector()

        data = collector.collect_run_keys()

        return save_evidence(
            data,
            str(
                self.output_directory
                / "registry_run_keys.json"
            ),
            collector.get_name()
        )

    def run_system_info(self) -> dict:
        """Collect Windows system information."""

        collector = SystemInfoCollector()

        data = [collector.collect()]

        return save_evidence(
            data,
            str(
                self.output_directory
                / "system_info.json"
            ),
            collector.get_name()
        )

    def run_usb(self) -> dict:
        """Collect USB storage device information."""

        collector = USBCollector()

        data = collector.collect()

        return save_evidence(
            data,
            str(
                self.output_directory
                / "usb_devices.json"
            ),
            collector.get_name()
        )

    def run_security_events(
        self,
        max_records: int = 100
    ) -> dict:
        """Collect Windows Security Event Log records."""

        collector = SecurityEventCollector()

        data = collector.collect(
            max_records
        )

        return save_evidence(
            data,
            str(
                self.output_directory
                / "security_events.json"
            ),
            collector.get_name()
        )

    def run_powershell_events(
        self,
        max_records: int = 100
    ) -> dict:
        """Collect Windows PowerShell Event Log records."""

        collector = PowerShellEventCollector()

        data = collector.collect(
            max_records
        )

        return save_evidence(
            data,
            str(
                self.output_directory
                / "powershell_events.json"
            ),
            collector.get_name()
        )

    def run_network(self) -> dict:
        """Collect active network connections."""

        collector = NetworkCollector()

        data = collector.collect()

        return save_evidence(
            data,
            str(
                self.output_directory
                / "network_connections.json"
            ),
            collector.get_name()
        )

    def run_processes(self) -> dict:
        """Collect running process information."""

        collector = ProcessCollector()

        data = collector.collect()

        return save_evidence(
            data,
            str(
                self.output_directory
                / "processes.json"
            ),
            collector.get_name()
        )

    def run_chrome_history(
        self,
        max_records: int = 100
    ) -> dict:
        """Collect Google Chrome browsing history."""

        collector = ChromeHistoryCollector()

        data = collector.collect(
            max_records
        )

        return save_evidence(
            data,
            str(
                self.output_directory
                / "chrome_history.json"
            ),
            collector.get_name()
        )