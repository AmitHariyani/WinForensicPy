"""
Windows Sysmon Event Log collector.

Collects Sysmon events from the Windows
Microsoft-Windows-Sysmon/Operational channel.
"""

import win32evtlog
import pywintypes


class SysmonEventCollector:
    """Collect Windows Sysmon Event Log records."""

    LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

    def get_name(self) -> str:
        """Return the name of this collector."""
        return "Windows Sysmon Event Log Collector"

    def collect(self, max_records: int = 100) -> list[dict]:
        """
        Collect recent Sysmon Event Log records.

        Parameters
        ----------
        max_records : int
            Maximum number of records to collect.

        Returns
        -------
        list[dict]
            Sysmon event records.

        Raises
        ------
        FileNotFoundError
            If the Sysmon Event Log channel does not exist.

        PermissionError
            If access to the channel is denied.
        """

        query = "*"

        try:
            query_handle = win32evtlog.EvtQuery(
                self.LOG_NAME,
                win32evtlog.EvtQueryReverseDirection,
                query,
            )

        except pywintypes.error as error:

            # Windows Event Log API uses error 15007
            # when the specified channel cannot be found.
            if error.winerror in (2, 15007):
                raise FileNotFoundError(
                    "The Sysmon Event Log channel was not found. "
                    "Sysmon may not be installed or configured "
                    "on this Windows host."
                ) from error

            # Access denied.
            if error.winerror == 5:
                raise PermissionError(
                    "Access to the Sysmon Event Log was denied. "
                    "Run WinForensicPy with appropriate privileges."
                ) from error

            raise RuntimeError(
                f"Unable to access the Sysmon Event Log: {error}"
            ) from error

        results = []

        try:

            while len(results) < max_records:

                events = win32evtlog.EvtNext(
                    query_handle,
                    min(10, max_records - len(results))
                )

                if not events:
                    break

                for event in events:

                    xml = win32evtlog.EvtRender(
                        event,
                        win32evtlog.EvtRenderEventXml
                    )

                    results.append(
                        {
                            "event_xml": xml,
                        }
                    )

                    if len(results) >= max_records:
                        break

        finally:
            win32evtlog.EvtClose(query_handle)

        return results