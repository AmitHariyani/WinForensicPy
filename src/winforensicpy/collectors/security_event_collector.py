"""
Windows Security Event Log collector.

Collects selected records from the Windows Security
Event Log for forensic analysis.
"""

import win32evtlog
import pywintypes


class SecurityEventCollector:
    """Collect Windows Security Event Log records."""

    def get_name(self) -> str:
        """Return the name of this collector."""
        return "Windows Security Event Log Collector"

    def collect(self, max_records: int = 100) -> list[dict]:
        """
        Collect recent Security Event Log records.

        Parameters
        ----------
        max_records : int
            Maximum number of records to collect.

        Returns
        -------
        list[dict]
            Security event records.

        Raises
        ------
        PermissionError
            If the Security Event Log cannot be accessed
            because the required Windows privilege is unavailable.
        """

        server = None
        log_name = "Security"

        try:
            handle = win32evtlog.OpenEventLog(
                server,
                log_name
            )
        except pywintypes.error as error:
            if error.winerror == 1314:
                raise PermissionError(
                    "Access to the Windows Security Event Log "
                    "requires appropriate Windows privileges. "
                    "Run WinForensicPy with Administrator privileges."
                ) from error

            raise

        results = []

        try:
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )

            while len(results) < max_records:

                events = win32evtlog.ReadEventLog(
                    handle,
                    flags,
                    0
                )

                if not events:
                    break

                for event in events:

                    results.append(
                        {
                            "record_number": event.RecordNumber,
                            "event_id": event.EventID & 0xFFFF,
                            "event_type": event.EventType,
                            "source_name": event.SourceName,
                            "computer_name": event.ComputerName,
                            "time_generated": str(
                                event.TimeGenerated
                            ),
                            "strings": event.StringInserts,
                        }
                    )

                    if len(results) >= max_records:
                        break

        finally:
            win32evtlog.CloseEventLog(handle)

        return results