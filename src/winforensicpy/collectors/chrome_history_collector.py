"""
Google Chrome browser history forensic collector.

Collects browsing history from the Chrome SQLite
History database.
"""

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path


class ChromeHistoryCollector:
    """Collect Google Chrome browsing history."""

    def get_name(self) -> str:
        """Return the name of this collector."""
        return "Google Chrome History Collector"

    def _get_history_path(self) -> Path:
        """
        Return the default Chrome History database path.

        Returns
        -------
        Path
            Chrome History database path.
        """

        local_app_data = os.environ.get("LOCALAPPDATA")

        if not local_app_data:
            raise EnvironmentError(
                "LOCALAPPDATA environment variable is not available."
            )

        return (
            Path(local_app_data)
            / "Google"
            / "Chrome"
            / "User Data"
            / "Default"
            / "History"
        )

    def collect(self, max_records: int = 100) -> list[dict]:
        """
        Collect recent Chrome browsing history.

        Parameters
        ----------
        max_records : int
            Maximum number of history records to collect.

        Returns
        -------
        list[dict]
            Chrome browsing history records.
        """

        history_path = self._get_history_path()

        if not history_path.exists():
            raise FileNotFoundError(
                f"Chrome History database was not found: "
                f"{history_path}"
            )

        temporary_directory = Path(
            tempfile.mkdtemp(
                prefix="winforensicpy_chrome_"
            )
        )

        temporary_database = (
            temporary_directory / "History"
        )

        try:
            shutil.copy2(
                history_path,
                temporary_database
            )

            connection = sqlite3.connect(
                temporary_database
            )

            try:
                cursor = connection.cursor()

                cursor.execute(
                    """
                    SELECT
                        urls.url,
                        urls.title,
                        urls.visit_count,
                        urls.last_visit_time
                    FROM urls
                    ORDER BY urls.last_visit_time DESC
                    LIMIT ?
                    """,
                    (max_records,)
                )

                rows = cursor.fetchall()

            finally:
                connection.close()

            results = []

            for row in rows:

                url, title, visit_count, last_visit_time = row

                results.append(
                    {
                        "url": url,
                        "title": title,
                        "visit_count": visit_count,
                        "last_visit_time": last_visit_time,
                    }
                )

            return results

        finally:
            shutil.rmtree(
                temporary_directory,
                ignore_errors=True
            )