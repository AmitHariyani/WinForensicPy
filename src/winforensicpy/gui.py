"""
WinForensicPy Graphical User Interface.

Provides the main Windows GUI for forensic artifact collection.
"""

import json
import tkinter as tk
from tkinter import ttk

from winforensicpy.collector_runner import CollectorRunner


class EvidenceViewer:
    """Display collected forensic evidence."""

    def __init__(
        self,
        parent,
        results: list[dict],
    ):
        """Initialize the Evidence Viewer."""

        self.parent = parent
        self.results = results

        self.window = tk.Toplevel(parent)

        self.window.title(
            "WinForensicPy - Forensic Evidence Viewer"
        )

        self.window.geometry("1200x750")
        self.window.minsize(1000, 650)

        self._create_header()
        self._create_notebook()

    def _create_header(self):
        """Create the evidence viewer header."""

        frame = ttk.Frame(
            self.window,
            padding=15
        )

        frame.pack(
            fill="x"
        )

        title = ttk.Label(
            frame,
            text="Forensic Evidence Viewer",
            font=("Segoe UI", 20, "bold")
        )

        title.pack(
            anchor="w"
        )

        subtitle = ttk.Label(
            frame,
            text=(
                "Collected Windows forensic artifacts "
                "and evidence integrity information"
            ),
            font=("Segoe UI", 10)
        )

        subtitle.pack(
            anchor="w",
            pady=(3, 0)
        )

    def _create_notebook(self):
        """Create tabs for each collected artifact."""

        self.notebook = ttk.Notebook(
            self.window
        )

        self.notebook.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=(0, 15)
        )

        for result in self.results:

            if result.get("status") == "SUCCESS":

                self._create_artifact_tab(
                    result
                )

            else:

                self._create_error_tab(
                    result
                )

    def _create_artifact_tab(self, result: dict):
        """Create a tab for a successfully collected artifact."""

        artifact_name = result["artifact"]

        frame = ttk.Frame(
            self.notebook
        )

        self.notebook.add(
            frame,
            text=artifact_name
        )

        self._create_summary(
            frame,
            result
        )

        records = result.get(
            "records",
            []
        )

        self._create_records_table(
            frame,
            records
        )

    def _create_summary(
        self,
        parent,
        result: dict
    ):
        """Create evidence summary section."""

        frame = ttk.LabelFrame(
            parent,
            text="Evidence Summary",
            padding=10
        )

        frame.pack(
            fill="x",
            padx=10,
            pady=10
        )

        records = result.get(
            "records",
            []
        )

        sha256 = result.get(
            "sha256",
            ""
        )

        evidence_file = result.get(
            "evidence_file",
            ""
        )

        metadata_file = result.get(
            "metadata_file",
            ""
        )

        ttk.Label(
            frame,
            text=f"Artifact: {result['artifact']}",
            font=("Segoe UI", 10, "bold")
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=5,
            pady=3
        )

        ttk.Label(
            frame,
            text=f"Records Collected: {len(records)}"
        ).grid(
            row=1,
            column=0,
            sticky="w",
            padx=5,
            pady=3
        )

        ttk.Label(
            frame,
            text=f"SHA-256: {sha256}"
        ).grid(
            row=2,
            column=0,
            sticky="w",
            padx=5,
            pady=3
        )

        ttk.Label(
            frame,
            text=f"Evidence File: {evidence_file}"
        ).grid(
            row=3,
            column=0,
            sticky="w",
            padx=5,
            pady=3
        )

        ttk.Label(
            frame,
            text=f"Metadata File: {metadata_file}"
        ).grid(
            row=4,
            column=0,
            sticky="w",
            padx=5,
            pady=3
        )

    def _create_records_table(
        self,
        parent,
        records: list[dict]
    ):
        """Create a table containing forensic records."""

        frame = ttk.LabelFrame(
            parent,
            text="Collected Evidence Records",
            padding=10
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10)
        )

        if not records:

            ttk.Label(
                frame,
                text="No records were collected."
            ).pack(
                padx=10,
                pady=10
            )

            return

        columns = []

        for record in records:

            for key in record.keys():

                if key not in columns:

                    columns.append(key)

        table_frame = ttk.Frame(
            frame
        )

        table_frame.pack(
            fill="both",
            expand=True
        )

        table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        vertical_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=table.yview
        )

        horizontal_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=table.xview
        )

        table.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set
        )

        table.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        vertical_scrollbar.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        horizontal_scrollbar.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        table_frame.rowconfigure(
            0,
            weight=1
        )

        table_frame.columnconfigure(
            0,
            weight=1
        )

        for column in columns:

            heading = column.replace(
                "_",
                " "
            ).title()

            table.heading(
                column,
                text=heading
            )

            table.column(
                column,
                width=180,
                minwidth=100,
                anchor="w"
            )

        for record in records:

            values = []

            for column in columns:

                value = record.get(
                    column,
                    ""
                )

                if isinstance(
                    value,
                    (dict, list)
                ):

                    value = json.dumps(
                        value,
                        ensure_ascii=False
                    )

                values.append(
                    str(value)
                )

            table.insert(
                "",
                "end",
                values=values
            )

        table.bind(
            "<Double-1>",
            lambda event: self._show_record_details(
                table
            )
        )

        button_frame = ttk.Frame(
            frame
        )

        button_frame.pack(
            fill="x",
            pady=(8, 0)
        )

        view_button = ttk.Button(
            button_frame,
            text="View Selected Record",
            command=lambda: self._show_record_details(
                table
            )
        )

        view_button.pack(
            side="left"
        )

    def _create_error_tab(
        self,
        result: dict
    ):
        """Create a tab for an unavailable or failed artifact."""

        artifact_name = result.get(
            "artifact",
            "Unknown Artifact"
        )

        frame = ttk.Frame(
            self.notebook,
            padding=20
        )

        self.notebook.add(
            frame,
            text=artifact_name
        )

        status = result.get(
            "status",
            "ERROR"
        )

        ttk.Label(
            frame,
            text=f"Status: {status}",
            font=("Segoe UI", 14, "bold")
        ).pack(
            anchor="w",
            pady=(10, 10)
        )

        message = result.get(
            "message",
            "No additional information available."
        )

        text = tk.Text(
            frame,
            height=8,
            wrap="word"
        )

        text.pack(
            fill="x",
            pady=10
        )

        text.insert(
            "1.0",
            message
        )

        text.configure(
            state="disabled"
        )

    def _show_record_details(
        self,
        table: ttk.Treeview
    ):
        """Show complete details of a selected evidence record."""

        selection = table.selection()

        if not selection:

            return

        item = table.item(
            selection[0]
        )

        columns = table["columns"]

        values = item.get(
            "values",
            []
        )

        record = {}

        for index, column in enumerate(columns):

            if index < len(values):

                record[column] = values[index]

        detail_window = tk.Toplevel(
            self.window
        )

        detail_window.title(
            "Forensic Evidence - Record Details"
        )

        detail_window.geometry(
            "850x650"
        )

        frame = ttk.Frame(
            detail_window,
            padding=10
        )

        frame.pack(
            fill="both",
            expand=True
        )

        text = tk.Text(
            frame,
            wrap="word",
            font=("Consolas", 10)
        )

        scrollbar = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=text.yview
        )

        text.configure(
            yscrollcommand=scrollbar.set
        )

        text.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        scrollbar.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        frame.rowconfigure(
            0,
            weight=1
        )

        frame.columnconfigure(
            0,
            weight=1
        )

        formatted_record = json.dumps(
            record,
            indent=4,
            ensure_ascii=False
        )

        text.insert(
            "1.0",
            formatted_record
        )

        text.configure(
            state="disabled"
        )


class WinForensicPyGUI:
    """Main WinForensicPy graphical user interface."""

    def __init__(
        self,
        root: tk.Tk
    ):
        """Initialize the WinForensicPy GUI."""

        self.root = root

        self.root.title(
            "WinForensicPy - Windows Forensic Artifact Collection Tool"
        )

        self.root.geometry(
            "1000x700"
        )

        self.root.minsize(
            900,
            650
        )

        self.runner = CollectorRunner()

        self._create_header()
        self._create_artifact_panel()
        self._create_control_panel()
        self._create_status_panel()

    def _create_header(self):
        """Create the application header."""

        header = ttk.Frame(
            self.root,
            padding=15
        )

        header.pack(
            fill="x"
        )

        title = ttk.Label(
            header,
            text="WinForensicPy",
            font=("Segoe UI", 22, "bold")
        )

        title.pack(
            anchor="w"
        )

        subtitle = ttk.Label(
            header,
            text=(
                "Windows Forensic Artifact Collection Tool"
            ),
            font=("Segoe UI", 11)
        )

        subtitle.pack(
            anchor="w",
            pady=(3, 0)
        )

        version = ttk.Label(
            header,
            text="Version 0.1.0",
            font=("Segoe UI", 9)
        )

        version.pack(
            anchor="w",
            pady=(5, 0)
        )

    def _create_artifact_panel(self):
        """Create the forensic artifact selection panel."""

        frame = ttk.LabelFrame(
            self.root,
            text="Forensic Artifacts",
            padding=15
        )

        frame.pack(
            fill="x",
            padx=15,
            pady=(0, 10)
        )

        self.artifacts = {}

        artifact_names = [
            "System Information",
            "Registry Run Keys",
            "USB Storage Devices",
            "Security Event Logs",
            "PowerShell Event Logs",
            "Sysmon Event Logs",
            "Network Connections",
            "Running Processes",
            "Google Chrome History",
        ]

        for index, artifact in enumerate(
            artifact_names
        ):

            variable = tk.BooleanVar(
                value=False
            )

            checkbox = ttk.Checkbutton(
                frame,
                text=artifact,
                variable=variable
            )

            checkbox.grid(
                row=index // 2,
                column=index % 2,
                sticky="w",
                padx=10,
                pady=8
            )

            self.artifacts[artifact] = variable

    def _create_control_panel(self):
        """Create collection control buttons."""

        frame = ttk.Frame(
            self.root,
            padding=(15, 5)
        )

        frame.pack(
            fill="x"
        )

        select_all_button = ttk.Button(
            frame,
            text="Select All",
            command=self._select_all
        )

        select_all_button.pack(
            side="left",
            padx=(0, 8)
        )

        clear_button = ttk.Button(
            frame,
            text="Clear Selection",
            command=self._clear_selection
        )

        clear_button.pack(
            side="left",
            padx=(0, 8)
        )

        collect_button = ttk.Button(
            frame,
            text="Collect Selected Artifacts",
            command=self._collect_selected
        )

        collect_button.pack(
            side="right"
        )

    def _create_status_panel(self):
        """Create the collection status panel."""

        frame = ttk.LabelFrame(
            self.root,
            text="Collection Status",
            padding=10
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=(5, 15)
        )

        self.status_text = tk.Text(
            frame,
            height=12,
            wrap="word",
            state="disabled"
        )

        self.status_text.pack(
            fill="both",
            expand=True
        )

        self._write_status(
            "WinForensicPy is ready."
        )

    def _select_all(self):
        """Select all forensic artifacts."""

        for variable in self.artifacts.values():

            variable.set(True)

        self._write_status(
            "All forensic artifacts selected."
        )

    def _clear_selection(self):
        """Clear all artifact selections."""

        for variable in self.artifacts.values():

            variable.set(False)

        self._write_status(
            "Artifact selection cleared."
        )

    def _collect_selected(self):
        """Collect selected forensic artifacts."""

        selected = [
            name
            for name, variable in self.artifacts.items()
            if variable.get()
        ]

        if not selected:

            self._write_status(
                "Please select at least one forensic artifact."
            )

            return

        self._write_status("")
        self._write_status("=" * 60)
        self._write_status(
            "FORENSIC COLLECTION STARTED"
        )
        self._write_status("=" * 60)

        results = []

        for artifact in selected:

            self._write_status(
                f"\nCollecting: {artifact}"
            )

            try:

                result, records = self._run_collector(
                    artifact
                )

                result["artifact"] = artifact
                result["status"] = "SUCCESS"
                result["records"] = records

                results.append(
                    result
                )

                self._write_status(
                    "Status: SUCCESS"
                )

                self._write_status(
                    f"Records Collected: {len(records)}"
                )

                self._write_status(
                    f"SHA-256: {result['sha256']}"
                )

            except PermissionError as error:

                result = {
                    "artifact": artifact,
                    "status": "PERMISSION DENIED",
                    "message": str(error),
                    "records": [],
                }

                results.append(
                    result
                )

                self._write_status(
                    "Status: PERMISSION DENIED"
                )

                self._write_status(
                    str(error)
                )

            except FileNotFoundError as error:

                result = {
                    "artifact": artifact,
                    "status": "NOT AVAILABLE",
                    "message": str(error),
                    "records": [],
                }

                results.append(
                    result
                )

                self._write_status(
                    "Status: NOT AVAILABLE"
                )

                self._write_status(
                    str(error)
                )

            except Exception as error:

                result = {
                    "artifact": artifact,
                    "status": "ERROR",
                    "message": str(error),
                    "records": [],
                }

                results.append(
                    result
                )

                self._write_status(
                    "Status: ERROR"
                )

                self._write_status(
                    str(error)
                )

        self._write_status("")
        self._write_status("=" * 60)
        self._write_status(
            "FORENSIC COLLECTION COMPLETED"
        )
        self._write_status("=" * 60)

        if results:

            EvidenceViewer(
                self.root,
                results
            )

    def _run_collector(
        self,
        artifact: str
    ):
        """
        Execute the collector associated with an artifact.

        Returns
        -------
        tuple
            Collection result and collected records.
        """

        if artifact == "System Information":

            result = self.runner.run_system_info()

        elif artifact == "Registry Run Keys":

            result = self.runner.run_registry()

        elif artifact == "USB Storage Devices":

            result = self.runner.run_usb()

        elif artifact == "Security Event Logs":

            result = self.runner.run_security_events(
                max_records=100
            )

        elif artifact == "PowerShell Event Logs":

            result = self.runner.run_powershell_events(
                max_records=100
            )

        elif artifact == "Network Connections":

            result = self.runner.run_network()

        elif artifact == "Running Processes":

            result = self.runner.run_processes()

        elif artifact == "Google Chrome History":

            result = self.runner.run_chrome_history(
                max_records=100
            )

        elif artifact == "Sysmon Event Logs":

            raise FileNotFoundError(
                "Sysmon Event Log channel is not available "
                "on this Windows host. Sysmon may not be "
                "installed or configured."
            )

        else:

            raise ValueError(
                f"Unknown artifact: {artifact}"
            )

        with open(
            result["evidence_file"],
            "r",
            encoding="utf-8"
        ) as file:

            records = json.load(file)

        return result, records

    def _write_status(
        self,
        message: str
    ):
        """Write a message to the status area."""

        self.status_text.configure(
            state="normal"
        )

        self.status_text.insert(
            "end",
            message + "\n"
        )

        self.status_text.see(
            "end"
        )

        self.status_text.configure(
            state="disabled"
        )


def start_gui():
    """Start the WinForensicPy graphical interface."""

    root = tk.Tk()

    WinForensicPyGUI(
        root
    )

    root.mainloop()


if __name__ == "__main__":
    start_gui()