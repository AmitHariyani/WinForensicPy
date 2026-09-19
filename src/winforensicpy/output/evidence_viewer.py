"""
WinForensicPy Evidence Viewer.

Provides a graphical window for viewing collected
forensic evidence records.
"""

import tkinter as tk
from tkinter import ttk
import json


class EvidenceViewer:
    """Display forensic evidence records in a GUI window."""

    def __init__(
        self,
        parent,
        artifact_name: str,
        records: list[dict],
        collection_result: dict,
    ):
        """Initialize the Evidence Viewer."""

        self.parent = parent
        self.artifact_name = artifact_name
        self.records = records
        self.collection_result = collection_result

        self.window = tk.Toplevel(parent)

        self.window.title(
            f"WinForensicPy - Evidence Viewer - {artifact_name}"
        )

        self.window.geometry("1100x700")
        self.window.minsize(900, 600)

        self._create_header()
        self._create_summary()
        self._create_table()
        self._create_buttons()

        self._display_records()

    def _create_header(self):
        """Create the viewer header."""

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
            font=("Segoe UI", 18, "bold")
        )

        title.pack(
            anchor="w"
        )

        artifact = ttk.Label(
            frame,
            text=f"Artifact: {self.artifact_name}",
            font=("Segoe UI", 11)
        )

        artifact.pack(
            anchor="w",
            pady=(5, 0)
        )

    def _create_summary(self):
        """Create evidence summary information."""

        frame = ttk.LabelFrame(
            self.window,
            text="Evidence Summary",
            padding=10
        )

        frame.pack(
            fill="x",
            padx=15,
            pady=(0, 10)
        )

        record_count = len(self.records)

        ttk.Label(
            frame,
            text=f"Records Collected: {record_count}"
        ).pack(
            anchor="w"
        )

        sha256 = self.collection_result.get(
            "sha256",
            ""
        )

        ttk.Label(
            frame,
            text=f"SHA-256: {sha256}"
        ).pack(
            anchor="w",
            pady=(3, 0)
        )

        evidence_file = self.collection_result.get(
            "evidence_file",
            ""
        )

        ttk.Label(
            frame,
            text=f"Evidence File: {evidence_file}"
        ).pack(
            anchor="w",
            pady=(3, 0)
        )

    def _create_table(self):
        """Create the evidence records table."""

        frame = ttk.Frame(
            self.window,
            padding=(15, 0)
        )

        frame.pack(
            fill="both",
            expand=True
        )

        self.table = ttk.Treeview(
            frame,
            show="headings"
        )

        vertical_scrollbar = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self.table.yview
        )

        horizontal_scrollbar = ttk.Scrollbar(
            frame,
            orient="horizontal",
            command=self.table.xview
        )

        self.table.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set
        )

        self.table.grid(
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

        frame.rowconfigure(
            0,
            weight=1
        )

        frame.columnconfigure(
            0,
            weight=1
        )

        self.table.bind(
            "<Double-1>",
            self._show_record_details
        )

    def _display_records(self):
        """Display evidence records in the table."""

        if not self.records:

            self.table["columns"] = (
                "message",
            )

            self.table.heading(
                "message",
                text="Information"
            )

            self.table.insert(
                "",
                "end",
                values=(
                    "No evidence records were collected.",
                )
            )

            return

        all_keys = []

        for record in self.records:

            for key in record.keys():

                if key not in all_keys:
                    all_keys.append(key)

        self.table["columns"] = all_keys

        for column in all_keys:

            self.table.heading(
                column,
                text=column.replace(
                    "_",
                    " "
                ).title()
            )

            self.table.column(
                column,
                width=180,
                minwidth=100
            )

        for record in self.records:

            values = []

            for key in all_keys:

                value = record.get(
                    key,
                    ""
                )

                if isinstance(
                    value,
                    (list, dict)
                ):
                    value = json.dumps(
                        value,
                        ensure_ascii=False
                    )

                values.append(
                    str(value)
                )

            self.table.insert(
                "",
                "end",
                values=values
            )

    def _create_buttons(self):
        """Create viewer action buttons."""

        frame = ttk.Frame(
            self.window,
            padding=15
        )

        frame.pack(
            fill="x"
        )

        view_button = ttk.Button(
            frame,
            text="View Selected Record",
            command=self._show_record_details
        )

        view_button.pack(
            side="left",
            padx=(0, 8)
        )

        close_button = ttk.Button(
            frame,
            text="Close",
            command=self.window.destroy
        )

        close_button.pack(
            side="right"
        )

    def _show_record_details(self, event=None):
        """Display complete details of the selected record."""

        selection = self.table.selection()

        if not selection:
            return

        item = self.table.item(
            selection[0]
        )

        values = item.get(
            "values",
            []
        )

        columns = self.table["columns"]

        details = {}

        for index, column in enumerate(columns):

            if index < len(values):

                details[column] = values[index]

        detail_window = tk.Toplevel(
            self.window
        )

        detail_window.title(
            "Evidence Record Details"
        )

        detail_window.geometry(
            "800x600"
        )

        text = tk.Text(
            detail_window,
            wrap="word"
        )

        scrollbar = ttk.Scrollbar(
            detail_window,
            orient="vertical",
            command=text.yview
        )

        text.configure(
            yscrollcommand=scrollbar.set
        )

        text.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(10, 0),
            pady=10
        )

        scrollbar.pack(
            side="right",
            fill="y",
            padx=(0, 10),
            pady=10
        )

        formatted = json.dumps(
            details,
            indent=4,
            ensure_ascii=False
        )

        text.insert(
            "1.0",
            formatted
        )

        text.configure(
            state="disabled"
        )