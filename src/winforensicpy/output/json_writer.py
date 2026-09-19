"""
JSON output utilities for WinForensicPy.
"""

import json
from pathlib import Path


def save_json(data: list[dict], output_file: str) -> Path:
    """
    Save collected forensic data as a JSON file.

    Parameters
    ----------
    data : list[dict]
        Collected forensic records.

    output_file : str
        Destination JSON file.

    Returns
    -------
    Path
        Path of the generated JSON file.
    """

    output_path = Path(output_file)

    # Create the parent directory if it does not exist.
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open(
        mode="w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False
        )

    return output_path