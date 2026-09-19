"""
Evidence metadata utilities for WinForensicPy.

Provides functionality for creating metadata associated
with collected forensic evidence.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


def save_metadata(
    evidence_file: str,
    collector_name: str,
    sha256_hash: str,
) -> Path:
    """
    Save metadata for a collected forensic evidence file.

    Parameters
    ----------
    evidence_file : str
        Path of the evidence file.

    collector_name : str
        Name of the collector that generated the evidence.

    sha256_hash : str
        SHA-256 hash of the evidence file.

    Returns
    -------
    Path
        Path of the generated metadata file.
    """

    evidence_path = Path(evidence_file)

    metadata = {
        "evidence_file": evidence_path.name,
        "collector": collector_name,
        "collection_time_utc": datetime.now(timezone.utc).isoformat(),
        "sha256": sha256_hash,
    }

    metadata_file = evidence_path.with_suffix(".metadata.json")

    with metadata_file.open(
        mode="w",
        encoding="utf-8"
    ) as file:

        json.dump(
            metadata,
            file,
            indent=4,
            ensure_ascii=False
        )

    return metadata_file