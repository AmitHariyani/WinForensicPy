"""
Evidence management utilities for WinForensicPy.

Provides a reusable workflow for saving forensic evidence,
calculating its SHA-256 hash, and creating metadata.
"""

from pathlib import Path

from winforensicpy.output.json_writer import save_json
from winforensicpy.output.metadata_writer import save_metadata
from winforensicpy.utils.hash_utils import calculate_sha256
from winforensicpy.utils.hash_writer import save_sha256


def save_evidence(
    data: list[dict],
    evidence_file: str,
    collector_name: str,
) -> dict:
    """
    Save forensic evidence and associated integrity information.

    Parameters
    ----------
    data : list[dict]
        Collected forensic records.

    evidence_file : str
        Destination JSON file.

    collector_name : str
        Name of the collector.

    Returns
    -------
    dict
        Paths and hash information for the generated evidence.
    """

    evidence_path = save_json(data, evidence_file)

    sha256_hash = calculate_sha256(str(evidence_path))

    hash_path = save_sha256(
        str(evidence_path),
        sha256_hash
    )

    metadata_path = save_metadata(
        str(evidence_path),
        collector_name,
        sha256_hash
    )

    return {
        "evidence_file": str(evidence_path),
        "sha256_file": str(hash_path),
        "metadata_file": str(metadata_path),
        "sha256": sha256_hash,
    }