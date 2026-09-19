"""
Hash output utilities for WinForensicPy.

Provides functionality for saving cryptographic hashes
of collected forensic evidence files.
"""

from pathlib import Path


def save_sha256(file_path: str, sha256_hash: str) -> Path:
    """
    Save a SHA-256 hash to a .sha256 file.

    Parameters
    ----------
    file_path : str
        Path of the evidence file.

    sha256_hash : str
        SHA-256 hash value.

    Returns
    -------
    Path
        Path of the generated hash file.
    """

    evidence_path = Path(file_path)

    hash_file = evidence_path.with_suffix(".sha256")

    with hash_file.open(
        mode="w",
        encoding="utf-8"
    ) as file:

        file.write(sha256_hash + "\n")

    return hash_file