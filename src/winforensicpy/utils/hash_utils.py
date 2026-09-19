"""
Hash utilities for WinForensicPy.

Provides cryptographic hashing functionality for
collected forensic evidence files.
"""

import hashlib
from pathlib import Path


def calculate_sha256(file_path: str) -> str:
    """
    Calculate the SHA-256 hash of a file.

    Parameters
    ----------
    file_path : str
        Path to the file.

    Returns
    -------
    str
        SHA-256 hexadecimal digest.
    """

    path = Path(file_path)

    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(block)

    return sha256.hexdigest()