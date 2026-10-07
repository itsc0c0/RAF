"""Per-workspace fingerprint key.

Vault never stores secret values. To recognize the same secret again (dedup,
allowlists) it stores ``HMAC-SHA256(key, value)`` where ``key`` is a random
per-workspace key kept in ``<workspace>/secrets/vault.key`` (mode 0600). Without
the key a fingerprint cannot be used to confirm a guessed secret offline.
Fingerprints are therefore workspace specific: copy the key file to share
allowlists between workspaces.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import secrets
import stat
from pathlib import Path

from raf.core.errors import IntegrityError

KEY_FILE = "vault.key"
FINGERPRINT_LENGTH = 32  # hex characters (128 bits of the HMAC)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def fingerprint(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:FINGERPRINT_LENGTH]


def _read_key(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise IntegrityError(
            f"Cannot open the Vault fingerprint key {path}.",
            reason=exc.strerror or type(exc).__name__,
            hint="The key must be a regular file (not a symlink) readable by you.",
        ) from exc
    with os.fdopen(fd, "r", encoding="ascii", errors="replace") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise IntegrityError(f"The Vault fingerprint key {path} is not a regular file.")
        if info.st_mode & 0o077:
            with contextlib.suppress(OSError):
                os.fchmod(handle.fileno(), 0o600)
        text = handle.read(256).strip()
    try:
        key = bytes.fromhex(text)
    except ValueError:
        key = b""
    if len(key) < 16:
        raise IntegrityError(
            f"The Vault fingerprint key {path} is corrupt.",
            hint="Restore it from a backup, or delete it to start over (existing fingerprints and allowlist "
            "entries will no longer match).",
        )
    return key


def load_or_create_key(secrets_dir: Path) -> bytes:
    """Return the workspace key, creating it (0600, exclusive create) on first use."""
    secrets_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        secrets_dir.chmod(0o700)
    path = secrets_dir / KEY_FILE
    with contextlib.suppress(FileNotFoundError):
        return _read_key(path)
    key = secrets.token_bytes(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
    except FileExistsError:
        return _read_key(path)  # created concurrently by another process
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(key.hex() + "\n")
    return key
