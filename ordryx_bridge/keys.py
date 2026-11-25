"""The bridge's key and signatures: the same ones Ordryx's own code makes and
checks, written here because the bridge is its own small program and carries
nothing of Ordryx's (a test of Ordryx's holds the two together). Written for
the older ``cryptography`` a Raspberry Pi's system may have too.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .calls import PRIVATE_NETWORKS

PROTOCOL = "ordryx-link/1"
KEY_FILE = "link.key"


def new_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def fingerprint(pub: str) -> str:
    """What a person compares by eye: 16 hex characters in fours."""
    raw = base64.urlsafe_b64decode(pub + "=" * (-len(pub) % 4))
    h = hashlib.sha256(raw).hexdigest()[:16].upper()
    return "-".join(h[i : i + 4] for i in range(0, 16, 4))


def sign(key: Ed25519PrivateKey, purpose: str, *parts: str) -> str:
    sig = key.sign("\n".join((PROTOCOL, purpose, *parts)).encode())
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def load(folder: Path) -> Ed25519PrivateKey | None:
    """Its key; None only when there's no file (a file that isn't a key raises:
    never quietly replaced by a new one)."""
    try:
        pem = (folder / KEY_FILE).read_bytes()
    except FileNotFoundError:
        return None
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("link.key isn't this bridge's kind of key")
    return key


def save(folder: Path, key: Ed25519PrivateKey) -> None:
    """Written whole or not at all, readable by the bridge's user only."""
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    tmp = folder / f".{KEY_FILE}.{os.getpid()}.partial"
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(pem)
    os.replace(tmp, folder / KEY_FILE)


def forget(folder: Path) -> None:
    (folder / KEY_FILE).unlink(missing_ok=True)


def private_ipv4(address) -> bool:
    """A private IPv4 address (RFC 1918) written exactly, as linkkeys'."""
    if not isinstance(address, str) or len(address) > 15:
        return False
    try:
        a = ipaddress.IPv4Address(address)
    except ValueError:
        return False
    return str(a) == address and any(a in n for n in PRIVATE_NETWORKS)
