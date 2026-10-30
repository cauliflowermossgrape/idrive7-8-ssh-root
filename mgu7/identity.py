"""Per-enrollment SSH identity: generate a fresh key for a single head unit,
persist it next to the tool, and export it in every format a person might need
to connect (OpenSSH, PKCS#1, PKCS#8, PuTTY PPK, authorized_keys, fingerprints).

The generated public key is what gets embedded in the enrollment certificate
(signed by the PMO CA) and installed into the head unit, so the unit authorizes
this key - and only this key - for root SSH. Each car gets its own unique key;
no shared login key ships in the repo.
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import sshcli

if getattr(sys, "frozen", False):
    HERE = os.path.dirname(os.path.abspath(sys.executable))
else:
    HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENROLL_DIR = os.path.join(HERE, "data", "enrollments")

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(text):
    text = _SLUG_RE.sub("-", (text or "").strip())
    return text.strip("-") or "unit"


# --- ssh wire helpers (used by the PuTTY PPK writer) -----------------------

def _ssh_string(blob):
    return struct.pack(">I", len(blob)) + blob


def _ssh_mpint(value):
    if value == 0:
        return _ssh_string(b"")
    blob = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if blob[0] & 0x80:
        blob = b"\x00" + blob
    return _ssh_string(blob)


def _rsa_public_blob(numbers):
    return _ssh_string(b"ssh-rsa") + _ssh_mpint(numbers.e) + _ssh_mpint(numbers.n)


def openssh_authorized_key(private_key, comment=""):
    """The single-line ``ssh-rsa AAAA... comment`` authorized_keys form."""
    pub = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    return pub.decode("ascii") + ((" " + comment) if comment else "")


def to_ppk_v2(private_key, comment=""):
    """Serialise an RSA key as an unencrypted PuTTY private key (PPK v2).

    The format and MAC are the ones the repo's own ``mgu7.ppk.PPK`` reader
    expects, so the output round-trips back through this tool.
    """
    priv = private_key.private_numbers()
    pub = private_key.public_key().public_numbers()
    public_blob = _rsa_public_blob(pub)
    # PuTTY stores RSA private fields in the order d, p, q, iqmp.
    private_blob = (
        _ssh_mpint(priv.d)
        + _ssh_mpint(priv.p)
        + _ssh_mpint(priv.q)
        + _ssh_mpint(priv.iqmp)
    )
    comment_b = comment.encode("utf-8")
    mac_key = hashlib.sha1(b"putty-private-key-file-mac-key").digest()
    mac_data = (
        _ssh_string(b"ssh-rsa")
        + _ssh_string(b"none")
        + _ssh_string(comment_b)
        + _ssh_string(public_blob)
        + _ssh_string(private_blob)
    )
    mac = hmac.new(mac_key, mac_data, hashlib.sha1).hexdigest()

    def _lines(blob):
        text = base64.b64encode(blob).decode("ascii")
        return [text[i:i + 64] for i in range(0, len(text), 64)]

    pub_lines = _lines(public_blob)
    priv_lines = _lines(private_blob)
    out = ["PuTTY-User-Key-File-2: ssh-rsa", "Encryption: none", "Comment: " + comment]
    out.append("Public-Lines: %d" % len(pub_lines))
    out.extend(pub_lines)
    out.append("Private-Lines: %d" % len(priv_lines))
    out.extend(priv_lines)
    out.append("Private-MAC: " + mac)
    return ("\r\n".join(out) + "\r\n").encode("ascii")


def fingerprints(private_key):
    """Return the SHA256 (OpenSSH style) and MD5 (legacy, colon-hex) prints."""
    blob = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    raw = base64.b64decode(blob.split(b" ")[1])
    sha = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    md5 = hashlib.md5(raw).hexdigest()
    md5 = ":".join(md5[i:i + 2] for i in range(0, len(md5), 2))
    return {"sha256": "SHA256:" + sha, "md5": "MD5:" + md5}


class Identity:
    """A generated RSA login key plus every export format of it."""

    def __init__(self, private_key, comment):
        self.key = private_key
        self.comment = comment

    @classmethod
    def generate(cls, comment, bits=2048):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        return cls(key, comment)

    @classmethod
    def from_pem(cls, data, comment=""):
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("Only RSA identities are supported.")
        return cls(key, comment)

    # --- individual formats -------------------------------------------------

    def openssh_private(self):
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )

    def pkcs1_pem(self):
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

    def pkcs8_pem(self):
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def ppk(self):
        return to_ppk_v2(self.key, self.comment)

    def authorized_key(self):
        return openssh_authorized_key(self.key, self.comment)

    def spki_pem(self):
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def fingerprints(self):
        return fingerprints(self.key)

    # --- bundle -------------------------------------------------------------

    def formats(self):
        """Return {filename: bytes} for every exported format."""
        auth = self.authorized_key()
        fp = self.fingerprints()
        return {
            "id_rsa": self.openssh_private(),            # OpenSSH private (ssh -i)
            "id_rsa.pkcs1.pem": self.pkcs1_pem(),        # -----BEGIN RSA PRIVATE KEY-----
            "id_rsa.pkcs8.pem": self.pkcs8_pem(),        # -----BEGIN PRIVATE KEY-----
            "id_rsa.ppk": self.ppk(),                    # PuTTY / WinSCP
            "id_rsa.pub": (auth + "\n").encode("ascii"), # authorized_keys line
            "id_rsa.pub.pem": self.spki_pem(),           # SubjectPublicKeyInfo
            "fingerprints.txt": ("%s\n%s\n" % (fp["sha256"], fp["md5"])).encode("ascii"),
        }

    def write(self, directory, meta=None):
        """Write every format into *directory*; return the path map."""
        os.makedirs(directory, exist_ok=True)
        paths = {}
        for name, blob in self.formats().items():
            path = os.path.join(directory, name)
            with open(path, "wb") as f:
                f.write(blob)
            if name in ("id_rsa", "id_rsa.pkcs1.pem", "id_rsa.pkcs8.pem", "id_rsa.ppk"):
                # Lock the saved private key to the current user. On Windows a
                # plain chmod does NOT strip the inherited 'Users' read ACE, so
                # a manual `ssh -i data\enrollments\...\id_rsa` would be rejected
                # as an 'UNPROTECTED PRIVATE KEY FILE'. secure_key_file fixes it.
                sshcli.secure_key_file(path)
            paths[name] = path
        if meta is not None:
            path = os.path.join(directory, "metadata.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2, sort_keys=True)
            paths["metadata.json"] = path
        return paths


def enrollment_dir(vin=None):
    """A stable per-car directory: by VIN when known, else by UTC timestamp."""
    if vin:
        name = _slug(vin.upper())
    else:
        name = "unit-" + datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return os.path.join(ENROLL_DIR, name)


def load_or_create(vin=None, comment=None, bits=2048, reuse=True):
    """Return (identity, directory, created). Reuses an existing per-car key
    unless *reuse* is False, so re-running ``enable`` keeps the same key."""
    directory = enrollment_dir(vin)
    comment = comment or ("mgu-root@" + (vin.upper() if vin else "unit"))
    existing = os.path.join(directory, "id_rsa.pkcs8.pem")
    if reuse and os.path.isfile(existing):
        with open(existing, "rb") as f:
            return Identity.from_pem(f.read(), comment), directory, False
    return Identity.generate(comment, bits), directory, True


def describe(identity, paths):
    """A human-readable block listing every format and where it was saved."""
    fp = identity.fingerprints()
    lines = []
    lines.append("SSH identity (comment %r)" % identity.comment)
    lines.append("  fingerprint %s" % fp["sha256"])
    lines.append("  fingerprint %s" % fp["md5"])
    lines.append("  authorized_keys line:")
    lines.append("    " + identity.authorized_key())
    labels = [
        ("id_rsa", "OpenSSH private key  (ssh -i <file> root@<ip>)"),
        ("id_rsa.pkcs1.pem", "PKCS#1 PEM           (BEGIN RSA PRIVATE KEY)"),
        ("id_rsa.pkcs8.pem", "PKCS#8 PEM           (BEGIN PRIVATE KEY)"),
        ("id_rsa.ppk", "PuTTY PPK v2         (PuTTY / WinSCP)"),
        ("id_rsa.pub", "OpenSSH public       (authorized_keys)"),
        ("id_rsa.pub.pem", "Public SPKI PEM"),
        ("fingerprints.txt", "Fingerprints"),
    ]
    lines.append("  saved formats:")
    for name, label in labels:
        if name in paths:
            lines.append("    %-20s %s" % (label, paths[name]))
    return "\n".join(lines)
