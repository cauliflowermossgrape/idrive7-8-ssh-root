"""Read-only coding backup, taken before a flash.

`flash` and `fix-key` invalidate the MGU's CAFD coding, which then has to be re-applied
afterwards (README, "Back up your coding before flashing"). This reads a full record of
the coding over the same ENET link the tool already uses, so the backup needs no extra
adapter or coding tool, and writes it next to a plain-text restore note.

Every read here is UDS 0x22 (ReadDataByIdentifier) in the default session: it opens no
diagnostic session, takes no SecurityAccess and sends no write. It cannot change the car.
"""
import datetime
import hashlib
import json
import os

from .hsfz import MGU, Profile, match_response

# A present identifier answers at once; an absent one answers with a negative response
# at once too, so the scan is paced by this short quiet window, not by the overall cap.
P_CODING = Profile('coding-scan', 2001, 80, 50, 0)

CODING_RANGE = (0x3000, 0x3FFF)       # the MGU's coding store
IDENT_RANGE = (0xF100, 0xF1FF)        # identification (part numbers, VIN, ...)
MAX_SILENT = 16                        # this many reads with no answer at all: the unit went quiet

RESTORE_NOTE = """MGU coding backup, taken read-only before a flash
VIN:   {vin}
Taken: {taken} UTC
CAFD:  {cafd}
SVK:   {svk}

Files
- coding_MGU.txt : the MGU's coding, byte for byte ({blocks} blocks, DID 0x3000-0x3FFF),
                   read twice and compared
- backup.json    : the same, plus the identification DIDs and the full SVK, as JSON
- SHA256SUMS     : checksums of the two files above

Restoring after a flash
The flash invalidates the CAFD coding; put it back with a coding tool (E-Sys or BimmerCode):
  1. Preferred: re-code HU_MGU by vehicle order (VO coding / "code by FA"). This rebuilds the
     coding for the car as it is optioned and is the most reliable path - see issue #10, where
     restoring a whole coding blob left settings resetting and VO coding fixed it, with root and
     the apps surviving.
  2. The byte-for-byte record above (coding_MGU.txt) is your reference to check the result
     against, or to write back block by block if you code by hand.
Navigation maps are not coding (they live on a separate disk partition), so the flash does not
touch them. BMW Digital Key pairings and some personal settings are lost on a flash regardless.
"""


def _read_did(client, dst, ident, profile=P_CODING):
    """Payload after `62 <DID>`, or None for a negative or absent identifier. Read only."""
    raw = client.request(dst, bytes((0x22, ident >> 8, ident & 0xFF)), profile)
    x = match_response(raw, dst)
    if x is None or x.negative:
        return None
    head = bytes((0x62, ident >> 8, ident & 0xFF))
    return x.data[3:] if x.data[:3] == head else None


def _scan(client, dst, first, last, label, log):
    log('  %s (0x%04X-0x%04X)...' % (label, first, last))
    found, silent = {}, 0
    for d in range(first, last + 1):
        body = _read_did(client, dst, d)
        if body is None:
            silent += 1
            if silent >= MAX_SILENT:
                log('    stopped at 0x%04X: the unit is no longer answering this range' % d)
                break
            continue
        silent = 0
        found['%04X' % d] = body.hex()
    log('    %d block(s)' % len(found))
    return found


def read_vin(client, dst=MGU):
    body = _read_did(client, dst, 0xF190)
    return body.decode('ascii', 'replace').strip('\x00 ') if body else None


def backup(client, svk, out_root, vin=None, log=print):
    """Read the MGU coding (twice, compared), identification and SVK, and write the backup.

    `client` is a connected EnetClient, `svk` the already-read Svk. Returns the backup dict;
    its 'verified' is True only when every coding block read the same both times.
    """
    vin = (vin or read_vin(client) or 'UNKNOWN').strip()
    taken = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    cafd = svk.find('CAFD')
    data = {
        'taken': taken, 'vin': vin,
        'svk': [str(r) for r in svk.records],
        'cafd': str(cafd) if cafd else 'none',
    }

    log('Reading the MGU coding and identification (read-only):')
    coding = _scan(client, MGU, *CODING_RANGE, 'coding', log)
    data['coding'] = coding
    data['identification'] = _scan(client, MGU, *IDENT_RANGE, 'identification', log)

    log('  verifying the coding (second read)...')
    diff = [d for d in coding if (_read_did(client, MGU, int(d, 16)) or b'').hex() != coding[d]]
    data['verified'] = not diff and bool(coding)
    log('    %s' % ('identical: %d blocks' % len(coding) if data['verified']
                    else ('differences in ' + ', '.join(diff)) if diff else 'no coding read'))

    folder = os.path.join(out_root, '%s-%s' % (datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S'),
                                               ''.join(c for c in vin if c.isalnum()) or 'UNKNOWN'))
    os.makedirs(folder)
    with open(os.path.join(folder, 'backup.json'), 'w') as f:
        json.dump(data, f, indent=1)
    with open(os.path.join(folder, 'coding_MGU.txt'), 'w') as f:
        f.write('# MGU (0x63) %s  VIN %s  %s UTC\n' % (data['cafd'], vin, taken))
        for d in sorted(coding):
            f.write('%s: %s\n' % (d, coding[d]))
    with open(os.path.join(folder, 'RESTORE.txt'), 'w') as f:
        f.write(RESTORE_NOTE.format(vin=vin, taken=taken, cafd=data['cafd'],
                                    svk=svk.summary(), blocks=len(coding)))
    with open(os.path.join(folder, 'SHA256SUMS'), 'w') as f:
        for name in ('backup.json', 'coding_MGU.txt', 'RESTORE.txt'):
            with open(os.path.join(folder, name), 'rb') as g:
                f.write('%s  %s\n' % (hashlib.sha256(g.read()).hexdigest(), name))

    data['folder'] = folder
    return data
