# V2 payload + SWE-header findings

## Payload (pulled from a real working unit, "VM 6969")

- `usr/share/sshd/authorized_keys.root` — the root login key the unit trusts.
  Its public key is **byte-identical to `data/assets/05_SSH_ROOT_KEY.pem`**, so
  we already hold the matching private key and can log in once this file is in
  place.
- `etc/…` (from `alwayson.tar`) — the always-on persistence set: `sshd.socket`
  override, `sshd-always-on-fw.service`, `keep-port22-open.sh`, and five
  `*.target.wants` symlinks (see `LINKS.txt`).
- Documented install (needs root on the unit):
  `mount -o remount,rw /` → `tar xf alwayson.tar -C /` → `systemctl daemon-reload`
  → `mount -o remount,ro /`.

## CORRECTION: there is NO unsigned file-drop region (earlier claim was wrong)

An earlier version of this file claimed the flash drops `debugCA.pem` through a
*separate unsigned region at `0xf0a000`*, and that we could add our key the same
way. **The full flash journal (`checkthis/flash_journal_20261020.log`) disproves
that.** Byte-by-byte, the real flash is two passes:

**Pass 1 (≈14:44:55) is a decoy/probe — nothing in it finalizes:**

| frame | TX | ECU response | meaning |
|-------|----|--------------|---------|
| 30 | `34 00 44 00F08000 01337000` (bogus huge size) | `74 …` positive | opens an `f08000` download |
| 31 | `34 00 44 00F0A000 00000637` | **`7F 34 22`** | `f0a000` download **REJECTED** (sequence error — `f08000` still open) |
| 32–33 | `36 01 …`, `36 02 …` (debugCA HAR) | `76 …` positive | the debugCA bytes land in the still-open **`f08000`** download, NOT at `f0a000` |
| 34 | `37` (finish) | **`7F 37 72`** | finish **REJECTED** — that `f08000` write is **discarded** |
| 35–36 | `31 01 …` routines | **`7F 31 22`** | apply routines **REJECTED** |

**Pass 2 (≈14:45:37) is the real flash:** `f08000` is re-opened with the *real*
size `0x1e774` (`34 00 44 00F08000 0001E774` → `74 …` positive), the big
**BMW-signed** blob is transferred, finished cleanly (`71 01 FF 01 01`), and the
gateway apply routines `31 01 0F 0C 00` / `31 01 10 0F` succeed (`71 …`).

The `f0a000` **RequestDownload** is rejected, but the debugCA HAR bytes are still
transferred (positively ACKed, `76 01` / `76 02`) into the `f08000` download that
frame 30 left open with the bogus `0x1337000` size. That archive has a **zeroed
header hash** and is **not referenced by the signed manifest** — it is the one
unchecked file the flash carries. The signed content is the big BMW-signed blob
written to `f08000` in pass 2 (`0x1e774`, finished cleanly); that one we cannot
modify or re-sign.

### The fix-key repair (what the tool now does)

`ssh_enable.py fix-key` re-runs the **exact** proven debug contract, changing
nothing except the bytes inside that one unsigned region: it swaps the debugCA
archive for a one-file `HAR#$%&@` that installs `/usr/share/sshd/authorized_keys.root`
= the OpenSSH public line of asset 05 (`SHA256:boqf5v7...`, the key whose private
half the tool writes out and connects with).

- `mgu7/har.py` `replace_region_with_file()` builds the key archive and **pads it
  to the original region's exact length** (1591 B), so the RequestDownload size
  byte and both TransferData block lengths (1400 + 191) are unchanged.
- `mgu7/flash.py` `patch_region_file()` rewrites only those two transfer frames.
  Validated offline: the contract still decodes to **174 frames**, frame 30 and
  every frame length are byte-identical, and **only the two transfer payloads
  differ** — they now decode to our key and nothing else.

Because every structural frame (session, SecurityAccess, RequestDownload, the
signed blob, the finalize routines, the reset) is identical to a flash that
already completes on these units, the realistic worst case is that the unit does
not persist this unsigned region — a **no-op, not a brick**.

### The one thing a bench unit still has to confirm

Whether that unsigned region actually lands `/usr/share/sshd/authorized_keys.root`
on the live rootfs (the stock key otherwise comes from the signed Application
SWFL `000056E5`, which `fix-key` does not touch). Run `fix-key` once on a bench
unit with `--verbose`, keep the flash journal, and check whether root login with
the tool's key then succeeds. If it does, issue #2 is fixed over ENET with no
signed `000056E5` image needed; if not, the journal shows exactly what the unit
did with the region.

## SWE header (the block flashed to 0x041000) — decoded

512 bytes, confirmed by diffing the id7 and id8 debug images (only the version
and one 256-byte run differ):

| offset | bytes            | meaning                                   |
|--------|------------------|-------------------------------------------|
| 0–4    | `08 00 00 56 ea` | SWE id `000056EA` (fixed)                 |
| 5–7    | version          | 030.016.002 (id7) / 036.010.004 (id8)     |
| 8–11   | `00 00 00 40`    | digest length 0x40 = 64 → SHA-512         |
| 12–267 | 256 bytes        | **RSA-2048 signature** over the SWE content |
| 268–511| `aa …`           | padding to 512                            |

**It cannot be reproduced offline.** The 256-byte field is an RSA-2048 signature
by BMW's private key (not the 1024-bit M7F1 key, and not in this repo). Any change
to the HAR content invalidates it, and we can't re-sign.

## Open question that decides whether V2's ENET file-drop is possible

Does a *debug-mode* flash verify this signature, or bypass it?
- bypass → we can flash a modified HAR (add `authorized_keys.root`); the stale
  signature is ignored. V2 works over ENET with no prior SSH access.
- enforced → no modified SWE flashes; the key can only be placed over SSH (needs
  an already-trusted key) or with BMW's signing key.

This needs a one-off bench-unit test (flash the image with one payload byte
changed; see if it is accepted) before any modified-image flasher is built or
shipped — flashing is the only irreversible, brick-capable step in this tool.
