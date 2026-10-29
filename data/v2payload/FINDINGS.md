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
