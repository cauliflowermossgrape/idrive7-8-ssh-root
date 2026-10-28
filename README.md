# iDrive7/8 SSH root

Enable the **root SSH service** on BMW MGU head units (iDrive 7 / MGU ID7,
ID8-BDC3 and ID8-BCP) entirely over the car's **ENET** diagnostic interface -
just an ENET cable and a laptop. It flashes the debug image, enrolls the SSH
identity and keeps SSH running with debug mode **off** (no `B7F8E5` DTC).
Optionally (advanced, off by default) it can give a car its own **unique SSH key**.

![MGU iDrive SSH Tool](docs/screenshot.png)

> **Disclaimer** - for use on **your own vehicle**, at your own risk. Flashing a
> head unit can wipe its coding and, in the worst case, brick the module. Read
> **Back up your coding before flashing** (below) first. The authors take no
> responsibility for any damage.

## Requirements

- **Python 3.9+** - only if you run from source. The prebuilt **`.exe` needs no
  Python** (see [GUI app](#gui-app)).
- **A system OpenSSH client** (`ssh` on your `PATH`). It ships with Windows 10/11
  (*Settings → Apps → Optional features → "OpenSSH Client"*) and is standard on
  WSL/macOS/Linux. Check with `ssh -V`.
- **Windows:** run your terminal / the app **as Administrator** so Windows uses
  the `169.254.x.x` link-local address on the ENET adapter.
- An **ENET cable**, ignition on / car awake.

## Install (source)

```
pip install -r requirements.txt     # one dependency: cryptography
```

## Quick start - the GUI (recommended)

```
python gui.py
```

The window (above) has a VIN field + **Detect VIN** (auto-reads it from the car
over ENET) and three buttons:

- **Flash + Enable** - first-time setup: flash the debug image, enroll, make SSH
  permanent.
- **Enable** - re-open SSH on an already-flashed unit (no flashing).
- **Disable** - revert persistence and stop debug/SSH.

Two tick-boxes: **Turn debug mode off after enabling** (on by default; keeps SSH
up with no `B7F8E5` DTC) and **Give this car its own unique SSH key** (off by
default, not recommended - see [below](#a-key-thats-unique-to-the-car-optional-not-recommended)).
Keys and a ready-to-run `ssh` command are written for you and their location is
printed in the log. No Python? Build / download the **`.exe`** - see
[GUI app](#gui-app).

## Command line (alternative)

```
python ssh_enable.py status     # read the current debug/SSH state (read-only)
python ssh_enable.py flash --vin WBS1234ABCDX12345   # one-time: flash the
                                 # debug package, then enable SSH
python ssh_enable.py enable     # re-open SSH on an already-flashed unit (no flashing)
python ssh_enable.py persist    # make SSH survive debug mode being OFF
python ssh_enable.py close      # turn the SSH service off again
python ssh_enable.py disable    # revert persistence + stop debug/SSH
```

## ⚠️ Back up your coding before flashing ⚠️ 

**`flash` reprograms the head unit and can wipe its coding / CAFD definitions.**
You will lose your saved settings.
Before the first `flash` on a car, make a full backup of the head unit's coding
so you can put it back afterwards. This happened on a real car during
development, and restoring from a backup fixed it.

1. **Before flashing** - read and save the head unit's coding with a coding
   tool. [BimmerCode](https://bimmercode.app/) worked here: connect, select the
   head unit (HU / MGU), and export/save its coding (BimmerCode keeps a backup
   of each module it writes; some tools also let you "read FA/coding" and save
   it). BMW dealer tools (ISTA/E-Sys) can also save a full backup.
2. **Flash + enable SSH** with this tool and grab the SSH key it saves for you.
3. **After flashing** - if any functions misbehave or coding looks reset,
   restore the saved coding for the head unit with the same tool. In BimmerCode
   this is its restore/undo of the module you backed up.

Only `flash` carries this risk - `enable`, `persist`, `close`, `disable` and
`status` do not reprogram the unit.

## What it does

- **flash** *(run once per head unit)* - writes the small debug package that
  the SSH service needs (a dev CA certificate plus the debug-mode binaries,
  ~131 KB, VIN-bound) and then enrolls the SSH identity. The head unit
  reboots itself; the tool waits and re-checks the unit automatically. It also
  writes the root SSH key out in every format (see *The SSH key*).
- **enable** - re-activates the SSH service on an already-flashed unit
  without flashing anything. Enrolls the unit identity
  (`31 01 A6 71` challenge, generated certificate, `31 01 A0 FD` install,
  `22 17 2A` readback) five times back to back - the SSH daemon comes up a
  few seconds after that.
- **close** - stops the SSH service again (`31 02 A0 FD`).
- **status** - reads the software version (SVK), the head unit IP, the
  debug-state DTC (`B7F8E5`) and probes port 22.

Everything runs against the gateway at `169.254.254.36:6801` by default;
the gateway is found automatically via UDP broadcast, so normally no
settings are needed.

## Check the connection

With the ENET cable in and the car awake, confirm the tool can reach the unit
(read-only, changes nothing):

```
python ssh_enable.py status
```

## Everyday use

Open SSH (after the one-time `flash`):

```
python ssh_enable.py enable
```

You should see the enrollment cycles, `MGU SSH port 22 is open`, and then
`SSH OK as root: uid=0(root)...` as final confirmation.

Connect with this car's own key (printed and saved during `enable`/`flash`) -
e.g. from WSL:

```
ssh -i data/enrollments/<VIN>/id_rsa root@169.254.36.47
```

(The IP is the one the tool prints during `status`/`enable`. With PuTTY or
WinSCP use `data\enrollments\<VIN>\id_rsa.ppk`.) See *The SSH key*.

Close it when done:

```
python ssh_enable.py close
```

## Options

```
--gateway 169.254.254.36   ENET gateway address ("auto" = UDP discovery)
--mgu-ip 169.254.36.47     head unit IP override for the SSH probe
--vin                     17-char VIN (required for "flash"; it is written
                           to the head unit, so it must match the car)
--arch                    id7 (default), id8-bdc3 or id8-bcp
--yes                     skip confirmation prompts
--verbose                 print every diagnostic frame on the wire
```

## The SSH key (and connect info)

Root SSH on the MGU is authorised against **one fixed key that is baked into the
flashed debug image** - shipped as `data/assets/05_SSH_ROOT_KEY.pem`. Enrollment
is a separate step: it installs a certificate built from the *enrollment* key
(`data/assets/01_PRIVATE_KEY.pem`) and signed by the PMO CA, which is only the
access gate the unit checks during the `A6 71` / `A0 FD` handshake - that key is
**not** a login key. The unit accepts the baked root key (asset 05) and only that
key for SSH. A per-car *unique* key is therefore **not possible** at enrollment
time - the unit will reject any key it doesn't already trust (confirmed against a
real head unit, a captured session of the official tool, and the working
OpenSSH/FileZilla login key, which matches asset 05).

So on `flash` / `enable` the tool enrolls with asset 01 and then writes out the
asset-05 login key -
in every format you might need to connect - under `data/enrollments/<VIN>/`,
together with a `connect.txt` (the MGU IP + a ready-to-run `ssh` command):

```
id_rsa             OpenSSH private key   -> ssh -i id_rsa root@<ip>
id_rsa.pkcs1.pem   PKCS#1 PEM            (-----BEGIN RSA PRIVATE KEY-----)
id_rsa.pkcs8.pem   PKCS#8 PEM            (-----BEGIN PRIVATE KEY-----)
id_rsa.ppk         PuTTY v2             (PuTTY / WinSCP)
id_rsa.pub         OpenSSH public       (authorized_keys line)
id_rsa.pub.pem     SubjectPublicKeyInfo PEM
fingerprints.txt   SHA256 + MD5 fingerprints
connect.txt        MGU IP + ssh command
metadata.json      VIN, arch, mgu_ip, challenge, timestamp, fingerprints
```

Private keys are `chmod 600`, and `data/enrollments/` is git-ignored.

### A key that's unique to the car (optional, not recommended)

> **Off by default.** The key swap can only be done **once**. If you reflash the
> unit, run the tool again, or lose the per-car key, you **cannot create a new
> identity** and may lose SSH access. Only turn this on if you know exactly why
> you need it and will keep the key safe.

Since enrollment can't change which key the unit trusts, the only way to a
per-car key is to log in with the baked key and edit the unit's real
`AuthorizedKeysFile` over SSH. On this hardware sshd reads keys from
`/usr/share/sshd/authorized_keys.root` (per `sshd_config`), **not**
`~/.ssh/authorized_keys`, and the rootfs is mounted read-only - so the tool
resolves the actual `AuthorizedKeysFile`, remounts `/` read-write just while it
edits, writes the key, and remounts read-only again. The tool does this only
when you pass `--unique-key` (or tick the GUI box), as a **replace**. By default
the shared baked key is kept.

```
python ssh_enable.py enable                 # keep the shared dev key (default)
python ssh_enable.py enable --unique-key    # swap in a per-car key (one-time, advanced)
```

1. enroll + log in with the baked key (as usual);
2. generate a key unique to this car and add it to the real `AuthorizedKeysFile`
   (remounting the ro rootfs rw just for the write), so the unit now trusts both;
3. verify login with the new key over a fresh connection;
4. **only then** remove the baked key line, so the car accepts only its own key.

> **If the new key doesn't connect right away, force-restart the head unit:**
> press and **hold the volume / power knob for ~20-30 s** until the screen goes
> dark and the unit reboots. It comes back up loaded with the new key. (This was
> needed on a real car after the key swap.)

The per-car key (all formats) + `connect.txt` replace the dev-key bundle in
`data/enrollments/<VIN>/`. Safety: if step 3 can't be verified, the dev key is
left in place so you never lose access; and if `authorized_keys` sits on a
read-only image, the removal may not stick (the tool says so) - the unique key
still works, with the dev key as fallback. Re-running `enable` always restores
access via the dev key.

## Persistent SSH (no more B7F8E5 DTC)

Stock behaviour ties `sshd.socket` to `debug.target`, so SSH only runs while
debug mode is active - and active debug mode sets the `B7F8E5` ("debugging
active") DTC. `persist` fixes that in one shot:

```
python ssh_enable.py persist           # on an already-enabled unit
python ssh_enable.py enable  --persist  # enable, then persist
python ssh_enable.py flash --vin ... --persist   # flash, enable, then persist
```

It logs in over SSH with this car's key, confirms root, uploads and runs
`sshd-always-on.sh install` on the head unit, then turns debug mode off
(`31 02 A0 FD`). Stock SSH dies without debug mode because of three separate
gates, all handled by the script (nothing in `/lib` or `/usr` is changed - it
only adds files under `/etc`, which `remove` deletes):

1. **Start** - `sshd.socket` is `WantedBy=debug.target` only, and the boot
   target is `early.target`, so the `/etc` override is also wanted by
   `early.target`, `sockets.target` and `multi-user.target`.
2. **Stop** - `sshd.socket` has `PartOf=debug.target`; the override drops it so
   leaving debug mode no longer stops the socket.
3. **Firewall** - port 22 is only accepted by a rule `firewalldZ` adds while
   debug mode is on; without it the nft input chain drops SSH. A small keeper
   service (`sshd-always-on-fw.service`) keeps a `tcp dport 22 accept` rule at
   the top of the ip/ip6 input chains, re-checked every 15 s.

The result: SSH keeps starting on every boot and stays reachable with debug
mode off, and the `B7F8E5` DTC clears. **Turning debug off is automatic** - you
do not need a separate step. Because the firewall keeper only re-checks every
~15 s, `persist` waits and re-probes port 22 for a few seconds after disabling
debug before reporting. If making SSH persistent fails, the tool deliberately
leaves debug mode ON so you do not lose access.

Want SSH persistent but debug mode left on? Add `--keep-debug`:

```
python ssh_enable.py enable --persist --keep-debug   # persistent SSH, DTC stays
```

To go back to stock entirely, use `disable` (reverts the override and stops
debug), or run `sh sshd-always-on.sh remove` on the unit by hand.

## GUI app

Run it from source with `python gui.py` (see [Quick start](#quick-start---the-gui-recommended)),
or use the standalone Windows `.exe` - **no Python needed**. It runs the exact
same code as the command line and streams the log into the window. Connection
details (gateway / variant / MGU IP) live in a small optional row.

### Build the Windows .exe

From a normal Command Prompt in the project root, with Python on `PATH`:

```
build_exe.bat
```

That installs PyInstaller, builds `dist\MGU-SSH\MGU-SSH.exe` (one-folder app via
`MGU-SSH.spec`), and copies `data\assets` and `sshd-always-on.sh` next to the
exe. **Keep the whole `dist\MGU-SSH\` folder together** - SSH keys / connect info
are written to `dist\MGU-SSH\data\enrollments\`. Run it **as Administrator** so
Windows uses the `169.254.x.x` link-local address on the ENET adapter.

## Folder contents

```
ssh_enable.py               the command-line tool
gui.py                      Tkinter GUI (VIN auto-detect, one-click)
sshd-always-on.sh           runs on the head unit to make SSH persistent
mgu7/                       diagnostic + flashing library
mgu7/sshcli.py              talks to the unit with the system OpenSSH client
mgu7/identity.py            SSH key all-format export (OpenSSH/PEM/PPK) + PPK writer
data/assets/                update material + PMO CA used by the tool
data/enrollments/<VIN>/     SSH key (all formats) + connect.txt per car (git-ignored)
docs/screenshot.png         the GUI screenshot used in this README
requirements.txt            cryptography (the SSH steps use the system ssh client)
MGU-SSH.spec, build_exe.bat PyInstaller build of the Windows .exe
```

Keep `data/` next to `ssh_enable.py`; the private keys are what get you into
the unit - treat them like passwords.

## License

Released into the **public domain** under [The Unlicense](LICENSE) - do whatever
you want with it, no attribution required.
