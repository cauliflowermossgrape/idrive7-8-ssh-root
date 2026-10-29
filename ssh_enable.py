import argparse
import datetime
import os
import sys
import time
import traceback
if getattr(sys, 'frozen', False):
    HERE = os.path.dirname(os.path.abspath(sys.executable))
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from mgu7 import assets as assets_mod
from mgu7 import diag, discovery, enroll, flash, hsfz, identity as identity_mod, sshcli
from mgu7.flash import ID7, ID8_BDC3, ID8_BCP
EXIT_OK = 0
EXIT_ERROR = 1

def log(*parts):
    print('[%s] %s' % (datetime.datetime.now().strftime('%H:%M:%S'), ' '.join((str(p) for p in parts))), flush=True)

class Tool:

    def __init__(self, args):
        self.args = args
        self.assets = assets_mod.Assets()
        self.client = None
        self.svk = None
        self.mgu_ip = None
        self.vin = (getattr(args, 'vin', None) or '').strip().upper() or None
        self.last_challenge = None

    def connect(self):
        args = self.args
        if not args.gateway or args.gateway == 'auto':
            log('Scanning active adapters for an ENET gateway (UDP 6811 broadcast)...')
            gateways = discovery.discover()
            if not gateways:
                raise SystemExit('No ENET gateway responded. A direct IP can be entered with --gateway.')
            if len(gateways) > 1:
                log('Found %d ENET gateways:' % len(gateways))
                for g in gateways:
                    log('   ', g.ip, '| VIN:', g.vin or 'not reported')
                raise SystemExit('More than one ENET gateway responded; pick one with --gateway <ip>.')
            log('Found 1 ENET gateway.', '| VIN:', gateways[0].vin or 'not reported')
            args.gateway = gateways[0].ip
            if gateways[0].vin and args.vin and (gateways[0].vin != args.vin.strip().upper()):
                log('WARNING: discovered VIN %s differs from --vin %s - double-check the VIN before flashing.' % (gateways[0].vin, args.vin))
            if gateways[0].vin and not self.vin:
                self.vin = gateways[0].vin
        client = hsfz.EnetClient(args.gateway, log=self.journal)
        log('Connecting to ENET gateway', args.gateway)
        client.connect()
        self.client = client
        try:
            self.svk = diag.read_svk(client)
            log('SVK:', self.svk.summary())
        except (hsfz.HsfzError, diag.DiagError) as e:
            log('SVK was not decoded:', e)
            raise
        if not self.svk.is_supported_mgu():
            if self.svk.is_nbt():
                raise SystemExit('This unit is an NBT/EVO head unit (BTLD %s); this tool only speaks MGU.' % ' '.join((r.version_hex() for r in self.svk.all_named('BTLD'))))
            raise SystemExit("Refusing to flash: this unit's BTLD is not 00003F36, so it is outside the supported MGU ID7/ID8 debug catalog. (Use --force to override.)" if not self.args.force else 'BTLD gate overridden by --force.')
        try:
            ips = diag.read_mgu_ip(client)
            self.mgu_ip = ips[0]
            log('MGU IP:', ips[0], '| netmask:', ips[1])
        except (hsfz.HsfzError, hsfz.UdsReject, diag.DiagError) as e:
            log('MGU IP was not decoded:', e)
        if self.args.mgu_ip:
            self.mgu_ip = self.args.mgu_ip
            log('MGU IP override:', self.mgu_ip)

    def journal(self, direction, frame):
        if not self.args.verbose:
            return
        tag = 'TX' if direction == 'tx' else 'RX'
        log('%s %02X>%02X type %04X: %s' % (tag, frame.src, frame.dst, frame.type, frame.payload[:64].hex(' ') + (' (%d bytes)' % len(frame.payload) if len(frame.payload) > 64 else '')))

    def probe(self, host, port=22, timeout=3.0):
        ok, ms = enroll.probe_port(host, port, timeout=timeout)
        log('MGU SSH port %d is %s (%.0f ms).' % (port, 'open' if ok else 'not open', ms))
        return ok

    def probe_open(self, host, attempts=3):
        for i in range(attempts):
            if self.probe(host, timeout=1.0 + i):
                return True
            if i + 1 < attempts:
                log('probe retry %d/%d...' % (i + 1, attempts - 1))
        return False

    def status(self):
        self.connect()
        log('Checking debug/SSH state...')
        state = diag.debug_state(self.client)
        if state.get('dtcs') is not None:
            log('DTC B7F8E5 (Debugging active / SSH is active!!!):', 'PRESENT' if state['dtc_debug'] else 'absent')
        if self.mgu_ip:
            self.probe(self.mgu_ip)
        else:
            log('No MGU IP known; pass --mgu-ip to probe port 22.')
        log('Status: debug/SSH-open state is', 'ON' if state.get('dtc_debug') else 'OFF (or not reported)' if state.get('dtcs') is None else 'OFF')
        return state

    def close(self):
        self.connect()
        if not self.args.yes:
            answer = input('Stop the MGU debug/SSH service (31 02 A0 FD)? [y/N] ').strip().lower()
            if answer not in ('y', 'yes'):
                raise SystemExit('Aborted.')
        log('Stopping the MGU SSH service (31 02 A0 FD)...')
        result = diag.close_ssh(self.client)
        log('Close routine result:', result)
        if self.mgu_ip:
            time.sleep(2.0)
            log("Note: after closing, the SSH state clears on the next service cycle; the port probe is best re-run with 'status'.")
        return result

    def wake_daemon(self, host):
        log('Initial SSH connection unavailable at %s:22 - restarting MGU (11 01) and waiting 15 seconds.' % host)
        try:
            self.client.request(hsfz.MGU, bytes((17, 1)), hsfz.P_ADVANCED)
        except (hsfz.HsfzError, hsfz.UdsReject) as e:
            log('MGU restart request did not complete cleanly:', e)
        try:
            self.client.close()
        except OSError:
            pass
        time.sleep(15.0)
        for attempt in range(2, 6):
            try:
                self.client.close()
            except OSError:
                pass
            try:
                self.client.connect()
                state = diag.debug_state(self.client)
                log('DTC B7F8E5 (debug/SSH active): %s' % ('PRESENT' if state.get('dtc_debug') else 'absent'))
            except (hsfz.HsfzError, hsfz.UdsReject, diag.DiagError, OSError) as e:
                log('diag not back yet after restart (%s)' % e)
            ok, ms = enroll.probe_port(host, 22, 15.0)
            log('MGU SSH port 22 is %s (%.0f ms).' % ('open' if ok else 'not open', ms))
            if ok:
                log('Proven SSH service channel established.')
                return True
            time.sleep((attempt - 1) * 0.2)
        return False

    def verify_ssh(self, identity):
        if not identity:
            return False
        if not self.probe_open(self.mgu_ip):
            log('Verifying with the MGU-restart wake sequence...')
            if not self.wake_daemon(self.mgu_ip):
                log("Port 22 did not come up after the restart; re-run 'status' after the MGU finishes its service cycle.")
                return False
        if not sshcli.available():
            log('OpenSSH client (ssh) not found on PATH; cannot verify the login. '
                'Install the Windows OpenSSH client or add ssh to PATH.')
            return False
        log('Port 22 is open - waiting 10 s for the SSH daemon to finish starting...')
        time.sleep(10)
        r = None
        for attempt in (1, 2, 3):
            log('Verifying SSH login as root with the recovered identity%s...' % ((' (retry %d)' % (attempt - 1)) if attempt > 1 else ''))
            r = sshcli.probe_login(self.mgu_ip, identity, command='id')
            if r.get('connected'):
                log('SSH OK as root:', r.get('output') or '(no output)')
                return True
            if attempt < 3:
                log('SSH not answering yet (%s) - retrying in 8 s...' % (r.get('error') or 'no response'))
                time.sleep(8)
        log('SSH verification failed:', (r or {}).get('error') or 'no data')
        return False

    def _resolve_enrollment_dir(self):
        """The per-car key directory for this unit: by VIN, or the only one that
        exists if the VIN is unknown."""
        if self.vin:
            d = identity_mod.enrollment_dir(self.vin)
            if os.path.isdir(d):
                return d
        root = identity_mod.ENROLL_DIR
        if os.path.isdir(root):
            subs = [os.path.join(root, n) for n in os.listdir(root)
                    if os.path.isfile(os.path.join(root, n, 'id_rsa.pkcs1.pem'))]
            if len(subs) == 1:
                return subs[0]
        return None

    def _load_identity(self):
        """Return the key-file path for this unit's saved identity, or None.
        (The system ssh client is given this path directly.)"""
        directory = self._resolve_enrollment_dir()
        if not directory:
            return None
        pem = os.path.join(directory, 'id_rsa.pkcs1.pem')
        if os.path.isfile(pem):
            return pem
        log('No saved key found in %s' % directory)
        return None

    def install_always_on(self, identity, mode='install'):
        """Upload sshd-always-on.sh to the unit (over the system ssh client) and
        run it (`install` wires sshd to start on every boot independent of debug
        mode; `remove` reverts to stock). *identity* is a key-file path.
        Returns True on success."""
        script_local = os.path.join(HERE, 'sshd-always-on.sh')
        if not os.path.isfile(script_local):
            log('sshd-always-on.sh not found next to ssh_enable.py; cannot change SSH persistence.')
            return False
        rc, uid, err = sshcli.run(self.mgu_ip, identity, 'id -u', timeout=30)
        if rc != 0:
            log('SSH connection failed: %s' % (err.strip() or 'exit %d' % rc))
            return False
        if uid.strip() != '0':
            log('The SSH session is not root (id -u=%r); aborting.' % uid.strip())
            return False
        log('Admin confirmed: root on the head unit.')
        remote = '/tmp/sshd-always-on.sh'
        log('Uploading sshd-always-on.sh and running: sh %s %s' % (remote, mode))
        rc, out, err = sshcli.push_and_run(self.mgu_ip, identity, script_local,
                                           remote, args=mode, timeout=60)
        for line in (out + err).splitlines():
            log('  | ' + line)
        if rc != 0:
            log('The %s step returned exit code %d.' % (mode, rc))
            return False
        log('sshd persistence %s succeeded.' % ('install' if mode == 'install' else 'removal'))
        return True

    def run_persist(self):
        """One-click: make sshd persistent, then turn debug mode off so the
        B7F8E5 DTC clears while SSH keeps running. Returns True on success."""
        if not self.mgu_ip:
            log('No MGU IP known; pass --mgu-ip. Debug mode left unchanged.')
            return False
        identity = self._load_identity()
        if identity is None:
            log('No per-car key found for this unit; run "enable" (or "flash") first. '
                'Debug mode left unchanged.')
            return False
        if not self.probe_open(self.mgu_ip):
            log('Port 22 is not open; bringing SSH up first...')
            if not self.wake_daemon(self.mgu_ip):
                log('SSH did not come up; run "enable" first. Debug mode left unchanged.')
                return False
        if not self.install_always_on(identity):
            log('SSH persistence failed; leaving debug mode ON so you do not lose access.')
            return False
        if self.args.keep_debug:
            log('SSH is now persistent. Leaving debug mode ON (--keep-debug); '
                'the B7F8E5 DTC stays until you disable debug.')
            return True
        log('Disabling debug mode (31 02 A0 FD) so the B7F8E5 DTC clears...')
        try:
            log('Close routine result:', diag.close_ssh(self.client))
        except (hsfz.HsfzError, hsfz.UdsReject) as e:
            log('The debug-stop routine was rejected (%s); SSH is persistent but debug mode is still on.' % e)
            return False
        # When debug mode drops, firewalldZ removes its port-22 accept rule; the
        # firewall keeper (sshd-always-on-fw.service) re-asserts ours, but it
        # only re-checks every ~15 s, so there can be a short window where the
        # port looks closed. Probe for up to ~25 s before concluding.
        time.sleep(3.0)
        still = False
        for _ in range(12):
            if self.probe(self.mgu_ip):
                still = True
                break
            time.sleep(2.0)
        state = diag.debug_state(self.client)
        dtc = state.get('dtc_debug')
        log('After disabling debug mode: port 22 %s; debug DTC B7F8E5 %s.' % (
            'is STILL OPEN' if still else 'is CLOSED - persistence may not have taken',
            'cleared' if dtc is False else ('STILL PRESENT' if dtc else 'unknown (not reported)')))
        if still and dtc is not True:
            log('DONE: SSH runs with debug mode OFF - no more B7F8E5 error.')
            return True
        log('Persist finished but verification was inconclusive; re-check with "status".')
        return still

    def persist(self):
        self.connect()
        return EXIT_OK if self.run_persist() else EXIT_ERROR

    def disable(self):
        """Full revert: if reachable, undo SSH persistence so it goes back to
        stock (debug-only), then stop the debug/SSH service."""
        self.connect()
        identity = self._load_identity()
        if identity and self.mgu_ip and self.probe_open(self.mgu_ip):
            log('Reverting SSH persistence (back to stock debug-only)...')
            self.install_always_on(identity, mode='remove')
        elif identity:
            log('SSH not reachable to revert persistence; stopping debug mode anyway.')
        log('Stopping the MGU debug/SSH service (31 02 A0 FD)...')
        try:
            log('Close routine result:', diag.close_ssh(self.client))
        except (hsfz.HsfzError, hsfz.UdsReject) as e:
            log('The debug-stop routine was rejected:', e)
            return EXIT_ERROR
        log('DONE: debug/SSH stopped. Persistence (if any) is reverted; SSH is '
            'debug-only again from the next boot.')
        return EXIT_OK

    # Resolve the file sshd actually reads keys from (AuthorizedKeysFile in
    # sshd_config, with %u/%h expanded) - on this unit that is
    # /usr/share/sshd/authorized_keys.root, NOT ~/.ssh/authorized_keys. Writing
    # anywhere else is silently ignored by sshd.
    _AKF_RESOLVER = (
        'u=$(id -un 2>/dev/null || echo root); '
        'h=$(getent passwd "$u" 2>/dev/null | cut -d: -f6); '
        '[ -n "$h" ] || h="${HOME:-/home/$u}"; '
        'akf=$(grep -iE "^[[:space:]]*AuthorizedKeysFile" /etc/ssh/sshd_config 2>/dev/null '
        '| head -1 | awk \'{$1="";sub(/^ /,"");print}\'); '
        '[ -n "$akf" ] || akf="$h/.ssh/authorized_keys"; '
        'TARGETS=""; for tok in $akf; do '
        'p=$(printf "%s" "$tok" | sed "s|%u|$u|g; s|%h|$h|g"); '
        'case "$p" in /*) : ;; *) p="$h/$p" ;; esac; '
        'TARGETS="$TARGETS $p"; done; '
    )

    def install_unique_key(self, bootstrap_key, new_pubkey_line):
        """Log in with the baked key and add *new_pubkey_line* to the real
        AuthorizedKeysFile (remounting the ro rootfs rw while writing). Leaves
        the baked key in place. *bootstrap_key* is a key-file path.
        Returns True if the new key is present in that file afterwards."""
        new = ' '.join(new_pubkey_line.split()).replace("'", '')
        if not new.startswith('ssh-'):
            log('Refusing to install a malformed public key.')
            return False
        body = (
            "NEW='%s'; T=$(echo $TARGETS | awk '{print $1}'); "
            '[ -n "$T" ] || T="$h/.ssh/authorized_keys"; '
            'RW=0; d=$(dirname "$T"); '
            '( : > "$d/.mgu_wt" ) 2>/dev/null && rm -f "$d/.mgu_wt" || '
            '{ mount -o remount,rw / 2>/dev/null && RW=1; }; '
            '[ -d "$d" ] || { mkdir -p "$d" 2>/dev/null; chmod 700 "$d" 2>/dev/null; }; '
            'touch "$T" 2>/dev/null; '
            'grep -qF "$NEW" "$T" 2>/dev/null || printf \'%%s\\n\' "$NEW" >> "$T"; '
            'chmod 600 "$T" 2>/dev/null; sync; '
            '[ "$RW" = 1 ] && mount -o remount,ro / 2>/dev/null; '
            'grep -qF "$NEW" "$T" 2>/dev/null && echo "INSTALLED_OK $T" || echo "INSTALL_FAIL $T"'
        ) % new
        script = self._AKF_RESOLVER + body
        rc, out, err = sshcli.run(self.mgu_ip, bootstrap_key, script, timeout=45)
        if rc != 0 and 'INSTALLED_OK' not in out:
            log('SSH connection failed: %s' % (err.strip() or 'exit %d' % rc))
            return False
        if 'INSTALLED_OK' in out:
            where = out.split('INSTALLED_OK', 1)[1].strip().split()[0]
            log('Per-car key added to %s on the unit.' % (where or 'authorized_keys'))
            return True
        detail = out.strip() or err.strip()
        log('Could not confirm the key was written%s.' % ((': ' + detail) if detail else
            ' (the AuthorizedKeysFile may be read-only).'))
        return False

    def remove_dev_key(self, key, dev_pubkey_body):
        """Log in (with the per-car key) and strip the baked dev key from every
        resolved AuthorizedKeysFile, so only this car's key remains.
        *key* is a key-file path."""
        dev = dev_pubkey_body.replace("'", '')
        body = (
            "DEV='%s'; found=0; "
            'for T in $TARGETS; do [ -f "$T" ] && grep -qF "$DEV" "$T" 2>/dev/null && found=1; done; '
            '[ "$found" = 1 ] || { echo REMOVED_OK; exit 0; }; '
            'RW=0; mount -o remount,rw / 2>/dev/null && RW=1; '
            'for T in $TARGETS; do [ -f "$T" ] || continue; '
            't="$T.mgu_tmp"; grep -vF "$DEV" "$T" > "$t" 2>/dev/null && cat "$t" > "$T" && rm -f "$t"; done; '
            'sync; [ "$RW" = 1 ] && mount -o remount,ro / 2>/dev/null; '
            'left=0; for T in $TARGETS; do [ -f "$T" ] && grep -qF "$DEV" "$T" 2>/dev/null && left=1; done; '
            '[ "$left" = 0 ] && echo REMOVED_OK || echo REMOVE_FAIL'
        ) % dev
        script = self._AKF_RESOLVER + body
        rc, out, err = sshcli.run(self.mgu_ip, key, script, timeout=45)
        if rc != 0 and 'REMOVED_OK' not in out:
            log('SSH connection failed while removing the dev key: %s' % (err.strip() or 'exit %d' % rc))
            return False
        return 'REMOVED_OK' in out

    def provision_unique_key(self, bootstrap_pem):
        """Generate a key unique to this car and install it over SSH (using the
        baked key to log in). On success the per-car key replaces the dev key as
        the saved identity + connect.txt. Returns the identity path to use.
        *bootstrap_pem* is a key-file path."""
        if not os.path.isfile(bootstrap_pem):
            log('Could not find the bootstrap key (%s); skipping unique-key step.' % bootstrap_pem)
            return bootstrap_pem
        dev_body = identity_mod.Identity.from_pem(self.assets.raw(5)).authorized_key().split()[1]
        new = identity_mod.Identity.generate('mgu-%s' % (self.vin or 'unit'))
        log('Generating a unique SSH key for this car and installing it over SSH...')
        if not self.install_unique_key(bootstrap_pem, new.authorized_key()):
            log('Unique-key install failed; keeping the shared dev key for login.')
            return bootstrap_pem
        directory = identity_mod.enrollment_dir(self.vin)
        meta = {
            'vin': self.vin,
            'arch': self.args.arch,
            'mgu_ip': self.mgu_ip,
            'created_utc': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'fingerprints': new.fingerprints(),
            'note': 'Unique per-car key, added to the head unit authorized_keys over SSH. The shared dev key still works as a fallback.',
        }
        paths = new.write(directory, meta)
        self.write_connect_info(directory, new, paths)
        percar = paths['id_rsa.pkcs1.pem']
        log('This car now has its own unique SSH key:')
        for line in identity_mod.describe(new, paths).splitlines():
            log('  ' + line)
        if not self.verify_ssh(percar):
            log('Installed the unique key but could not verify login with it; '
                'leaving the shared dev key in place so you keep access.')
            return percar
        log('Verified: the unit accepts this car\'s unique key.')
        # Replace: now that the new key is proven, drop the shared dev key.
        if self.remove_dev_key(percar, dev_body):
            log('Shared dev key removed - this car now accepts ONLY its own unique key.')
        else:
            log('Could not remove the shared dev key (it may be in a read-only image); '
                'this car\'s unique key works, and the dev key still works as a fallback.')
        log('NOTE: if the new key does not connect yet, force-restart the head '
            'unit - press and HOLD the volume/power knob ~20-30 s until it reboots '
            '- so it comes back up loaded with the new key.')
        return percar

    def enable(self):
        args = self.args
        self.connect()
        log('Enable mode: enroll-only (no flashing).')
        if self.mgu_ip and self.probe(self.mgu_ip):
            log('Port 22 is already open; enrolling anyway to refresh the identity.')
        log('Enrolling this unit (A6 71 challenge -> certificate -> A0 FD install)...')
        identity = self.do_enroll()
        verified = bool(identity and self.mgu_ip and self.verify_ssh(identity))
        if not verified and not getattr(self, '_identity_is_baked', True):
            log('The saved per-car key did not log in; falling back to the baked key.')
            identity = self._write_baked_identity()
            verified = bool(identity and self.mgu_ip and self.verify_ssh(identity))
        if verified and self.args.unique_key and getattr(self, '_identity_is_baked', True):
            identity = self.provision_unique_key(identity) or identity
        if self.args.persist and verified:
            log('--persist: making SSH survive debug mode being off...')
            self.run_persist()
        if verified:
            log('DONE: MGU SSH enabled - connect with root + %s.' % identity)
            return EXIT_OK
        log('FAILED: enrollment completed and port 22 is open, but SSH login as '
            'root was REJECTED (publickey denied), so SSH is NOT usable. The key '
            'written to %s is the one the unit refused. See issue #2: on some '
            'software levels the unit does not trust this key.' % identity)
        return EXIT_ERROR

    def flash(self):
        args = self.args
        vin = args.vin
        if not vin:
            raise SystemExit('--vin is required for flash (it is written to the MGU with 2E F1 90, so it must match the car).')
        self.vin = vin
        arch = args.arch
        self.connect()
        if self.mgu_ip:
            self.probe(self.mgu_ip)
        log('Flash mode: writing the %s debug image.' % ('MGU ID7 (BDC2/BDC3)' if arch == ID7 else arch))
        if not args.yes:
            answer = input('Flash the %s debug image now? The MGU switches into programming mode and reboots.\nVIN %s will be written to the unit. [y/N] ' % ('MGU ID7 (BDC2/BDC3)' if arch == ID7 else arch, vin)).strip().lower()
            if answer not in ('y', 'yes'):
                raise SystemExit('Aborted.')
        self.do_flash()
        log('Enrolling this unit (A6 71 challenge -> certificate -> A0 FD install)...')
        identity = self.do_enroll()
        verified = bool(identity and self.mgu_ip and self.verify_ssh(identity))
        if not verified and not getattr(self, '_identity_is_baked', True):
            log('The saved per-car key did not log in; falling back to the baked key.')
            identity = self._write_baked_identity()
            verified = bool(identity and self.mgu_ip and self.verify_ssh(identity))
        if verified and self.args.unique_key and getattr(self, '_identity_is_baked', True):
            identity = self.provision_unique_key(identity) or identity
        if self.args.persist and verified:
            log('--persist: making SSH survive debug mode being off...')
            self.run_persist()
        if verified:
            log('DONE: MGU flashed + SSH enabled - connect with root + %s.' % identity)
            return EXIT_OK
        log('FAILED: the flash and enrollment completed and port 22 is open, but '
            'SSH login as root was REJECTED (publickey denied), so SSH is NOT '
            'usable. The key written to %s is the one the unit refused. See issue '
            '#2: on some software levels the unit does not trust this key, and '
            'note the flash still clears the CAFD coding - restore it from backup.'
            % identity)
        return EXIT_ERROR

    def do_flash(self):
        args = self.args
        material = self.assets.raw(int(flash.CONTRACTS[args.arch][3]))
        operands_blob = self.assets.raw(7)
        operands = flash.SecurityOperands(operands_blob)
        data = flash.FlashData.build(args.arch, args.vin, material)
        log('Flash contract:', data.label, '- frames:', len(data.frames), '| transfer parts:', len(data.parts), '| TransferData bytes:', data.transfer_bytes)
        engine = flash.FlashEngine(self.client, operands, gate=lambda: self.svk is not None and self.svk.is_supported_mgu() or args.force)
        counters = []

        def progress(human, count, percent, part, kind, text):
            line = 'Frame %d/%d; %d%%; transfer part %d; %s; %s' % (human, count, percent, part, kind, text)
            if not counters or counters[-1] != line:
                log(line)
                counters.append(line)
        result = engine.run(data, progress)
        log(result.summary())
        log('Waiting for the MGU to finish restarting before enrolling (%d s)...' % args.restart_wait)
        time.sleep(args.restart_wait)
        self.client.close()
        self.connect()
        self.svk = diag.read_svk(self.client)
        if not self.svk.is_supported_mgu():
            log('Warning: SVK gate no longer passes after flash.')

    def do_enroll(self):
        """Enroll exactly as the proven premium-tool sequence does: the
        certificate is built from the enrollment key (data/assets/01) and
        signed by the PMO CA - this is the access gate the unit checks during
        the A6 71 / A0 FD handshake. The key the unit actually authorises for
        *root SSH login* is a separate key baked into the flashed debug image
        (data/assets/05 = the openssh key that logs in via OpenSSH/FileScript);
        the enrollment key (asset 01) is NOT a login key. So we enroll with
        asset 01 but write out and connect with asset 05. It is written out in
        every format plus a connect.txt under data/enrollments/<VIN>/. Returns
        the path to the login private key."""
        asset1 = self.assets.raw(1)
        ssh_key = self.assets.raw(5)
        enrollment_key = enroll.RsaKeyPair.from_pem_bytes(asset1, expect_pkcs8=True)
        pmo_key = enroll.RsaKeyPair.from_pem_bytes(self.assets.raw(4), expect_pkcs8=False)
        for cycle in range(1, 6):
            challenge, payload, raw = enroll.read_challenge(self.client)
            certificate = enroll.build_certificate(challenge, enrollment_key, self.assets.raw(3), pmo_key)
            if cycle == 1:
                log('Challenge identity:', challenge)
                log('Generated certificate: %d bytes DER / %d bytes PEM' % (len(certificate.der), len(certificate.pem)))
            enroll.install_certificate(self.client, certificate, self.assets.raw(3))
            enroll.readback_certificate_address(self.client)
            log('Enroll cycle %d/5: certificate installed, 172A readback accepted.' % cycle)
            if cycle < 5:
                time.sleep(0.2)
        self.last_challenge = challenge
        directory = identity_mod.enrollment_dir(self.vin)
        baked = identity_mod.Identity.from_pem(ssh_key, comment='mgu-root@%s' % (self.vin or 'unit'))
        # Prefer an existing per-car key (a saved key whose fingerprint differs
        # from the baked key): after a unique-key replace the baked key no longer
        # works, so re-enrolling must log in with the per-car key, not clobber it
        # with the baked one. If that saved key turns out not to work, enable()/
        # flash() fall back to the baked key via _write_baked_identity().
        existing = os.path.join(directory, 'id_rsa.pkcs1.pem')
        if os.path.isfile(existing):
            try:
                with open(existing, 'rb') as f:
                    cur = identity_mod.Identity.from_pem(f.read())
                if cur.fingerprints()['sha256'] != baked.fingerprints()['sha256']:
                    self._identity_is_baked = False
                    log('Using the saved per-car key for this unit (%s).'
                        % cur.fingerprints()['sha256'])
                    return existing
            except Exception:
                pass
        return self._write_baked_identity(baked)

    def _write_baked_identity(self, baked=None):
        """Write the baked-key bundle (all formats + connect.txt) into the
        enrollment dir and return its private-key path. Backs up any differing
        saved key first so nothing is ever lost."""
        if baked is None:
            baked = identity_mod.Identity.from_pem(
                self.assets.raw(5), comment='mgu-root@%s' % (self.vin or 'unit'))
        self._identity_is_baked = True
        directory = identity_mod.enrollment_dir(self.vin)
        existing = os.path.join(directory, 'id_rsa.pkcs1.pem')
        if os.path.isfile(existing):
            try:
                cur = identity_mod.Identity.from_pem(open(existing, 'rb').read())
                if cur.fingerprints()['sha256'] != baked.fingerprints()['sha256']:
                    import shutil as _sh
                    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
                    backup = os.path.join(directory, 'previous-key-%s' % stamp)
                    os.makedirs(backup, exist_ok=True)
                    for n in os.listdir(directory):
                        fp = os.path.join(directory, n)
                        if os.path.isfile(fp):
                            _sh.copy2(fp, os.path.join(backup, n))
                    log('Saved the previous key (%s) to %s before refreshing.'
                        % (cur.fingerprints()['sha256'], backup))
            except Exception:
                pass
        meta = {
            'vin': self.vin,
            'arch': self.args.arch,
            'mgu_ip': self.mgu_ip,
            'created_utc': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'challenge': getattr(self, 'last_challenge', None),
            'fingerprints': baked.fingerprints(),
            'note': 'This is the root SSH key baked into the flashed debug image - the key the unit authorises for root login (shared across units flashed with this image).',
        }
        paths = baked.write(directory, meta)
        self.write_connect_info(directory, baked, paths)
        log('Root SSH key (in all formats) and connect.txt written:')
        for line in identity_mod.describe(baked, paths).splitlines():
            log('  ' + line)
        return paths['id_rsa.pkcs1.pem']

    def write_connect_info(self, directory, ident, paths):
        """Drop a connect.txt next to the key with the MGU IP + ready-to-run
        ssh command, so the user knows exactly what to connect to."""
        host = self.mgu_ip or '<MGU IP - run "python ssh_enable.py status" to find it>'
        key = paths.get('id_rsa', os.path.join(directory, 'id_rsa'))
        ppk = paths.get('id_rsa.ppk', os.path.join(directory, 'id_rsa.ppk'))
        fp = ident.fingerprints()
        text = (
            'MGU iDrive SSH - connection info\n'
            '================================\n'
            'VIN:        %s\n'
            'Host (IP):  %s\n'
            'Port:       22\n'
            'User:       root\n'
            'Key:        %s\n'
            'PuTTY key:  %s\n'
            'Fingerprint:%s\n\n'
            'Connect (OpenSSH / WSL / macOS / Linux):\n'
            '    ssh -i "%s" root@%s\n\n'
            'PuTTY / WinSCP: use %s as the private key, host %s, user root.\n'
            % ((self.vin or '').upper() or 'unknown', host, key, ppk, fp['sha256'], key, host, ppk, host)
        )
        path = os.path.join(directory, 'connect.txt')
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text)
            log('Connection info (MGU IP + ssh command) saved to %s' % path)
            if self.mgu_ip:
                log('  Connect with: ssh -i "%s" root@%s' % (key, self.mgu_ip))
        except OSError as e:
            log('Could not write connect.txt: %s' % e)

def main(argv=None):
    parser = argparse.ArgumentParser(description='MGU ID7/ID8 SSH enable, status and close tool (flash-debug-mode + SSH-identity enroll).')
    parser.add_argument('action', choices=('enable', 'flash', 'close', 'disable', 'status', 'persist'), help='enable = enroll-only (re-open SSH on an already-flashed unit, no flashing); flash = flash the debug image + enroll; persist = make SSH start on every boot then turn debug mode off (clears the B7F8E5 DTC); disable = revert persistence + stop debug/SSH; close = stop debug/SSH; status = read state')
    parser.add_argument('--gateway', default='auto', help="ENET gateway/ZGW address, or 'auto' for UDP 6811 broadcast discovery (default: %(default)s)")
    parser.add_argument('--vin', help='17-char VIN (required for enable; written to the MGU with 2E F1 90)')
    parser.add_argument('--arch', default=ID7, choices=(ID7, ID8_BDC3, ID8_BCP), help='head-unit variant (default: %(default)s)')
    parser.add_argument('--mgu-ip', help='MGU IP override for the SSH probe/enroll verification (default: read via 22 17 2A)')
    parser.add_argument('--restart-wait', type=int, default=20, help='seconds to wait after the flash before enrolling (default: %(default)s)')
    parser.add_argument('--yes', action='store_true', help='do not ask for confirmation')
    parser.add_argument('--reflash', action='store_true', help="(kept for compatibility) 'flash' now always flashes explicitly")
    parser.add_argument('--force', action='store_true', help='skip the BTLD 00003F36 gate')
    parser.add_argument('--unique-key', action=argparse.BooleanOptionalAction, default=False, help="give this car its OWN unique SSH key (advanced, OFF by default, NOT recommended): after enrolling with the shared dev key, generate a per-car key, add it to the unit's authorized_keys over SSH, verify it, then remove the shared dev key. This can only be done ONCE - after a reflash or a lost key you cannot create a new identity. Default keeps the shared dev key")
    parser.add_argument('--persist', action='store_true', help='after enable/flash, make SSH start on every boot and turn debug mode off (clears the B7F8E5 DTC)')
    parser.add_argument('--keep-debug', action='store_true', help='when persisting, leave debug mode ON (do not run 31 02 A0 FD); the B7F8E5 DTC will remain')
    parser.add_argument('--verbose', action='store_true', help='print every HSFZ frame')
    args = parser.parse_args(argv)
    tool = Tool(args)
    try:
        if args.action == 'status':
            tool.status()
        elif args.action == 'close':
            tool.close()
        elif args.action == 'flash':
            return tool.flash()
        elif args.action == 'persist':
            return tool.persist()
        elif args.action == 'disable':
            return tool.disable()
        else:
            return tool.enable()
    except KeyboardInterrupt:
        print('\nInterrupted.')
        return 130
    except (hsfz.HsfzError, hsfz.UdsReject, diag.DiagError, flash.FlashError, enroll.EnrollError) as e:
        log('FAILED:', e)
        if args.verbose:
            traceback.print_exc()
        return EXIT_ERROR
    finally:
        try:
            tool.client and tool.client.close()
        except OSError:
            pass
    return EXIT_OK
if __name__ == '__main__':
    sys.exit(main())
