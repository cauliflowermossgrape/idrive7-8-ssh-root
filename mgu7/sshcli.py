"""Talk to the head unit with the *system* OpenSSH client (ssh/scp) instead of
paramiko.

The MGU's sshd is happy with a normal OpenSSH client - that is how it is reached
by hand (and by FileZilla) - but paramiko 4.x fights the key/algorithm
negotiation. Shelling out to `ssh` uses exactly the client that already works,
on Windows (the bundled OpenSSH in C:\\Windows\\System32\\OpenSSH) as well as
WSL/Linux/macOS.

Everything here takes a private-key *file path* (any format OpenSSH reads:
OpenSSH, PKCS#1 or PKCS#8 PEM) - no in-memory key objects."""

import contextlib
import os
import shutil
import subprocess
import tempfile
import uuid

SSH_USER = 'root'
SSH_PORT = 22

# Non-interactive, short connect timeout. The unit regenerates its SSH host key
# on every reflash/enroll, so we must NOT remember or verify it. We do NOT point
# known_hosts at os.devnull: on Windows that resolves to "NUL", which some
# OpenSSH builds treat as a real, persistent file - a host key written there on
# the first connect then triggers a fatal "REMOTE HOST IDENTIFICATION HAS
# CHANGED" that aborts the login before the key is ever offered (issue #2). The
# host-key files are instead pointed at a fresh, empty temp file per call (see
# empty_known_hosts), so every connection is genuinely "new" on every platform.
_COMMON_OPTS = [
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'CheckHostIP=no',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'PreferredAuthentications=publickey',
    '-o', 'ConnectTimeout=15',
    '-o', 'ServerAliveInterval=10',
    '-o', 'ServerAliveCountMax=3',
    '-o', 'LogLevel=ERROR',
]


@contextlib.contextmanager
def empty_known_hosts():
    """Yield a path to a fresh, empty known_hosts file, removed afterwards.

    Used for both UserKnownHostsFile and GlobalKnownHostsFile so the host key
    the unit presents is never remembered or compared against a stale entry -
    reliably, unlike os.devnull on Windows (see _COMMON_OPTS)."""
    tmp = os.path.join(tempfile.gettempdir(), 'mgu_kh_' + uuid.uuid4().hex)
    try:
        with open(tmp, 'w'):
            pass
    except OSError:
        tmp = os.devnull  # fall back; worst case the old behaviour
    try:
        yield tmp
    finally:
        if tmp != os.devnull:
            try:
                os.remove(tmp)
            except OSError:
                pass


def secure_key_file(path):
    """Lock *path* down so the OpenSSH client will accept it as a private key.

    On Windows a key written under the user's profile/Desktop inherits an ACL
    that grants the Users / Authenticated Users group read access; OpenSSH then
    refuses it with 'UNPROTECTED PRIVATE KEY FILE' / 'bad permissions' and the
    key 'will be ignored'. Python's os.chmod(0o600) does NOT fix this on Windows
    (it only toggles the read-only bit, not the ACL). We grant the current user
    full control and then strip every inherited ACE, so the final DACL is this
    user only - which satisfies OpenSSH and still lets us rewrite/delete it. On
    POSIX a plain 0600 is enough. Best-effort: never raises."""
    try:
        if os.name == 'nt':
            user = os.environ.get('USERNAME') or os.environ.get('USER') or ''
            if user:
                # Grant first, THEN drop inheritance: if the grant name failed to
                # resolve, inheritance:r alone would leave the file with no ACEs
                # at all (unreadable even by us), which is worse than too-open.
                subprocess.run(['icacls', path, '/grant:r', '%s:F' % user],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(['icacls', path, '/inheritance:r'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.chmod(path, 0o600)
    except (OSError, ValueError):
        pass


def ssh_binary():
    return shutil.which('ssh') or ('ssh.exe' if os.name == 'nt' else 'ssh')


def available():
    """True if a usable OpenSSH client is on PATH."""
    return shutil.which('ssh') is not None or (
        os.name == 'nt' and shutil.which('ssh.exe') is not None)


@contextlib.contextmanager
def prepared_key(key_path):
    """Yield a key path the OpenSSH client will accept, cleaning it up after.

    OpenSSH refuses a private key other accounts can read ('UNPROTECTED PRIVATE
    KEY FILE'). On Windows a key under the user's Desktop usually inherits an
    ACL that grants the Users group read, which trips that check. We copy the
    key into a fresh temp file, lock it to the current user only, hand that to
    ssh, and delete it afterwards so no key copy lingers."""
    try:
        with open(key_path, 'rb') as f:
            data = f.read()
    except OSError:
        yield key_path  # let ssh report the real error
        return
    tmp = os.path.join(tempfile.gettempdir(), 'mgu_id_' + uuid.uuid4().hex)
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        yield key_path
        return
    try:
        secure_key_file(tmp)
        yield tmp
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _base_argv(host, key_path, user=SSH_USER, port=SSH_PORT, known_hosts=None):
    kh = []
    if known_hosts:
        kh = ['-o', 'UserKnownHostsFile=' + known_hosts,
              '-o', 'GlobalKnownHostsFile=' + known_hosts]
    return ([ssh_binary(), '-i', key_path, '-p', str(port)]
            + _COMMON_OPTS + kh + ['%s@%s' % (user, host)])


def run(host, key_path, command, user=SSH_USER, port=SSH_PORT, timeout=45,
        stdin_data=None):
    """Run a remote command. Returns (returncode, stdout, stderr)."""
    if isinstance(stdin_data, str):
        stdin_data = stdin_data.encode('utf-8')
    with prepared_key(key_path) as key, empty_known_hosts() as kh:
        argv = _base_argv(host, key, user, port, known_hosts=kh) + [command]
        try:
            p = subprocess.run(argv, input=stdin_data, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout)
            out = p.stdout.decode('utf-8', 'replace')
            err = p.stderr.decode('utf-8', 'replace')
            return p.returncode, out, err
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or b'').decode('utf-8', 'replace') if e.stdout else ''
            return 255, out, 'ssh timed out after %ss' % timeout
        except FileNotFoundError:
            return 255, '', ('OpenSSH client not found. Install the Windows OpenSSH '
                             'client (Settings > Apps > Optional features) or add ssh to PATH.')


def probe_login(host, key_path, user=SSH_USER, port=SSH_PORT, timeout=30,
                command='id'):
    """Try to log in and run a command (default: id). Returns a dict with
    'connected', 'output', 'rc' and (on failure) 'error'."""
    rc, out, err = run(host, key_path, command, user, port, timeout)
    res = {'host': host, 'user': user, 'connected': rc == 0,
           'output': out.strip(), 'rc': rc}
    if rc != 0:
        res['error'] = (err.strip() or ('exit code %d' % rc))
    return res


def push_and_run(host, key_path, local_file, remote, args='', user=SSH_USER,
                 port=SSH_PORT, timeout=60, normalize_eol=False):
    """Upload a local script to *remote* (via cat over the ssh channel, no scp
    needed) and run it with `sh`, then delete it. Returns (rc, stdout, stderr).

    With normalize_eol=True, CRLF/CR line endings are converted to LF before
    upload. The MGU's BusyBox shell treats a trailing CR as part of the token,
    so a CRLF script fails with "set: illegal option -" on the first option
    line. A Windows checkout (core.autocrlf) or a Notepad edit can introduce
    CRLF, so shell scripts are always normalized."""
    try:
        with open(local_file, 'rb') as f:
            data = f.read()
    except OSError as e:
        return 255, '', 'cannot read %s: %s' % (local_file, e)
    if normalize_eol:
        data = data.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    rc, out, err = run(host, key_path,
                       "cat > '%s' && chmod +x '%s'" % (remote, remote),
                       user, port, timeout=30, stdin_data=data)
    if rc != 0:
        return rc, out, err
    return run(host, key_path,
               "sh '%s' %s; r=$?; rm -f '%s'; exit $r" % (remote, args, remote),
               user, port, timeout)
