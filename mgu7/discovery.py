import ctypes
import ctypes.util
import ctypes.wintypes
import platform
import select
import socket
import struct
import time as _time
DISCOVERY_PORT = 6811
PROBE = b'\x00\x00\x00\x00\x00\x11'
MARKER = b'BMWVIN'
FALLBACK_BROADCASTS = ('255.255.255.255', '169.254.255.255')
IFF_UP = 1
IFF_BROADCAST = 2

# struct sockaddr differs by OS: the BSD family (macOS included) prefixes a
# 1-byte sa_len before a 1-byte sa_family; Linux has no sa_len and a 2-byte
# sa_family. Reading the wrong layout makes AF_INET (2) look like family 0 on
# little-endian Linux, so every interface is skipped and discovery silently
# falls back to the unbound broadcast it was meant to replace. The IPv4 address
# sits at the same offset (sa_data[2:6]) in both; only the family field moves.
_BSD_SOCKADDR = platform.system() in ('Darwin', 'FreeBSD', 'OpenBSD', 'NetBSD', 'DragonFly')

class _Sockaddr(ctypes.Structure):
    if _BSD_SOCKADDR:
        _fields_ = [('sa_len', ctypes.c_ubyte), ('sa_family', ctypes.c_ubyte), ('sa_data', ctypes.c_ubyte * 14)]
    else:
        _fields_ = [('sa_family', ctypes.c_ushort), ('sa_data', ctypes.c_ubyte * 14)]

class _Ifaddrs(ctypes.Structure):
    pass
_Ifaddrs._fields_ = [('ifa_next', ctypes.POINTER(_Ifaddrs)), ('ifa_name', ctypes.c_char_p), ('ifa_flags', ctypes.c_uint), ('ifa_addr', ctypes.POINTER(_Sockaddr)), ('ifa_netmask', ctypes.POINTER(_Sockaddr)), ('ifa_dstaddr', ctypes.POINTER(_Sockaddr)), ('ifa_data', ctypes.c_void_p)]

def _ipv4_from_sockaddr(sa_ptr):
    if not sa_ptr:
        return None
    sa = sa_ptr.contents
    if sa.sa_family != socket.AF_INET:
        return None
    return bytes(bytearray(sa.sa_data[2:6]))

class Gateway:

    def __init__(self, ip, vin=''):
        self.ip = ip
        self.vin = (vin or '')[:17]

    def __repr__(self):
        return 'Gateway(%s%s)' % (self.ip, ', vin=%s' % self.vin if self.vin else '')

def parse_reply(data):
    if not data:
        return None
    text = data.replace(b'\x00', b'').decode('ascii', 'replace')
    i = text.find('BMWVIN')
    if i < 0:
        return None
    return text[i + 6:i + 6 + 17]

def windows_broadcast_addresses():
    try:
        if platform.system() != 'Windows':
            return []
        import ctypes
        from ctypes import wintypes
        AF_INET = 2
        GAA_FLAGS = 8 | 16 | 512

        class SOCKET_ADDRESS(ctypes.Structure):
            _fields_ = [('lpSockaddr', ctypes.c_void_p), ('iSockaddrLength', wintypes.INT)]

        class UNICAST(ctypes.Structure):
            _fields_ = [('Length', wintypes.ULONG), ('Flags', wintypes.ULONG), ('Next', ctypes.c_void_p), ('Address', SOCKET_ADDRESS), ('OnLinkPrefixLength', ctypes.c_ubyte), ('SiteIdPrefixLength', ctypes.c_ubyte)]

        class ADAPTER_ADDRESSES(ctypes.Structure):
            _fields_ = [('Length', wintypes.ULONG), ('IfIndex', wintypes.ULONG), ('Next', ctypes.c_void_p), ('AdapterName', ctypes.c_char_p), ('FirstUnicastAddress', ctypes.c_void_p)]
        size = ctypes.wintypes.ULONG(16 * 1024)
        buf = ctypes.create_string_buffer(size.value)
        for _ in range(4):
            ret = ctypes.windll.iphlpapi.GetAdaptersAddresses(AF_INET, GAA_FLAGS, None, buf, ctypes.byref(size))
            if ret == 0:
                break
            if ret != 111:
                return []
            buf = ctypes.create_string_buffer(size.value)
        else:
            return []
        broadcasts = []
        cur = ctypes.cast(buf, ctypes.POINTER(ADAPTER_ADDRESSES))
        while cur:
            adapter = cur.contents
            ua = ctypes.cast(adapter.FirstUnicastAddress, ctypes.POINTER(UNICAST)) if adapter.FirstUnicastAddress else None
            while ua:
                sa = ctypes.cast(ua.contents.Address.lpSockaddr, ctypes.c_void_p)
                if sa:
                    raw = ctypes.string_at(sa, ua.contents.Address.iSockaddrLength)
                    if len(raw) >= 8 and struct.unpack_from('<H', raw)[0] == AF_INET:
                        ip = struct.unpack_from('<I', raw, 4)[0]
                        prefix = ua.contents.OnLinkPrefixLength
                        if 0 <= prefix <= 32:
                            mask = 4294967295 << 32 - prefix & 4294967295 if prefix else 0
                            bcast = ip | ~mask & 4294967295
                            text = '.'.join((str(bcast >> s & 255) for s in (24, 16, 8, 0)))
                            if text not in broadcasts:
                                broadcasts.append(text)
                ua = ctypes.cast(ua.contents.Next, ctypes.POINTER(UNICAST)) if ua.contents.Next else None
            cur = ctypes.cast(adapter.Next, ctypes.POINTER(ADAPTER_ADDRESSES)) if adapter.Next else None
        return broadcasts
    except Exception:
        return []

def posix_broadcast_targets():
    """Return [(broadcast, source)] for every up IPv4 interface that can broadcast.

    macOS/Linux route an unbound 255.255.255.255 out of the default interface,
    so the ENET probe never reaches the car on a second adapter. Binding each
    probe to that interface's own address is what selects the right NIC - no
    root, no SO_BINDTODEVICE.
    """
    targets, ptr = [], ctypes.POINTER(_Ifaddrs)()
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    if libc.getifaddrs(ctypes.byref(ptr)) != 0:
        return targets
    try:
        cur = ptr
        while cur:
            entry = cur.contents
            ip = _ipv4_from_sockaddr(entry.ifa_addr)
            mask = _ipv4_from_sockaddr(entry.ifa_netmask)
            if ip and mask and entry.ifa_flags & IFF_UP and entry.ifa_flags & IFF_BROADCAST:
                addr = struct.unpack('>I', ip)[0]
                netmask = struct.unpack('>I', mask)[0]
                bcast = socket.inet_ntoa(struct.pack('>I', addr | ~netmask & 4294967295))
                source = socket.inet_ntoa(ip)
                if (bcast, source) not in targets:
                    targets.append((bcast, source))
            cur = entry.ifa_next
    finally:
        libc.freeifaddrs(ptr)
    return targets

def broadcast_targets():
    """[(broadcast, source)] to try; source None lets the OS choose the route."""
    if platform.system() == 'Windows':
        targets = [(b, None) for b in windows_broadcast_addresses()]
    else:
        targets = posix_broadcast_targets()
    # Always ALSO probe the limited/link-local fallbacks unbound, exactly as the
    # pre-1.3.0 tool did. The per-adapter enumeration can miss the ENET APIPA
    # 169.254.x.x broadcast (on Windows the adapter's primary address is often a
    # DHCP one and the auto-config 169.254 is not exposed as a broadcast), yet
    # that is where the gateway actually is - dropping these fallbacks regressed
    # discovery in 1.3.0 (issue #48). Additive and de-duplicated, so the bound
    # per-interface probes from the macOS/Linux fix are kept.
    have = {b for b, _ in targets}
    for fb in FALLBACK_BROADCASTS:
        if fb not in have:
            targets.append((fb, None))
    return targets

def _respond(sock, log, wait_s):
    deadline = _time.monotonic() + wait_s
    while True:
        remain = deadline - _time.monotonic()
        if remain <= 0:
            return
        ready, _, _ = select.select([sock], [], [], remain)
        if not ready:
            return
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            return
        vin = parse_reply(data)
        if vin is None:
            log('Ignored a UDP %d reply from %s (no BMWVIN marker).' % (DISCOVERY_PORT, addr[0]))
            continue
        yield Gateway(addr[0], vin)

def _discover_bound(targets, timeout_ms, overall_ms, log):
    """Probe from every interface at once so one adapter being slow or asleep
    cannot consume the whole receive window before another one replies."""
    sockets = []
    try:
        for bcast, source in targets:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                if source:
                    sock.bind((source, 0))
                sock.setblocking(False)
            except OSError as e:
                log('Skipped %s: %s' % (bcast, e))
                sock.close()
                continue
            try:
                sock.sendto(PROBE, (bcast, DISCOVERY_PORT))
            except OSError as e:
                log('Skipped %s: %s' % (bcast, e))
                sock.close()
                continue
            log('ENET discovery broadcast -> %s:%d (from %s)' % (bcast, DISCOVERY_PORT, source or 'auto'))
            sockets.append(sock)
        if not sockets:
            return []
        results, order = {}, []
        deadline = _time.monotonic() + overall_ms / 1000.0
        quiet = _time.monotonic() + timeout_ms / 1000.0
        while True:
            now = _time.monotonic()
            if now >= deadline or (order and now >= quiet):
                break
            ready, _, _ = select.select(sockets, [], [], min(0.1, deadline - now))
            if not ready:
                continue
            for sock in ready:
                try:
                    data, addr = sock.recvfrom(4096)
                except OSError:
                    continue
                vin = parse_reply(data)
                if vin is None:
                    log('Ignored a UDP %d reply from %s (no BMWVIN marker).' % (DISCOVERY_PORT, addr[0]))
                    continue
                if addr[0] not in results:
                    results[addr[0]] = vin
                    order.append(addr[0])
                    quiet = _time.monotonic() + timeout_ms / 1000.0
        return [Gateway(ip, results[ip]) for ip in order]
    finally:
        for sock in sockets:
            sock.close()

def discover(timeout_ms=500, overall_ms=None, broadcasts=None, log=None):
    log = log or (lambda *a, **k: None)
    overall_ms = overall_ms or timeout_ms * 4
    if broadcasts is not None:
        targets = [(b, None) for b in broadcasts]
    else:
        targets = broadcast_targets()
    if platform.system() != 'Windows':
        return _discover_bound(targets, timeout_ms, overall_ms, log)
    results, order = {}, []
    for bcast, _ in targets:
        log('ENET discovery broadcast -> %s:%d (from %s)' % (bcast, DISCOVERY_PORT, 'auto'))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                sock.sendto(PROBE, (bcast, DISCOVERY_PORT))
            except OSError:
                continue
            sock.settimeout(max(timeout_ms, 1) / 1000.0)
            for gw in _respond(sock, log, timeout_ms / 1000.0):
                if gw.ip not in results:
                    results[gw.ip] = gw.vin
                    order.append(gw.ip)
        finally:
            sock.close()
    return [Gateway(ip, results[ip]) for ip in order]

