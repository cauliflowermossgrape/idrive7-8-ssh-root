import hashlib
import re
import socket
import struct
import time
from .hsfz import EnetClient, HsfzError, Response, UdsReject, X, GATEWAY, MGU, TESTER, P_ADVANCED, P_SVK, P_READ_IP
SLEEP_TESTER_PRESENT_MS = 1050
SLEEP_HARD_RESET_MS = 3500
RESPONSE_TIMEOUT_MS = 15000
STOP_LIMIT_36_24 = 10
ID7 = 'id7'
ID8_BDC3 = 'id8-bdc3'
ID8_BCP = 'id8-bcp'
CONTRACTS = {ID7: ('A', 174, 0, '13', 'MGU ID7 • BDC2 / BDC3'), ID8_BDC3: ('a', 173, 7, '14', 'MGU ID8 • BDC3'), ID8_BCP: ('B', 173, 9, '15', 'MGU ID8 • BCP')}
_VIN_RE = re.compile('^[A-HJ-NPR-Z0-9]{17}$')
_HEX_RE = re.compile('^[0-9A-F]+$')
U_SID_ECHO = {34: 2, 46: 2, 49: 3}

class FlashError(Exception):
    pass

class HFrame:
    __slots__ = ('type', 'src', 'dst', 'payload')

    def __init__(self, ftype, src, dst, payload):
        if ftype != 1:
            raise FlashError('A diagnostic frame with a UDS payload is required.')
        if src != TESTER:
            raise FlashError('The frame came from an unexpected tester address 0x%02X.' % src)
        if dst not in (MGU, GATEWAY):
            raise FlashError('The frame was aimed at an unexpected ECU address 0x%02X.' % dst)
        self.type = ftype
        self.src = src
        self.dst = dst
        self.payload = bytes(payload)

class PFrame:
    __slots__ = ('h',)

    def __init__(self, hframe):
        self.h = hframe

    @property
    def payload(self):
        return self.h.payload

    @property
    def sid(self):
        return self.payload[0]

    @property
    def sub(self):
        return self.payload[1]

    @property
    def is_transfer(self):
        return self.sid == 54

    @property
    def is_finish(self):
        return self.sid == 55

    @property
    def is_suppressed_tester_present(self):
        return self.sid == 62 and self.sub == 128

    @property
    def is_ecu_reset(self):
        return self.sid == 17 and self.sub == 1

    @property
    def kind(self):
        labels = {16: 'Diagnostic session', 17: 'ECU reset', 34: 'Read identifier', 39: 'Security access', 40: 'Communication control', 46: 'Write identifier', 49: 'Routine control', 52: 'Request download', 55: 'Finish transfer', 62: 'Tester present', 133: 'DTC setting'}
        if self.is_transfer:
            return 'Transfer data block %02X' % self.sub
        return labels.get(self.sid, 'Unknown service')

class Part:
    __slots__ = ('start', 'end', 'index', 'count')

    def __init__(self, start, end, index, count):
        self.start = start
        self.end = end
        self.index = index
        self.count = count

def _decode_hex_check(text):
    if not text:
        return b''
    if len(text) % 2 != 0 or not _HEX_RE.match(text):
        raise FlashError('The flash material contains invalid hexadecimal data.')
    return bytes.fromhex(text)

class FlashData:

    def __init__(self, name, vin, frames, parts, padding):
        self.name = name
        self.vin = vin
        self.frames = frames
        self.parts = parts
        self.padding = padding

    @property
    def variant(self):
        return CONTRACTS[self.name][0]

    @property
    def label(self):
        return CONTRACTS[self.name][4]

    @property
    def validated(self):
        return len(self.frames) == CONTRACTS[self.name][1]

    @property
    def transfer_bytes(self):
        return sum((p.count for p in self.parts))

    def part_at(self, index):
        for p in self.parts:
            if p.start <= index <= p.end:
                return p.index
        return 0

    @staticmethod
    def build(name, vin, material):
        if name not in CONTRACTS:
            raise FlashError('Unsupported MGU flash contract.')
        variant, nframes, npad, asset, label = CONTRACTS[name]
        vin = FlashData._normalize_vin(vin)
        if not material:
            raise FlashError('The flash material image is required.')
        frames, padding = FlashData._parse_material(material, vin)
        FlashData._validate_boundaries(frames, vin)
        parts = FlashData._scan_parts(frames)
        if len(frames) != nframes or padding != npad:
            raise FlashError('The %s flash contract decoded %d frames and %d padding byte(s); expected %d frames and %d padding byte(s).' % (label, len(frames), padding, nframes, npad))
        return FlashData(name, vin, frames, parts, padding)

    @staticmethod
    def _normalize_vin(vin):
        vin = (vin or '').strip().upper()
        if not _VIN_RE.match(vin):
            raise FlashError('A valid 17-character VIN (excluding I, O and Q) is required.')
        return vin

    @staticmethod
    def _parse_material(material, vin):
        blob = bytearray()
        entries = 0
        start = None
        n = len(material)
        i = 0
        while i < n:
            b = material[i]
            if b == 10:
                if start is not None:
                    line = bytes(material[start:i]).strip(b'\r \t\x0b\x0c')
                    blob += _decode_hex_check(line.decode('ascii', errors='strict') if line else '')
                    if entries == 170:
                        blob += vin.encode('ascii')
                    entries += 1
                    start = None
            elif start is None:
                start = i
            i += 1
        if start is not None:
            line = bytes(material[start:]).strip(b'\r \t\x0b\x0c')
            blob += _decode_hex_check(line.decode('ascii', 'strict') if line else '')
            if entries == 170:
                blob += vin.encode('ascii')
            entries += 1
        if entries == 0:
            raise FlashError('The flash material contains no data.')
        frames = []
        padding = 0
        off = 0
        data = bytes(blob)
        while off + 6 <= len(data):
            ln = struct.unpack('>I', data[off:off + 4])[0]
            if data[off + 4] == 0 and data[off + 5] == 1 and (ln >= 2) and (off + 6 + ln <= len(data)):
                frames.append(PFrame(HFrame(1, data[off + 6], data[off + 7], data[off + 8:off + 6 + ln])))
                off += 6 + ln
            else:
                off += 1
                padding += 1
        padding += len(data) - off
        return (frames, padding)

    @staticmethod
    def _validate_boundaries(frames, vin):
        if len(frames) < 5:
            raise FlashError('Flash contract is unexpectedly short.')
        if frames[0].payload != bytes.fromhex('31 03 A0 FD') or frames[1].payload != bytes.fromhex('22 80 00') or frames[-1].payload != bytes.fromhex('11 01'):
            raise FlashError('Flash contract boundary commands do not match the proven sequence.')
        vin_frame = bytes.fromhex('2E F1 90') + vin.encode('ascii')
        if sum((1 for f in frames if f.payload == vin_frame)) != 1:
            raise FlashError('Flash contract must contain exactly one vehicle-identification write frame.')
        if sum((1 for f in frames if f.sid == 39 and f.sub == 17)) != 2:
            raise FlashError('Flash contract must contain two SecurityAccess seed requests.')

    @staticmethod
    def _scan_parts(frames):
        parts = []
        start = -1
        last_bn = -1
        count = 0

        def close(end):
            nonlocal start, last_bn, count
            if start >= 0:
                parts.append(Part(start, end, len(parts) + 1, count))
                start = -1
                last_bn = -1
                count = 0
        for i, f in enumerate(frames):
            if f.is_transfer:
                bn = f.sub
                if start < 0 or (last_bn >= bn and (not (last_bn == 255 and bn == 0))):
                    close(i - 1)
                    start = i
                last_bn = bn
                count += len(f.payload)
            elif f.is_finish:
                close(i)
            else:
                close(i - 1)
        close(len(frames) - 1)
        return parts

class SecurityOperands:
    MAGIC = b'M7F1'
    PREFIX = bytes((255, 255, 255, 255, 0, 0, 63, 54))

    def __init__(self, blob):
        if not blob or len(blob) != 268:
            raise FlashError('The M7F1 security operands must contain exactly 268 bytes.')
        if blob[0:4] != self.MAGIC:
            raise FlashError('The M7F1 security operands are unavailable.')
        if struct.unpack('<H', blob[4:6])[0] != 1 or struct.unpack('<H', blob[6:8])[0] != 12 or struct.unpack('<H', blob[8:10])[0] != 128 or (struct.unpack('<H', blob[10:12])[0] != 128):
            raise FlashError('The M7F1 security operands are unavailable.')
        self.exponent = int.from_bytes(bytes(reversed(blob[12:140])), 'little')
        self.modulus = int.from_bytes(bytes(reversed(blob[140:268])), 'little')
        if self.exponent <= 0 or self.modulus <= 0:
            raise FlashError('The M7F1 security operands are unavailable.')

    def compute_key_payload(self, seed, level):
        if len(seed) != 8:
            raise FlashError('The M7F1 seed must contain 8 bytes.')
        digest = hashlib.sha256(self.PREFIX + bytes(seed)).digest()
        value = int.from_bytes(digest, 'little')
        key = pow(value, self.exponent, self.modulus)
        try:
            field = key.to_bytes(128, 'big')
        except OverflowError:
            raise FlashError('The M7F1 key exceeded its 128-byte field.')
        words = b''.join((field[i:i + 4] for i in range(124, -4, -4)))
        payload = bytes((39, level, 0, 0, 0, 32)) + words
        if len(payload) != 134:
            raise FlashError('The M7F1 key did not produce a full 1024-bit field.')
        return payload

def _is_seed_level(b):
    return b == 1 or b == 17

def _x_is_7f(payload, sid, nrc):
    return payload is not None and len(payload) == 3 and (payload[0] == 127) and (payload[1] == sid) and (payload[2] == nrc)

def _x_is_negative(payload):
    return payload is not None and len(payload) >= 3 and (payload[0] == 127)

def _x_is_positive(payload, request_sid):
    if not payload or not len(payload):
        return False
    if payload[0] != 103:
        return payload[0] == request_sid + 64 & 255
    return True

def _matches_rd_f08000(payload):
    return len(payload) == 11 and payload[0] == 52 and (payload[1] == 0) and (payload[2] == 68) and (payload[3] == 0) and (payload[4] == 240) and (payload[5] == 128) and (payload[6] == 0) and (payload[7] == 1) and (payload[8] == 51) and (payload[9] == 112) and (payload[10] == 0)

def _matches_rd_f0a00xx(payload, b2):
    return len(payload) == 11 and payload[0] == 52 and (payload[1] == 0) and (payload[2] == 68) and (payload[3] == 0) and (payload[4] == 240) and (payload[5] == 160) and (payload[6] == 0) and (payload[7] == 0) and (payload[8] == 0) and (payload[9] == 6) and (payload[10] == b2)

def _is_22_f1_86(payload):
    return payload is not None and len(payload) == 3 and (payload[0] == 34) and (payload[1] == 241) and (payload[2] == 134)

def _same_endpoints(a, b):
    return a.src == b.src and a.dst == b.dst

def validate_route(response, request_frame, where='ECU response'):
    frame = response.frame
    t = request_frame
    if frame is None:
        raise HsfzError('Flash frame: the %s was missing.' % where)
    if frame.type != 1:
        raise HsfzError('Flash frame: the %s used HSFZ type 0x%04X.' % (where, frame.type))
    if t.dst != GATEWAY:
        ok = frame.src == t.dst
    else:
        if frame.src == 0 or frame.src == t.src:
            raise HsfzError('Flash frame: the %s came from unexpected HSFZ endpoint 0x%02X→0x%02X; expected a response to 0x%02X→0x%02X.' % (where, frame.src, frame.dst, t.src, t.dst))
        ok = frame.src != t.dst
    if not (ok and frame.dst == t.src):
        raise HsfzError('Flash frame: the %s came from unexpected HSFZ endpoint 0x%02X→0x%02X; expected a response to 0x%02X→0x%02X.' % (where, frame.src, frame.dst, t.src, t.dst))

def validate_payload(response_payload, request_payload, where='ECU response'):
    data = response_payload
    req_sid = request_payload[0]
    if not data or not len(data):
        raise UdsReject('The ECU returned an empty UDS response.', req_sid, 0)
    if data[0] == 127:
        if len(data) >= 3:
            raise UdsReject('The ECU rejected service 0x%02X with NRC 0x%02X.' % (data[1], data[2]), data[1], data[2])
        raise UdsReject('The negative UDS response was truncated.', req_sid, 0)
    if data[0] != req_sid + 64 & 255:
        raise UdsReject('Unexpected UDS response service 0x%02X; expected 0x%02X.' % (data[0], req_sid + 64 & 255), req_sid, 0)
    n = U_SID_ECHO.get(req_sid, 0)
    if n == 0:
        return
    if len(request_payload) < 1 + n or len(data) < 1 + n:
        raise UdsReject('The positive UDS response is too short to verify its echoed identifier.', req_sid, 0)
    for i in range(n):
        if data[1 + i] != request_payload[1 + i]:
            raise UdsReject('The positive UDS response echoes a different subfunction or identifier.', req_sid, 0)

def extract_seed(response_payload, seed_level):
    data = response_payload
    if data is not None and len(data) >= 10 and (data[0] == 103) and (data[1] == seed_level):
        return data[2:10]
    return None

def describe_response(response, request_frame):
    frame = response.frame
    t = request_frame
    if frame is None:
        return 'the final HSFZ response was missing'
    if frame.type != 1:
        return 'the final HSFZ frame used type 0x%04X from 0x%02X to 0x%02X' % (frame.type, frame.src, frame.dst)
    if t.dst != GATEWAY:
        route_ok = frame.src == t.dst
    else:
        route_ok = frame.src != 0 and frame.src != t.src and (frame.src != t.dst)
    if not (route_ok and frame.dst == t.src):
        return 'the final diagnostic response used endpoint 0x%02X to 0x%02X instead of the requested route' % (frame.src, frame.dst)
    data = response.payload.data if response.payload is not None else b''
    if not data or not len(data):
        return 'the final diagnostic response had an empty UDS payload'
    if data[0] == 127:
        if len(data) >= 3:
            return 'the final UDS response was 7F %02X %02X (service 0x%02X, NRC 0x%02X)' % (data[1], data[2], data[1], data[2])
        return 'the final negative UDS response was truncated to %d byte(s)' % len(data)
    return 'the final UDS response was unexpected or short (SID 0x%02X, %d byte(s))' % (data[0], len(data))

class FlashResult:

    def __init__(self, variant, vin, frames, keys, pendings, reset_silences, rule_3422, expected_compat, warnings, legacy_advances):
        self.variant = variant
        self.vin = vin
        self.frames = frames
        self.keys = keys
        self.pendings = pendings
        self.reset_silences = reset_silences
        self.rule_3422 = rule_3422
        self.expected_compat = expected_compat
        self.warnings = warnings
        self.legacy_advances = legacy_advances

    def summary(self):
        return 'Flash sequence finished: %d frames, %d security responses, %d pending responses, %d response warning(s), including %d legacy-response advance(s). Expected compatibility response: %d.' % (self.frames, self.keys, self.pendings, self.warnings, self.legacy_advances, self.expected_compat)

def patch_region_file(data, path, filedata):
    """Rewrite the ONE unsigned HAR region of a built FlashData so it installs
    *path*/*filedata* instead of the stock file it carried (debugCA).

    The debug contract writes a single unsigned HAR region (RequestDownload to
    ...F0 A0 xx) that is NOT covered by the BMW signature. This replaces its
    content with our own one-file archive, padded to the original region's exact
    length, then re-splits it across the SAME TransferData frames with the SAME
    block numbers and lengths. The frame count, every frame length, the
    RequestDownload and the whole rest of the proven sequence are unchanged - only
    the content bytes of that region's transfer frames differ. Returns a small
    info dict (region size + frame indices touched)."""
    frames = data.frames
    rd = None
    for i, f in enumerate(frames):
        p = f.payload
        if len(p) >= 7 and p[0] == 52 and p[4] == 240 and p[5] == 160:  # 34 .. F0 A0
            rd = i
            break
    if rd is None:
        raise FlashError('This flash contract has no unsigned HAR region (F0A0 '
                         'RequestDownload); the key-flash repair is not available for it.')
    xf = []
    j = rd + 1
    while j < len(frames) and frames[j].payload and frames[j].payload[0] == 54:  # 0x36
        xf.append(j)
        j += 1
    if not xf:
        raise FlashError('The unsigned HAR region carries no TransferData frames.')
    orig = b''.join(frames[k].payload[2:] for k in xf)
    from . import har
    region = har.replace_region_with_file(orig, path, filedata)
    if len(region) != len(orig):
        raise FlashError('The patched region length changed (%d != %d).' % (len(region), len(orig)))
    pos = 0
    for k in xf:
        old = frames[k]
        blen = len(old.payload) - 2
        new_payload = bytes((54, old.payload[1])) + region[pos:pos + blen]
        pos += blen
        frames[k] = PFrame(HFrame(old.h.type, old.h.src, old.h.dst, new_payload))
    return {'rd_index': rd, 'transfer_indices': xf, 'region_bytes': len(orig)}


class FlashEngine:

    def __init__(self, client, operands, gate=None, response_timeout_ms=RESPONSE_TIMEOUT_MS, tester_present_ms=SLEEP_TESTER_PRESENT_MS, hard_reset_ms=SLEEP_HARD_RESET_MS):
        self.client = client
        self.operands = operands
        self.gate = gate
        self.response_timeout_ms = response_timeout_ms
        self.tester_present_ms = tester_present_ms
        self.hard_reset_ms = hard_reset_ms

    @staticmethod
    def _validated(data):
        return data is not None and data.validated

    @staticmethod
    def _is_df_tail_routine(data, i):
        n = len(data.frames)
        if not FlashEngine._validated(data) or (i != n - 3 and i != n - 2):
            return False
        f = data.frames[i]
        if not f or f.sid != 49 or f.sub != 1 or (f.h.dst != GATEWAY):
            return False
        expected = bytes((49, 1, 15, 12, 0)) if i == n - 3 else bytes((49, 1, 16, 15))
        if f.payload != expected:
            return False
        return FlashEngine._is_final_reset(data, n - 1)

    @staticmethod
    def _is_final_reset(data, i):
        n = len(data.frames)
        if not FlashEngine._validated(data) or i != n - 1:
            return False
        prev = data.frames[n - 2]
        last = data.frames[i]
        return prev is not None and prev.h.src == TESTER and (prev.h.dst == GATEWAY) and (prev.payload == bytes((49, 1, 16, 15))) and (last is not None) and (last.h.src == TESTER) and (last.h.dst == MGU) and (last.payload == bytes((17, 1)))

    @staticmethod
    def _readiness_probe_silent(data, i):
        frames = data.frames if data is not None else None
        if not frames or i < 0 or i + 1 >= len(frames):
            return False
        t2 = frames[i].h
        t3 = frames[i + 1].h
        if not _is_22_f1_86(t2.payload) or not _same_endpoints(t2, t3) or len(t2.payload) != len(t3.payload):
            return False
        if t2.payload != t3.payload:
            return False
        j = i
        while j > 0 and _same_endpoints(frames[j - 1].h, t2) and _is_22_f1_86(frames[j - 1].payload):
            j -= 1
        if j == 0:
            return False
        prev = frames[j - 1]
        if prev.is_ecu_reset and prev.h.src == t2.src:
            return prev.h.dst == t2.dst
        return False

    @staticmethod
    def _prep_routine_silent(data, i):
        frames = data.frames if data is not None else None
        if not FlashEngine._validated(data):
            return False
        n = len(frames)
        num = 0 if data.variant == 'A' else -1
        flag = data.variant == 'B' and i == 46
        if i != 40 + num and (not flag):
            return False
        num2 = 46 if flag else 40 + num
        if num2 + 2 >= n:
            return False
        t2, t3, t4 = (frames[num2].h, frames[num2 + 1].h, frames[num2 + 2].h)
        trio = t2.src == TESTER and t2.dst == MGU and (t2.payload == bytes((49, 3, 160, 253))) and (t3.src == TESTER) and (t3.dst == MGU) and (t3.payload == bytes((34, 128, 0))) and (t4.src == TESTER) and (t4.dst == MGU) and (t4.payload == bytes((49, 1, 166, 113)))
        if not trio or flag:
            return trio
        if 38 + num + 1 >= n:
            return False
        t5 = frames[38 + num].h
        t6 = frames[39 + num].h
        if t5.src == TESTER and t5.dst == MGU and (t5.payload == bytes((17, 1))) and (t6.src == TESTER) and (t6.dst == GATEWAY):
            return t6.payload == bytes((62, 128))
        return False

    @staticmethod
    def _rule_7f_34_22(data, i, prev_positive, payload):
        frames = data.frames if data is not None else None
        if not prev_positive or not FlashEngine._validated(data) or i != 30 or (not _x_is_7f(payload, 52, 34)):
            return False
        n = len(frames)
        if i - 1 < 0 or i + 1 >= n:
            return False
        b2 = 55 if data.variant == 'A' else 52
        t2, t3, t4 = (frames[i - 1].h, frames[i].h, frames[i + 1].h)
        if not (t3.src == TESTER and t3.dst == MGU and _same_endpoints(t2, t3) and _same_endpoints(t3, t4) and _matches_rd_f08000(t2.payload) and _matches_rd_f0a00xx(t3.payload, b2)):
            return False
        if len(t4.payload) == 1402 and t4.payload[0] == 54:
            return t4.payload[1] == 1
        return False

    @staticmethod
    def _expected_compat(data, i, payload, flag5):
        if flag5:
            return 'Expected compatibility response: the exact protected nested RequestDownload returned 7F 34 22. The protected sequence advances without resending this frame.'
        frames = data.frames if data is not None else None
        if not FlashEngine._validated(data) or i < 0 or i >= len(frames):
            return None
        f = frames[i]
        flag = data.variant == 'A'
        num = 0 if flag else -1
        flag3 = False
        if flag and i == 33:
            flag3 = f.payload == bytes((55,)) and _x_is_7f(payload, 55, 114)
        elif i == 34 + num:
            flag3 = f.payload == bytes((49, 1, 2, 2, 18, 64, 0, 4, 16, 0, 0, 0)) and _x_is_7f(payload, 49, 34)
        elif i == 35 + num:
            flag3 = f.payload == bytes((49, 1, 255, 1)) and _x_is_7f(payload, 49, 34)
        elif i == 0 or i == 40 + num or (data.variant == 'B' and i == 46):
            flag3 = f.payload == bytes((49, 3, 160, 253)) and _x_is_7f(payload, 49, 49)
        elif i == 1 or i == 41 + num or (data.variant == 'B' and i == 47):
            flag3 = f.payload == bytes((34, 128, 0)) and _x_is_7f(payload, 34, 49)
        elif i == 2 or i == 42 + num or (data.variant == 'B' and i == 48):
            flag3 = f.payload == bytes((49, 1, 166, 113)) and _x_is_7f(payload, 49, 49)
        if not flag3:
            return None
        if payload is not None and len(payload) >= 3 and (payload[0] == 127) and (len(payload) == 3):
            desc = 'the final UDS response was 7F %02X %02X (service 0x%02X, NRC 0x%02X)' % (payload[1], payload[2], payload[1], payload[2])
        else:
            desc = 'the protected response matched this compatibility rule'
        return 'Expected compatibility response: %s. The protected sequence advances without resending this frame.' % desc

    def run(self, data, progress=None):
        progress = progress or (lambda *a, **k: None)
        frames = data.frames
        count = len(frames)
        n = count
        operands = self.operands
        if operands is None:
            raise FlashError('Flash is locked because no supported M7F1 security operands were provided.')
        if self.gate is not None and (not self.gate()):
            raise FlashError('Flash is locked because the current connection has no freshly decoded supported BTLD 00003F36 SVK.')
        num = 0
        keys = 0
        pendings = 0
        reset_silences = 0
        rule_3422 = 0
        expected_compat = 0
        warnings = 0
        legacy_advances = 0
        consecutive_36_24 = 0
        last_positive = False
        expected_keys = sum((1 for f in frames if f.sid == 39 and _is_seed_level(f.sub)))
        for i in range(count):
            p = frames[i]
            t = p.h
            prev_positive = last_positive
            last_positive = False
            human = i + 1
            part = data.part_at(i)
            percent = int(100.0 * i / count) if count else 0
            progress(human, count, percent, part, p.kind, 'TX 0x%02X → 0x%02X • %d bytes' % (t.src, t.dst, len(t.payload)))
            if p.is_suppressed_tester_present:
                self.client.send_suppressed(t.dst, t.payload)
                num += 1
                time.sleep(self.tester_present_ms / 1000.0)
                progress(human, count, percent, part, p.kind, 'Sent with suppressed positive response; the required pause completed.')
                continue
            if self._is_df_tail_routine(data, i):
                v2 = self.client.await_routine(t.payload)
            elif not self._is_final_reset(data, i):
                v2 = self.client.await_one(t.dst, t.payload, self.response_timeout_ms)
            else:
                v2 = self.client.await_reset(t.dst, t.payload, self.response_timeout_ms)
            num += 1
            pendings += v2.pending
            is_seed = p.sid == 39 and _is_seed_level(p.sub)
            if v2.timeout:
                if is_seed:
                    raise FlashError('Flash frame %d/%d: SecurityAccess seed response timed out; the sequence was stopped before the next vehicle frame.' % (human, count))
                if p.is_ecu_reset:
                    reset_silences += 1
                    warnings += 1
                    legacy_advances += 1
                    progress(human, count, percent, part, p.kind, 'The hard-reset response was not observed. The required reset pause will be applied.')
                    time.sleep(self.hard_reset_ms / 1000.0)
                elif self._readiness_probe_silent(data, i):
                    expected_compat += 1
                    progress(human, count, percent, part, p.kind, 'Expected compatibility response: the read-only post-reset readiness probe was silent. The next protected frame is the same probe, so readiness will be checked once more.')
                elif self._prep_routine_silent(data, i):
                    expected_compat += 1
                    progress(human, count, percent, part, p.kind, 'Expected compatibility response: the exact repeated post-reset preparation routine was silent. The protected sequence advances without resending this frame.')
                else:
                    warnings += 1
                    legacy_advances += 1
                    progress(human, count, percent, part, p.kind, 'Legacy parity warning: the ECU response timed out after %d pending response(s). The pinned worker advances to %s without resending this frame.' % (v2.pending, 'the next protected frame' if i + 1 < count else 'the end of the protected sequence'))
                    if p.is_ecu_reset:
                        time.sleep(self.hard_reset_ms / 1000.0)
                continue
            if is_seed:
                consecutive_36_24 = 0
                validate_route(v2, t, 'SecurityAccess seed response')
                validate_payload(v2.payload.data, t.payload, 'SecurityAccess seed response')
                seed = extract_seed(v2.payload.data, p.sub)
                if seed is None:
                    raise FlashError('Flash frame %d/%d: the ECU returned a short or unexpected SecurityAccess seed; the sequence was stopped before the next vehicle frame.' % (human, count))
                key_level = (p.sub & 254) + 2
                key_payload = operands.compute_key_payload(seed, key_level)
                progress(human, count, percent, part, p.kind, 'Seed accepted; sending the locally calculated key.')
                v3 = self.client.await_one(t.dst, key_payload, self.response_timeout_ms)
                pendings += v3.pending
                if v3.timeout:
                    raise FlashError('Flash frame %d/%d: SecurityAccess key response timed out; the sequence was stopped before the next vehicle frame.' % (human, count))
                validate_route(v3, t, 'SecurityAccess key response')
                validate_payload(v3.payload.data, key_payload, 'SecurityAccess key response')
                keys += 1
                progress(human, count, percent, part, p.kind, 'Positive response received.' if v2.pending == 0 else 'Positive response received after %d pending response(s).' % v2.pending)
                last_positive = True
                continue
            ex = None
            try:
                validate_route(v2, t)
                validate_payload(v2.payload.data, t.payload)
            except (HsfzError, UdsReject) as e:
                ex = e
            if ex is not None:
                flag4 = _x_is_7f(v2.payload.data, 54, 36)
                if flag4:
                    consecutive_36_24 += 1
                elif _x_is_negative(v2.payload.data):
                    consecutive_36_24 = 0
                elif _x_is_positive(v2.payload.data, p.sid):
                    consecutive_36_24 = 0
                flag5 = rule_3422 == 0 and self._rule_7f_34_22(data, i, prev_positive, v2.payload.data)
                if flag5:
                    rule_3422 += 1
                compat = self._expected_compat(data, i, v2.payload.data, flag5)
                if compat is not None:
                    expected_compat += 1
                    progress(human, count, percent, part, p.kind, compat)
                    if p.is_ecu_reset:
                        time.sleep(self.hard_reset_ms / 1000.0)
                    continue
                warnings += 1
                legacy_advances += 1
                text2 = describe_response(v2, t)
                text3 = 'Legacy parity warning: %s. The pinned worker advances to %s without resending this frame.' % (text2, 'the next protected frame' if i + 1 < count else 'the end of the protected sequence')
                if flag4:
                    text3 += ' Consecutive service 0x36 / NRC 0x24 count: %d/10.' % consecutive_36_24
                progress(human, count, percent, part, p.kind, text3)
                if consecutive_36_24 >= STOP_LIMIT_36_24:
                    raise UdsReject('Flash frame %d/%d: the pinned worker stop limit was reached after 10 consecutive service 0x36 / NRC 0x24 responses. The next protected frame was not sent.' % (human, count), 54, 36)
                if p.is_ecu_reset:
                    time.sleep(self.hard_reset_ms / 1000.0)
            else:
                consecutive_36_24 = 0
                progress(human, count, percent, part, p.kind, 'Positive response received.' if v2.pending == 0 else 'Positive response received after %d pending response(s).' % v2.pending)
                last_positive = True
                if p.is_ecu_reset:
                    time.sleep(self.hard_reset_ms / 1000.0)
        if num != count or keys != expected_keys:
            raise FlashError('The flash sequence did not complete every required frame and SecurityAccess exchange (%d/%d frames, %d/%d keys).' % (num, count, keys, expected_keys))
        return FlashResult(data.variant, data.vin, num, keys, pendings, reset_silences, rule_3422, expected_compat, warnings, legacy_advances)
