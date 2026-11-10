import struct
from .hsfz import EnetClient, HsfzError, UdsReject, X, MGU, GATEWAY, TESTER, P_ADVANCED, P_SVK, P_READ_IP, P_ISTEP, match_response, require_response
REQUEST_SVK = bytes.fromhex('22 F1 01')
REQUEST_IP = bytes.fromhex('22 17 2A')
REQUEST_DTC = bytes.fromhex('19 02 0C')
ROUTINE_DEBUG_STOP = bytes.fromhex('31 02 A0 FD')
ROUTINE_DEBUG_RESULTS = bytes.fromhex('31 03 A0 FD')
# The exact tail the proven flash runs to leave programming mode and return the
# unit to the application: deactivate programming mode, run the finish routine,
# then hard-reset. The matching "programming ON" routine (31 01 0F 0C 03) is sent
# before SecurityAccess in the flash, so this family needs no security unlock.
PROG_MODE_OFF = bytes.fromhex('31 01 0F 0C 00')
PROG_FINISH = bytes.fromhex('31 01 10 0F')
ECU_RESET = bytes.fromhex('11 01')
SVK_TYPES = {1: 'HWEL', 5: 'CAFD', 6: 'BTLD', 8: 'SWFL', 13: 'SWFK'}
BTLD_MGU = '00003F36'
BTC_NBT = ('00001275', '00001FFD')
DTC_DEBUG_SSH_ACTIVE = 'B7F8E5'

class DiagError(Exception):
    pass

class SvkRecord:

    def __init__(self, rec_type, version, trip_a, trip_b, trip_c):
        self.type = rec_type
        self.name = SVK_TYPES.get(rec_type, '?%d' % rec_type)
        self.version = version
        self.trip = (trip_a, trip_b, trip_c)

    def version_hex(self):
        return '%08X' % self.version

    def trip_text(self):
        return '%03d.%03d.%03d' % self.trip

    def __str__(self):
        return '%s %s_%s' % (self.name, self.version_hex(), self.trip_text())

class Svk:

    def __init__(self, records):
        self.records = records

    def all_named(self, name):
        return [r for r in self.records if r.name == name]

    def find(self, name, version_hex=None):
        recs = self.all_named(name)
        if len(recs) != 1:
            return None
        if version_hex is not None and recs[0].version_hex() != version_hex:
            return None
        return recs[0]

    def is_supported_mgu(self):
        return self.find('BTLD', BTLD_MGU) is not None

    def is_nbt(self):
        return any((self.find('BTLD', v) is not None for v in BTC_NBT))

    def summary(self):
        return ', '.join((str(r) for r in self.records))

def parse_svk(payload):
    if not payload:
        raise DiagError('The SVK response is missing.')
    idx = payload.find(bytes.fromhex('62 F1 01'))
    if idx < 0:
        raise DiagError('The SVK response does not contain 62 F1 01.')
    body = payload[idx + 3:]
    strict_ok = idx == 0 and len(body) % 8 == 0
    records = []
    start = None
    if strict_ok:
        start = 0
    else:
        for i in range(len(body) - 16 + 1):
            if _svk_record_at(body, i) and _svk_record_at(body, i + 8):
                start = i
                break
    if start is None:
        raise DiagError('The SVK response contains no known record pairs.')
    i = start
    while i + 7 < len(body):
        if body[i] in SVK_TYPES:
            version = struct.unpack('>I', body[i + 1:i + 5])[0]
            records.append(SvkRecord(body[i], version, body[i + 5], body[i + 6], body[i + 7]))
        i += 8
    if not records:
        raise DiagError('The SVK response contains no known records.')
    return Svk(records)

def _svk_record_at(body, i):
    return i + 7 < len(body) and body[i] in SVK_TYPES and (body[i + 1] == 0) and (body[i + 2] == 0)

def read_svk(client, dst=MGU):
    raw = client.request(dst, REQUEST_SVK, P_SVK)
    x = match_response(raw, dst)
    if x is None:
        raise DiagError('The MGU returned no complete identification response.')
    x.require(REQUEST_SVK[0])
    return parse_svk(x.data)

def parse_mgu_ip(payload, dst=MGU):
    if not payload:
        raise DiagError('The MGU IP response is missing.')
    idx = payload.find(bytes.fromhex('62 17 2A 00'))
    if idx < 0:
        raise DiagError('The MGU IP response does not contain 62 17 2A 00.')
    body = payload[idx + 4:]
    if len(body) < 12:
        raise DiagError('The MGU IP response did not contain four IPv4 addresses.')
    ips = [struct.unpack('>I', body[i:i + 4])[0] for i in range(0, 12, 4)]
    texts = ['%d.%d.%d.%d' % (v >> 24 & 255, v >> 16 & 255, v >> 8 & 255, v & 255) for v in ips]
    return tuple(texts)

def read_mgu_ip(client, dst=MGU):
    raw = client.request(dst, REQUEST_IP, P_READ_IP)
    x = match_response(raw, dst)
    if x is None:
        raise DiagError('The MGU returned no IP-configuration response.')
    x.require(REQUEST_IP[0])
    return parse_mgu_ip(x.data)

def read_dtcs(client, dst=MGU, profile=P_ISTEP):
    raw = client.request(dst, REQUEST_DTC, profile)
    x = match_response(raw, dst)
    if x is None:
        raise DiagError('The MGU returned no DTC response.')
    x.require(REQUEST_DTC[0])
    codes = []
    body = x.data
    for i in range(len(body) - 2):
        code = '%02X%02X%02X' % (body[i], body[i + 1], body[i + 2])
        if code not in codes:
            codes.append(code)
    return codes

def debug_state(client, dst=MGU, include_results=False):
    state = {'debug': None, 'dtc_debug': None, 'dtcs': None}
    if include_results:
        try:
            raw = client.request(dst, ROUTINE_DEBUG_RESULTS, P_ADVANCED)
            x = match_response(raw, dst)
            if x is not None:
                x.require(ROUTINE_DEBUG_RESULTS[0])
                state['routine'] = x.data
        except (HsfzError, UdsReject):
            state['routine'] = None
    try:
        state['dtcs'] = read_dtcs(client, dst)
        state['dtc_debug'] = DTC_DEBUG_SSH_ACTIVE in state['dtcs']
    except (HsfzError, UdsReject, DiagError):
        pass
    return state

def close_ssh(client, dst=MGU):
    raw = client.request(dst, ROUTINE_DEBUG_STOP, P_ADVANCED)
    x = match_response(raw, dst)
    if x is None or not x.data or (not len(x.data)):
        return 'missing'
    if x.negative:
        raise UdsReject('The ECU rejected service 0x%02X with NRC 0x%02X.' % (x.sid, x.nrc), x.sid, x.nrc)
    if x.data[0] != 113:
        raise UdsReject('Unexpected UDS response service 0x%02X; expected 0x71.' % x.data[0], 49, 0)
    if len(x.data) >= 4:
        if x.data[1:4] != ROUTINE_DEBUG_STOP[1:4]:
            raise UdsReject('The routine stop echoed a different identifier.', 49, 0)
    return 'confirmed'

def _routine_status(client, dst, req):
    """Send one request best-effort and describe the reply. Never raises."""
    try:
        x = match_response(client.request(dst, req, P_ADVANCED), dst)
        if x is None:
            return 'no response'
        if x.negative:
            return '7F %02X %02X' % (x.sid, x.nrc)
        return 'ok'
    except (HsfzError, UdsReject):
        return 'link dropped'

def exit_programming(client, dst=MGU):
    """Leave programming mode the way a completed flash does, so the unit reboots
    into the application instead of back to the blue programming screen.

    Replicates the proven flash tail: deactivate programming mode
    (31 01 0F 0C 00), run the finish-programming routine (31 01 10 0F), then
    hard-reset (11 01). A plain ECU reset alone is NOT enough - the unit comes
    back up still in programming mode because the programming-active state was
    never cleared; those two routines are what clear it. This routine family is
    sent before SecurityAccess in the flash, so no security unlock is needed.

    Every step is best-effort (a stuck unit may answer a NRC, and the reset drops
    the link as it reboots). Returns a {'prog_mode_off', 'finish', 'reset'} dict.
    """
    status = {'prog_mode_off': None, 'finish': None, 'reset': None}
    status['prog_mode_off'] = _routine_status(client, dst, PROG_MODE_OFF)
    status['finish'] = _routine_status(client, dst, PROG_FINISH)
    try:
        x = match_response(client.request(dst, ECU_RESET, P_ADVANCED), dst)
        if x is None:
            status['reset'] = 'sent (no reply - the unit is rebooting)'
        elif x.negative:
            status['reset'] = '7F %02X %02X' % (x.sid, x.nrc)
        else:
            status['reset'] = 'ok (51 01)'
    except (HsfzError, UdsReject):
        status['reset'] = 'sent (link dropped on reset, expected)'
    return status
