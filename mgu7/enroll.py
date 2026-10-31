import base64
import hashlib
import re
import socket
import struct
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from .hsfz import EnetClient, HsfzError, UdsReject, X, MGU, TESTER, P_ADVANCED, match_response, require_response
ROUTINE_CHALLENGE = bytes.fromhex('31 01 A6 71')
ROUTINE_INSTALL = bytes.fromhex('31 01 A0 FD')
DID_READBACK = bytes.fromhex('22 17 2A')
SSH_PORT = 22
SSH_USER = 'root'
_CHALLENGE_RE = re.compile('^[0-9A-F]{64}$')

class EnrollError(Exception):
    pass
OID_SHA256_RSA = bytes.fromhex('2A 86 48 86 F7 0D 01 01 0B')
OID_RSA = bytes.fromhex('2A 86 48 86 F7 0D 01 01 01')

def _der_len(n):
    if n < 128:
        return bytes((n,))
    out = bytearray()
    while n:
        out.insert(0, n & 255)
        n >>= 8
    return bytes((128 | len(out),)) + bytes(out)

def _tlv(tag, content):
    return bytes((tag,)) + _der_len(len(content)) + content

def _seq(*parts):
    return _tlv(48, b''.join(parts))

def _set(*parts):
    return _tlv(49, b''.join(parts))

def _int(value_bytes):
    value_bytes = value_bytes.lstrip(b'\x00') or b'\x00'
    if value_bytes[0] & 128:
        value_bytes = b'\x00' + value_bytes
    return _tlv(2, value_bytes)

def _oid(raw):
    return _tlv(6, raw)

def _octetstring(content):
    return _tlv(4, content)

def _bitstring(content):
    return _tlv(3, b'\x00' + content)

def _utc(text):
    return _tlv(23, text.encode('ascii'))

def _attr(oid_hex, value_tag, value_text):
    return _set(_seq(_oid(bytes.fromhex(oid_hex)), _tlv(value_tag, value_text.encode('utf-8'))))

def _int_from_int(value):
    if value < 0:
        raise EnrollError('Negative DER integers are not supported.')
    width = (value.bit_length() + 8) // 8 or 1
    content = value.to_bytes(width, 'big')
    while len(content) > 1 and content[0] == 0 and (content[1] < 128):
        content = content[1:]
    return _tlv(2, content)

class RsaKeyPair:

    def __init__(self, private):
        if not isinstance(private, rsa.RSAPrivateKey):
            raise EnrollError('An RSA private key is required.')
        self.private = private
        self.public = private.public_key()
        self.n = private.public_key().public_numbers().n
        self.e = private.public_key().public_numbers().e

    @classmethod
    def from_pem_bytes(cls, blob, expect_pkcs8=False, strict_label=None):
        try:
            text = blob.decode('ascii')
        except UnicodeDecodeError:
            raise EnrollError('The RSA key PEM is not ASCII.')
        label = strict_label or ('PRIVATE KEY' if expect_pkcs8 else None)
        if label:
            begin = '-----BEGIN %s-----' % label
            end = '-----END %s-----' % label
            if begin not in text or end not in text:
                raise EnrollError('The RSA key is not a supported %s PEM value.' % label)
        try:
            key = serialization.load_pem_private_key(blob, password=None)
        except (ValueError, TypeError) as e:
            raise EnrollError('The RSA private key PEM could not be parsed: %s' % e)
        return cls(key)

    def spki_der(self):
        pub = _seq(_oid(OID_RSA), _tlv(5, b''))
        pubkey = _seq(_int_from_int(self.n), _int_from_int(self.e))
        return _seq(pub, _bitstring(pubkey))

    def sign_pkcs1_sha256(self, message):
        digest = hashlib.sha256(message).digest()
        return self.private.sign(digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))

def _extract_pem_body(blob, label):
    if not blob:
        raise EnrollError('A PEM value is required.')
    text = blob.decode('ascii', 'replace')
    begin = '-----BEGIN %s-----' % label
    end = '-----END %s-----' % label
    i = text.find(begin)
    j = text.find(end)
    if i < 0 or j <= i:
        raise EnrollError('The value is not a supported %s PEM.' % label)
    body = ''.join((c for c in text[i + len(begin):j] if not c.isspace()))
    try:
        return base64.b64decode(body, validate=True)
    except Exception as e:
        raise EnrollError('The %s PEM body is not valid base64: %s' % (label, e))

class EnrolledCertificate:

    def __init__(self, der, pem):
        self.der = der
        self.pem = pem if isinstance(pem, bytes) else pem.encode('ascii')

    def pem_bytes(self):
        return self.pem if isinstance(self.pem, bytes) else self.pem.encode('ascii')
ISSUER_CN = 'PMOIntermediateCA UID=3939fa9a-c199-450a-9d6b-5e2341ad3641'

def build_certificate(challenge, enrollment_key, pmo_certificate_pem, pmo_private_key, installation_key=None):
    if not _CHALLENGE_RE.match(challenge or ''):
        raise EnrollError('A 64-character uppercase hexadecimal challenge identity is required.')
    _extract_pem_body(pmo_certificate_pem, 'CERTIFICATE')
    alg_id = _seq(_oid(OID_SHA256_RSA), _tlv(5, b''))
    pub_client = _seq(_int_from_int(enrollment_key.n), _int_from_int(enrollment_key.e))
    pub_pmo = _seq(_int_from_int(pmo_private_key.n), _int_from_int(pmo_private_key.e))
    ski = hashlib.sha1(pub_client).digest()
    aki = hashlib.sha1(pub_pmo).digest()
    spki_client = enrollment_key.spki_der()
    issuer = _seq(_attr('55 04 06', 19, 'DE'), _attr('55 04 08', 19, 'Bavaria'), _attr('55 04 07', 19, 'Vehicle'), _attr('55 04 0A', 19, 'BMW AG'), _attr('55 04 0B', 19, 'Head Unit'), _attr('55 04 03', 19, ISSUER_CN))
    subject = _seq(_attr('55 04 06', 19, 'DE'), _attr('55 04 08', 12, 'Bavaria'), _attr('55 04 07', 12, 'Vehicle'), _attr('55 04 0A', 12, 'BMW AG'), _attr('55 04 0B', 12, 'Head Unit'), _attr('55 04 03', 12, challenge))
    validity = _seq(_utc('700101000100Z'), _utc('380930235900Z'))
    spki = _seq(_seq(_oid(OID_RSA), _tlv(5, b'')), _bitstring(_seq(_int_from_int(enrollment_key.n), _int_from_int(enrollment_key.e))))
    extensions = _tlv(163, _seq(_seq(_oid(bytes.fromhex('55 1D 13')), _tlv(4, _seq())), _seq(_oid(bytes.fromhex('55 1D 0F')), _tlv(1, b'\xff'), _octetstring(bytes.fromhex('03 02 05 E0'))), _seq(_oid(bytes.fromhex('55 1D 25')), _octetstring(bytes.fromhex('30 0A 06 08 2B 06 01 05 05 07 03 02'))), _seq(_oid(bytes.fromhex('60 86 48 01 86 F8 42 01 01')), _octetstring(bytes.fromhex('03 02 07 80'))), _seq(_oid(bytes.fromhex('55 1D 0E')), _octetstring(_octetstring(ski))), _seq(_oid(bytes.fromhex('55 1D 23')), _octetstring(_seq(_tlv(128, aki))))))
    tbs = _seq(_tlv(160, _int(bytes.fromhex('02'))), _int(bytes.fromhex('01 A9')), alg_id, issuer, validity, subject, spki, extensions)
    signature = pmo_private_key.sign_pkcs1_sha256(tbs)
    if len(signature) != 256:
        raise EnrollError('The PMO signer did not return a 2048-bit signature.')
    cert_der = _seq(tbs, alg_id, _bitstring(signature))
    pem = pem_encode(cert_der, 'CERTIFICATE')
    return EnrolledCertificate(cert_der, pem.encode('ascii'))

def pem_encode(der, label):
    text = base64.b64encode(der).decode('ascii')
    lines = [text[i:i + 64] for i in range(0, len(text), 64)]
    return '-----BEGIN %s-----\r\n%s\r\n-----END %s-----\r\n' % (label, '\r\n'.join(lines), label)

def read_challenge(client, dst=MGU):
    raw = client.request(dst, ROUTINE_CHALLENGE, P_ADVANCED)
    validate_routine_response(raw, ROUTINE_CHALLENGE, dst)
    payload = match_response(raw, dst).data
    filtered = [c for c in payload.decode('ascii', 'replace').upper() if c in '0123456789ABCDEF']
    text = ''.join(filtered)
    if len(text) < 64:
        raise EnrollError('The enrollment challenge was not decoded from the A6 71 response.')
    return (text[-64:], payload, raw)

def validate_routine_response(raw_frames, request, src=MGU, where=''):
    x = match_response(raw_frames, src)
    if x is None:
        raise UdsReject('The ECU returned no complete diagnostic response for service 0x%02X%s.' % (request[0], ' (%s)' % where if where else ''), request[0], 0)
    try:
        x.require(request[0])
    except HsfzError as e:
        raise EnrollError(str(e))
    return x

def _pem_crlf(blob):
    return bytes(blob).replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')

def build_install_request(certificate, pmo_certificate_pem):
    # Match the Windows wire format without changing the certificate assets.
    return ROUTINE_INSTALL + _pem_crlf(certificate.pem_bytes()) + _pem_crlf(pmo_certificate_pem)

# RoutineControl 0xA0FD (start) reports debug-mode activation in the status
# byte of its positive reply: "71 01 A0 FD <status>". A known-good capture
# returns 0x00 on success (port 22 then opens on its own); a unit that accepts
# the certificate but refuses to activate returns 0x01. 0x00 is the only
# success - any other value is a rejection, not an install.
ROUTINE_STATUS_OK = 0x00


def install_certificate(client, certificate, pmo_certificate_pem, dst=MGU):
    """Install the enrollment certificate (RoutineControl start 0xA0FD) and
    return the routine status byte. 0x00 = debug mode activated; any other
    value means the unit rejected activation and the caller must treat the
    enrollment as failed. Raises EnrollError on a malformed reply."""
    request = build_install_request(certificate, pmo_certificate_pem)
    raw = client.request(dst, request, P_ADVANCED)
    x = validate_routine_response(raw, request, dst, 'install')
    data = x.data
    if len(data) < 5 or data[1:4] != ROUTINE_INSTALL[1:4]:
        raise EnrollError(
            'The A0 FD install reply was not a routine status (expected '
            '"71 01 A0 FD <status>", got %s).' % data.hex())
    return data[4]

def readback_certificate_address(client, dst=MGU):
    raw = client.request(dst, DID_READBACK, P_ADVANCED)
    validate_routine_response(raw, DID_READBACK, dst, 'readback')

def probe_port(host, port=SSH_PORT, timeout=3.0):
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (True, (time.monotonic() - start) * 1000.0)
    except OSError:
        return (False, (time.monotonic() - start) * 1000.0)

class Probe:

    def __init__(self, host, port=SSH_PORT, timeout=3.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def run(self):
        return probe_port(self.host, self.port, self.timeout)

class Enroll:

    def __init__(self, uds, materials=None, log=None):
        self.uds = uds
        self.materials = materials or {}
        self.log = log or (lambda *a, **k: None)

    def _assets(self):
        from . import assets as assets_mod
        return assets_mod.Assets()

    def read_challenge(self):
        payload = self.uds.routine_start(42608 + 1)
        return extract_challenge_text(payload)

    def build(self, challenge):
        a = self._assets()
        key01 = RsaKeyPair.from_pem_bytes(a.raw(1), expect_pkcs8=True)
        key04 = RsaKeyPair.from_pem_bytes(a.raw(4), expect_pkcs8=False)
        cert = build_certificate(challenge, key01, a.raw(3), key04)
        self.cert = cert
        return cert

    def install(self, certificate):
        a = self._assets()
        request = build_install_request(certificate, a.raw(3))
        self.uds.transport.request(self.uds.dst, request, P_ADVANCED)

    def confirm(self):
        self.uds.read_did(5930)

    def enroll(self, public_blob=None):
        challenge = self.read_challenge()
        self.log('MGU SSH enrollment: challenge %s' % challenge)
        cert = self.build(challenge)
        self.log('MGU SSH enrollment: certificate %d bytes DER' % len(cert.der))
        self.install(cert)
        self.log('MGU SSH enrollment: A0 FD install accepted')
        self.confirm()
        self.log('MGU SSH enrollment: 172A readback accepted')
        return challenge

def extract_challenge_text(payload):
    filtered = [c for c in payload.decode('ascii', 'replace').upper() if c in '0123456789ABCDEF']
    text = ''.join(filtered)
    if len(text) < 64:
        raise EnrollError('The enrollment challenge was not decoded from the A6 71 response.')
    return text[-64:]
