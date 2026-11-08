"""Read-only coding backup checks, against a fake ENET gateway. No real vehicle, no writes."""
import os
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mgu7 import diag, hsfz, preflight

TESTER = 0xF4
MGU = 0x63
VIN = 'WBA00000000000000'

# Present coding blocks, contiguous so the scan's silent-run cutoff doesn't stop early.
CODING = {0x3000: b'\x11\x22\x33', 0x3001: b'\xaa\xbb', 0x3002: b'\x01',
          0x3003: b'\xde\xad\xbe\xef', 0x3004: b'\x00', 0x3005: b'\x7f\x7f'}
IDENT = {0xF100: b'\x01\x02', 0xF101: b'SVK', 0xF102: b'\x03'}


def _svk_record(cls, ident, a, b, c):
    return bytes([cls]) + struct.pack('>I', ident) + bytes([a, b, c])


# 62 F1 01 + records (BTLD 00003F36 makes it a supported MGU; one CAFD, one SWFL)
SVK = bytes.fromhex('62F101') + (
    _svk_record(0x06, 0x00003F36, 30, 16, 6) +     # BTLD
    _svk_record(0x08, 0x00005CC5, 30, 16, 2) +     # SWFL
    _svk_record(0x05, 0x00003E52, 8, 10, 128))     # CAFD


def _uds_response(payload):
    """Build the UDS response for one 0x22 read, or a negative for an absent DID."""
    did = (payload[1] << 8) | payload[2]
    head = bytes((0x62, payload[1], payload[2]))
    if did == 0xF101:
        return SVK
    if did == 0xF190:
        return head + VIN.encode('ascii')
    if did in CODING:
        return head + CODING[did]
    if did in IDENT:
        return head + IDENT[did]
    return bytes((0x7F, 0x22, 0x31))               # requestOutOfRange


class FakeGateway:
    """Answers 0x22 reads over HSFZ and records every UDS service id it was sent."""

    def __init__(self):
        self.sids = []
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(('127.0.0.1', 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        conn, _ = self.srv.accept()
        buf = b''
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 6:
                    length, ftype = struct.unpack('>IH', buf[:6])
                    if len(buf) < 6 + length:
                        break
                    src, dst, payload = buf[6], buf[7], buf[8:6 + length]
                    buf = buf[6 + length:]
                    if payload:
                        self.sids.append(payload[0])
                    resp = _uds_response(payload)
                    body = bytes((dst, TESTER)) + resp
                    conn.sendall(struct.pack('>IH', len(body), hsfz.TYPE_DIAG) + body)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.srv.close()


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.gw = FakeGateway()
        self.client = hsfz.EnetClient('127.0.0.1', self.gw.port)
        self.client.connect()

    def tearDown(self):
        self.client.close()
        self.gw.close()

    def test_backup_is_complete_verified_and_read_only(self):
        svk = diag.read_svk(self.client)
        self.assertIsNotNone(svk.find('BTLD', '00003F36'))
        with tempfile.TemporaryDirectory() as tmp:
            result = preflight.backup(self.client, svk, tmp, log=lambda *a: None)

            # every present coding block captured, and the whole thing verified
            self.assertEqual(set(result['coding']), {'%04X' % d for d in CODING})
            self.assertTrue(result['verified'])
            self.assertEqual(result['vin'], VIN)

            folder = result['folder']
            for name in ('backup.json', 'coding_MGU.txt', 'RESTORE.txt', 'SHA256SUMS'):
                self.assertTrue(os.path.isfile(os.path.join(folder, name)), name)

            note = Path(folder, 'RESTORE.txt').read_text()
            self.assertIn('vehicle order', note)
            self.assertIn('read-only', note)

            coding_txt = Path(folder, 'coding_MGU.txt').read_text()
            self.assertIn('3000: 112233', coding_txt)

        # read-only: the tool sent nothing but 0x22 ReadDataByIdentifier
        self.assertEqual(set(self.gw.sids), {0x22})
        for forbidden in (0x2E, 0x31, 0x27, 0x10, 0x11, 0x34, 0x14):
            self.assertNotIn(forbidden, self.gw.sids)

    def test_verify_flags_a_changing_block(self):
        # a gateway whose coding read differs the second time must not verify
        svk = diag.read_svk(self.client)
        flip = {'n': 0}
        original = preflight._read_did

        def flaky(client, dst, ident, profile=preflight.P_CODING):
            if ident == 0x3000:
                flip['n'] += 1
                if flip['n'] == 2:
                    return b'\x99\x99\x99'      # second read of 0x3000 differs
            return original(client, dst, ident, profile)

        with tempfile.TemporaryDirectory() as tmp:
            preflight._read_did = flaky
            try:
                result = preflight.backup(self.client, svk, tmp, log=lambda *a: None)
            finally:
                preflight._read_did = original
            self.assertFalse(result['verified'])


if __name__ == '__main__':
    unittest.main()
