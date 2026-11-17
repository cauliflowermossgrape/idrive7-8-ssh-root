"""The flash must stop at the programming-session frame (10 02) when the HU keeps
refusing it (7F 10 22) past the retry window, and report that refusal as the error
- instead of marching on to a guaranteed SecurityAccess (27) failure (7F 27 7F).
Covers issues #60 / #69 / #72. No real vehicle: a fake client replays responses."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mgu7 import flash
from mgu7.hsfz import Response, T, TYPE_DIAG, MGU, TESTER


def _diag(payload):
    return Response(T(TYPE_DIAG, MGU, TESTER, payload), pending=0, timeout=False)


class FakeClient:
    """Answers 10 03 positively, refuses 10 02 forever, records every request sent."""

    def __init__(self):
        self.sent = []

    def await_one(self, dst, request, timeout_ms):
        self.sent.append(bytes(request))
        sid, sub = request[0], (request[1] if len(request) > 1 else None)
        if sid == 0x10 and sub == 0x03:
            return _diag(b'\x50\x03\x00\x32\x01\xf4')   # positive extended session
        if sid == 0x10 and sub == 0x02:
            return _diag(b'\x7f\x10\x22')               # programming session refused
        # Anything else (e.g. a 27 SecurityAccess) would be a positive echo; it must
        # never be reached in this test.
        return _diag(bytes((request[0] + 0x40,)) + request[1:])


class StubData:
    """Minimal stand-in for Material: unvalidated so the compat-rule helpers all
    short-circuit, with a hand-built frame list ending 10 03, 10 02, 27 11."""
    validated = False
    variant = 'A'
    vin = 'WBA00000000000000'

    def __init__(self, frames):
        self.frames = frames

    def part_at(self, i):
        return 0


def _pframe(payload):
    return flash.PFrame(flash.HFrame(1, TESTER, MGU, payload))


class ProgrammingSessionAbort(unittest.TestCase):

    def _run(self):
        frames = [
            _pframe(b'\x10\x03'),                    # extended session (ok)
            _pframe(b'\x10\x02'),                    # programming session (refused)
            _pframe(b'\x27\x11\xff\xff\xff\xff'),    # SecurityAccess seed (must not run)
        ]
        client = FakeClient()
        engine = flash.FlashEngine(
            client, operands=object(), gate=None,
            reachable_wait_ms=300, reachable_poll_ms=100, response_timeout_ms=1000)
        with self.assertRaises(flash.FlashError) as ctx:
            engine.run(StubData(frames))
        return client, str(ctx.exception)

    def test_aborts_on_programming_session_refusal(self):
        client, msg = self._run()
        self.assertIn('refused to enter programming mode', msg)
        self.assertIn('7F 10 22', msg)
        self.assertIn('before SecurityAccess', msg)

    def test_security_access_is_never_sent(self):
        client, _ = self._run()
        self.assertTrue(any(r[:2] == b'\x10\x02' for r in client.sent),
                        'the 10 02 frame should have been attempted')
        self.assertFalse(any(r and r[0] == 0x27 for r in client.sent),
                         'SecurityAccess (27) must never be sent after a refused 10 02')

    def test_retried_before_giving_up(self):
        client, _ = self._run()
        attempts = sum(1 for r in client.sent if r[:2] == b'\x10\x02')
        self.assertGreaterEqual(attempts, 2, 'the session frame should be retried, not abandoned at once')

    def test_does_not_abort_when_session_is_entered(self):
        """Guard: when 10 02 succeeds, the engine must NOT raise - the abort is for
        a genuinely refused session only, never a session that comes up."""
        class OkClient(FakeClient):
            def await_one(self, dst, request, timeout_ms):
                self.sent.append(bytes(request))
                if request[0] == 0x10 and request[1] == 0x02:
                    return _diag(b'\x50\x02')           # programming session entered
                if request[0] == 0x10 and request[1] == 0x03:
                    return _diag(b'\x50\x03\x00\x32\x01\xf4')
                return _diag(bytes((request[0] + 0x40,)) + request[1:])

        frames = [_pframe(b'\x10\x03'), _pframe(b'\x10\x02')]
        client = OkClient()
        engine = flash.FlashEngine(
            client, operands=None, gate=None,
            reachable_wait_ms=300, reachable_poll_ms=100, response_timeout_ms=1000)
        result = engine.run(StubData(frames), stop_after=1)   # no exception
        self.assertTrue(any(r[:2] == b'\x10\x02' for r in client.sent))


if __name__ == '__main__':
    unittest.main()
