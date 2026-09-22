import importlib.util
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import unittest

BRIDGE = pathlib.Path(__file__).resolve().parents[1] / "tools/ptp_status_bridge.py"
spec = importlib.util.spec_from_file_location("bridge", BRIDGE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

# Synthetic schema. These are deliberately NOT asserted to be Timebeat fields.
MAPPING = {
    "clock": "/clock", "state": "/state", "observed_at": "/observed",
    "offset": "/offset", "offset_multiplier_to_ns": 1,
    "gm": "/gm", "domain": "/domain", "scale": "/scale", "tai_offset": "/tai",
    "states": {"locked": "synced", "free": "unsynced", "hold": "holdover"},
}


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.sample = dict(clock="enp129s0d4", state="locked", observed=100,
                           offset=45, gm="gm1", domain=50, scale="tai", tai=37)

    def normalize(self, **changes):
        return bridge.normalize(dict(self.sample, **changes), MAPPING, "exanic0", "enp129s0d4",
                                101, 20_000_000_000, 5)

    def test_mapping_and_freshness(self):
        observed, message = self.normalize()
        self.assertEqual(observed, 100)
        self.assertEqual(message, b"v1 exanic0 synced 45 tai gm1 50 37 19000000000")
        for changes in [dict(observed=90), dict(observed=102), dict(clock="other"),
                        dict(offset=float("nan")), dict(offset=True), dict(domain=256),
                        dict(scale="guess"), dict(gm='bad"name'), dict(tai=-1), dict(offset=1e30)]:
            with self.subTest(changes=changes), self.assertRaises((ValueError, TypeError)):
                self.normalize(**changes)

    def test_outage_unknown_and_fractional_offset(self):
        self.assertIn(b" holdover unknown ", self.normalize(state="hold", offset=None)[1])
        self.assertIn(b" unknown ", self.normalize(state="unrecognised")[1])
        self.assertIn(b" -1001 ", self.normalize(offset=-1000.1)[1])
        self.assertIn(b" 1001 ", self.normalize(offset=1000.1)[1])
        self.assertEqual(bridge.observed_seconds("1970-01-01T00:01:40Z"), 100)
        with self.assertRaises(ValueError):
            bridge.observed_seconds("1970-01-01T00:01:40")

    def test_json_pointer(self):
        self.assertEqual(bridge.pointer({"a/b": [{"~": 3}]}, "/a~1b/0/~0"), 3)

    def test_real_bridge_socket_and_outage(self):
        with tempfile.TemporaryDirectory(prefix="ptp-bridge-test-") as directory:
            root = pathlib.Path(directory)
            mapping, snapshot, endpoint = root / "mapping.json", root / "snapshot.json", root / "status.sock"
            mapping.write_text(json.dumps(MAPPING))
            snapshot.write_text(json.dumps(dict(self.sample, observed=time.time())))
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
                receiver.bind(str(endpoint))
                receiver.settimeout(2)
                process = subprocess.Popen(
                    [sys.executable, "-B", str(BRIDGE), "--input-file", str(snapshot),
                     "--mapping", str(mapping), "--socket", str(endpoint), "--clock-id", "exanic0",
                     "--expected-source-clock", "enp129s0d4", "--interval", "0.02", "--max-age", "5"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                )
                try:
                    first = receiver.recv(512)
                    second = receiver.recv(512)
                    self.assertEqual(first, second)  # Cached data does not acquire a new monotonic timestamp.
                    snapshot.unlink()
                    receiver.settimeout(0.15)
                    for _ in range(20):
                        try:
                            receiver.recv(512)
                        except socket.timeout:
                            break
                    else:
                        self.fail("bridge sent fresh data after its source disappeared")
                    self.assertIsNone(process.poll())
                    snapshot.write_text(json.dumps(dict(self.sample, observed=time.time(), state="hold", offset=None)))
                    receiver.settimeout(2)
                    self.assertIn(b" holdover unknown ", receiver.recv(512))
                finally:
                    process.terminate()
                    process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
