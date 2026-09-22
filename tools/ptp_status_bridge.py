#!/usr/bin/env python3
"""Read a provider's JSON snapshot and send advisory status to the capture socket.

No Timebeat endpoint or JSON schema is assumed. The mapping must be verified
against the installed version. This process never adjusts any clock.
"""

import argparse
import datetime
import json
import math
import re
import socket
import sys
import time
import urllib.request
from pathlib import Path

TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
MAX_DOCUMENT = 1024 * 1024


def pointer(document, path):
    """Resolve an explicit JSON Pointer (including arrays)."""
    if path == "":
        return document
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("JSON pointers must start with /")
    for component in path[1:].split("/"):
        component = component.replace("~1", "/").replace("~0", "~")
        document = document[int(component)] if isinstance(document, list) else document[component]
    return document


def field(document, mapping, name):
    spec = mapping[name]
    # Scale and leap offset may be explicit operator declarations. Health,
    # identity and measurement time must always come from actual telemetry.
    if isinstance(spec, dict) and set(spec) == {"literal"} and name in {"scale", "tai_offset"}:
        return spec["literal"]
    return pointer(document, spec)


def token(value):
    if not isinstance(value, str) or not TOKEN.fullmatch(value):
        raise ValueError("invalid clock/GM identifier")
    return value


def number(value):
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
        raise ValueError("expected a finite JSON number")
    return value


def observed_seconds(value):
    if isinstance(value, str):
        stamp = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("measurement timestamp must include a UTC offset")
        return stamp.timestamp()
    return number(value)  # Numeric measurement timestamps are Unix seconds.


def normalize(document, mapping, clock_id, expected_clock, now_wall, now_mono, max_age):
    if field(document, mapping, "clock") != expected_clock:
        raise ValueError("telemetry is for a different clock")
    observed = observed_seconds(field(document, mapping, "observed_at"))
    age = now_wall - observed
    if not math.isfinite(age) or age < 0 or age > max_age:
        raise ValueError("telemetry measurement is stale or in the future")
    observed_ns = int(now_mono - age * 1_000_000_000)
    if observed_ns <= 0:
        raise ValueError("measurement predates this boot")
    raw_state = field(document, mapping, "state")
    if not isinstance(raw_state, (str, bool, int)):
        raise ValueError("invalid state")
    state_key = str(raw_state).lower() if isinstance(raw_state, bool) else str(raw_state)
    state = mapping["states"].get(state_key, "unknown")
    if state not in {"synced", "unsynced", "holdover", "unknown"}:
        raise ValueError("invalid state mapping")
    raw_offset = field(document, mapping, "offset")
    offset = "unknown"
    if raw_offset is not None:
        multiplier = number(mapping["offset_multiplier_to_ns"])
        if multiplier <= 0:
            raise ValueError("offset multiplier must be positive")
        scaled = number(number(raw_offset) * multiplier)
        # Round away from zero: fractional values must not hide a threshold breach.
        offset = math.ceil(scaled) if scaled >= 0 else math.floor(scaled)
        if not -(1 << 63) <= offset < (1 << 63):
            raise ValueError("offset outside int64 range")
    gm = field(document, mapping, "gm")
    gm = "unknown" if gm is None else token(gm)
    domain = number(field(document, mapping, "domain"))
    tai = number(field(document, mapping, "tai_offset"))
    if int(domain) != domain or not 0 <= domain <= 255 or int(tai) != tai or not 0 <= tai <= 1000:
        raise ValueError("invalid PTP domain or TAI-UTC offset")
    scale = field(document, mapping, "scale")
    if scale not in {"utc", "tai"}:
        raise ValueError("input scale must be utc or tai")
    message = f"v1 {token(clock_id)} {state} {offset} {scale} {gm} {int(domain)} {int(tai)} {observed_ns}"
    return observed, message.encode("ascii")


def read_document(args):
    if args.input_file:
        with open(args.input_file, "rb") as source:
            data = source.read(MAX_DOCUMENT + 1)
    else:
        # No proxy discovery: this is meant for a local status endpoint.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(args.url, timeout=args.timeout) as response:
            data = response.read(MAX_DOCUMENT + 1)
    if len(data) > MAX_DOCUMENT:
        raise ValueError("status document exceeds 1 MiB")
    return json.loads(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input-file", help="JSON snapshot, refreshed atomically by telemetry collector")
    source.add_argument("--url", help="verified JSON status endpoint; not assumed to exist in Timebeat 2.2.20")
    parser.add_argument("--mapping", required=True, type=Path)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--clock-id", required=True, help="capture clock ID, e.g. exanic0")
    parser.add_argument("--expected-source-clock", required=True, help="exact identity in provider JSON")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--max-age", type=float, default=5.0)
    args = parser.parse_args()
    for value in (args.interval, args.timeout, args.max_age):
        if not math.isfinite(value) or value <= 0:
            parser.error("interval, timeout and max-age must be positive finite numbers")
    if args.url and not args.url.startswith(("http://", "https://")):
        parser.error("only HTTP(S) status endpoints are supported")
    token(args.clock_id)
    mapping = json.loads(args.mapping.read_text())
    previous_error = None
    last_observed, last_message = None, None
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        while True:
            try:
                observed, message = normalize(
                    read_document(args), mapping, args.clock_id, args.expected_source_clock,
                    time.time(), time.monotonic_ns(), args.max_age,
                )
                # Re-reading a cached snapshot must not renew its lifetime.
                if observed == last_observed:
                    message = last_message
                else:
                    last_observed, last_message = observed, message
                sock.sendto(message, args.socket)
                if previous_error:
                    print("PTP bridge: telemetry delivery recovered", file=sys.stderr)
                previous_error = None
            except (OSError, ValueError, KeyError, TypeError, IndexError, OverflowError) as exc:
                error = f"{type(exc).__name__}: {exc}"
                if error != previous_error:
                    print(f"PTP bridge: {error}; capture continues, status will expire", file=sys.stderr)
                previous_error = error
            time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
