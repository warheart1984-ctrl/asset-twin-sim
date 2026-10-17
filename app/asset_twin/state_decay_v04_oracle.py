"""Committed expected verdicts for State-Decay Test Spec v0.4.

The v0.4 fixtures isolate the two admissibility inputs from the composite v0.3
shift.  This file is committed before the v0.4 harness is implemented or run.
The conditions, clock, permit model, and three-step plan remain the v0.3
values; only one condition changes in each negative fixture.
"""

from __future__ import annotations

import hashlib
import json


ORACLE_V04: dict[str, dict[str, tuple[str, ...]]] = {
    "ground_bearing_change_only": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "HOLD"),
    },
    "ground_bearing_control": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "RUN", "RUN"),
    },
    "outrigger_load_change_only": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "HOLD"),
    },
    "outrigger_load_control": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "RUN", "RUN"),
    },
}


def oracle_digest() -> str:
    payload = json.dumps(ORACLE_V04, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


ORACLE_SHA256 = "8052b2bacb53266adb355c767c6a98e17e1ba6f469eab4109151c953f234134b"
