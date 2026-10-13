"""Committed v0.3 expected verdicts.

This fixture is intentionally separate from the runner.  It is the test
oracle: the harness consumes these rows and never derives expected answers
from its own observations.
"""

from __future__ import annotations

import hashlib
import json


ORACLE_V03: dict[str, dict[str, tuple[str, ...]]] = {
    "shift_between_steps": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "HOLD"),
    },
    "drift_inside_tolerance": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "RUN", "RUN"),
    },
    "stale_reading": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "HOLD"),
    },
    "missing_reading": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "HOLD"),
    },
    "future_dated_reading": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "HOLD"),
    },
    "malformed_reading": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "HOLD"),
    },
    "several_shifts": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "RUN", "HOLD"),
    },
    "age_exactly_X": {
        "baseline": ("RUN", "RUN"),
        "gated": ("RUN", "RUN"),
    },
    "age_X_plus_1": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "RUN", "HOLD"),
    },
    "thresholds_exact": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "RUN", "RUN"),
    },
    "threshold_just_past": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "HOLD"),
    },
    "one_required_reading_stale": {
        "baseline": ("RUN", "RUN", "RUN"),
        "gated": ("RUN", "HOLD"),
    },
}


def oracle_digest() -> str:
    payload = json.dumps(ORACLE_V03, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# Filled from the fixture itself and asserted by the harness tests.
ORACLE_SHA256 = "89b900a126e42dc168c30425f67ea46d56cd79631ed9aca9bc78573f2c1a03fd"
