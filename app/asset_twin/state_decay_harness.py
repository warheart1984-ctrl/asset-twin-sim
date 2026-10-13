"""Deterministic State-Decay Test Spec v0.3 harness.

This module compares two simulation-only execution arms:

* ``baseline`` validates a signed permit, expiry, and revocation only.
* ``gated`` performs those checks and re-evaluates every live permit
  condition at the start of every atomic step.

The harness deliberately has its own discrete clock and in-memory evidence
chain.  It never uses wall-clock time, real equipment, a control bus, or the
production ``EvidenceLedger``.  That makes a run reproducible byte-for-byte
for a given seed and makes the comparison about the execution gate rather
than about scheduling or filesystem state.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Any, Literal, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .twin_core import canonical
from .state_decay_oracle import ORACLE_SHA256, ORACLE_V03, oracle_digest

ArmName = Literal["baseline", "gated"]
Verdict = Literal["RUN", "HOLD"]


@dataclass(frozen=True)
class Reading:
    """A sensor reading at a simulated tick."""

    name: str
    value: float
    reading_tick: int

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "value": self.value,
            "reading_tick": self.reading_tick,
        }


@dataclass(frozen=True)
class PermitConditions:
    required_ground_bearing: float = 100.0
    safety_factor: float = 1.2
    planned_outrigger_load: float = 100.0
    outrigger_tolerance: float = 5.0
    freshness_window: int = 2

    def as_dict(self) -> dict[str, object]:
        return {
            "required_ground_bearing": self.required_ground_bearing,
            "safety_factor": self.safety_factor,
            "planned_outrigger_load": self.planned_outrigger_load,
            "outrigger_tolerance": self.outrigger_tolerance,
            "freshness_window": self.freshness_window,
        }


@dataclass(frozen=True)
class StateChange:
    """Apply ``readings`` after this many completed steps."""

    after_step: int
    label: str
    readings: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        return {
            "after_step": self.after_step,
            "label": self.label,
            "readings": _readings_as_dict(self.readings),
        }


@dataclass(frozen=True)
class ScenarioSpec:
    name: str
    seed: str = "asset-twin-state-decay-v0.3"
    steps: int = 3
    conditions: PermitConditions = field(default_factory=PermitConditions)
    state_a: Mapping[str, object] = field(default_factory=dict)
    state_changes: tuple[StateChange, ...] = ()
    token_expiry_tick: int = 100
    revoked: bool = False
    human_note: str = "v0.3 human note: observation only; no override"


@dataclass(frozen=True)
class PermitToken:
    payload: Mapping[str, object]
    signature_hex: str
    public_key_hex: str

    def as_dict(self) -> dict[str, object]:
        return {
            "payload": dict(self.payload),
            "signature_hex": self.signature_hex,
            "public_key_hex": self.public_key_hex,
        }


class DeterministicEd25519:
    """Derive an Ed25519 key deterministically from a scenario seed."""

    def __init__(self, seed: str) -> None:
        material = hashlib.sha256(b"asset-twin-state-decay-ed25519\0" + seed.encode("utf-8")).digest()
        self._private = Ed25519PrivateKey.from_private_bytes(material)
        self._public = self._private.public_key()

    def issue(
        self,
        *,
        permit_id: str,
        conditions: PermitConditions,
        issued_tick: int,
        expires_tick: int,
        motion_plan_id: str,
    ) -> PermitToken:
        payload = {
            "algorithm": "Ed25519",
            "conditions": conditions.as_dict(),
            "expires_tick": expires_tick,
            "issued_tick": issued_tick,
            "motion_plan_id": motion_plan_id,
            "permit_id": permit_id,
        }
        signature = self._private.sign(canonical(payload)).hex()
        public_key = self._public.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        return PermitToken(payload=payload, signature_hex=signature, public_key_hex=public_key)

    @staticmethod
    def verify(token: PermitToken) -> bool:
        try:
            public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(token.public_key_hex))
            public.verify(bytes.fromhex(token.signature_hex), canonical(dict(token.payload)))
            return True
        except (TypeError, ValueError):
            return False
        except Exception:
            return False


class EvidenceLog:
    """Canonical, deterministic, tamper-detecting evidence chain."""

    genesis = "sha256:genesis"

    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    @property
    def _head(self) -> str:
        return str(self.records[-1]["digest"]) if self.records else self.genesis

    def append(self, kind: str, body: Mapping[str, object]) -> dict[str, object]:
        record: dict[str, object] = {
            "kind": kind,
            "prev": self._head,
            "body": copy.deepcopy(dict(body)),
        }
        record["digest"] = "sha256:" + hashlib.sha256(canonical(record)).hexdigest()
        self.records.append(record)
        return copy.deepcopy(record)

    def verify(self) -> tuple[bool, list[str]]:
        problems: list[str] = []
        previous = self.genesis
        for index, record in enumerate(self.records):
            if record.get("prev") != previous:
                problems.append(f"entry {index}: prev mismatch")
                break
            digest = record.get("digest")
            unsigned = {key: value for key, value in record.items() if key != "digest"}
            expected = "sha256:" + hashlib.sha256(canonical(unsigned)).hexdigest()
            if digest != expected:
                problems.append(f"entry {index}: digest mismatch")
                break
            previous = str(digest)
        return (not problems, problems)

    def tamper(self, *, kind: str, field: str, value: object) -> int:
        for index, record in enumerate(self.records):
            if record.get("kind") == kind:
                body = record["body"]
                if not isinstance(body, dict):
                    raise TypeError("evidence body is not a mapping")
                body[field] = value
                return index
        raise KeyError(kind)

    def as_list(self) -> list[dict[str, object]]:
        return copy.deepcopy(self.records)


@dataclass(frozen=True)
class ConditionResult:
    verdict: Literal["ALLOW", "HOLD"]
    rule: str
    ages: Mapping[str, int | None]
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "rule": self.rule,
            "ages": dict(self.ages),
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class StepDecision:
    step: int
    event_id: str
    tick: int
    state: str
    verdict: Verdict
    token_valid: bool
    live_condition: ConditionResult | None
    state_snapshot: Mapping[str, object]
    ages: Mapping[str, int | None]
    rule: str

    def as_dict(self) -> dict[str, object]:
        return {
            "step": self.step,
            "event_id": self.event_id,
            "tick": self.tick,
            "state": self.state,
            "verdict": self.verdict,
            "token_valid": self.token_valid,
            "live_condition": self.live_condition.as_dict() if self.live_condition else None,
            "state_snapshot": dict(self.state_snapshot),
            "ages": dict(self.ages),
            "rule": self.rule,
        }


@dataclass(frozen=True)
class ArmResult:
    arm: ArmName
    token: PermitToken
    decisions: tuple[StepDecision, ...]
    steps_run: int
    evidence: EvidenceLog

    @property
    def verdicts(self) -> tuple[Verdict, ...]:
        return tuple(decision.verdict for decision in self.decisions)

    def as_dict(self) -> dict[str, object]:
        valid, problems = self.evidence.verify()
        return {
            "arm": self.arm,
            "token": self.token.as_dict(),
            "decisions": [decision.as_dict() for decision in self.decisions],
            "steps_run": self.steps_run,
            "evidence": self.evidence.as_list(),
            "evidence_verify": {"valid": valid, "problems": problems},
        }


@dataclass(frozen=True)
class OracleExpectation:
    baseline: tuple[Verdict, ...]
    gated: tuple[Verdict, ...]


@dataclass(frozen=True)
class CaseResult:
    spec: ScenarioSpec
    oracle: OracleExpectation
    baseline: ArmResult
    gated: ArmResult
    oracle_matches: bool
    tamper_detected: bool
    tamper_problems: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.oracle_matches and self.tamper_detected


def _readings_as_dict(readings: Mapping[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, reading in sorted(readings.items()):
        if isinstance(reading, Reading):
            result[name] = reading.as_dict()
        else:
            result[name] = copy.deepcopy(reading)
    return result


def _reading(name: str, value: float, tick: int = 0) -> Reading:
    return Reading(name=name, value=value, reading_tick=tick)


def _safe_state(tick: int = 0) -> dict[str, Reading]:
    return {
        "ground_bearing": _reading("ground_bearing", 130.0, tick),
        "outrigger_load": _reading("outrigger_load", 100.0, tick),
    }


def _unsafe_state(tick: int = 1) -> dict[str, Reading]:
    return {
        "ground_bearing": _reading("ground_bearing", 119.0, tick),
        "outrigger_load": _reading("outrigger_load", 110.0, tick),
    }


def evaluate_conditions(
    readings: Mapping[str, object],
    conditions: PermitConditions,
    current_tick: int,
) -> ConditionResult:
    """Evaluate every required reading without averaging or best-of logic."""

    ages: dict[str, int | None] = {}
    reasons: list[str] = []
    required = ("ground_bearing", "outrigger_load")
    for name in required:
        raw = readings.get(name)
        if not isinstance(raw, Reading) or raw.name != name:
            ages[name] = None
            reasons.append(f"{name}: missing or malformed")
            continue
        age = current_tick - raw.reading_tick
        ages[name] = age
        if age < 0:
            reasons.append(f"{name}: future-dated reading")
        elif age > conditions.freshness_window:
            reasons.append(f"{name}: stale age {age} > {conditions.freshness_window}")

    ground = readings.get("ground_bearing")
    if isinstance(ground, Reading) and ground.name == "ground_bearing":
        required_ground = conditions.required_ground_bearing * conditions.safety_factor
        if ground.value < required_ground:
            reasons.append(f"ground_bearing {ground.value} < required {required_ground}")

    load = readings.get("outrigger_load")
    if isinstance(load, Reading) and load.name == "outrigger_load":
        delta = abs(load.value - conditions.planned_outrigger_load)
        if delta > conditions.outrigger_tolerance:
            reasons.append(f"|outrigger_load-planned| {delta} > {conditions.outrigger_tolerance}")

    if reasons:
        return ConditionResult(
            verdict="HOLD",
            rule="all required readings fresh and valid; ground_bearing >= required*safety_factor; |outrigger_load-planned| <= tolerance",
            ages=ages,
            reasons=tuple(reasons),
        )
    return ConditionResult(
        verdict="ALLOW",
        rule="all required readings fresh and valid; ground_bearing >= required*safety_factor; |outrigger_load-planned| <= tolerance",
        ages=ages,
        reasons=(),
    )


def _permit_id(spec: ScenarioSpec) -> str:
    return hashlib.sha256(canonical({"seed": spec.seed, "name": spec.name, "conditions": spec.conditions.as_dict()})).hexdigest()


def _motion_plan_id(spec: ScenarioSpec) -> str:
    events = [_event_id(spec, step) for step in range(1, spec.steps + 1)]
    return hashlib.sha256(canonical(events)).hexdigest()


def _event_id(spec: ScenarioSpec, step: int) -> str:
    return hashlib.sha256(f"{spec.seed}:atomic-step:{step}".encode()).hexdigest()


def _token_valid(token: PermitToken, signer: DeterministicEd25519, tick: int, revoked: bool) -> tuple[bool, str]:
    if not signer.verify(token):
        return False, "invalid Ed25519 signature"
    payload = token.payload
    if revoked:
        return False, "permit revoked"
    if tick < int(payload["issued_tick"]):
        return False, "permit is not yet valid"
    if tick > int(payload["expires_tick"]):
        return False, "permit expired"
    return True, "signed permit valid"


def _apply_changes(
    spec: ScenarioSpec,
    completed_steps: int,
    state_label: str,
    readings: Mapping[str, object],
    evidence: EvidenceLog,
) -> tuple[str, Mapping[str, object]]:
    current_label = state_label
    current_readings = readings
    for change in spec.state_changes:
        if change.after_step == completed_steps:
            current_label = change.label
            current_readings = change.readings
            evidence.append("state_change", {
                "after_step": completed_steps,
                "state": current_label,
                "readings": _readings_as_dict(current_readings),
            })
    return current_label, current_readings


def run_arm(spec: ScenarioSpec, arm: ArmName) -> ArmResult:
    signer = DeterministicEd25519(spec.seed)
    token = signer.issue(
        permit_id=_permit_id(spec),
        conditions=spec.conditions,
        issued_tick=0,
        expires_tick=spec.token_expiry_tick,
        motion_plan_id=_motion_plan_id(spec),
    )
    evidence = EvidenceLog()
    evidence.append("authorization", {
        "arm": arm,
        "token": token.as_dict(),
        "conditions": spec.conditions.as_dict(),
        "seed": spec.seed,
    })
    evidence.append("human_note", {"arm": arm, "tick": 0, "note": spec.human_note})

    tick = 0
    state_label = "A"
    readings: Mapping[str, object] = spec.state_a
    decisions: list[StepDecision] = []
    steps_run = 0
    for step in range(1, spec.steps + 1):
        state_label, readings = _apply_changes(spec, step - 1, state_label, readings, evidence)
        token_ok, token_reason = _token_valid(token, signer, tick, spec.revoked)
        live = evaluate_conditions(readings, spec.conditions, tick) if arm == "gated" else None
        if not token_ok:
            verdict: Verdict = "HOLD"
            rule = token_reason
        elif live is not None and live.verdict == "HOLD":
            verdict = "HOLD"
            rule = "; ".join(live.reasons)
        else:
            verdict = "RUN"
            rule = token_reason if live is None else live.rule
        decision = StepDecision(
            step=step,
            event_id=_event_id(spec, step),
            tick=tick,
            state=state_label,
            verdict=verdict,
            token_valid=token_ok,
            live_condition=live,
            state_snapshot=_readings_as_dict(readings),
            ages=live.ages if live else {name: None for name in ("ground_bearing", "outrigger_load")},
            rule=rule,
        )
        decisions.append(decision)
        evidence.append("decision", {
            "arm": arm,
            **decision.as_dict(),
        })
        if verdict == "HOLD":
            break
        steps_run += 1
        evidence.append("step", {"arm": arm, "step": step, "tick": tick, "result": "completed"})
        tick += 1

    return ArmResult(arm=arm, token=token, decisions=tuple(decisions), steps_run=steps_run, evidence=evidence)


def run_case(spec: ScenarioSpec, oracle: OracleExpectation) -> CaseResult:
    baseline = run_arm(spec, "baseline")
    gated = run_arm(spec, "gated")
    oracle_matches = baseline.verdicts == oracle.baseline and gated.verdicts == oracle.gated
    tampered = copy.deepcopy(gated.evidence)
    tampered.tamper(kind="decision", field="verdict", value="TAMPERED")
    tamper_valid, tamper_problems = tampered.verify()
    tamper_detected = not tamper_valid
    return CaseResult(
        spec=spec,
        oracle=oracle,
        baseline=baseline,
        gated=gated,
        oracle_matches=oracle_matches,
        tamper_detected=tamper_detected,
        tamper_problems=tuple(tamper_problems),
    )


def _with_state_tick(readings: Mapping[str, object], tick: int) -> dict[str, object]:
    return {
        name: replace(value, reading_tick=tick) if isinstance(value, Reading) else value
        for name, value in readings.items()
    }


def _fixture_oracle(name: str) -> OracleExpectation:
    expected = ORACLE_V03[name]
    return OracleExpectation(
        baseline=tuple(expected["baseline"]),
        gated=tuple(expected["gated"]),
    )


def default_cases(seed: str = "asset-twin-state-decay-v0.3") -> tuple[tuple[ScenarioSpec, OracleExpectation], ...]:
    conditions = PermitConditions()
    safe = _safe_state(0)
    unsafe = _unsafe_state(1)
    base = dict(seed=seed, state_a=safe, conditions=conditions)
    return (
        (
            ScenarioSpec(name="shift_between_steps", state_changes=(StateChange(1, "B", unsafe),), **base),
            _fixture_oracle("shift_between_steps"),
        ),
        (
            ScenarioSpec(
                name="drift_inside_tolerance",
                state_changes=(StateChange(1, "B", {"ground_bearing": _reading("ground_bearing", 120.0, 1), "outrigger_load": _reading("outrigger_load", 104.0, 1)}),),
                **base,
            ),
            _fixture_oracle("drift_inside_tolerance"),
        ),
        (
            ScenarioSpec(name="stale_reading", state_changes=(StateChange(1, "B", _with_state_tick(unsafe, 0)),), **base),
            _fixture_oracle("stale_reading"),
        ),
        (
            ScenarioSpec(name="missing_reading", state_changes=(StateChange(1, "B", {"outrigger_load": unsafe["outrigger_load"]}),), **base),
            _fixture_oracle("missing_reading"),
        ),
        (
            ScenarioSpec(name="future_dated_reading", state_changes=(StateChange(1, "B", _with_state_tick(unsafe, 2)),), **base),
            _fixture_oracle("future_dated_reading"),
        ),
        (
            ScenarioSpec(name="malformed_reading", state_changes=(StateChange(1, "B", {"ground_bearing": {"value": 130}, "outrigger_load": unsafe["outrigger_load"]}),), **base),
            _fixture_oracle("malformed_reading"),
        ),
        (
            ScenarioSpec(
                name="several_shifts",
                state_changes=(
                    StateChange(1, "B", {"ground_bearing": _reading("ground_bearing", 125.0, 1), "outrigger_load": _reading("outrigger_load", 103.0, 1)}),
                    StateChange(2, "C", unsafe),
                ),
                **base,
            ),
            _fixture_oracle("several_shifts"),
        ),
        (
            ScenarioSpec(
                name="age_exactly_X",
                steps=2,
                conditions=replace(conditions, freshness_window=1),
                state_changes=(StateChange(1, "B", _with_state_tick(safe, 0)),),
                **{key: value for key, value in base.items() if key != "conditions"},
            ),
            _fixture_oracle("age_exactly_X"),
        ),
        (
            ScenarioSpec(
                name="age_X_plus_1",
                steps=3,
                conditions=replace(conditions, freshness_window=1),
                state_changes=(StateChange(2, "B", _with_state_tick(safe, 0)),),
                **{key: value for key, value in base.items() if key != "conditions"},
            ),
            _fixture_oracle("age_X_plus_1"),
        ),
        (
            ScenarioSpec(
                name="thresholds_exact",
                state_changes=(StateChange(1, "B", {"ground_bearing": _reading("ground_bearing", 120.0, 1), "outrigger_load": _reading("outrigger_load", 105.0, 1)}),),
                **base,
            ),
            _fixture_oracle("thresholds_exact"),
        ),
        (
            ScenarioSpec(
                name="threshold_just_past",
                state_changes=(StateChange(1, "B", {"ground_bearing": _reading("ground_bearing", 119.99, 1), "outrigger_load": _reading("outrigger_load", 105.01, 1)}),),
                **base,
            ),
            _fixture_oracle("threshold_just_past"),
        ),
        (
            ScenarioSpec(
                name="one_required_reading_stale",
                conditions=replace(conditions, freshness_window=0),
                state_changes=(StateChange(1, "B", {"ground_bearing": _reading("ground_bearing", 130.0, 0), "outrigger_load": _reading("outrigger_load", 100.0, 1)}),),
                **{key: value for key, value in base.items() if key != "conditions"},
            ),
            _fixture_oracle("one_required_reading_stale"),
        ),
    )


def run_suite(seed: str = "asset-twin-state-decay-v0.3") -> tuple[CaseResult, ...]:
    # The expected rows and their fingerprint are loaded before any arm runs.
    # A changed oracle is a fixture change, not a result of this execution.
    if oracle_digest() != ORACLE_SHA256:
        raise RuntimeError("committed v0.3 oracle fingerprint does not match its fixture")
    return tuple(run_case(spec, oracle) for spec, oracle in default_cases(seed))


def deterministic_snapshot(seed: str = "asset-twin-state-decay-v0.3") -> object:
    return [
        {
            "name": result.spec.name,
            "baseline": result.baseline.as_dict(),
            "gated": result.gated.as_dict(),
        }
        for result in run_suite(seed)
    ]


def format_report(results: Sequence[CaseResult], seed: str = "asset-twin-state-decay-v0.3") -> str:
    first = results[0].spec if results else ScenarioSpec(name="empty", seed=seed)
    lines = [
        "State-Decay Test Spec v0.3",
        "simulation-only; discrete clock; Ed25519 permit; no wall-clock time",
        f"seed={seed}",
        "oracle_loaded_before_execution=True",
        f"oracle_fixture=state_decay_oracle.py oracle_sha256={oracle_digest()}",
        f"freshness_window={first.conditions.freshness_window} safety_factor={first.conditions.safety_factor} tolerance={first.conditions.outrigger_tolerance}",
        "",
    ]
    for result in results:
        lines.append(f"case={result.spec.name} pass={result.passed}")
        lines.append(f"parameters={json.dumps(result.spec.conditions.as_dict(), sort_keys=True)}")
        lines.append("step | state | tick | baseline | gated | oracle")
        max_steps = max(len(result.baseline.decisions), len(result.gated.decisions), len(result.oracle.baseline), len(result.oracle.gated))
        for index in range(max_steps):
            baseline = result.baseline.decisions[index].verdict if index < len(result.baseline.decisions) else "—"
            gated = result.gated.decisions[index].verdict if index < len(result.gated.decisions) else "—"
            state = (result.gated.decisions[index].state if index < len(result.gated.decisions) else result.baseline.decisions[index].state if index < len(result.baseline.decisions) else "—")
            tick = (result.gated.decisions[index].tick if index < len(result.gated.decisions) else result.baseline.decisions[index].tick if index < len(result.baseline.decisions) else "—")
            expected = f"{result.oracle.baseline[index] if index < len(result.oracle.baseline) else '—'}/{result.oracle.gated[index] if index < len(result.oracle.gated) else '—'}"
            lines.append(f"{index + 1} | {state} | {tick} | {baseline} | {gated} | {expected}")
        baseline_verify = result.baseline.evidence.verify()
        gated_verify = result.gated.evidence.verify()
        baseline_hashes = [str(record["digest"]) for record in result.baseline.evidence.records]
        gated_hashes = [str(record["digest"]) for record in result.gated.evidence.records]
        lines.append(f"steps_run baseline={result.baseline.steps_run} gated={result.gated.steps_run}")
        lines.append(
            f"evidence_verify baseline={baseline_verify} gated={gated_verify} "
            f"tamper_verify=(False, {list(result.tamper_problems)!r})"
        )
        lines.append(f"evidence_hashes baseline={baseline_hashes} gated={gated_hashes}")
        lines.append("evidence_log_baseline=" + json.dumps(result.baseline.evidence.as_list(), sort_keys=True, separators=(",", ":")))
        lines.append("evidence_log_gated=" + json.dumps(result.gated.evidence.as_list(), sort_keys=True, separators=(",", ":")))
        lines.append("")
    reproducible = deterministic_snapshot(seed) == deterministic_snapshot(seed)
    lines.append(f"oracle_all_pass={all(result.passed for result in results)}")
    lines.append(f"reproducible={reproducible}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", default="asset-twin-state-decay-v0.3")
    args = parser.parse_args(argv)
    results = run_suite(args.seed)
    print(format_report(results, args.seed))
    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
