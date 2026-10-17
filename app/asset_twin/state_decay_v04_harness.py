"""Deterministic State-Decay Test Spec v0.4 isolation harness.

This module reuses the frozen v0.3 permit, clock, condition, signing, and
evidence primitives.  It changes only the fixtures and adds an explicit action
invocation trace so a HOLD can be checked against the simulated action
boundary, not inferred from a missing completion record.
"""

from __future__ import annotations

import argparse
import copy
import json
from dataclasses import dataclass, replace
from typing import Literal, Mapping, Sequence

from .state_decay_harness import (
    DeterministicEd25519,
    EvidenceLog,
    OracleExpectation,
    PermitConditions,
    Reading,
    ScenarioSpec,
    StateChange,
    StepDecision,
    _apply_changes,
    _event_id,
    _motion_plan_id,
    _permit_id,
    _readings_as_dict,
    _token_valid,
    evaluate_conditions,
)
from .state_decay_v04_oracle import ORACLE_SHA256, ORACLE_V04, oracle_digest

ArmName = Literal["baseline", "gated"]
Verdict = Literal["RUN", "HOLD"]


@dataclass(frozen=True)
class ArmResult:
    arm: ArmName
    token: object
    decisions: tuple[StepDecision, ...]
    steps_run: int
    action_invocations: tuple[int, ...]
    evidence: EvidenceLog

    @property
    def verdicts(self) -> tuple[Verdict, ...]:
        return tuple(decision.verdict for decision in self.decisions)  # type: ignore[return-value]

    def as_dict(self) -> dict[str, object]:
        valid, problems = self.evidence.verify()
        return {
            "arm": self.arm,
            "decisions": [decision.as_dict() for decision in self.decisions],
            "steps_run": self.steps_run,
            "action_invocations": list(self.action_invocations),
            "evidence_verify": {"valid": valid, "problems": problems},
            "evidence": self.evidence.as_list(),
        }


@dataclass(frozen=True)
class CaseResult:
    spec: ScenarioSpec
    oracle: OracleExpectation
    baseline: ArmResult
    gated: ArmResult
    oracle_matches: bool
    action_boundary_matches: bool
    tamper_detected: bool
    tamper_problems: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.oracle_matches and self.action_boundary_matches and self.tamper_detected


def _reading(name: str, value: float, tick: int = 0) -> Reading:
    return Reading(name=name, value=value, reading_tick=tick)


def _safe_state(tick: int = 0) -> dict[str, Reading]:
    return {
        "ground_bearing": _reading("ground_bearing", 130.0, tick),
        "outrigger_load": _reading("outrigger_load", 100.0, tick),
    }


def _fixture_oracle(name: str) -> OracleExpectation:
    expected = ORACLE_V04[name]
    return OracleExpectation(
        baseline=tuple(expected["baseline"]),
        gated=tuple(expected["gated"]),
    )


def _run_action(step: int, invocations: list[int]) -> None:
    """The simulated action boundary; no physical controller is involved."""
    invocations.append(step)


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
    evidence.append("authorization", {"arm": arm, "token": token.as_dict(), "seed": spec.seed, "conditions": spec.conditions.as_dict()})
    evidence.append("human_note", {"arm": arm, "tick": 0, "note": spec.human_note})

    tick = 0
    state_label = "A"
    readings: Mapping[str, object] = spec.state_a
    decisions: list[StepDecision] = []
    action_invocations: list[int] = []
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
        evidence.append("decision", {"arm": arm, **decision.as_dict()})

        if verdict == "HOLD":
            evidence.append("execution_gate", {"arm": arm, "step": step, "gate": "CLOSED", "action_invoked": False})
            break

        evidence.append("execution_gate", {"arm": arm, "step": step, "gate": "OPEN"})
        _run_action(step, action_invocations)
        steps_run += 1
        evidence.append("step", {"arm": arm, "step": step, "tick": tick, "result": "completed", "action_invoked": True})
        tick += 1

    return ArmResult(
        arm=arm,
        token=token,
        decisions=tuple(decisions),
        steps_run=steps_run,
        action_invocations=tuple(action_invocations),
        evidence=evidence,
    )


def run_case(spec: ScenarioSpec, oracle: OracleExpectation) -> CaseResult:
    baseline = run_arm(spec, "baseline")
    gated = run_arm(spec, "gated")
    expected_invocations = tuple(index + 1 for index, verdict in enumerate(gated.verdicts) if verdict == "RUN")
    action_boundary_matches = (
        gated.action_invocations == expected_invocations
        and (2 not in gated.action_invocations if gated.verdicts == ("RUN", "HOLD") else True)
    )
    tampered = copy.deepcopy(gated.evidence)
    tampered_index = tampered.tamper(kind="decision", field="verdict", value="TAMPERED")
    tamper_valid, tamper_problems = tampered.verify()
    assert tampered_index == 2
    return CaseResult(
        spec=spec,
        oracle=oracle,
        baseline=baseline,
        gated=gated,
        oracle_matches=baseline.verdicts == oracle.baseline and gated.verdicts == oracle.gated,
        action_boundary_matches=action_boundary_matches,
        tamper_detected=not tamper_valid,
        tamper_problems=tuple(tamper_problems),
    )


def default_cases(seed: str = "asset-twin-state-decay-v0.4") -> tuple[tuple[ScenarioSpec, OracleExpectation], ...]:
    conditions = PermitConditions()
    safe = _safe_state(0)
    base = dict(seed=seed, state_a=safe, conditions=conditions)
    return (
        (
            ScenarioSpec(
                name="ground_bearing_change_only",
                state_changes=(StateChange(1, "B", {"ground_bearing": _reading("ground_bearing", 119.0, 1), "outrigger_load": _reading("outrigger_load", 100.0, 1)}),),
                **base,
            ),
            _fixture_oracle("ground_bearing_change_only"),
        ),
        (
            ScenarioSpec(
                name="ground_bearing_control",
                state_changes=(StateChange(1, "B", {"ground_bearing": _reading("ground_bearing", 120.0, 1), "outrigger_load": _reading("outrigger_load", 100.0, 1)}),),
                **base,
            ),
            _fixture_oracle("ground_bearing_control"),
        ),
        (
            ScenarioSpec(
                name="outrigger_load_change_only",
                state_changes=(StateChange(1, "B", {"ground_bearing": _reading("ground_bearing", 130.0, 1), "outrigger_load": _reading("outrigger_load", 110.0, 1)}),),
                **base,
            ),
            _fixture_oracle("outrigger_load_change_only"),
        ),
        (
            ScenarioSpec(
                name="outrigger_load_control",
                state_changes=(StateChange(1, "B", {"ground_bearing": _reading("ground_bearing", 130.0, 1), "outrigger_load": _reading("outrigger_load", 105.0, 1)}),),
                **base,
            ),
            _fixture_oracle("outrigger_load_control"),
        ),
    )


def run_suite(seed: str = "asset-twin-state-decay-v0.4") -> tuple[CaseResult, ...]:
    if oracle_digest() != ORACLE_SHA256:
        raise RuntimeError("committed v0.4 oracle fingerprint does not match its fixture")
    return tuple(run_case(spec, oracle) for spec, oracle in default_cases(seed))


def deterministic_snapshot(seed: str = "asset-twin-state-decay-v0.4") -> object:
    return [
        {
            "name": result.spec.name,
            "baseline": result.baseline.as_dict(),
            "gated": result.gated.as_dict(),
        }
        for result in run_suite(seed)
    ]


def format_report(results: Sequence[CaseResult], seed: str = "asset-twin-state-decay-v0.4") -> str:
    lines = [
        "State-Decay Test Spec v0.4",
        "simulation-only; discrete clock; Ed25519 permit; explicit action trace",
        f"seed={seed}",
        "oracle_loaded_before_execution=True",
        f"oracle_fixture=state_decay_v04_oracle.py oracle_sha256={oracle_digest()}",
        "conditions=required_ground_bearing:100.0 safety_factor:1.2 planned_outrigger_load:100.0 outrigger_tolerance:5.0 freshness_window:2",
        "",
    ]
    for result in results:
        lines.append(f"case={result.spec.name} pass={result.passed}")
        lines.append(f"oracle_match={result.oracle_matches} action_boundary_match={result.action_boundary_matches}")
        lines.append("step | state | tick | baseline | gated | oracle")
        max_steps = max(len(result.baseline.decisions), len(result.gated.decisions))
        for index in range(max_steps):
            baseline = result.baseline.decisions[index].verdict if index < len(result.baseline.decisions) else "—"
            gated = result.gated.decisions[index].verdict if index < len(result.gated.decisions) else "—"
            decision = result.gated.decisions[index] if index < len(result.gated.decisions) else result.baseline.decisions[index]
            expected = f"{result.oracle.baseline[index] if index < len(result.oracle.baseline) else '—'}/{result.oracle.gated[index] if index < len(result.oracle.gated) else '—'}"
            lines.append(f"{index + 1} | {decision.state} | {decision.tick} | {baseline} | {gated} | {expected}")
        lines.append(f"steps_run baseline={result.baseline.steps_run} gated={result.gated.steps_run}")
        lines.append(f"action_invocations baseline={list(result.baseline.action_invocations)} gated={list(result.gated.action_invocations)}")
        lines.append(f"gated_step_2_action_invoked={2 in result.gated.action_invocations}")
        lines.append(f"evidence_verify baseline={result.baseline.evidence.verify()} gated={result.gated.evidence.verify()}")
        lines.append(f"tamper_verify=(False, {list(result.tamper_problems)!r})")
        lines.append(f"evidence_hashes baseline={[str(record['digest']) for record in result.baseline.evidence.records]}")
        lines.append(f"evidence_hashes gated={[str(record['digest']) for record in result.gated.evidence.records]}")
        lines.append("")
    reproducible = deterministic_snapshot(seed) == deterministic_snapshot(seed)
    lines.append(f"oracle_all_pass={all(result.passed for result in results)}")
    lines.append(f"reproducible={reproducible}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", default="asset-twin-state-decay-v0.4")
    args = parser.parse_args(argv)
    results = run_suite(args.seed)
    print(format_report(results, args.seed))
    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
