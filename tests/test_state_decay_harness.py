from __future__ import annotations

import pytest

from app.asset_twin.state_decay_harness import (
    DeterministicEd25519,
    OracleExpectation,
    PermitConditions,
    Reading,
    ScenarioSpec,
    StateChange,
    default_cases,
    deterministic_snapshot,
    main,
    run_case,
    run_suite,
)
from app.asset_twin.state_decay_oracle import ORACLE_SHA256, oracle_digest


def test_shift_proves_hold_blocks_the_next_atomic_step() -> None:
    result = run_suite()[0]

    assert result.spec.name == "shift_between_steps"
    assert result.baseline.verdicts == ("RUN", "RUN", "RUN")
    assert result.gated.verdicts == ("RUN", "HOLD")
    assert result.baseline.steps_run == 3
    assert result.gated.steps_run == 1
    assert result.gated.decisions[1].state == "B"
    assert result.gated.decisions[1].live_condition is not None
    assert result.gated.decisions[1].live_condition.verdict == "HOLD"
    assert result.gated.evidence.verify() == (True, [])


@pytest.mark.parametrize("spec, oracle", default_cases(), ids=[spec.name for spec, _ in default_cases()])
def test_every_v03_variation_matches_its_explicit_oracle(spec, oracle) -> None:
    result = run_case(spec, oracle)
    assert result.passed, spec.name
    assert result.oracle_matches
    assert result.tamper_detected


def test_same_seed_reproduces_tokens_decisions_and_evidence_hashes() -> None:
    assert deterministic_snapshot("repro-seed") == deterministic_snapshot("repro-seed")
    first = run_suite("repro-seed")[0]
    other = run_suite("different-seed")[0]
    assert first.baseline.token.signature_hex != other.baseline.token.signature_hex
    assert first.baseline.evidence.as_list() != other.baseline.evidence.as_list()


def test_oracle_fixture_fingerprint_is_fixed_before_execution() -> None:
    assert oracle_digest() == ORACLE_SHA256
    assert len(ORACLE_SHA256) == 64


def test_ed25519_permit_is_invalid_after_payload_tampering() -> None:
    signer = DeterministicEd25519("permit-seed")
    token = signer.issue(
        permit_id="permit-1",
        conditions=PermitConditions(),
        issued_tick=0,
        expires_tick=5,
        motion_plan_id="motion-1",
    )
    assert signer.verify(token)
    tampered_payload = dict(token.payload)
    tampered_payload["expires_tick"] = 500
    tampered = token.__class__(
        payload=tampered_payload,
        signature_hex=token.signature_hex,
        public_key_hex=token.public_key_hex,
    )
    assert not signer.verify(tampered)


def test_human_note_is_evidence_only_and_never_an_override() -> None:
    safe = {
        "ground_bearing": Reading("ground_bearing", 130.0, 0),
        "outrigger_load": Reading("outrigger_load", 100.0, 0),
    }
    spec = ScenarioSpec(
        name="human-note-only",
        state_a=safe,
        state_changes=(
            StateChange(
                after_step=1,
                label="B",
                readings={
                    "ground_bearing": Reading("ground_bearing", 119.0, 1),
                    "outrigger_load": Reading("outrigger_load", 110.0, 1),
                },
            ),
        ),
        human_note="operator observed a concern; counted overrides are out of scope",
    )
    result = run_case(
        spec,
        oracle=OracleExpectation(baseline=("RUN", "RUN", "RUN"), gated=("RUN", "HOLD")),
    )
    notes = [record for record in result.gated.evidence.as_list() if record["kind"] == "human_note"]
    assert len(notes) == 1
    assert result.gated.steps_run == 1
    assert result.gated.verdicts == ("RUN", "HOLD")


def test_cli_emits_a_passing_report(capsys) -> None:
    assert main(["--seed", "cli-seed"]) == 0
    output = capsys.readouterr().out
    assert "State-Decay Test Spec v0.3" in output
    assert "oracle_loaded_before_execution=True" in output
    assert f"oracle_sha256={ORACLE_SHA256}" in output
    assert "evidence_hashes baseline=[" in output
    assert "tamper_verify=(False, ['entry 2: digest mismatch'])" in output
    assert "oracle_all_pass=True" in output
    assert "reproducible=True" in output
