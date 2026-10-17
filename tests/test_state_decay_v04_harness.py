from __future__ import annotations

import pytest

from app.asset_twin.state_decay_v04_harness import default_cases, main, run_case, run_suite
from app.asset_twin.state_decay_v04_oracle import ORACLE_SHA256, oracle_digest


def test_v04_oracle_is_fixed_before_execution() -> None:
    assert oracle_digest() == ORACLE_SHA256
    assert len(ORACLE_SHA256) == 64


@pytest.mark.parametrize("spec, oracle", default_cases(), ids=[spec.name for spec, _ in default_cases()])
def test_each_isolated_fixture_matches_oracle_and_action_trace(spec, oracle) -> None:
    result = run_case(spec, oracle)

    assert result.passed, spec.name
    assert result.baseline.action_invocations == (1, 2, 3)
    assert result.gated.action_invocations == ((1,) if "change_only" in spec.name else (1, 2, 3))

    gate_records = [record for record in result.gated.evidence.as_list() if record["kind"] == "execution_gate"]
    step_records = [record for record in result.gated.evidence.as_list() if record["kind"] == "step"]
    if "change_only" in spec.name:
        assert gate_records[-1]["body"] == {
            "arm": "gated",
            "step": 2,
            "gate": "CLOSED",
            "action_invoked": False,
        }
        assert not any(record["body"].get("step") == 2 for record in step_records)


def test_ground_and_load_changes_are_independently_causal() -> None:
    ground = run_suite("causal-seed")[0]
    load = run_suite("causal-seed")[2]

    ground_reasons = ground.gated.decisions[1].live_condition.reasons  # type: ignore[union-attr]
    load_reasons = load.gated.decisions[1].live_condition.reasons  # type: ignore[union-attr]
    assert any("ground_bearing" in reason for reason in ground_reasons)
    assert not any("outrigger_load" in reason for reason in ground_reasons)
    assert any("outrigger_load" in reason for reason in load_reasons)
    assert not any("ground_bearing" in reason for reason in load_reasons)


def test_v04_cli_prints_the_action_boundary_proof(capsys) -> None:
    assert main(["--seed", "cli-v04-seed"]) == 0
    output = capsys.readouterr().out
    assert "State-Decay Test Spec v0.4" in output
    assert "oracle_loaded_before_execution=True" in output
    assert f"oracle_sha256={ORACLE_SHA256}" in output
    assert "action_invocations baseline=[1, 2, 3] gated=[1]" in output
    assert "gated_step_2_action_invoked=False" in output
    assert "tamper_verify=(False, ['entry 2: digest mismatch'])" in output
    assert "oracle_all_pass=True" in output
    assert "reproducible=True" in output
