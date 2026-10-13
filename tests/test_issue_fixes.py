"""Regression coverage for the two open GitHub issues."""

from __future__ import annotations

import json

import pytest

from app.asset_twin.authorization import AuthorizationError, Principal
from app.asset_twin.evidence import EvidenceChainError, EvidenceLedger
from app.asset_twin.models import Telemetry, VetoDecision


def _telemetry(asset_id: str, seq: int = 1) -> Telemetry:
    return Telemetry(
        asset_id=asset_id,
        seq=seq,
        at=f"2026-10-13T00:00:{seq:02d}Z",
        rpm=3000.0,
        vibration_mm_s=2.0,
        exhaust_temp_c=420.0,
        oil_pressure_kpa=500.0,
        ambient_temp_c=20.0,
        ambient_pressure_kpa=101.3,
        operator_setpoint_rpm=3000.0,
    )


@pytest.fixture()
def isolated_service(tmp_path, monkeypatch):
    import app.asset_twin.evidence as evidence
    import app.asset_twin.service as service

    monkeypatch.setenv("JARVIS_ASSET_TWIN_DIR", str(tmp_path))
    monkeypatch.setattr(evidence, "_ledger", None)
    for name in (
        "_assets",
        "_gates",
        "_decisions",
        "_health",
        "_last_seq",
        "_latest",
        "_cycle_locks",
        "_tenant_assets",
        "_history",
    ):
        monkeypatch.setattr(service, name, {})
    return service


def test_issue_2_rechecks_a_cached_tenant_after_b_updates_the_file(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    ledger = EvidenceLedger(path)
    ledger.append("tenant-A", "measurement", {"n": 1})
    ledger.append("tenant-A", "cycle", {"n": 2})
    ledger.append("tenant-B", "measurement", {"n": 3})

    records = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(records[0])
    first["body"]["n"] = 999
    records[0] = json.dumps(first)
    path.write_text("\n".join(records) + "\n", encoding="utf-8")

    # B's cached head is revalidated first, but it must not make A's cached
    # head look current.
    ledger.check("tenant-B")
    with pytest.raises(EvidenceChainError, match="tenant-A|digest mismatch"):
        ledger.check("tenant-A")


def test_issue_1_separates_read_veto_and_write_capabilities(isolated_service) -> None:
    service = isolated_service
    read_only = Principal.read_only("reader", "tenant-A")
    veto_only = Principal.veto_only("safety-operator", "tenant-A")
    writer = Principal.writer("reviewer", "tenant-A")

    with pytest.raises(AuthorizationError, match="memory.write"):
        service.run_cycle("tenant-A", _telemetry("auth-read-cycle"), principal=read_only)

    approve_target = service.run_cycle("tenant-A", _telemetry("auth-approve"), principal=writer).decision.decision_id
    with pytest.raises(AuthorizationError, match="memory.write"):
        service.decide_human(
            "tenant-A",
            VetoDecision(decision_id=approve_target, verdict="approve", reviewer="reviewer", at="2026-10-13T00:01:00Z"),
            principal=read_only,
        )
    with pytest.raises(AuthorizationError, match="memory.write"):
        service.decide_human(
            "tenant-A",
            VetoDecision(decision_id=approve_target, verdict="approve", reviewer="safety-operator", at="2026-10-13T00:01:01Z"),
            principal=veto_only,
        )

    stop_target = service.run_cycle("tenant-A", _telemetry("auth-stop")).decision.decision_id
    service.decide_human(
        "tenant-A",
        VetoDecision(decision_id=stop_target, verdict="hold", reviewer="safety-operator", at="2026-10-13T00:01:02Z"),
        principal=veto_only,
    )
    with pytest.raises(ValueError, match="terminal stop"):
        service.decide_human(
            "tenant-A",
            VetoDecision(decision_id=stop_target, verdict="hold", reviewer="safety-operator", at="2026-10-13T00:01:03Z"),
            principal=veto_only,
        )

    writer_target = service.run_cycle("tenant-A", _telemetry("auth-writer")).decision.decision_id
    service.decide_human(
        "tenant-A",
        VetoDecision(decision_id=writer_target, verdict="approve", reviewer="reviewer", at="2026-10-13T00:01:04Z"),
        principal=writer,
    )
    with pytest.raises(AuthorizationError, match="memory.write"):
        service.execute("tenant-A", writer_target, "auth-writer", principal=veto_only)
    with pytest.raises(ValueError, match="already approved"):
        service.decide_human(
            "tenant-A",
            VetoDecision(decision_id=writer_target, verdict="approve", reviewer="reviewer", at="2026-10-13T00:01:05Z"),
            principal=writer,
        )

    records = [json.loads(line) for line in service.get_ledger()._path.read_text(encoding="utf-8").splitlines()]
    verdicts = [record for record in records if record["kind"] == "veto"]
    assert len(verdicts) == 2
    assert {record["body"]["verdict"] for record in verdicts} == {"hold", "approve"}
    assert verdicts[0]["body"]["authorization_policy"] == "asset-twin.verdict.v1"
