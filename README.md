# asset-twin-sim

A **simulation-only** asset twin with a human veto, extracted from
[persistence-memory](https://github.com/warheart1984-ctrl/persistence-memory) (PR #64) with its history intact.

Telemetry goes in; a twin estimates state and health; a decision packet recommends an action with its risk and evidence; **nothing
moves until a human approves it**, and every step is written to a tenant-scoped, hash-chained evidence ledger. The "asset" is an
in-process simulator. This code never touches a real machine.

| | |
|---|---|
| `twin_core.py`, `simulator.py` | state/health estimation and the simulated turbine |
| `decision.py` | anomaly -> risk -> recommendation, with an expiry |
| `veto.py` | the gate: approve / veto / hold, atomic claim before execution, superseded and expired packets |
| `execution.py` | simulated controller; refuses anything unapproved, expired, superseded or for a different asset |
| `evidence.py` | append-only hash chain per tenant; restart recovery; fails closed if the file changes underneath it |
| `service.py` | the orchestrator: sequence checks, per-asset serialisation, write-ahead execution intent, bounded memory |

## Guarantees the tests pin down

- a cycle never executes; execution needs an explicit approval that is still the newest for that asset
- a veto and an execute cannot both win; two executes cannot both win; an approval is recorded before it can be used
- stale or replayed telemetry is rejected, also after a restart (sequence and health are recovered from the verified chain)
- if the audit trail is broken, nothing acts; the execution intent is written before the asset moves
- memory is bounded (per-asset retention, per-tenant asset cap)

## Status: core is standalone, the HTTP layer is not here yet

The package (`app/asset_twin/`) needs only `pydantic` and the standard library and runs on its own:

```python
import app.asset_twin.service as svc
```

What is **not** here: the REST endpoints (`/api/jarvis/asset-twin/{cycle,decide,execute,audit}`), which still live in the ledger's
`app/main.py` together with its auth (write scope, tenant). `tests/test_asset_twin.py` includes API-level tests that import
`app.main` and so cannot run here until a small FastAPI layer (or a thin adapter) is added; the core tests in that file are
independent of it.

Extracted from the `asset-twin-sim-veto` branch of persistence-memory at `f46c813`.

## State-decay test harness v0.3

The deterministic harness compares a static-authorization baseline with a
per-step execution gate:

```bash
python -m app.asset_twin.state_decay_harness
```

It uses a discrete clock, seed-derived Ed25519 permits, atomic motion steps,
strict freshness and threshold rules, and a canonical in-memory evidence
chain. The report covers the State B shift, in-tolerance drift, stale/missing/
future/malformed readings, repeated shifts, boundary values, an explicit
oracle, and a tamper check. In the main case the baseline runs the next step
under changed conditions while the gated arm records `HOLD` before that step
and runs zero steps under State B.

This is a simulation comparison only. It does not establish a general claim
about token systems or real lifting equipment. Hash-chain verification detects
edits to the recorded chain; signing or anchoring the evidence log is outside
v0.3.

The shareable run evidence is recorded in
[`evidence/state_decay_v03_shareable-run.md`](evidence/state_decay_v03_shareable-run.md).
