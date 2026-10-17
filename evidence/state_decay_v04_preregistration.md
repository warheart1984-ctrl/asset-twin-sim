# State-Decay Test Spec v0.4 pre-registration

Status: PRE-REGISTERED — expected verdicts frozen before harness execution.

This experiment isolates the two admissibility inputs that changed together in
v0.3. The permit model, deterministic clock, Ed25519 signing, three-step plan,
State A, thresholds, and freshness rules remain unchanged from v0.3.

## Frozen v0.3 conditions

| Parameter | Value |
|---|---:|
| State A ground bearing | 130.0 |
| State A outrigger load | 100.0 |
| Required ground bearing | 100.0 |
| Safety factor | 1.2 |
| Required ground threshold | 120.0 |
| Planned outrigger load | 100.0 |
| Load tolerance | 5.0 |
| Freshness window | 2 ticks |
| Steps | 3 |

State changes are applied after a completed step and before the next step's
decision. The gated arm must evaluate the current readings before the action
function is invoked. The harness will record the action invocation list and the
step-2 invocation flag explicitly.

## Isolated fixtures and expected verdicts

| Fixture | Changed condition | Unchanged control | Baseline | Gated |
|---|---|---|---|---|
| `ground_bearing_change_only` | ground bearing `130.0 → 119.0` | load remains `100.0` | `RUN, RUN, RUN` | `RUN, HOLD` |
| `ground_bearing_control` | ground bearing `130.0 → 120.0` | load remains `100.0` | `RUN, RUN, RUN` | `RUN, RUN, RUN` |
| `outrigger_load_change_only` | load `100.0 → 110.0` | ground remains `130.0` | `RUN, RUN, RUN` | `RUN, HOLD` |
| `outrigger_load_control` | load `100.0 → 105.0` | ground remains `130.0` | `RUN, RUN, RUN` | `RUN, RUN, RUN` |

The negative cases fail if the gated arm executes step 2, if the HOLD reason
does not identify the changed condition, or if the unchanged control condition
is required to become inadmissible. The positive controls fail if a permitted
state change alone causes HOLD.

The expected verdict fixture is committed in
`app/asset_twin/state_decay_v04_oracle.py` before the v0.4 harness is run.
