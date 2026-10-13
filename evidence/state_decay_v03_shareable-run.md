# State-Decay Test Spec v0.3 evidence

Run in the cloud environment on 2026-10-13 with:

```bash
.venv/bin/python -m app.asset_twin.state_decay_harness --seed shareable-run
```

The expected verdicts came from the separately committed oracle fixture before
the harness executed:

- Oracle commit: `73f1d264c2fb8eaca2ae1023aac0a9e79b1c091a`
- Oracle SHA-256: `89b900a126e42dc168c30425f67ea46d56cd79631ed9aca9bc78573f2c1a03fd`
- Oracle fingerprint matched: `True`

## Oracle comparison

| Case | Baseline | Gated | Result |
|---|---|---|---|
| `shift_between_steps` | `RUN, RUN, RUN` | `RUN, HOLD` | pass |
| `drift_inside_tolerance` | `RUN, RUN, RUN` | `RUN, RUN, RUN` | pass |
| `stale_reading` | `RUN, RUN, RUN` | `RUN, HOLD` | pass |
| `missing_reading` | `RUN, RUN, RUN` | `RUN, HOLD` | pass |
| `future_dated_reading` | `RUN, RUN, RUN` | `RUN, HOLD` | pass |
| `malformed_reading` | `RUN, RUN, RUN` | `RUN, HOLD` | pass |
| `several_shifts` | `RUN, RUN, RUN` | `RUN, RUN, HOLD` | pass |
| `age_exactly_X` | `RUN, RUN` | `RUN, RUN` | pass |
| `age_X_plus_1` | `RUN, RUN, RUN` | `RUN, RUN, HOLD` | pass |
| `thresholds_exact` | `RUN, RUN, RUN` | `RUN, RUN, RUN` | pass |
| `threshold_just_past` | `RUN, RUN, RUN` | `RUN, HOLD` | pass |
| `one_required_reading_stale` | `RUN, RUN, RUN` | `RUN, HOLD` | pass |

## Main shift case

```text
step | state | tick | baseline | gated | oracle
1 | A | 0 | RUN | RUN | RUN/RUN
2 | B | 1 | RUN | HOLD | RUN/HOLD
3 | B | 2 | RUN | — | RUN/—
steps_run baseline=3 gated=1
```

The gated arm therefore ran zero steps under State B; its step-2 decision was
HOLD before the atomic step could run.

## Evidence verification and tamper test

```text
baseline_verify=(True, [])
gated_verify=(True, [])
tamper_verify=(False, ['entry 2: digest mismatch'])
```

Baseline evidence hashes:

```text
sha256:3fc5537a727fe386da076a1b1cc88be1bda4df2405b73e52f93834a08d3f1024
sha256:b0c9c5f0cdbb29be3a58a10cc129764bf7fe0dd6360081bbef0747e4f7dcce3d
sha256:9f23015af2b3ba83094901f203c6692b2a5949924be8a6eaa7a76c2bede89288
sha256:e8282e1c8347cbad9a6b313db4c5f1e4449ace973e003b5a5bb542389355f14e
sha256:b506e3882e884e617e9f3b4fdad9ef067c9b7929c55decd70ec20367c4661f80
sha256:8fbcafa4a60127bd49ead798a12d93346b6ceddb0d53963bc64c8357522821b4
sha256:01837e3887a1986b693133c995095a156ec39f27e1a451fa565c01757f7f71b5
sha256:4d36e9f55a1c5dfc54692f7feadd27dfc04a3801e87dc110a608e08ff790c8d9
sha256:f8f607362c101e90a35a19c2e2745d1a3db86a3ad97732f1e115408a5e3bc47b
```

Gated evidence hashes:

```text
sha256:d1e274e80fe61be576883a8132bb4e9928f02a9728991f994f8563e91ebb3c18
sha256:e08367d6b1296954302195c4ffba3feeb3f7448a8f534bb52af452191fbceafa
sha256:9e7737034982f03383046de5ce7c0701d0f732c7f69296a1e0f32874700fbeb6
sha256:fa26e3b7a6178f508d472ee7dfd15c1aa3fc0495af932404c1943e993903077e
sha256:86c46a21d3dd127cc710a6a5196054215d8526ecec57ee288a750fc992fb35c9
sha256:8aa28d2df6c834e0e555b326dfc38461a7cfeff0e8c58dcfab7474e59a448613
```

The harness test suite completed with:

```text
18 passed
oracle_all_pass=True
reproducible=True
```
