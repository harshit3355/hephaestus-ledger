# HEPHAESTUS LEDGER benchmark: is the live AI deployment the approved one?

_Synthetic scenarios, local test keys (a test CA stands in for Fulcio, a test timestamp authority for Rekor). Every number below was produced by the command in the provenance section._

- 26 scenarios: 19 injected provenance breaks, 4 benign deployments, 3 negative cases that provenance cannot see by design.
- Live components and RGS weights: image 3, model 3, infra 2, policy 2, workload_identity 2, sbom 1 (max RGS 13). Mean true RGS over the breaks: 3.32.
- The mechanism's detection of the injected breaks is **true by construction**: every break violates an edge the verifier checks, and both were written by the same author. What is measured is what each baseline and the ablation miss, the benign flags and the negative cases.

## Results

| Method | Breaks detected | Rate | Exact component localization | Mean RGS on breaks | Benign flagged | Negatives detected |
|---|---|---|---|---|---|---|
| Container SBOM only (baseline) | 2/19 | 10.5% | 2/19 | 0.11 | 0/4 | 0/3 |
| Image signature only (baseline) | 1/19 | 5.3% | 0/19 | 0.16 | 0/4 | 0/3 |
| SLSA provenance, no AI config/model binding (baseline) | 4/19 | 21.1% | 0/19 | 0.63 | 0/4 | 0/3 |
| Manual release manifest (baseline) | 5/19 | 26.3% | 3/19 | 0.68 | 0/4 | 0/3 |
| DPG without graph linking (ablation) | 14/19 | 73.7% | 14/19 | 2.16 | 1/4 | 0/3 |
| **Deployment Provenance Graph (mechanism)** | 19/19 | 100.0% | 19/19 | 3.32 | 1/4 | 0/3 |

A baseline reports only the components it inspects and implicitly accepts the rest, so its RGS counts only what it looked at. Exact localization = the flagged component set equals the true tampered set.

## Ablation: what graph linking adds

Breaks the full DPG detects and the no-linking ablation (every claim valid on its own, no release root, no cross-edges) misses:

- `model_config_from_unapproved_run`
- `stale_policy_bundle`
- `wrong_workload_identity`
- `replayed_release_root`
- `mutable_tag_moved`

Each is assembled from validly signed parts that belong to a different release or run.

## Per scenario

Cells: `yes`/`miss` for breaks and negatives, `ok`/`flag` for benign runs; DPG columns show the RGS.

| Scenario | Kind | When | Truth | sbom only | signature only | slsa only | manual manifest | dpg no linking | dpg |
|---|---|---|---|---|---|---|---|---|---|
| `clean` | benign | assembly | - | ok | ok | ok | ok | ok | ok |
| `sanctioned_rollback` | benign | assembly | - | ok | ok | ok | ok | ok | ok |
| `hotfix_release` | benign | assembly | - | ok | ok | ok | ok | ok | ok |
| `sbom_regenerated` | benign | drift | - | ok | ok | ok | ok | flag | flag |
| `image_swapped_after_signing` | break | drift | image, sbom | miss | yes | yes | yes | 4 | 4 |
| `sbom_for_other_digest` | break | assembly | sbom | yes | miss | miss | miss | 1 | 1 |
| `sbom_missing` | break | assembly | sbom | yes | miss | miss | miss | 1 | 1 |
| `model_id_changed` | break | drift | model | miss | miss | miss | yes | 3 | 3 |
| `prompt_config_changed` | break | drift | model | miss | miss | miss | yes | 3 | 3 |
| `model_config_from_unapproved_run` | break | assembly | model | miss | miss | miss | miss | miss | 3 |
| `fork_workflow_identity` | break | assembly | image, sbom | miss | miss | yes | miss | 4 | 4 |
| `other_branch_identity` | break | assembly | image, sbom | miss | miss | yes | miss | 4 | 4 |
| `unapproved_workflow_file` | break | assembly | image, sbom | miss | miss | miss | miss | 4 | 4 |
| `unpinned_action` | break | assembly | image | miss | miss | miss | miss | 3 | 3 |
| `tfplan_state_mismatch` | break | drift | infra | miss | miss | miss | yes | 2 | 2 |
| `unapproved_plan_applied` | break | assembly | infra | miss | miss | miss | miss | 2 | 2 |
| `secret_scope_expansion` | break | drift | infra, workload_identity | miss | miss | miss | yes | 4 | 4 |
| `stale_policy_bundle` | break | assembly | policy | miss | miss | miss | miss | miss | 2 |
| `policy_version_label_spoof` | break | drift | policy | miss | miss | miss | miss | 2 | 2 |
| `wrong_workload_identity` | break | assembly | workload_identity | miss | miss | miss | miss | miss | 2 |
| `replayed_release_root` | break | assembly | image, infra, model, policy, sbom | miss | miss | miss | miss | miss | 11 |
| `expired_cert` | break | assembly | image, sbom | miss | miss | yes | miss | 4 | 4 |
| `mutable_tag_moved` | break | drift | image, sbom | miss | miss | miss | miss | miss | 4 |
| `malicious_commit_approved` | negative | assembly | image | miss | miss | miss | miss | miss | miss |
| `provider_silent_model_update` | negative | drift | model | miss | miss | miss | miss | miss | miss |
| `lying_runtime_observer` | negative | drift | image | miss | miss | miss | miss | miss | miss |

## Scenario descriptions and the mechanism's reasons

- `clean`: release 1.4.0 deployed exactly as approved. DPG: no gap.
- `sanctioned_rollback`: rollback to 1.3.0 re-approved as a new root (sequence 3). DPG: no gap.
- `hotfix_release`: hotfix 1.4.1 built, approved (sequence 3) and deployed. DPG: no gap.
- `sbom_regenerated`: registry-attached SBOM regenerated (new serialNumber), same contents. DPG: sbom: no verified SBOM attestation for this SBOM and this digest.
- `image_swapped_after_signing`: running image replaced after signing, with a matching attacker SBOM. DPG: image: no verified build provenance for the running digest; sbom: no verified SBOM attestation for this SBOM and this digest.
- `sbom_for_other_digest`: attached SBOM is the previous build's (describes another digest). DPG: sbom: no verified SBOM attestation for this SBOM and this digest.
- `sbom_missing`: SBOM step skipped: no SBOM for the running image. DPG: sbom: no verified SBOM attestation for this SBOM and this digest.
- `model_id_changed`: endpoint switched to another model ID after approval. DPG: model: model manifest/config has no verified claim.
- `prompt_config_changed`: system prompt and temperature edited in the live config. DPG: model: model manifest/config has no verified claim.
- `model_config_from_unapproved_run`: model config taken from the unapproved canary run (validly signed). DPG: model: model manifest/config has no verified claim.
- `fork_workflow_identity`: image built by the same workflow in a fork (CA still issues a cert). DPG: image: no verified build provenance for the running digest; sbom: no verified SBOM attestation for this SBOM and this digest.
- `other_branch_identity`: image built from refs/heads/feature-x. DPG: image: no verified build provenance for the running digest; sbom: no verified SBOM attestation for this SBOM and this digest.
- `unapproved_workflow_file`: image built on main by .github/workflows/debug.yml. DPG: image: no verified build provenance for the running digest; sbom: no verified SBOM attestation for this SBOM and this digest.
- `unpinned_action`: approved hotfix was built with actions/checkout@v4 (mutable ref). DPG: image: no verified build provenance for the running digest.
- `tfplan_state_mismatch`: applied state differs from the approved plan (ingress made external). DPG: infra: applied state matches no verified plan.
- `unapproved_plan_applied`: a locally produced, unattested plan was applied. DPG: infra: applied state matches no verified plan.
- `secret_scope_expansion`: workload identity gained Key Vault Secrets Officer. DPG: infra: applied state matches no verified plan; workload_identity: runtime identity/roles not declared by a verified plan.
- `stale_policy_bundle`: policy bundle 1.3.0 from the superseded release (validly signed). DPG: policy: policy bundle digest + version has no verified claim.
- `policy_version_label_spoof`: bundle content reverted to 1.3.0 rules, version label still 1.4.0. DPG: policy: policy bundle digest + version has no verified claim.
- `wrong_workload_identity`: pod runs as the canary identity (declared in a signed plan). DPG: workload_identity: runtime identity/roles not declared by a verified plan.
- `replayed_release_root`: old root (sequence 1) replayed: release 1.3.0 redeployed without re-approval. DPG: image: no verified build provenance for the running digest; sbom: no verified SBOM attestation for this SBOM and this digest; infra: applied state matches no verified plan; model: model manifest/config has no verified claim; policy: policy bundle digest + version has no verified claim.
- `expired_cert`: stolen ephemeral key used 2 h after its 10-minute certificate expired. DPG: image: no verified build provenance for the running digest; sbom: no verified SBOM attestation for this SBOM and this digest.
- `mutable_tag_moved`: approved release pinned a tag; the tag was moved to the canary build. DPG: image: no verified build provenance for the running digest; sbom: no verified SBOM attestation for this SBOM and this digest.
- `malicious_commit_approved`: backdoor merged to main, then built, attested and approved normally. DPG: no gap.
- `provider_silent_model_update`: provider changes weights behind the same model ID and version. DPG: no gap.
- `lying_runtime_observer`: compromised node agent reports the approved digest while running another. DPG: no gap.

## Negative results

- Benign scenarios the DPG flags: `sbom_regenerated`. An SBOM attached to the image that is not byte-identical to the attested one cannot be proven, so non-reproducible SBOM tooling produces operational false positives.
- Negative cases the DPG misses: `malicious_commit_approved`, `provider_silent_model_update`, `lying_runtime_observer`. Provenance proves where a component came from, not that the approved source was benign, that a provider kept the weights behind a model ID, or that the runtime observer reports the truth.

## Provenance

- commit: `225b50f19b75cefcf23a55a0cff8a420698ddcd6`
- command: `python -m hephaestus_ledger bench --out reports`
- python: `3.10.6`
- platform: `Windows-10-10.0.26200-SP0`
- cryptography: `50.0.1`
- terraform_fixture: `1.16.2`
- fixtures_sha256: `aa3f7149b870cd62`
- generated_at: `2026-09-29T09:16:30+00:00`
- seed: `7`
