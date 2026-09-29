# Threat model

HEPHAESTUS LEDGER answers one question at promotion or runtime: *is every component of the live AI
deployment reachable from the currently approved release root?* It never deploys, rolls back or
blocks anything itself; it produces per-component gaps, an RGS and an exit code that a promotion
gate or alert can act on.

## Assets

- The identity of what is actually serving: image, SBOM, applied infrastructure, model endpoint and
  config, policy bundle, workload identity.
- The release decision: which CI run, from which commit, is approved for which environment.
- The verifier's trust root and release ledger.

## Trust boundaries

| Input | Trust | Why |
|---|---|---|
| Trust root (CA key, timestamp key, approver identities, builder identity policy) | trusted, code-reviewed | it defines who may attest and approve; a wrong identity policy accepts the wrong builder |
| Release ledger | trusted, append-only | the verifier takes the highest sequence as current; an attacker who can delete the newest root can make an older one current again |
| Attestations (DSSE envelopes) | untrusted until verified | fetched from a registry or store anyone may write to; each is checked for CA chain, signature, timestamp, certificate window, signer identity and pinned build dependencies |
| Live assembly (runtime observer report) | **trusted, not verified** | the verifier checks what the observer reports; a lying observer is out of reach (`lying_runtime_observer`) |
| OCI layout on disk (`verify DIR/oci`) | untrusted | the manifest blob must hash to its digest, and that digest replaces the reported one |
| Test keys in this repository | **public, test-only** | derived from a seed string anyone can recompute; they exist to make fixtures reproducible |

## Threats and controls

| Threat | Control | Scenario |
|---|---|---|
| Image swapped after signing, with a matching attacker SBOM | the digest must have build provenance from the approved run and be pinned by that run's plan | `image_swapped_after_signing` |
| Build from a fork, another branch, or another workflow file of the same repo | signer identity must match issuer, repository, exact workflow path and ref | `fork_workflow_identity`, `other_branch_identity`, `unapproved_workflow_file` |
| Build used a mutable third-party action ref | build provenance must list only SHA-pinned `pkg:githubactions/` dependencies | `unpinned_action` |
| Stolen short-lived signing key used later | the timestamp authority's time must fall in the certificate window | `expired_cert` |
| Validly signed parts from another run or an older release (mix-and-match) | every claim must come from the run and commit of the active root | `model_config_from_unapproved_run`, `stale_policy_bundle`, `wrong_workload_identity` |
| Old approval replayed / silent rollback | the highest-sequence root is current; a rollback needs a new root | `replayed_release_root` vs `sanctioned_rollback` |
| Mutable image tag moved to another (validly built) image | the approved plan must pin `@sha256:` of the running digest | `mutable_tag_moved` |
| Infra drift, unattested plan, role/scope expansion | applied state must equal a plan from the approved run; runtime roles must equal declared roles | `tfplan_state_mismatch`, `unapproved_plan_applied`, `secret_scope_expansion` |
| Model or prompt config edited live; policy label kept while content reverted | model manifest and policy bundle are compared by digest, not by label | `model_id_changed`, `prompt_config_changed`, `policy_version_label_spoof` |
| A tampered benchmark report is presented as evidence | reports record commit SHA, command, seed, tool versions and fixture hash; regenerate from the commit | - |
| Supply-chain compromise of this repository's CI | third-party actions pinned by commit SHA; workflow token is read-only | - |

## Not controlled (documented blind spots)

- **Approved but malicious source** (`malicious_commit_approved`): provenance proves origin, not intent.
- **Provider-side model changes** behind the same model ID/version (`provider_silent_model_update`):
  needs behavioral fingerprinting or provider attestation, not provenance.
- **Lying runtime observer** (`lying_runtime_observer`): needs hardware/runtime attestation of the node.
- **Signing-key compromise inside the certificate window**: the local test CA and timestamp authority
  have no transparency log, so a key holder who signs within the 10-minute window is indistinguishable
  from the legitimate run. Keyless Sigstore with Rekor monitoring narrows this; it is not exercised here.
- **Ledger rollback** by someone with write access to the verifier's ledger.
