"""Deployment Provenance Graph verifier, its ablation, and the baselines.

Every method maps a World to {component: reason} for the live components it cannot prove. The
Reproducibility Gap Score (RGS) is the weighted sum over those components.
"""
from __future__ import annotations

import re
from collections import defaultdict

from . import attest
from .attest import digest
from .world import BUILD, DEPLOY_KEYS, MODEL, PLAN, POLICY, SBOM, World, manifest_of, sbom_subject, tf_inputs

# ponytail: fixed weights; behaviour-defining parts (code, model) count most. Unweighted counts are reported too.
WEIGHTS = {"image": 3, "model": 3, "infra": 2, "policy": 2, "workload_identity": 2, "sbom": 1}


def rgs(gaps: dict) -> int:
    return sum(WEIGHTS[c] for c in gaps)


def _identity_ok(idn: dict, pol: dict, pin_workflow: bool = True) -> bool:
    return (idn.get("issuer") == pol["issuer"] and idn.get("repository") == pol["repository"]
            and idn.get("ref") == pol["ref"] and idn.get("event_name") in pol["events"]
            and (not pin_workflow or idn.get("job_workflow_ref") == f"{pol['repository']}/{pol['workflow']}@{pol['ref']}"))


def _pinned(stmt: dict) -> bool:
    deps = stmt["predicate"]["buildDefinition"]["resolvedDependencies"]
    return all(re.fullmatch(r"pkg:githubactions/[^@]+@[0-9a-f]{40}", d["uri"])
               for d in deps if d["uri"].startswith("pkg:githubactions/"))


def attested(w: World) -> list[tuple[dict, dict]]:
    """(signer identity, statement) for every claim whose signature, CA chain, timestamp, certificate
    window and signer identity verify, and whose build (if any) used only SHA-pinned actions."""
    out = []
    for env in w.envelopes:
        if attest.check(env, w.trust) or not _identity_ok(env["cert"]["identity"], w.trust["identity"]):
            continue
        st = attest.decode(env)
        if st["predicateType"] == BUILD and not _pinned(st):
            continue
        out.append((env["cert"]["identity"], st))
    return out


def active_root(w: World, environment: str) -> dict | None:
    """Highest-sequence verified approval for the environment. An older root is superseded, not revoked:
    presenting it again (replay, silent rollback) does not make its run current."""
    roots = [attest.decode(e) for e in w.ledger
             if not attest.check(e, w.trust) and e["cert"]["identity"] in w.trust["approvers"]]
    roots = [r for r in roots if r["predicate"]["environment"] == environment]
    return max(roots, key=lambda r: r["predicate"]["sequence"], default=None)


def _subj(st: dict) -> str:
    return st["subject"][0]["digest"]["sha256"]


def dpg(w: World, link: bool = True) -> dict[str, str]:
    """link=True: the mechanism. A live component is proven only if it is reachable from the active
    release root: root -> (run, commit) -> signed claim -> component, plus the cross-edges the approved
    Terraform plan asserts (image digest pinned, workload identity declared, model endpoint declared).
    link=False (ablation): each component needs *some* valid, policy-conformant claim, looked up by its own
    digest (what per-artifact `cosign verify-attestation` gives you); no root, no run, no cross-edges."""
    claims = attested(w)
    live = w.live
    if link:
        root = active_root(w, live["environment"])
        if root is None:
            return {c: "no approved release root" for c in WEIGHTS}
        run = (root["predicate"]["run_id"], root["subject"][0]["digest"]["gitCommit"])
        claims = [(i, s) for i, s in claims if (i["run_id"], i["sha"]) == run]
    by = defaultdict(list)
    for _, s in claims:
        by[s["predicateType"]].append(s)
    plans = [tf_inputs(s["predicate"]["plan"]) for s in by[PLAN]]
    gaps = {}

    d = live["image"]["digest"]
    if not any(_subj(s) == d for s in by[BUILD]):
        gaps["image"] = "no verified build provenance for the running digest"
    elif link and not any(p["terraform_data.container_app"]["image"].endswith("@sha256:" + d) for p in plans):
        gaps["image"] = "the approved plan does not pin the running digest"

    sb = live["sbom"]
    if sb is None or not any(_subj(s) == d and digest(s["predicate"]) == digest(sb) for s in by[SBOM]):
        gaps["sbom"] = "no verified SBOM attestation for this SBOM and this digest"

    if not any(p == tf_inputs(live["infra_state"]) for p in plans):
        gaps["infra"] = "applied state matches no verified plan"

    m = live["model"]
    if not any(_subj(s) == digest(m) for s in by[MODEL]):
        gaps["model"] = "model manifest/config has no verified claim"
    elif link and not any(p["terraform_data.model_deployment"] == {k: m[k] for k in DEPLOY_KEYS} for p in plans):
        gaps["model"] = "model endpoint differs from the approved plan"

    pol = live["policy"]
    if not any(_subj(s) == digest(pol["bundle"]) and s["predicate"]["version"] == pol["version"] for s in by[POLICY]):
        gaps["policy"] = "policy bundle digest + version has no verified claim"

    wi = live["workload_identity"]
    if not any({k: p["terraform_data.workload_identity"][k] for k in ("client_id", "roles")} == wi for p in plans):
        gaps["workload_identity"] = "runtime identity/roles not declared by a verified plan"
    return gaps


def sbom_only(w: World) -> dict[str, str]:
    """Container SBOM only: an SBOM is attached and describes the running digest."""
    sb = w.live["sbom"]
    if sb is None:
        return {"sbom": "no SBOM attached"}
    return {} if sbom_subject(sb) == w.live["image"]["digest"] else {"sbom": "SBOM describes another digest"}


def signature_only(w: World) -> dict[str, str]:
    """Some claim over the running digest has a valid signature chaining to the CA. No identity, no time."""
    d = w.live["image"]["digest"]
    ok = any(not attest.check(e, w.trust, timestamp=False) and _subj(attest.decode(e)) == d for e in w.envelopes)
    return {} if ok else {"image": "no valid signature over the running digest"}


def slsa_only(w: World) -> dict[str, str]:
    """SLSA build provenance for the image, verified like a typical admission policy (cosign / Kyverno
    verifyImages): signature, timestamp in cert window, issuer + repository + ref. The identity is matched
    with the common `.github/workflows/.*@refs/heads/main` wildcard, and resolved dependencies are not
    inspected. Nothing about model, config, infra, policy or workload identity."""
    d, pol = w.live["image"]["digest"], w.trust["identity"]
    for e in w.envelopes:
        st = attest.decode(e)
        if (st["predicateType"] == BUILD and _subj(st) == d and not attest.check(e, w.trust)
                and _identity_ok(e["cert"]["identity"], pol, pin_workflow=False)):
            return {}
    return {"image": "no SLSA provenance from the expected builder identity"}


def manual_manifest(w: World) -> dict[str, str]:
    """Compare the live assembly with the release manifest a human recorded at deploy time."""
    now = manifest_of(w.live)
    return {k: "differs from the release manifest" for k, v in w.manifest.items() if now[k] != v}


METHODS = {"sbom_only": sbom_only, "signature_only": signature_only, "slsa_only": slsa_only,
           "manual_manifest": manual_manifest, "dpg_no_linking": lambda w: dpg(w, link=False), "dpg": dpg}
