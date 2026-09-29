"""Synthetic deployment world: CI runs that build and attest artifacts, signed release roots, and the
live assembly a runtime observer reports. Everything is deterministic and local.

- Images are real OCI image layouts (index, manifest, config, one tar layer) built in memory.
- SBOMs are CycloneDX 1.5 JSON generated here from the image's files (not produced by syft).
- Terraform plan/state use the JSON shapes of real Terraform output (fixtures/terraform), with
  per-release `input` values substituted.
- Model manifests, policy bundles and workload identities are synthetic.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from . import attest
from .attest import digest, sha256

ROOT = Path(__file__).resolve().parent.parent
TF_DIR = ROOT / "fixtures" / "terraform"

ISSUER = "https://token.actions.githubusercontent.com"
REPO = "example-org/inference-app"
WORKFLOW = ".github/workflows/release.yml"
MAIN = "refs/heads/main"
REGISTRY = "registry.example.test/inference"
T0 = 1_780_000_000  # fixed clock: every run, certificate and timestamp is relative to it

BUILD = "https://slsa.dev/provenance/v1"
SBOM = "https://cyclonedx.org/bom"
PLAN = "https://hephaestus-ledger.example/terraform-plan/v0.1"
MODEL = "https://hephaestus-ledger.example/model-config/v0.1"
POLICY = "https://hephaestus-ledger.example/policy-bundle/v0.1"
APPROVAL = "https://hephaestus-ledger.example/release-approval/v0.1"
APPROVER = {"issuer": "https://approvals.example.test", "subject": "release-board@example.test"}

PINNED_ACTIONS = ["pkg:githubactions/actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                  "pkg:githubactions/actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"]
PROD_ID = {"name": "id-inference-prod", "client_id": "00000000-0000-4000-8000-000000000001",
           "roles": ["Cognitive Services OpenAI User"]}
PROMPT_V2 = "You are a support assistant. Answer only from the provided documents."
MODEL_V2 = {"provider": "azure-openai", "endpoint": "https://inference.example.test/", "model_id": "gpt-4o",
            "model_version": "2024-11-20",
            "config": {"system_prompt_sha256": sha256(PROMPT_V2.encode()), "temperature": 0.2, "max_output_tokens": 1024}}
RULES_13 = {"deny_public_ingress": True, "max_output_tokens": 4096, "blocked_tools": ["shell"]}
RULES_14 = {"deny_public_ingress": True, "max_output_tokens": 2048, "blocked_tools": ["http_fetch", "shell"],
            "pii_redaction": True}
DEPLOY_KEYS = ("provider", "endpoint", "model_id", "model_version")


def oci_image(files: dict[str, bytes]) -> tuple[str, dict[str, bytes]]:
    """Deterministic OCI image layout. Returns (manifest digest, {layout path: bytes})."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(files):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(files[name]), 0, 0o644
            tar.addfile(info, io.BytesIO(files[name]))
    layer = buf.getvalue()
    config = attest.canon({"architecture": "amd64", "os": "linux", "config": {"Entrypoint": ["python", "app/serve.py"]},
                           "rootfs": {"type": "layers", "diff_ids": ["sha256:" + sha256(layer)]}})
    manifest = attest.canon({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + sha256(config),
                   "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:" + sha256(layer),
                    "size": len(layer)}]})
    d = sha256(manifest)
    index = attest.canon({"schemaVersion": 2, "manifests": [
        {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + d, "size": len(manifest)}]})
    return d, {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}', "index.json": index,
               **{f"blobs/sha256/{sha256(b)}": b for b in (layer, config, manifest)}}


def oci_digest(layout: Path) -> str:
    """Manifest digest of an on-disk OCI layout, after checking the blob hashes to it."""
    d = json.loads((layout / "index.json").read_text())["manifests"][0]["digest"].split(":", 1)[1]
    if sha256((layout / "blobs" / "sha256" / d).read_bytes()) != d:
        raise ValueError(f"{layout}: manifest blob does not hash to {d}")
    return d


def cyclonedx(image_digest: str, files: dict[str, bytes], serial: str = "1") -> dict:
    reqs = files.get("app/requirements.txt", b"").decode().split()
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "serialNumber": f"urn:uuid:00000000-0000-4000-8000-{int(serial):012d}",
            "metadata": {"component": {"type": "container", "name": REGISTRY,
                                       "hashes": [{"alg": "SHA-256", "content": image_digest}]}},
            "components": [{"type": "library", "name": r.split("==")[0], "version": r.split("==")[1],
                            "purl": f"pkg:pypi/{r.split('==')[0]}@{r.split('==')[1]}"} for r in reqs]
                          + [{"type": "file", "name": n, "hashes": [{"alg": "SHA-256", "content": sha256(files[n])}]}
                             for n in sorted(files)]}


def sbom_subject(sbom: dict) -> str:
    return sbom["metadata"]["component"]["hashes"][0]["content"]


def _fixture(name: str) -> dict:
    return json.loads((TF_DIR / name).read_text(encoding="utf-8"))


def tf_plan(image_ref: str, identity: dict, model: dict, ingress: str = "internal", min_replicas: int = 2) -> dict:
    inputs = {"terraform_data.workload_identity": dict(identity),
              "terraform_data.container_app": {"image": image_ref, "identity_client_id": identity["client_id"],
                                               "ingress": ingress, "min_replicas": min_replicas},
              "terraform_data.model_deployment": {k: model[k] for k in DEPLOY_KEYS}}
    plan = _fixture("plan.json")
    plan["variables"]["image"]["value"] = image_ref
    for r in plan["planned_values"]["root_module"]["resources"]:
        r["values"]["input"] = copy.deepcopy(inputs[r["address"]])
    for rc in plan["resource_changes"]:
        rc["change"]["after"]["input"] = copy.deepcopy(inputs[rc["address"]])
    return plan


def tf_state(plan: dict) -> dict:
    state, inputs = _fixture("state.json"), tf_inputs(plan)
    for r in state["values"]["root_module"]["resources"]:
        r["values"]["input"] = copy.deepcopy(inputs[r["address"]])
        r["values"]["output"] = copy.deepcopy(inputs[r["address"]])
    return state


def tf_inputs(doc: dict) -> dict:
    """{address: input} from a plan (planned_values) or a state (values) document."""
    mod = (doc.get("planned_values") or doc["values"])["root_module"]
    return {r["address"]: r["values"]["input"] for r in mod["resources"]}


@dataclass
class World:
    trust: dict
    keys: dict                                         # generator-only: CA / TSA / approver private keys
    envelopes: list = field(default_factory=list)      # every attestation the verifier can fetch
    ledger: list = field(default_factory=list)         # signed release roots (append-only)
    live: dict = field(default_factory=dict)           # what the runtime observer reports
    manifest: dict = field(default_factory=dict)       # manual release manifest (baseline input only)
    releases: dict = field(default_factory=dict)       # generator bookkeeping; verifiers never read it
    layouts: dict = field(default_factory=dict)        # image digest -> OCI layout files (for `demo`)


def new_world(seed: str) -> World:
    k = {n: attest.derive_key(n, seed) for n in ("ca", "tsa", "approver")}
    trust = {"ca": attest.pub(k["ca"]), "tsa": attest.pub(k["tsa"]), "approvers": [APPROVER],
             "identity": {"issuer": ISSUER, "repository": REPO, "workflow": WORKFLOW, "ref": MAIN,
                          "events": ["push", "workflow_dispatch"]}}
    return World(trust=trust, keys={**k, "seed": seed})


def build_run(w: World, run_id: int, *, version: str = "1.4.0", repo: str = REPO, ref: str = MAIN,
              workflow: str = WORKFLOW, model: dict = MODEL_V2, policy: tuple = ("1.4.0", RULES_14),
              identity: dict = PROD_ID, tag: str | None = None, actions: list = PINNED_ACTIONS,
              extra_files: dict | None = None) -> dict:
    """One CI run: build the image, generate SBOM/plan, attest all of it with the run's OIDC identity."""
    t = T0 + 3600 * (run_id - 100)
    commit = hashlib.sha1(f"{repo}@{run_id}".encode()).hexdigest()
    files = {"app/serve.py": f"# inference app {version}\n".encode(),
             "app/requirements.txt": b"fastapi==0.115.0\nhttpx==0.27.2\n", **(extra_files or {})}
    d, layout = oci_image(files)
    w.layouts[d] = layout
    image_ref = f"{REGISTRY}:{tag}" if tag else f"{REGISTRY}@sha256:{d}"
    sbom = cyclonedx(d, files)
    plan = tf_plan(image_ref, identity, model)
    pol = {"version": policy[0], "bundle": policy[1]}
    idn = {"issuer": ISSUER, "repository": repo, "job_workflow_ref": f"{repo}/{workflow}@{ref}", "ref": ref,
           "sha": commit, "run_id": str(run_id), "event_name": "push"}
    key = attest.derive_key(f"run-{run_id}-{repo}", w.keys["seed"])
    cert = attest.issue_cert(w.keys["ca"], key, idn, t, t + 600)  # Fulcio-style 10 minute certificate
    build = {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1",
                                 "externalParameters": {"workflow": {"repository": repo, "path": workflow, "ref": ref}},
                                 "resolvedDependencies": [{"uri": f"git+https://github.com/{repo}@{ref}",
                                                           "digest": {"gitCommit": commit}}]
                                 + [{"uri": a} for a in actions]},
             "runDetails": {"builder": {"id": f"https://github.com/{repo}/{workflow}@{ref}"},
                            "metadata": {"invocationId": str(run_id)}}}
    stmts = [attest.statement([(image_ref, {"sha256": d})], BUILD, build),
             attest.statement([(image_ref, {"sha256": d})], SBOM, sbom),
             attest.statement([("plan.json", {"sha256": digest(plan)})], PLAN, {"plan": plan}),
             attest.statement([("model-manifest", {"sha256": digest(model)})], MODEL, {"manifest": model}),
             attest.statement([("policy-bundle", {"sha256": digest(pol["bundle"])})], POLICY, {"version": pol["version"]})]
    w.envelopes += [attest.sign(s, key, cert, w.keys["tsa"], t + 60) for s in stmts]
    rel = {"run_id": run_id, "commit": commit, "digest": d, "image_ref": image_ref,
           "sbom": sbom, "plan": plan, "state": tf_state(plan), "model": model, "policy": pol, "identity": identity,
           "key": key, "cert": cert, "t": t}
    w.releases[run_id] = rel
    return rel


def approve(w: World, sequence: int, rel: dict, environment: str = "prod") -> None:
    """The release root: an approver signs (environment, sequence, run, commit)."""
    t = rel["t"] + 1800
    cert = attest.issue_cert(w.keys["ca"], w.keys["approver"], APPROVER, T0 - 86400, T0 + 365 * 86400)
    stmt = attest.statement([(f"git+https://github.com/{REPO}", {"gitCommit": rel["commit"]})], APPROVAL,
                            {"environment": environment, "sequence": sequence, "run_id": str(rel["run_id"])})
    w.ledger.append(attest.sign(stmt, w.keys["approver"], cert, w.keys["tsa"], t))


def deploy(rel: dict, environment: str = "prod") -> dict:
    """The live assembly as a runtime observer (node agent / cloud API) would report it."""
    return {"environment": environment,
            "image": {"ref": rel["image_ref"], "digest": rel["digest"]},
            "sbom": copy.deepcopy(rel["sbom"]),
            "infra_state": copy.deepcopy(rel["state"]),
            "model": copy.deepcopy(rel["model"]),
            "policy": copy.deepcopy(rel["policy"]),
            "workload_identity": {"client_id": rel["identity"]["client_id"], "roles": list(rel["identity"]["roles"])}}


def manifest_of(live: dict) -> dict:
    """What a release engineer writes down: image reference, model + config hash, infra hash,
    policy version label, workload identity. No signatures, no SBOM."""
    m = live["model"]
    return {"image": live["image"]["ref"],
            "model": {"model_id": m["model_id"], "model_version": m["model_version"], "config_sha256": digest(m["config"])},
            "infra": digest(tf_inputs(live["infra_state"])),
            "policy": live["policy"]["version"],
            "workload_identity": live["workload_identity"]["client_id"]}
