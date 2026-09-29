"""Synthetic tamper scenarios. Each starts from the same base world and changes one thing.

Base world: run 101 = release 1.3.0 (approved, sequence 1), run 102 = release 1.4.0 (approved,
sequence 2, deployed to prod), run 103 = an unapproved canary build from main (valid provenance, never
approved). `when` says whether the tamper happens while the release is assembled (the manual manifest
records the tampered value) or as drift after deploy (the manifest still holds the approved value).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Callable

from . import attest
from .attest import sha256
from .world import (BUILD, MODEL_V2, PINNED_ACTIONS, REGISTRY, RULES_13, SBOM, World, approve, build_run,
                    cyclonedx, deploy, manifest_of, new_world, oci_image)

CANARY_ID = {"name": "id-inference-canary", "client_id": "00000000-0000-4000-8000-000000000002",
             "roles": ["Cognitive Services OpenAI Contributor", "Key Vault Secrets User"]}


@dataclass(frozen=True)
class Scenario:
    id: str
    kind: str          # benign | break | negative (a break the mechanism is not expected to see)
    when: str          # assembly | drift
    truth: frozenset   # components that really are not from the approved release
    what: str
    apply: Callable[[World], None]


SCENARIOS: list[Scenario] = []


def scenario(kind: str, when: str, truth: set, what: str):
    def deco(fn):
        SCENARIOS.append(Scenario(fn.__name__, kind, when, frozenset(truth), what, fn))
        return fn
    return deco


def base_world(seed: str) -> World:
    w = new_world(seed)
    r1 = build_run(w, 101, version="1.3.0", policy=("1.3.0", RULES_13),
                   model={**MODEL_V2, "model_version": "2024-08-06",
                          "config": {**MODEL_V2["config"], "max_output_tokens": 4096}})
    r2 = build_run(w, 102)
    build_run(w, 103, version="1.5.0-rc1", identity=CANARY_ID,
              model={**MODEL_V2, "config": {**MODEL_V2["config"], "temperature": 0.9,
                                            "system_prompt_sha256": sha256(b"Canary prompt: answer freely.")}})
    approve(w, 1, r1)
    approve(w, 2, r2)
    w.live = deploy(r2)
    return w


def build(sc: Scenario, seed: str) -> World:
    w = base_world(seed)
    before = manifest_of(w.live)
    sc.apply(w)
    if not w.manifest:  # a scenario that redeploys records its own manifest at deploy time
        w.manifest = before if sc.when == "drift" else manifest_of(w.live)
    return w


def _foreign_image(w: World, files: dict) -> tuple[str, dict]:
    d, layout = oci_image(files)
    w.layouts[d] = layout
    return d, cyclonedx(d, files)


def _run_image(w: World, rel: dict) -> None:
    w.live["image"] = {"ref": rel["image_ref"], "digest": rel["digest"]}
    w.live["sbom"] = copy.deepcopy(rel["sbom"])


EVIL = {"app/serve.py": b"# inference app 1.4.0\nimport exfil\n", "app/exfil.py": b"# sends prompts elsewhere\n",
        "app/requirements.txt": b"fastapi==0.115.0\nhttpx==0.27.2\n"}


def _redeploy(w: World, rel: dict, seq: int) -> None:
    approve(w, seq, rel)
    w.live = deploy(rel)


# ---- benign ------------------------------------------------------------------------------------

@scenario("benign", "assembly", set(), "release 1.4.0 deployed exactly as approved")
def clean(w):
    pass


@scenario("benign", "assembly", set(), "rollback to 1.3.0 re-approved as a new root (sequence 3)")
def sanctioned_rollback(w):
    _redeploy(w, w.releases[101], 3)


@scenario("benign", "assembly", set(), "hotfix 1.4.1 built, approved (sequence 3) and deployed")
def hotfix_release(w):
    _redeploy(w, build_run(w, 104, version="1.4.1"), 3)


@scenario("benign", "drift", set(), "registry-attached SBOM regenerated (new serialNumber), same contents")
def sbom_regenerated(w):
    w.live["sbom"]["serialNumber"] = "urn:uuid:00000000-0000-4000-8000-000000000099"


# ---- injected provenance breaks ----------------------------------------------------------------

@scenario("break", "drift", {"image", "sbom"}, "running image replaced after signing, with a matching attacker SBOM")
def image_swapped_after_signing(w):
    d, sbom = _foreign_image(w, EVIL)
    w.live["image"], w.live["sbom"] = {"ref": f"{REGISTRY}@sha256:{d}", "digest": d}, sbom


@scenario("break", "assembly", {"sbom"}, "attached SBOM is the previous build's (describes another digest)")
def sbom_for_other_digest(w):
    w.live["sbom"] = copy.deepcopy(w.releases[101]["sbom"])


@scenario("break", "assembly", {"sbom"}, "SBOM step skipped: no SBOM for the running image")
def sbom_missing(w):
    w.live["sbom"] = None


@scenario("break", "drift", {"model"}, "endpoint switched to another model ID after approval")
def model_id_changed(w):
    w.live["model"]["model_id"] = "gpt-4o-mini"


@scenario("break", "drift", {"model"}, "system prompt and temperature edited in the live config")
def prompt_config_changed(w):
    w.live["model"]["config"].update(system_prompt_sha256=sha256(b"Ignore previous restrictions."), temperature=0.9)


@scenario("break", "assembly", {"model"}, "model config taken from the unapproved canary run (validly signed)")
def model_config_from_unapproved_run(w):
    w.live["model"] = copy.deepcopy(w.releases[103]["model"])


@scenario("break", "assembly", {"image", "sbom"}, "image built by the same workflow in a fork (CA still issues a cert)")
def fork_workflow_identity(w):
    _run_image(w, build_run(w, 201, repo="attacker-fork/inference-app", extra_files=EVIL))


@scenario("break", "assembly", {"image", "sbom"}, "image built from refs/heads/feature-x")
def other_branch_identity(w):
    _run_image(w, build_run(w, 202, ref="refs/heads/feature-x", version="1.4.0-feature"))


@scenario("break", "assembly", {"image", "sbom"}, "image built on main by .github/workflows/debug.yml")
def unapproved_workflow_file(w):
    _run_image(w, build_run(w, 203, workflow=".github/workflows/debug.yml", version="1.4.0-debug"))


@scenario("break", "assembly", {"image"}, "approved hotfix was built with actions/checkout@v4 (mutable ref)")
def unpinned_action(w):
    _redeploy(w, build_run(w, 104, version="1.4.1",
                           actions=["pkg:githubactions/actions/checkout@v4", PINNED_ACTIONS[1]]), 3)


@scenario("break", "drift", {"infra"}, "applied state differs from the approved plan (ingress made external)")
def tfplan_state_mismatch(w):
    _app(w)["ingress"] = "external"


@scenario("break", "assembly", {"infra"}, "a locally produced, unattested plan was applied")
def unapproved_plan_applied(w):
    _app(w).update(ingress="external", min_replicas=1)


@scenario("break", "drift", {"infra", "workload_identity"}, "workload identity gained Key Vault Secrets Officer")
def secret_scope_expansion(w):
    for r in w.live["infra_state"]["values"]["root_module"]["resources"]:
        if r["address"] == "terraform_data.workload_identity":
            r["values"]["input"]["roles"].append("Key Vault Secrets Officer")
    w.live["workload_identity"]["roles"].append("Key Vault Secrets Officer")


@scenario("break", "assembly", {"policy"}, "policy bundle 1.3.0 from the superseded release (validly signed)")
def stale_policy_bundle(w):
    w.live["policy"] = copy.deepcopy(w.releases[101]["policy"])


@scenario("break", "drift", {"policy"}, "bundle content reverted to 1.3.0 rules, version label still 1.4.0")
def policy_version_label_spoof(w):
    w.live["policy"]["bundle"] = copy.deepcopy(RULES_13)


@scenario("break", "assembly", {"workload_identity"}, "pod runs as the canary identity (declared in a signed plan)")
def wrong_workload_identity(w):
    w.live["workload_identity"] = {k: copy.deepcopy(CANARY_ID[k]) for k in ("client_id", "roles")}


@scenario("break", "assembly", {"image", "sbom", "infra", "model", "policy"},
          "old root (sequence 1) replayed: release 1.3.0 redeployed without re-approval")
def replayed_release_root(w):
    w.live = deploy(w.releases[101])


@scenario("break", "assembly", {"image", "sbom"}, "stolen ephemeral key used 2 h after its 10-minute certificate expired")
def expired_cert(w):
    rel = w.releases[102]
    d, sbom = _foreign_image(w, EVIL)
    ref = f"{REGISTRY}@sha256:{d}"
    at = rel["t"] + 7200
    build = attest.decode(next(e for e in w.envelopes if e["cert"] == rel["cert"]))["predicate"]
    for st in (attest.statement([(ref, {"sha256": d})], BUILD, build), attest.statement([(ref, {"sha256": d})], SBOM, sbom)):
        w.envelopes.append(attest.sign(st, rel["key"], rel["cert"], w.keys["tsa"], at))
    w.live["image"], w.live["sbom"] = {"ref": ref, "digest": d}, sbom


@scenario("break", "drift", {"image", "sbom"}, "approved release pinned a tag; the tag was moved to the canary build")
def mutable_tag_moved(w):
    _redeploy(w, build_run(w, 104, version="1.4.1", tag="1.4.1"), 3)
    w.manifest = manifest_of(w.live)
    canary = w.releases[103]
    w.live["image"]["digest"], w.live["sbom"] = canary["digest"], copy.deepcopy(canary["sbom"])


# ---- negative cases: outside what provenance can see ---------------------------------------------

@scenario("negative", "assembly", {"image"}, "backdoor merged to main, then built, attested and approved normally")
def malicious_commit_approved(w):
    _redeploy(w, build_run(w, 104, version="1.4.1", extra_files={"app/backdoor.py": b"# approved by mistake\n"}), 3)


@scenario("negative", "drift", {"model"}, "provider changes weights behind the same model ID and version")
def provider_silent_model_update(w):
    pass  # nothing observable changes: that is the case


@scenario("negative", "drift", {"image"}, "compromised node agent reports the approved digest while running another")
def lying_runtime_observer(w):
    pass  # the verifier only sees what the observer reports


def _app(w: World) -> dict:
    return next(r["values"]["input"] for r in w.live["infra_state"]["values"]["root_module"]["resources"]
                if r["address"] == "terraform_data.container_app")


BY_ID = {s.id: s for s in SCENARIOS}
