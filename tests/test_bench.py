import json

import pytest

from hephaestus_ledger.__main__ import demo, verify
from hephaestus_ledger.bench import bench
from hephaestus_ledger.scenarios import BY_ID, SCENARIOS, build
from hephaestus_ledger.verify import dpg

LINKING_ONLY = {"model_config_from_unapproved_run", "stale_policy_bundle", "wrong_workload_identity",
                "replayed_release_root", "mutable_tag_moved"}


@pytest.fixture(scope="module")
def rep():
    return bench("7")


def test_contract_scenario_counts(rep):
    assert rep["scenarios"] >= 20 and rep["breaks"] >= 15 and rep["negatives"] >= 1


def test_mechanism_localizes_every_break(rep):
    """Fails if the graph linking or any edge check breaks."""
    for r in rep["rows"]:
        if r["kind"] == "break":
            assert r["methods"]["dpg"]["exact"], r["id"]


def test_mechanism_accepts_clean_deployments(rep):
    for r in rep["rows"]:
        if r["kind"] == "benign" and r["id"] != "sbom_regenerated":
            assert not r["methods"]["dpg"]["detected"], r["id"]


def test_ablation_loses_exactly_the_mix_and_match_breaks(rep):
    assert set(rep["linking_only"]) == LINKING_ONLY


def test_documented_blind_spots_stay_blind(rep):
    for r in rep["rows"]:
        if r["kind"] == "negative":
            assert not any(x["detected"] for x in r["methods"].values()), r["id"]


def test_superseded_root_is_not_current_but_reapproval_is():
    assert dpg(build(BY_ID["replayed_release_root"], "7"))
    assert not dpg(build(BY_ID["sanctioned_rollback"], "7"))


def test_results_do_not_depend_on_the_key_seed():
    a, b = bench("7"), bench("other-seed")
    assert [r["methods"]["dpg"]["flagged"] for r in a["rows"]] == [r["methods"]["dpg"]["flagged"] for r in b["rows"]]


def test_cli_verifies_the_image_on_disk(tmp_path):
    demo("clean", "7", tmp_path)
    assert verify(tmp_path) == 0
    d = json.loads((tmp_path / "oci" / "index.json").read_text())["manifests"][0]["digest"].split(":")[1]
    blob = tmp_path / "oci" / "blobs" / "sha256" / d
    blob.write_bytes(blob.read_bytes() + b" ")
    with pytest.raises(ValueError):  # a manifest blob that no longer hashes to its name is rejected outright
        verify(tmp_path)


def test_cli_exit_code_on_a_break(tmp_path):
    demo("stale_policy_bundle", "7", tmp_path)
    assert verify(tmp_path) == 1


def test_every_scenario_has_a_unique_id():
    assert len(BY_ID) == len(SCENARIOS)
