import base64
import copy
import json

from hephaestus_ledger import attest
from hephaestus_ledger.world import T0, TF_DIR, cyclonedx, oci_image, tf_inputs, tf_plan, tf_state, MODEL_V2, PROD_ID

SEED = "unit"
CA, TSA, KEY = (attest.derive_key(n, SEED) for n in ("ca", "tsa", "k"))
TRUST = {"ca": attest.pub(CA), "tsa": attest.pub(TSA)}


def _env(at=T0 + 60):
    cert = attest.issue_cert(CA, KEY, {"repository": "r"}, T0, T0 + 600)
    return attest.sign(attest.statement([("x", {"sha256": "ab"})], "t", {"p": 1}), KEY, cert, TSA, at)


def test_valid_envelope_verifies():
    assert attest.check(_env(), TRUST) is None


def test_tampered_payload_fails():
    env = _env()
    st = json.loads(base64.b64decode(env["payload"]))
    st["subject"][0]["digest"]["sha256"] = "cd"
    env["payload"] = base64.b64encode(attest.canon(st)).decode()
    assert attest.check(env, TRUST) == "signature does not verify"


def test_cert_from_another_ca_fails():
    env = _env()
    env["cert"] = attest.issue_cert(attest.derive_key("rogue", SEED), KEY, {"repository": "r"}, T0, T0 + 600)
    assert attest.check(env, TRUST) == "certificate not issued by the trusted CA"


def test_signature_after_cert_expiry_fails_but_passes_signature_only():
    env = _env(at=T0 + 3600)
    assert attest.check(env, TRUST) == "signed outside the certificate's validity window"
    assert attest.check(env, TRUST, timestamp=False) is None


def test_editing_the_timestamp_breaks_the_tsa_signature():
    env = copy.deepcopy(_env(at=T0 + 3600))
    env["tlog"]["integrated_time"] = T0 + 60
    assert attest.check(env, TRUST) == "no valid timestamp for this payload"


def test_oci_image_is_reproducible_and_content_addressed():
    files = {"app/serve.py": b"print(1)\n"}
    assert oci_image(files)[0] == oci_image(dict(files))[0]
    assert oci_image(files)[0] != oci_image({"app/serve.py": b"print(2)\n"})[0]
    assert cyclonedx(oci_image(files)[0], files)["metadata"]["component"]["hashes"][0]["content"] == oci_image(files)[0]


def test_terraform_fixture_is_real_output_and_state_follows_plan():
    plan = json.loads((TF_DIR / "plan.json").read_text())
    assert plan["terraform_version"] and plan["resource_changes"][0]["change"]["actions"] == ["create"]
    p = tf_plan("registry.example.test/inference@sha256:" + "1" * 64, PROD_ID, MODEL_V2)
    assert tf_inputs(tf_state(p)) == tf_inputs(p)
    assert tf_inputs(p)["terraform_data.workload_identity"]["client_id"] == PROD_ID["client_id"]
