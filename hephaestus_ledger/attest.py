"""Signing primitives: canonical JSON, in-toto Statements in DSSE envelopes, a local test CA standing
in for Sigstore Fulcio (short-lived certificates bound to OIDC identity claims) and a local test
timestamp authority standing in for the Rekor transparency log's integrated time.

Every private key is derived from a public seed string. They are TEST-ONLY keys: anyone can
recompute them, which is the point (reproducible fixtures) and why they must never sign anything real.
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PAYLOAD_TYPE = "application/vnd.in-toto+json"


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def digest(obj) -> str:
    return sha256(canon(obj))


def derive_key(name: str, seed: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"TEST-ONLY|{seed}|{name}".encode()).digest())


def pub(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _ok(pub_hex: str, sig_hex: str, msg: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def statement(subjects: list[tuple[str, dict]], predicate_type: str, predicate: dict) -> dict:
    return {"_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": n, "digest": d} for n, d in subjects],
            "predicateType": predicate_type, "predicate": predicate}


def issue_cert(ca: Ed25519PrivateKey, key: Ed25519PrivateKey, identity: dict, not_before: int, not_after: int) -> dict:
    body = {"public_key": pub(key), "identity": identity, "not_before": not_before, "not_after": not_after}
    return {**body, "ca_sig": ca.sign(canon(body)).hex()}


def sign(stmt: dict, key: Ed25519PrivateKey, cert: dict, tsa: Ed25519PrivateKey, at: int) -> dict:
    payload = canon(stmt)
    entry = {"payload_sha256": sha256(payload), "integrated_time": at}
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"sig": key.sign(pae(PAYLOAD_TYPE, payload)).hex()}],
            "cert": cert, "tlog": {**entry, "sig": tsa.sign(canon(entry)).hex()}}


def decode(env: dict) -> dict:
    return json.loads(base64.b64decode(env["payload"]))


def check(env: dict, trust: dict, timestamp: bool = True) -> str | None:
    """Why the envelope does not verify, or None. `timestamp=False` is a signature-only check."""
    cert = env["cert"]
    body = {k: cert[k] for k in ("public_key", "identity", "not_before", "not_after")}
    if not _ok(trust["ca"], cert["ca_sig"], canon(body)):
        return "certificate not issued by the trusted CA"
    payload = base64.b64decode(env["payload"])
    if not _ok(cert["public_key"], env["signatures"][0]["sig"], pae(env["payloadType"], payload)):
        return "signature does not verify"
    if not timestamp:
        return None
    t = env["tlog"]
    entry = {"payload_sha256": t["payload_sha256"], "integrated_time": t["integrated_time"]}
    if t["payload_sha256"] != sha256(payload) or not _ok(trust["tsa"], t["sig"], canon(entry)):
        return "no valid timestamp for this payload"
    if not cert["not_before"] <= t["integrated_time"] <= cert["not_after"]:
        return "signed outside the certificate's validity window"
    return None
