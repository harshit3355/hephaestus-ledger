"""Tamper benchmark: which verification method notices that the live AI deployment is not the approved one?"""
from __future__ import annotations

import datetime
import hashlib
import json
import platform
import subprocess
import sys
from importlib.metadata import version

from .scenarios import SCENARIOS, build
from .verify import METHODS, WEIGHTS, rgs
from .world import ROOT, TF_DIR

LABELS = {"sbom_only": "Container SBOM only (baseline)",
          "signature_only": "Image signature only (baseline)",
          "slsa_only": "SLSA provenance, no AI config/model binding (baseline)",
          "manual_manifest": "Manual release manifest (baseline)",
          "dpg_no_linking": "DPG without graph linking (ablation)",
          "dpg": "**Deployment Provenance Graph (mechanism)**"}


def provenance(**extra) -> dict:
    def git(*args):
        r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    sha = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain", "--", "hephaestus_ledger", "fixtures"))
    fx = hashlib.sha256()
    for p in sorted(TF_DIR.iterdir()):
        fx.update(p.name.encode() + p.read_bytes().replace(b"\r\n", b"\n"))
    return {"commit": (sha or "unknown") + ("-dirty" if dirty else ""),
            "command": "python -m hephaestus_ledger " + " ".join(sys.argv[1:]),
            "python": platform.python_version(), "platform": platform.platform(),
            "cryptography": version("cryptography"),
            "terraform_fixture": json.loads((TF_DIR / "plan.json").read_text())["terraform_version"],
            "fixtures_sha256": fx.hexdigest()[:16],
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            **extra}


def bench(seed: str) -> dict:
    rows = []
    for sc in SCENARIOS:
        w = build(sc, seed)
        res = {}
        for m, fn in METHODS.items():
            gaps = fn(w)
            res[m] = {"flagged": sorted(gaps), "rgs": rgs(gaps), "detected": bool(gaps),
                      "exact": set(gaps) == sc.truth, "reasons": gaps}
        rows.append({"id": sc.id, "kind": sc.kind, "when": sc.when, "what": sc.what, "truth": sorted(sc.truth),
                     "true_rgs": rgs(dict.fromkeys(sc.truth)), "methods": res})
    kinds = {k: [r for r in rows if r["kind"] == k] for k in ("break", "benign", "negative")}
    summary = {}
    for m in METHODS:
        br = kinds["break"]
        det = sum(r["methods"][m]["detected"] for r in br)
        summary[m] = {"breaks_detected": det, "breaks": len(br), "rate": round(det / len(br), 4),
                      "exact_localization": sum(r["methods"][m]["exact"] for r in br),
                      "mean_rgs_on_breaks": round(sum(r["methods"][m]["rgs"] for r in br) / len(br), 2),
                      "benign_flagged": sum(r["methods"][m]["detected"] for r in kinds["benign"]),
                      "benign": len(kinds["benign"]),
                      "negatives_detected": sum(r["methods"][m]["detected"] for r in kinds["negative"]),
                      "negatives": len(kinds["negative"]),
                      "missed_breaks": [r["id"] for r in br if not r["methods"][m]["detected"]]}
    return {"seed": seed, "scenarios": len(rows), "breaks": len(kinds["break"]), "benign": len(kinds["benign"]),
            "negatives": len(kinds["negative"]), "weights": WEIGHTS, "max_rgs": sum(WEIGHTS.values()),
            "mean_true_rgs_on_breaks": round(sum(r["true_rgs"] for r in kinds["break"]) / len(kinds["break"]), 2),
            "summary": summary,
            "linking_only": [r["id"] for r in kinds["break"]
                             if r["methods"]["dpg"]["detected"] and not r["methods"]["dpg_no_linking"]["detected"]],
            "rows": rows}


def _cell(r: dict, m: str) -> str:
    x = r["methods"][m]
    if r["kind"] == "benign":
        return "flag" if x["detected"] else "ok"
    return (str(x["rgs"]) if m.startswith("dpg") else "yes") if x["detected"] else "miss"


def markdown(rep: dict) -> str:
    s, ms = rep["summary"], list(METHODS)
    L = ["# HEPHAESTUS LEDGER benchmark: is the live AI deployment the approved one?", "",
         "_Synthetic scenarios, local test keys (a test CA stands in for Fulcio, a test timestamp authority for "
         "Rekor). Every number below was produced by the command in the provenance section._", "",
         f"- {rep['scenarios']} scenarios: {rep['breaks']} injected provenance breaks, {rep['benign']} benign "
         f"deployments, {rep['negatives']} negative cases that provenance cannot see by design.",
         f"- Live components and RGS weights: " + ", ".join(f"{k} {v}" for k, v in rep["weights"].items())
         + f" (max RGS {rep['max_rgs']}). Mean true RGS over the breaks: {rep['mean_true_rgs_on_breaks']}.",
         "- The mechanism's detection of the injected breaks is **true by construction**: every break violates an "
         "edge the verifier checks, and both were written by the same author. What is measured is what each "
         "baseline and the ablation miss, the benign flags and the negative cases.", "",
         "## Results", "",
         "| Method | Breaks detected | Rate | Exact component localization | Mean RGS on breaks | Benign flagged | Negatives detected |",
         "|---|---|---|---|---|---|---|"]
    for m in ms:
        x = s[m]
        L.append(f"| {LABELS[m]} | {x['breaks_detected']}/{x['breaks']} | {100 * x['rate']:.1f}% | "
                 f"{x['exact_localization']}/{x['breaks']} | {x['mean_rgs_on_breaks']} | "
                 f"{x['benign_flagged']}/{x['benign']} | {x['negatives_detected']}/{x['negatives']} |")
    L += ["", "A baseline reports only the components it inspects and implicitly accepts the rest, so its RGS "
              "counts only what it looked at. Exact localization = the flagged component set equals the true tampered set.", "",
          "## Ablation: what graph linking adds", "",
          "Breaks the full DPG detects and the no-linking ablation (every claim valid on its own, no release root, "
          "no cross-edges) misses:", "", *(f"- `{i}`" for i in rep["linking_only"]), "",
          "Each is assembled from validly signed parts that belong to a different release or run.", "",
          "## Per scenario", "",
          "Cells: `yes`/`miss` for breaks and negatives, `ok`/`flag` for benign runs; DPG columns show the RGS.", "",
          "| Scenario | Kind | When | Truth | " + " | ".join(m.replace("_", " ") for m in ms) + " |",
          "|---|---|---|---|" + "---|" * len(ms)]
    for r in rep["rows"]:
        L.append(f"| `{r['id']}` | {r['kind']} | {r['when']} | {', '.join(r['truth']) or '-'} | "
                 + " | ".join(_cell(r, m) for m in ms) + " |")
    L += ["", "## Scenario descriptions and the mechanism's reasons", ""]
    for r in rep["rows"]:
        reasons = "; ".join(f"{k}: {v}" for k, v in r["methods"]["dpg"]["reasons"].items()) or "no gap"
        L.append(f"- `{r['id']}`: {r['what']}. DPG: {reasons}.")
    fp = [r["id"] for r in rep["rows"] if r["kind"] == "benign" and r["methods"]["dpg"]["detected"]]
    blind = [r["id"] for r in rep["rows"] if r["kind"] == "negative" and not r["methods"]["dpg"]["detected"]]
    L += ["", "## Negative results", "",
          f"- Benign scenarios the DPG flags: {', '.join(f'`{i}`' for i in fp) or 'none'}. An SBOM attached to the "
          "image that is not byte-identical to the attested one cannot be proven, so non-reproducible SBOM "
          "tooling produces operational false positives.",
          f"- Negative cases the DPG misses: {', '.join(f'`{i}`' for i in blind) or 'none'}. Provenance proves where "
          "a component came from, not that the approved source was benign, that a provider kept the weights "
          "behind a model ID, or that the runtime observer reports the truth.", "",
          "## Provenance", "", *(f"- {k}: `{v}`" for k, v in rep["provenance"].items()), ""]
    return "\n".join(L)
