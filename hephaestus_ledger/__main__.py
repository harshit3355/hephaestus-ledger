"""CLI: write a scenario's deployment evidence to disk, verify it, or run the tamper benchmark."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import bench as bench_mod
from .scenarios import BY_ID, build
from .verify import WEIGHTS, dpg, rgs
from .world import World, oci_digest

FILES = ("trust", "attestations", "ledger", "live")


def _dump(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8", newline="\n")


def demo(scenario: str, seed: str, out: Path) -> None:
    w = build(BY_ID[scenario], seed)
    for name, obj in zip(FILES, (w.trust, w.envelopes, w.ledger, w.live)):
        _dump(out / f"{name}.json", obj)
    for rel, data in w.layouts.get(w.live["image"]["digest"], {}).items():
        (out / "oci" / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / "oci" / rel).write_bytes(data)
    print(f"wrote scenario {scenario!r} to {out}")


def verify(src: Path) -> int:
    trust, envelopes, ledger, live = (json.loads((src / f"{n}.json").read_text(encoding="utf-8")) for n in FILES)
    if (src / "oci").is_dir():  # check the image on disk, not only the digest the observer reported
        on_disk = oci_digest(src / "oci")
        if on_disk != live["image"]["digest"]:
            print(f"observer reported sha256:{live['image']['digest']}, image on disk is sha256:{on_disk}")
        live["image"]["digest"] = on_disk
    gaps = dpg(World(trust=trust, keys={}, envelopes=envelopes, ledger=ledger, live=live))
    for c in WEIGHTS:
        print(f"{'GAP ' if c in gaps else 'ok  '} {c:18s} {gaps.get(c, 'reachable from the active release root')}")
    print(f"RGS {rgs(gaps)}/{sum(WEIGHTS.values())}")
    return 1 if gaps else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m hephaestus_ledger", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="write one scenario's trust root, attestations, ledger, live assembly, OCI image")
    d.add_argument("--scenario", default="clean", choices=sorted(BY_ID))
    d.add_argument("--seed", default="7")
    d.add_argument("--out", default="build/demo")
    v = sub.add_parser("verify", help="verify a directory written by `demo`; exit 1 if any component has a gap")
    v.add_argument("dir")
    b = sub.add_parser("bench", help="run every scenario through every method")
    b.add_argument("--seed", default="7")
    b.add_argument("--out", default="reports")
    a = ap.parse_args(argv)

    if a.cmd == "demo":
        demo(a.scenario, a.seed, Path(a.out))
        return 0
    if a.cmd == "verify":
        return verify(Path(a.dir))
    rep = bench_mod.bench(a.seed)
    rep["provenance"] = bench_mod.provenance(seed=a.seed)
    for m, x in rep["summary"].items():
        print(f"{m:16s} breaks {x['breaks_detected']:2d}/{x['breaks']}  benign flagged {x['benign_flagged']}/{x['benign']}"
              f"  negatives {x['negatives_detected']}/{x['negatives']}")
    out = Path(a.out)
    _dump(out / "benchmark.json", rep)
    (out / "benchmark.md").write_text(bench_mod.markdown(rep), encoding="utf-8", newline="\n")
    print(f"wrote {out / 'benchmark.json'} and {out / 'benchmark.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
