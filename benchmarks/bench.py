"""Benchmarks E1-E5 (doc 07 Section 2).

Every measurement is repeated --reps times (10 by default) and reported as
mean +/- std. Results go to benchmarks/results.csv and PNGs to
benchmarks/plots/.

    python benchmarks/bench.py                 # everything
    python benchmarks/bench.py --only E1,E5    # a subset
    python benchmarks/bench.py --reps 3 --max-mb 10   # a quick pass

E2-E4 need the ABE runtime (charm-crypto); E1 and E5 run on plain
`cryptography` alone, so they work outside the container too.
"""
import argparse
import csv
import os
import statistics
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto import aes_stream, ecc_wrap  # noqa: E402

PLOTS_DIR = Path(__file__).resolve().parent / "plots"
RESULTS_CSV = Path(__file__).resolve().parent / "results.csv"
ALL_EXPERIMENTS = ("E1", "E2", "E3", "E4", "E5")
ATTRIBUTE_RANGE = range(1, 11)
RECIPIENT_RANGE = (1, 2, 5, 10, 20, 30, 40, 50)
DEFAULT_SIZES_MB = (1, 10, 50, 100)

_rows = []


def record(experiment, x, metric, samples, unit="ms"):
    mean = statistics.mean(samples)
    std = statistics.pstdev(samples) if len(samples) > 1 else 0.0
    _rows.append({
        "experiment": experiment, "x": x, "metric": metric,
        "mean": round(mean, 4), "std": round(std, 4), "unit": unit, "reps": len(samples),
    })
    print("  %-3s %-22s x=%-8s %9.3f +/- %.3f %s" % (experiment, metric, x, mean, std, unit))
    return mean, std


def timed(fn, reps):
    """Returns a list of elapsed milliseconds."""
    out = []
    for _ in range(reps):
        start = time.perf_counter()
        fn()
        out.append((time.perf_counter() - start) * 1000.0)
    return out


def _abe():
    """Imported lazily so E1/E5 run without charm-crypto installed."""
    from crypto import abe_kem
    return abe_kem


def _and_policy(n, version=1):
    return " and ".join("ATTR%d_V%d" % (i, version) for i in range(n))


# ----------------------------------------------------------------- E1

def e1_aes(reps, sizes_mb, workdir):
    """AES-GCM encrypt/decrypt time against file size."""
    print("E1: AES-256-GCM streaming, %s MB" % list(sizes_mb))
    key = os.urandom(aes_stream.KEY_SIZE)
    file_id = uuid.uuid4().bytes
    for mb in sizes_mb:
        plain = workdir / ("e1-%d.bin" % mb)
        cipher = workdir / ("e1-%d.svlt" % mb)
        out = workdir / ("e1-%d.out" % mb)
        with open(plain, "wb") as fh:
            block = os.urandom(1024 * 1024)
            for _ in range(mb):
                fh.write(block)

        enc = timed(lambda: aes_stream.encrypt_file(str(plain), str(cipher), key, file_id), reps)
        dec = timed(lambda: aes_stream.decrypt_file(str(cipher), str(out), key, file_id), reps)
        enc_mean, _ = record("E1", mb, "aes_encrypt", enc)
        dec_mean, _ = record("E1", mb, "aes_decrypt", dec)
        record("E1", mb, "encrypt_throughput_MBps", [mb / (enc_mean / 1000.0)], unit="MB/s")
        record("E1", mb, "decrypt_throughput_MBps", [mb / (dec_mean / 1000.0)], unit="MB/s")
        for p in (plain, cipher, out):
            p.unlink(missing_ok=True)


# ----------------------------------------------------------------- E2

def e2_abe_encap_decap(reps):
    """ABE encap/decap against the number of attributes in the policy."""
    abe_kem = _abe()
    print("E2: ABE encap/decap vs policy size")
    pk, msk = abe_kem.setup()
    file_id = uuid.uuid4().bytes
    for n in ATTRIBUTE_RANGE:
        policy = _and_policy(n)
        attrs = ["ATTR%d_V1" % i for i in range(n)]
        sk = abe_kem.keygen(pk, msk, attrs)
        _, ct = abe_kem.encap(pk, policy, file_id)
        record("E2", n, "abe_encap", timed(lambda: abe_kem.encap(pk, policy, file_id), reps))
        record("E2", n, "abe_decap", timed(lambda: abe_kem.decap(pk, sk, ct, file_id), reps))
        record("E2", n, "ct_key_bytes", [len(ct)], unit="bytes")


# ----------------------------------------------------------------- E3

def e3_abe_keygen(reps):
    """ABE keygen against the number of attributes in the user's key."""
    abe_kem = _abe()
    print("E3: ABE keygen vs user attribute count")
    pk, msk = abe_kem.setup()
    for n in ATTRIBUTE_RANGE:
        attrs = ["ATTR%d_V1" % i for i in range(n)]
        record("E3", n, "abe_keygen", timed(lambda: abe_kem.keygen(pk, msk, attrs), reps))
        record("E3", n, "sk_bytes", [len(abe_kem.serialize_sk(abe_kem.keygen(pk, msk, attrs)))], unit="bytes")


# ----------------------------------------------------------------- E4

def e4_hybrid(reps, sizes_mb, workdir):
    """Hybrid (ABE on 32 bytes + AES on the file) vs the ABE constant alone.

    This is the argument for the hybrid design: ABE cost is a constant that does
    not grow with the file, so total time tracks AES throughput.
    """
    abe_kem = _abe()
    print("E4: hybrid total time vs file size")
    pk, msk = abe_kem.setup()
    policy = _and_policy(2)
    sk = abe_kem.keygen(pk, msk, ["ATTR0_V1", "ATTR1_V1"])

    file_id_const = uuid.uuid4().bytes
    _, ct_const = abe_kem.encap(pk, policy, file_id_const)
    abe_overhead = statistics.mean(
        timed(lambda: abe_kem.encap(pk, policy, file_id_const), reps)
    ) + statistics.mean(
        timed(lambda: abe_kem.decap(pk, sk, ct_const, file_id_const), reps)
    )
    record("E4", 0, "abe_constant_overhead", [abe_overhead])

    for mb in sizes_mb:
        plain = workdir / ("e4-%d.bin" % mb)
        cipher = workdir / ("e4-%d.svlt" % mb)
        out = workdir / ("e4-%d.out" % mb)
        with open(plain, "wb") as fh:
            block = os.urandom(1024 * 1024)
            for _ in range(mb):
                fh.write(block)

        def one_round():
            file_id = uuid.uuid4().bytes
            key, ct = abe_kem.encap(pk, policy, file_id)
            aes_stream.encrypt_file(str(plain), str(cipher), key, file_id)
            recovered = abe_kem.decap(pk, sk, ct, file_id)
            aes_stream.decrypt_file(str(cipher), str(out), recovered, file_id)

        samples = timed(one_round, max(1, reps // 2))
        total, _ = record("E4", mb, "hybrid_round_trip", samples)
        record("E4", mb, "aes_share_of_total_pct", [100.0 * (total - abe_overhead) / total], unit="%")
        for p in (plain, cipher, out):
            p.unlink(missing_ok=True)


# ----------------------------------------------------------------- E5

def e5_ecc_vs_abe(reps, with_abe=True):
    """ECC per-recipient wrapping vs one ABE encap -- the key report graph.

    ECC wrap time and stored metadata grow linearly with the number of
    authorized users; ABE pays one constant cost per file regardless.
    """
    print("E5: ECC wrap vs ABE encap, recipients %s" % list(RECIPIENT_RANGE))
    key = os.urandom(aes_stream.KEY_SIZE)
    file_id = uuid.uuid4().bytes
    publics = [ecc_wrap.generate_keypair()[1] for _ in range(max(RECIPIENT_RANGE))]
    ids = [uuid.uuid4().bytes for _ in range(max(RECIPIENT_RANGE))]

    for n in RECIPIENT_RANGE:
        def wrap_all():
            for i in range(n):
                ecc_wrap.wrap_key(key, publics[i], file_id, ids[i])

        record("E5", n, "ecc_wrap_all_recipients", timed(wrap_all, reps))
        eph, nonce, wrapped = ecc_wrap.wrap_key(key, publics[0], file_id, ids[0])
        record("E5", n, "ecc_metadata_bytes", [n * (len(eph) + len(nonce) + len(wrapped) + 16)], unit="bytes")

    if not with_abe:
        return
    try:
        abe_kem = _abe()
    except ImportError as exc:
        print("  (ABE comparison line skipped: %s)" % exc)
        return
    pk, _msk = abe_kem.setup()
    policy = _and_policy(2)
    abe_samples = timed(lambda: abe_kem.encap(pk, policy, file_id), reps)
    _, ct = abe_kem.encap(pk, policy, file_id)
    for n in RECIPIENT_RANGE:
        record("E5", n, "abe_encap_once", abe_samples)
        record("E5", n, "abe_metadata_bytes", [len(ct)], unit="bytes")


# ----------------------------------------------------------------- plots

def _series(experiment, metric):
    rows = sorted((r for r in _rows if r["experiment"] == experiment and r["metric"] == metric),
                  key=lambda r: r["x"])
    return [r["x"] for r in rows], [r["mean"] for r in rows], [r["std"] for r in rows]


def write_plots():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is not installed; skipping plots (results.csv still written).")
        return

    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    def line_plot(filename, title, xlabel, ylabel, series):
        drawn = False
        fig, ax = plt.subplots(figsize=(7, 4.5))
        for label, (xs, ys, errs) in series:
            if not xs:
                continue
            ax.errorbar(xs, ys, yerr=errs, marker="o", capsize=3, label=label)
            drawn = True
        if not drawn:
            plt.close(fig)
            return
        ax.set_title(title)
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        ax.grid(True, alpha=0.3)
        ax.legend()
        fig.tight_layout()
        fig.savefig(PLOTS_DIR / filename, dpi=140)
        plt.close(fig)
        print("  wrote %s" % (PLOTS_DIR / filename))

    line_plot("e1_aes.png", "E1: AES-256-GCM streaming", "File size (MB)", "Time (ms)", [
        ("encrypt", _series("E1", "aes_encrypt")),
        ("decrypt", _series("E1", "aes_decrypt")),
    ])
    line_plot("e2_abe_policy.png", "E2: ABE encap/decap vs policy size",
              "Attributes in policy", "Time (ms)", [
                  ("encap", _series("E2", "abe_encap")),
                  ("decap", _series("E2", "abe_decap")),
              ])
    line_plot("e3_abe_keygen.png", "E3: ABE keygen vs user attributes",
              "Attributes in key", "Time (ms)", [("keygen", _series("E3", "abe_keygen"))])
    line_plot("e4_hybrid.png", "E4: hybrid round trip vs file size",
              "File size (MB)", "Time (ms)", [("ABE encap+decap + AES", _series("E4", "hybrid_round_trip"))])
    line_plot("e5_ecc_vs_abe_time.png", "E5: sharing cost vs number of recipients",
              "Recipients", "Wrap time (ms)", [
                  ("ECC, one wrap per recipient", _series("E5", "ecc_wrap_all_recipients")),
                  ("ABE, one encap per file", _series("E5", "abe_encap_once")),
              ])
    line_plot("e5_ecc_vs_abe_metadata.png", "E5: stored key metadata vs recipients",
              "Recipients", "Metadata (bytes)", [
                  ("ECC recipient rows", _series("E5", "ecc_metadata_bytes")),
                  ("ABE ct_key", _series("E5", "abe_metadata_bytes")),
              ])


def write_csv():
    with open(RESULTS_CSV, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["experiment", "x", "metric", "mean", "std", "unit", "reps"])
        writer.writeheader()
        writer.writerows(_rows)
    print("  wrote %s (%d rows)" % (RESULTS_CSV, len(_rows)))


def main(argv=None):
    parser = argparse.ArgumentParser(description="SecureVault benchmarks E1-E5")
    parser.add_argument("--only", default=",".join(ALL_EXPERIMENTS),
                        help="comma-separated subset, e.g. E1,E5")
    parser.add_argument("--reps", type=int, default=10, help="repetitions per measurement")
    parser.add_argument("--max-mb", type=int, default=100, help="largest file size for E1/E4")
    parser.add_argument("--no-abe", action="store_true",
                        help="skip everything needing charm-crypto (E2, E3, E4, the ABE line in E5)")
    args = parser.parse_args(argv)

    chosen = [e.strip().upper() for e in args.only.split(",") if e.strip()]
    unknown = [e for e in chosen if e not in ALL_EXPERIMENTS]
    if unknown:
        parser.error("unknown experiment(s): %s" % ", ".join(unknown))
    sizes = tuple(mb for mb in DEFAULT_SIZES_MB if mb <= args.max_mb) or (args.max_mb,)

    def guarded(name, fn):
        """Skip an ABE experiment with a clear message if charm-crypto is absent."""
        try:
            fn()
        except ImportError as exc:
            print("%s skipped: the ABE runtime is not available (%s)." % (name, exc))

    with tempfile.TemporaryDirectory(prefix="securevault-bench-") as tmp:
        workdir = Path(tmp)
        if "E1" in chosen:
            e1_aes(args.reps, sizes, workdir)
        if "E2" in chosen and not args.no_abe:
            guarded("E2", lambda: e2_abe_encap_decap(args.reps))
        if "E3" in chosen and not args.no_abe:
            guarded("E3", lambda: e3_abe_keygen(args.reps))
        if "E4" in chosen and not args.no_abe:
            guarded("E4", lambda: e4_hybrid(args.reps, sizes, workdir))
        if "E5" in chosen:
            e5_ecc_vs_abe(args.reps, with_abe=not args.no_abe)

    write_csv()
    write_plots()
    return 0


if __name__ == "__main__":
    sys.exit(main())
