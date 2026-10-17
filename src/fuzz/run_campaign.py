#!/usr/bin/env python3
"""Run isolated, instrumented codec targets and preserve acceptance evidence."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes(root):
    files = [root / p for p in ["Cargo.toml", "Cargo.lock", "fuzz/Cargo.toml",
                               "fuzz/Cargo.lock", "fuzz/run_campaign.py"]]
    for directory in ["crates", "bins", "config", "fuzz/fuzz_targets", "fuzz/seeds"]:
        files.extend(p for p in (root / directory).rglob("*") if p.is_file())
    return {str(p.relative_to(root)): digest(p) for p in sorted(set(files))}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def version(command, root):
    return subprocess.check_output(command, cwd=root, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=1800)
    parser.add_argument("--seed", type=int, default=20261017)
    parser.add_argument("--results", default="fuzz/results/campaign-" +
                        datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    args = parser.parse_args()
    if args.seconds < 1:
        parser.error("--seconds must be positive")
    root = Path(__file__).resolve().parent.parent
    results = (root / args.results).resolve()
    if root not in results.parents or results.exists():
        parser.error("--results must be a new directory inside the workspace")
    results.mkdir(parents=True)
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
    env["LSAN_OPTIONS"] = "exitcode=23"
    options = ["-max_len=65536", "-timeout=10", "-rss_limit_mb=512",
               f"-seed={args.seed}", "-detect_leaks=1", "-print_final_stats=1"]
    targets = ["message", "sa", "structured"]
    before = source_hashes(root)
    metadata = {
        "started_utc": utc_now(), "workspace": str(root), "host": platform.platform(),
        "os_release": Path("/etc/os-release").read_text(),
        "stable": version(["rustc", "--version"], root),
        "nightly": version(["rustc", "+nightly", "--version"], root),
        "cargo": version(["cargo", "--version"], root),
        "cargo_fuzz": version(["cargo", "fuzz", "--version"], root),
        "sanitizer": "address with integrated LeakSanitizer enabled",
        "sanitizer_environment": {key: env[key] for key in ["ASAN_OPTIONS", "LSAN_OPTIONS"]},
        "source_sha256_before": before, "preflight": [],
        "initial_corpus": {},
    }
    for target in targets:
        corpus = root / "fuzz/corpus" / target
        corpus.mkdir(parents=True, exist_ok=True)
        for seed in (root / "fuzz/seeds" / target).iterdir():
            destination = corpus / seed.name
            if not destination.exists():
                destination.write_bytes(seed.read_bytes())
        metadata["initial_corpus"][target] = {p.name: digest(p) for p in sorted(corpus.iterdir()) if p.is_file()}
    save(results / "environment.json", metadata)
    for target in targets:
        command = ["cargo", "+nightly", "fuzz", "run", "--sanitizer", "address", target,
                   "--", "-runs=1", *options]
        with (results / f"{target}-preflight.log").open("w") as log:
            status = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
        metadata["preflight"].append({"target": target, "command": command, "exit_status": status})
        save(results / "environment.json", metadata)
        if status != 0:
            print(f"{target}: sanitizer preflight failed ({status}); campaign not started", flush=True)
            return 1
    metadata["binary_sha256"] = {
        target: digest(root / "fuzz/target/x86_64-unknown-linux-gnu/release" / target)
        for target in targets
    }
    save(results / "environment.json", metadata)
    runs = []
    try:
        for target in targets:
            artifacts = results / f"{target}-artifacts"
            artifacts.mkdir()
            command = ["cargo", "+nightly", "fuzz", "run", "--sanitizer", "address", target,
                       "--", f"-max_total_time={args.seconds}",
                       f"-artifact_prefix={artifacts}/", *options]
            log = results / f"{target}.log"
            stream = log.open("w")
            started = time.monotonic()
            process = subprocess.Popen(command, cwd=root, env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            runs.append({"target": target, "command": command, "process": process,
                         "stream": stream, "started": started, "started_utc": utc_now(),
                         "log": str(log.relative_to(root))})
        while any(run["process"].poll() is None for run in runs):
            for run in runs:
                if run["process"].poll() is not None and "ended_utc" not in run:
                    run["ended_utc"] = utc_now()
                    run["wall_seconds"] = round(time.monotonic() - run["started"], 3)
            time.sleep(1)
    finally:
        report = []
        for run in runs:
            process = run["process"]
            if process.poll() is None:
                # Stop the process group, including the instrumented child.
                import signal
                os.killpg(process.pid, signal.SIGTERM)
            status = process.wait()
            run["stream"].close()
            text = (root / run["log"]).read_text()
            duration = re.search(r"Done \d+ runs in (\d+) second", text)
            statistics = {key: int(value) for key, value in
                          re.findall(r"stat::([a-z_]+):\s*(\d+)", text)}
            diagnostics = [line for line in text.splitlines() if any(token in line for token in
                           ["ERROR:", "SUMMARY:", "fatal error", "panicked at", "runtime error:"])]
            entry = {key: run[key] for key in ["target", "command", "started_utc", "log"]}
            entry.update({"ended_utc": run.get("ended_utc", utc_now()),
                          "wall_seconds": run.get("wall_seconds", round(time.monotonic() - run["started"], 3)),
                          "exit_status": status, "completed_fuzz_seconds": int(duration[1]) if duration else None,
                          "statistics": statistics, "sanitizer_diagnostics": diagnostics,
                          "log_sha256": digest(root / run["log"]),
                          "passed": status == 0 and duration is not None and int(duration[1]) >= args.seconds
                                    and not diagnostics})
            report.append(entry)
        after = source_hashes(root)
        metadata["source_sha256_after"] = after
        metadata["sources_unchanged"] = before == after
        metadata["ended_utc"] = utc_now()
        save(results / "environment.json", metadata)
        save(results / "campaign.json", report)
        print(json.dumps(report, indent=2), flush=True)
    return 0 if len(report) == 3 and all(run["passed"] for run in report) and before == after else 1


if __name__ == "__main__":
    raise SystemExit(main())
