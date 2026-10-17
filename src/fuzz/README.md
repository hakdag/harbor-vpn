# IKEv2 codec fuzzing

The runner explicitly enables AddressSanitizer and leak detection, with no changes to host tracing settings. It first verifies sanitizer exit checks in one-run preflights and refuses a long campaign if a preflight fails. Run it in an environment permitting LeakSanitizer tracing.

The application and ordinary tests use stable Rust. These isolated libFuzzer targets use nightly and AddressSanitizer through cargo-fuzz; they perform no network or protocol actions.

Run the following commands from the repository’s `src/` directory.

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cargo +nightly fuzz build
python3 fuzz/run_campaign.py --seconds 1800 --seed 20261017 --results fuzz/results/NEW-CAMPAIGN
```

The runner executes three independent fuzz processes concurrently for 30 minutes each, retains stdout/stderr in the new results directory, and records commands, per-process timestamps, exit status, statistics, sanitizer diagnostics and log hashes in `campaign.json`. `environment.json` records toolchains, explicit sanitizer settings, source hashes before/after, binary hashes, initial corpus hashes and clean sanitizer preflights. Existing results directories are never overwritten. The default is a timestamped directory. Each target has a 65,536-byte input cap (one byte above the codec hard ceiling), 10-second per-input timeout and 512 MiB RSS limit. A nonzero exit must be investigated, not counted as a successful campaign. Long runs can vary even with a fixed seed because scheduling and time limits vary.

Targets:

- `message`: raw and typed complete-message decoding, support checks, bounded serialize/reparse and deterministic re-encoding. Also patches the outer length in a copy to reach deeper structural parsing after mutation.
- `sa`: standalone SA structures, nested lengths/counts/markers/attributes, and serialize/reparse when the body fits a full message.
- `structured`: typed payload construction from fuzz bytes, including valid and invalid models, variable resource policy and encode/decode/encode invariants.

Checked-in `seeds/` are synthetic independent fixtures and malformed examples, without credentials or live traffic. `corpus/` holds the mutable coverage corpus. Cargo-fuzz creates missing corpus directories automatically; copy seeds when starting clean:

```sh
mkdir -p fuzz/corpus/message fuzz/corpus/sa fuzz/corpus/structured
cp fuzz/seeds/message/* fuzz/corpus/message/
cp fuzz/seeds/sa/* fuzz/corpus/sa/
cp fuzz/seeds/structured/* fuzz/corpus/structured/
```

For a bounded pull-request smoke run use `python3 fuzz/run_campaign.py --seconds 60 --results fuzz/results/smoke`. For a scheduled longer run use the default 1800 seconds. No CI provider integration has been configured in this repository; these are locally executable commands.

Minimize a failure with `cargo +nightly fuzz tmin TARGET PATH_TO_ARTIFACT`, retain a synthetic/sanitized reproducer under tests or seeds, add a deterministic regression test, fix it and rerun the affected target. For timeout/OOM findings inspect whether the resource policy or harness is responsible. LibFuzzer logs contain synthetic input dictionary bytes; never seed real credential-bearing traffic.

Mutable corpus, build outputs, crash artifacts and logs are ignored by Git. The small seed set, lockfile, campaign summaries and report are reviewable source artifacts. Preserve local logs for evidence; they are not proof of complete RFC correctness or native-client interoperability.

## Restricted tracing environments

The recorded 30-minute runs completed their fuzz loops but then exited 1 because LeakSanitizer could not trace threads in the sandbox. Their zero-byte artifacts are exit-time tooling artifacts, not discovered malformed-packet reproducers. Preserve these logs and exit statuses; do not call the long campaign a clean sanitizer pass. The same empty artifacts replay successfully outside the sandbox with leak detection enabled, and separate one-minute outside-sandbox verification runs are recorded alongside the long-run evidence. No sanitizer was disabled and no host tracing/sysctl setting was changed. For a fully clean long-run acceptance gate, run the documented 1800-second campaign in an environment permitting LeakSanitizer tracing.

## Milestone 1 acceptance rerun

The full-duration clean-exit rerun is retained under `results/milestone-1-acceptance-20261017/`. That directory is separate from the original sandbox-failed evidence. Its sanitizer logs are explicitly included in the approved checkpoint; mutable corpus, binaries and crash artifacts remain excluded. See the repository’s `features/milestone_1_verification.md` for results and checkpoint scope.

Acceptance rerun outcome: all three targets completed 1,801 seconds and exited 0 with AddressSanitizer and LeakSanitizer enabled; 1,166,366,909 executions combined, no reported findings. Source hashes were unchanged. The earlier tracing limitation is closed for the full-duration rerun.
