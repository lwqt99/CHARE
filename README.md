# CHARE reproducibility artifact

This repository accompanies *CHARE: Registered Encryption with Hidden Qualifications and Retained State*. It contains the Go/PBC research prototype, the raw synthetic lifecycle runs, the figure and table scripts, and the Python reference implementations and replay fixtures.

## Quick verification

Use Python 3.10 or newer. Start from the repository root and run the integrity check on a fresh checkout or extraction.

```sh
python verify_artifact.py
```

Run the following in a disposable copy if you want to preserve the archived checksums. The reference scripts write replay receipts and logs into their own directories.

```sh
python -B prospective_reference/RUN_REFERENCE.py
python -B history_reference/current/run_increment.py
```

The first command runs ten serial controller scenario groups and replays two Type-A coordinate fixtures using public inputs. The second runs six reference checks for qualification compatibility, affine replay, and two-part admission. The controller fixtures use trusted public source bindings and canonical empty-policy targets.

## Reproduce the paper figures and tables

```sh
python -m pip install -r requirements.txt
python analysis/plot_reviewed_figures.py results/native --output reviewed_figures
python verify_artifact.py --figures reviewed_figures
```

The last command compares the 48 regenerated plot points and the 18-row service byte ledger with their archived CSVs. The figure script also exports PDF, SVG, PNG, and inline TeX. For the full 138-row analysis summary, run:

```sh
python analysis/plot_paper_study.py results/native --output reproduced
```

The archived batch contains three trials at each capacity of 4, 8, and 16. The paper reports the three-trial medians and observed ranges. The measured parameters define the experimental profile. The concrete security analysis is separate from this evaluation.

## Run the native prototype (optional)

The archived-data and Python reference checks above do not require PBC. Native execution uses Go 1.23 or newer, CGO, a C compiler, and the GMP and PBC headers and libraries. The Go dependency is vendored. The following example uses a shell on Linux:

```sh
artifact_root="$PWD"
cd go
go test -mod=vendor ./... -count=1
CHARE_REPLAY_PARAMS="$artifact_root/results/native/parameters.txt" \
  go test -mod=vendor ./internal/core \
  -run '^(TestRetainedAffinePointAndNativeContext|TestLedgerFactFailureWitnessInActualPBC)$' -count=1 -v
go run -mod=vendor ./cmd/goland -profile sanity -out "$artifact_root/review-output/native"
```

Use the default paper profile for the nine-case workload. It reruns the tests before measuring and uses fresh protocol randomness. System library search paths and loader settings are described in [the native build notes](go/docs/BUILD.md). Archived run data remain under the repository-level results directory.

## Contents

| Path | Evidence |
| --- | --- |
| [go/](go/) | Native prototype, tests, fixed benchmark configurations, and vendored Go binding |
| [results/](results/) | Nine archived native trials, public parameters, and functional diagnostics |
| [analysis/](analysis/) | Plot and table reconstruction from the original batch |
| [prospective_reference/](prospective_reference/) | Serial admission checks and independent replay of two public fixtures |
| [history_reference/](history_reference/) | Qualification, affine replay, and admission checks |
| [independent_recovery/](independent_recovery/), [disclosure/](disclosure/), [enrollment/](enrollment/) | Additional public replay inputs and checks |
| [provenance.json](provenance.json) | Recorded and exported source hashes |
| [SHA256SUMS](SHA256SUMS) | SHA-256 digests of the published payload files |

[README.txt](README.txt) documents additional replay commands and recorded results. The source-DH baseline receives the authorized list. The RIPE code exercises its algebraic core. All inputs are synthetic. Third-party source notices are preserved with the vendored dependencies.
