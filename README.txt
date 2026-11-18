CHARE serial admission and pending-opening replay

Run:
  python prospective_reference/RUN_REFERENCE.py

Python 3.10 or newer is required. This exercises ten serial controller scenario
groups and two existing Type-A coordinate fixtures. The fixtures use canonical
empty-policy targets and the core-only service. The replay receives public points
and saved contexts, with expected hashes checked separately. The controller
uses trusted fixture generation, pad-only linear relations and a conservative
envelope. The older Go/PBC measurements and their tools appear below.

CHARE supplemental history audits and native affine check

From this directory, with Python 3.10 or newer:
  python history_reference/current/run_increment.py

This runs the separate finite-field and order-131 reference checks for
qualification compatibility, affine replay, and two-part admission.
The small curve is for functional diagnostics. Its encoding and context KDF
are the reference formats. The original native lifecycle data are unchanged.

Recorded history-audit costs are in
  history_reference/review_round2/auditor/results/benchmark_raw.json
To time the same coefficient-only benchmark on your own machine:
  python history_reference/review_round2/auditor/benchmark.py
This regenerates its saved results. The paper reports the archived run.

For the additional native checks, install GMP and PBC as described below,
change into go/, and set CHARE_REPLAY_PARAMS to the absolute path of
results/native/parameters.txt in this archive. Run:
  go test -mod=vendor ./internal/core -run '^(TestRetainedAffinePointAndNativeContext|TestLedgerFactFailureWitnessInActualPBC)$' -count=1 -v
The affine test creates a new fixture using the archived Type-A parameters
and the prototype's native KDF. It retains the initial ciphertext and its
context during replay. The pre-existing qualification unit test uses its
own small PBC parameters. Both are functional checks outside the timed
lifecycle runs. Results are recorded in results/functional_diagnostics.log.

CHARE revised manuscript figure reproduction

Install the dependencies listed in requirements.txt and run:
  python analysis/plot_reviewed_figures.py results/native --output reviewed_figures

The command verifies the nine-case batch, then exports PDF, SVG, PNG and inline
TeX. The included expected_plot_points.csv and expected_service_bytes.csv in
analysis/ are generated from the raw batch and can be compared byte for byte.
The released PDFs embed Times New Roman. The script also accepts a serif
substitute when reproducing on a machine without that font.

The plan-byte ledger multiplies the recorded plan size by the number of pad
capsules, readiness messages and contributions in the same trial. It accounts
for one complete plan per serialized object. The other bytes include payload,
authentication and framing. It measures serialized size in memory.

Earlier analysis and independent replay commands follow.

CHARE anonymous review supplement

This archive contains the prototype and the evidence for the paper's evaluation.
The native trials use synthetic qualifications. They cover three independent
protocol states at each capacity 4, 8, and 16 with one public Type-A parameter
profile. The recorded results include all nine cases and 1,704 checks.
The Go measurements cover fixed cohorts and retained-prefix diagnostics.
The Python enrollment examples and independent pairing replay are separate.

Reproduce the tables and plots from the measured trials:
  python -m pip install -r requirements.txt
  python analysis/plot_paper_study.py results/native --output reproduced
The analysis validates the data hashes and recomputes all three-trial medians
and observed minima and maxima. The expected table contains 138 summary rows.

Replay the four recoveries using actual curve and target-group operations:
  python independent_recovery/independent_pairing.py --output recovery.json
Compare the target and key digests with independent_recovery/recorded_results.json.
See enrollment/README.md for the commands for the six enrollment traces.

Optional native execution requires Go 1.23 or newer, CGO, a C compiler, GMP,
and PBC. The measured Go module, with the module path anonymized, is in go/.
Run 'go test -mod=vendor ./... -count=1' in that directory. Run its shared
GoLand CHARE Batch configuration or 'go run -mod=vendor ./cmd/goland'.
config/paper.json specifies the nine-case batch. Fresh runs have new data and
depend on the machine. The attached timings are the original observations.

The data and dependency checksums are in SHA256SUMS. The file provenance.json
records the original and exported hashes for measured files. First-party
module paths and machine or repository metadata are anonymized. The source
hashes in results/native/source_manifest.json refer to the measured originals.
Vendor source, attribution, and licenses are preserved. Measurements and
functional outcomes are unchanged. A DH baseline takes the authorized list
as input. RIPE code exercises the algebraic core.

The additional disclosure checks exercise the reference auditor and the joint
pad rule. Run:
  python disclosure/auditor/check_auditor.py --output auditor.json
  python disclosure/pad/verify_joint_pad.py --output joint_pad.json --fixture joint_fixture.json
  python disclosure/pad/cross_call_curve.py replay --backend independent_recovery/independent_pairing.py --fixture disclosure/pad/cross_call_curve_public.json --expected disclosure/pad/cross_call_curve_expected.json --output cross_call_replay.json

The cross-call example adds one public-coordinate recovery and uses a reference
KDF. It uses the supplied pairing backend and checks the original synthetic
ciphertext and context. The native trial files and their summaries are the
recorded nine-case batch. The new fixture adds no native timing data.
