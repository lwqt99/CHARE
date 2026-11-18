# CHARE Go/PBC prototype

For reproduction of the archived measurements and portable reference checks,
start with the [artifact README](../README.md).

Use Go 1.23 or newer, CGO, a C compiler, and GMP/PBC development headers and
libraries. The binding is vendored. From this directory, run
`go test -mod=vendor ./... -count=1` for the native functional suite.
`go run -mod=vendor ./cmd/goland -profile sanity` runs the small profile after
the tests. The default paper profile uses `config/paper.json` and runs nine
cases, with three trials at each capacity 4, 8, and 16. The launcher enforces an
overall timeout. An optional `-params` path specifies a trusted public Type-A
parameter file. The `-out` flag specifies a separate destination for fresh
measurement output.

The shared GoLand configurations can be opened from this module directory.
See the [build notes](docs/BUILD.md) for library search paths, the
[benchmark notes](docs/PAPER_STUDY.md) for the measurement boundary, and the
[RIPE scope](docs/RIPE_CORE.md) for the algebraic reference implementation.
The archived batch lives in [the artifact results directory](../results/native/).
