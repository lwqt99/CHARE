# Vendored wrapper changes

The upstream Go wrapper is pinned to commit
`3e516ca0c5d64646fd1c3aeb1ecd41dacba1f0c6`. The source bundle contains the
documented local patches below; it is not byte-identical to that commit.
Licenses and upstream copyright notices remain in `vendor`.

## Temporary-file memstream (Windows and other fallback targets)

`vendor/github.com/Nik-U/pbc/memstream_other.go` originally terminated output
with `bufp[*sizep] = '\0'`. Here `bufp` is a `char **`; indexing it does not
terminate the allocated character buffer and can write outside the caller's
pointer object. The patch uses `(*bufp)[*sizep] = '\0'` only after a successful
read, and checks seek, size, and allocation failures before reading. Failure
returns a null buffer and zero length, following the existing interface.

This was identified by source inspection, not by a claimed observed exploit.
In an actual native regression run, the parameter printer also returned an
empty string. A separate C check showed MSVCRT `tmpfile()` returning
`errno=13 (Permission denied)` on this host. The Windows path now creates a
temporary file in the user's Windows temporary directory, opens it with
exclusive sharing and deletion on close, and transfers its handle to the
same C runtime's `FILE *`. It does not need drive-root write permission.
Errors fail closed and release the created handle/file. Other fallback
platforms retain their existing `tmpfile()` behavior.
The actual parameter-print/parse round trip has a native regression test.
The Linux/POSIX memstream and BSD/macOS code paths are unchanged. Protocol
algebra, randomness, and parameter generation are unchanged.

Do not overwrite this patch with `go mod vendor` without reapplying and
retesting it. Normal `go test`/`go build` use the included vendor directory.
The result package records hashes of the actual vendored source files.

## Native object lifetimes (all platforms, v0.5.1)

The wrapper owns C allocations through Go objects with finalizers. Passing a
field such as `element.cptr` to C does not keep its containing Go owner alive.
In particular, the previous `&big2mpz(i).i[0]` passed a pointer owned by a
temporary finalizable GMP wrapper. Go could finalize it while C was using it.
The relevant Go contract is `runtime.KeepAlive`; see the Go runtime
documentation and `src/runtime/mfinal.go` in the actual Go distribution.

This local patch keeps receivers and input owners alive through the C calls
used by this project: 14 arithmetic methods, six element conversion methods,
the pairing symmetry/G1/GT-length queries, and parameter serialization.
`MulBig`, `PowBig`, and `SetBig` now name and keep alive the temporary GMP
owner. The two underlying GMP import/export helpers also retain their owners.
Go `defer runtime.KeepAlive(owner)` is used so early return paths retain the
owner too. The patch does not disable GC, alter scalar distributions, change
group formulas, change serialization, or alter the native Montgomery fix.
Unused upstream APIs have not received a general lifecycle audit; do not
interpret this project-specific patch as certification of the whole wrapper.

`TestNativeGCChainedOperations` performs actual multi-limb group arithmetic,
serialization, root and row validation while a separate goroutine requests
garbage collection. It failed at its first bilinearity check before this
patch and passed all 32 iterations afterward. This supports the diagnosed
lifetime defect; it does not reconstruct the precise finalizer schedule of
an earlier batch's projection failure. That failed batch is retained and
excluded from the final implementation evidence. Only the test changes GC
settings, restoring them on exit; the measured runner keeps its normal GC.

The Linux build uses these same Go lifetime fixes. Keep this patched vendor
directory in the source transfer and do not replace it with an unpatched
upstream download. Regression checks establish implementation behavior, not
cryptographic security or a concrete security level.
