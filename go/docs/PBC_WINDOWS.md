# Windows native-library compatibility

Linux remains the main VM execution path. These notes describe the actual
Windows validation environment, not a requirement to replace a working Linux
PBC installation or a claim about concrete security strength.

The local native build used MinGW-w64 GCC 8.1.0, official PBC 0.5.14 source,
and MSYS2 `mingw-w64-x86_64-gmp` 6.3.0-2. The GMP package SHA-256 was
`8924433974c4add46cb46ea4f6ef283b5c5139d3f552375115b5580f855015cc`.
Dependencies and binaries are not included in the portable source ZIP.

## A large-field check is necessary

On this Windows ABI, `sizeof(unsigned long)` is 4, while `sizeof(mp_limb_t)`
is 8. PBC 0.5.14 `arith/montfp.c` computes its Montgomery reduction constant as

```c
p->negpinv = -mpz_get_ui(z);
```

Here `mpz_get_ui` truncates to 32 bits before the value is assigned to a
64-bit limb. The required invariant is `prime_low_limb * negpinv == -1`
modulo one limb. An actual C check on this environment showed the original
line violating it. The local PBC source build changes that one line to

```c
p->negpinv = -(mp_limb_t) mpz_getlimbn(z, 0);
```

This obtains and negates the complete low limb. On an ABI where both widths
are equal the low-limb value is the same; it is not a change to the field or
pairing construction. Do not silently mix the patched DLL with unrelated
headers or GMP libraries. Record actual build provenance.

The original small functional fixture has an order of 641 and a coordinate
prime fitting 32 bits; PBC uses its naive field backend for that fixture.
Consequently those tests passed while the first actual 160/512 batch failed
public projection equations. `TestNativeLargeFieldBilinearity` now exercises
multi-limb arithmetic and public root verification before every batch. It
does not change parameters, bypass validation, or retry failed cases until
they pass. A bad native library must fail this gate.

The separate Go wrapper temporary-file patch is documented in
`VENDOR_PATCHES.md`. Both platforms use the same CHARE protocol source.

## Observed local validation

After the native-library and wrapper fixes, the complete 36-test gate and
the `sanity` one-command batch passed. The batch covered N=4 and N=8 with
two attributes and generated Type-A size parameters. Earlier failed logs
and result packages were retained. This does not establish the user's VM
environment, paper-grid throughput, or a concrete security level.

Native dependencies were created only under ignored `build/native`.
No global MinGW/GMP/PBC installation or other paper project was changed.
