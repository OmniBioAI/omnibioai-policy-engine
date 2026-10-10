# Building omnibioai-policy-engine

The nine modules under `app/core/`, `app/services/`, and `app/api/` listed in
`setup.py`'s `EXTENSIONS` are shipped as Cython-compiled extensions for IP
protection. This document covers how to build them reproducibly and the
pitfalls that motivated it.

## Supported Cython version

**Cython 3.2.5** is the version that actually matches the `.c` files
committed at `HEAD`, and is now pinned exactly in `pyproject.toml`
(`Cython==3.2.5`). Do not bump this casually: a newer or older Cython
produces a materially different `.c` file (different internal helper
ordering, string tables, etc.), and `git diff` on the generated sources is
the only way anyone reviewing a PR can tell a real source change from
generator noise.

If a Cython upgrade is genuinely needed (security fix, new Python version
support), regenerate **all** nine `.c` files in the same commit as the
`pyproject.toml` bump, and call that out explicitly in the PR description —
treat it as a deliberate compatibility decision, not a side effect of
`pip install --upgrade`.

## Reproducible build steps

```bash
python -m venv .venv
source .venv/bin/activate
pip install "Cython==3.2.5" setuptools wheel
pip install -e .          # installs runtime deps + builds extensions
# or, to just (re)generate/compile in place:
python setup.py build_ext --inplace
```

`setup.py` generates the `.c` files from the `.py` sources via `cythonize()`
and then compiles them. Both steps run every time `setup.py build_ext` is
invoked, but `cythonize()` only regenerates a `.c` file whose `.py` source
actually changed — see "Generated-source maintenance" below for why that
matters.

## macOS build fix (spawn / BrokenProcessPool)

`cythonize()` used to default to `nthreads=os.cpu_count() or 4`, farming
`.py` -> `.c` generation out to a multiprocessing pool. On macOS, Python's
default start method is `spawn`, which re-imports `setup.py` in each worker
process; that re-execution crashes before any extension is generated,
surfacing as `BrokenProcessPool`.

`setup.py` now defaults to **serial generation** (`nthreads=0`), which is
safe on every platform. Set the `CYTHON_NTHREADS` environment variable to
opt into parallel generation where it's known to be safe (e.g. Linux CI):

```bash
CYTHON_NTHREADS=4 python setup.py build_ext --inplace
```

## Linux ARM64 build considerations

Nine `*.cpython-313-aarch64-linux-gnu.so` files (plus a mirrored copy under
`build/lib.linux-aarch64-cpython-313/`) are **intentionally tracked in git**
for Linux ARM64 / CPython 3.13. Do not delete, regenerate, or overwrite
them from a macOS build — a macOS build only ever produces
`*.cpython-*-darwin.so` files alongside them.

One tracked artifact, `build/lib.linux-aarch64-cpython-313/app/core/middleware.cpython-313-aarch64-linux-gnu.so`
(and its `.o` in `build/temp.linux-aarch64-cpython-313/`), does not
correspond to anything in the current `EXTENSIONS` list — there is no
`app/core/middleware.py` built today. This is a stale tracked artifact from
an earlier module layout; flagged here for the repo owner to confirm it can
be removed, rather than removed unilaterally.

## Python version compatibility

Verified locally on macOS (arm64) with Cython 3.2.5: Python 3.11, 3.12, and
3.13 all build cleanly and pass the full test suite (133 passed, 2 xfailed).
Python 3.10 was not available in this environment and was not tested
locally — CI should cover it (see below).

CI (`.github/workflows/ci.yml`) currently runs a single Python 3.11 job and
has no explicit version matrix. Since the compiled extensions are
Python-version-specific (`cpython-3XX-...`), consider extending CI to a
3.10–3.13 matrix (mirroring the sibling `omnibioai-security-sdk` repo's CI)
so each supported interpreter's build is actually exercised, not just 3.11.

## Binary artifact policy

- Tracked: Linux ARM64 `.so` files for CPython 3.13, both at the package
  paths and under `build/lib.linux-aarch64-cpython-313/`. Treat these as
  release artifacts; changing this policy is an owner decision, not a build
  hygiene cleanup.
- Ignored (local only, never tracked): macOS `.so` files
  (`*.cpython-*-darwin.so`), macOS build directories
  (`build/lib.macosx-*/`, `build/temp.macosx-*/`), and `*.egg-info/`. See
  `.gitignore`.
- The generated `.c` files themselves are tracked and must stay committed —
  they're what makes the build reproducible without requiring every
  consumer to run Cython.

## Generated-source maintenance

`cythonize()` only regenerates a `.c` file when its corresponding `.py` file
has changed since the `.c` was last produced. **This audit found that
several `.c` files committed at `HEAD` were stale relative to their `.py`
sources** — most seriously, `app/core/tenancy.c` and `app/core/engine.c`
were last regenerated at an earlier commit, before the tenancy
`resource_scope`/admin-role gate was added in `security: require tenant
resource context`. The compiled extensions therefore silently skipped that
security check (admin-scope and missing-tenant-context requests were
incorrectly allowed), while the pure-Python source enforced it correctly.
Regenerating against current sources with Cython 3.2.5 and rebuilding
closes this gap; the full test suite (previously 2 failing when run against
the stale compiled extensions) now passes end to end against the compiled
`.so` files.

**Takeaway: whenever a `.py` file behind a Cython extension changes, its
`.c` file must be regenerated and committed in the same PR.** There is
currently no automated check for this — consider a CI step that runs
`cythonize()` and fails the build if it produces a diff against committed
`.c` files.

## Troubleshooting

- **`BrokenProcessPool` / spawn errors on macOS during `build_ext`**: fixed
  by the serial-by-default `nthreads` change above. If you still see this,
  make sure you're not manually passing `CYTHON_NTHREADS` > 0 on macOS.
- **`git diff --check` reports trailing whitespace in generated `.c`
  files**: this is Cython 3.2.5 itself emitting a trailing space after `*`
  in some wrapped comment lines. It is a benign generator artifact, not a
  style issue to hand-fix — hand-editing generated C will be undone by the
  next `cythonize()` run.
- **Compiled module behaves differently than the `.py` source**: check
  whether the `.c` file is stale (compare `git log -1 -- path/to/file.c` vs
  `path/to/file.py`); if the `.py` is newer, regenerate and recommit the
  `.c`.
