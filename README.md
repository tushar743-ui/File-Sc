# taintscan

A static taint analyzer for Python. It parses a codebase with Python's own `ast` module,
tracks untrusted values from where they enter to where they are dangerous, and reports
only the ones that connect, with the route they took.

Rules are data. Adding a vulnerability class means editing `rules.yaml`.

## Install, run, test

```bash
make                                    # install, test, and scan the corpus
```

That is the whole setup. `make` creates a virtualenv, installs the package and its two
dependencies, runs the test suite, and scans `corpus/`. If `python3 -m venv` is
unavailable on the machine, it falls back to installing into a local `.deps/` directory
and sets `PYTHONPATH` itself, so the single command works either way.

The individual targets, if you want them separately:

```bash
make install                            # install only
make test                               # pytest
make scan TARGET=./your/repo            # table output
make sarif TARGET=./your/repo           # results.sarif
make bench                              # score against corpus/labels.json
make verify-sarif                       # validate SARIF against the published schema
make baseline TARGET=./your/repo        # write .scanner-baseline.json
make demo                               # scan demo_vulnerable.py, one file, every rule
make clean
```

Without `make`, the documented path is the usual one:

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"   # install
.venv/bin/scanner scan ./target --rules rules.yaml            # run
.venv/bin/pytest                                              # test
```

The only runtime dependency is PyYAML. Everything else is the standard library.

## Usage

```bash
scanner scan ./target --rules rules.yaml --format sarif > results.sarif
scanner scan ./target --rules rules.yaml --format table
scanner scan ./target --rules rules.yaml --fail-on high

scanner baseline --rules rules.yaml ./target > .scanner-baseline.json
scanner scan --rules rules.yaml --baseline .scanner-baseline.json ./target

scanner bench ./corpus --rules rules.yaml --labels corpus/labels.json
```

`--fail-on` exits 1 when a finding at or above that severity survives. Without it the
exit code is 0 unless the scan itself failed, which exits 2. Other flags: `--jobs`,
`--exclude DIR` (repeatable), `--root`, `--quiet`, `-o/--output`.

## Scanning a large open-source repository

One command clones a repository and scans it:

```bash
make scan-repo REPO=getsentry/sentry                 # GitHub org/name shorthand
make scan-repo REPO=https://github.com/psf/requests  # or a full git URL
make scan-repo REPO=/path/to/checkout                # or a local checkout
make scan-repo REPO=django/django FMT=sarif          # table (default), summary, or sarif
```

Clones land in `.repos/`, shallow, and are reused on the next run. `.repos/` is
gitignored and `make clean` leaves it alone.

For repositories in the thousands of files, `--format summary` is the format to use.
The full `table` format prints every hop of every taint path, which on a repository the
size of Sentry is several thousand lines. `summary` prints counts by rule, by severity
and by file, then one line per finding, and ends with a total:

A finding is one route; a sink is one dangerous line. Three entry points reaching the
same line are three findings and one sink. `summary` clusters by sink and marks the
count, so the footer reports both:

```
BY RULE
  py.hardcoded-secret  69
  py.unsafe-html       10
  py.path-traversal     2
  py.ssrf               2

BY SEVERITY
  high  83

BY FILE
  tests/sentry/backup/test_comparators.py  27
  ...
HIGH  py.unsafe-html  src/sentry/web/helpers.py:42:16  (23 hops)  x6 entry points
...
76 sink(s) in 26 file(s), 83 finding(s) counting entry points
```

The SARIF keeps every route as its own result with its own `codeFlows`, because whoever
fixes the line wants all of them.

Progress goes to stderr as `scanner: 4250/8246 files  38.1s`, so a long scan is never a
silent one, and it stays out of the way when you redirect stdout to a file. `--quiet`
turns it off for CI.

Two properties matter at this size. Memory is bounded: the cross-file module cache is an
LRU of `MODULE_CACHE_SIZE` parsed modules per worker, so peak resident memory is flat in
repository size rather than linear in it. Scanning Sentry, 8,246 files and 333 MB, peaks
at about 1.2 GB across eight workers and holds there; before the cache was bounded the
same scan passed 4.5 GB and was still climbing when it finished. Files above
`MAX_FILE_BYTES` (2 MB) are skipped rather than parsed, and a file that fails to parse is
skipped rather than failing the run, so one vendored minified blob does not stop a scan.

## Architecture

A scan is four stages.

**Discovery and indexing.** `engine.py` walks the target, skipping vendor directories,
and builds a map from dotted module name to file path. Every suffix of each module path
is registered, so `from mypkg.utils import helper` resolves inside a `src/` layout
without configuration.

**Parsing and name resolution.** Each file is parsed once into a `ModuleInfo` that holds
the AST, an index of every function and class by qualified name, and a `Resolver`. The
resolver builds the module's alias table from its imports and turns an expression into a
dotted name.

**Analysis.** `KIND_REGISTRY` maps a rule's `kind` to an analyzer class. Rules are grouped
by kind and each analyzer sees only its own. The loader validates the fields every rule
shares and hands the rest through untouched as `spec`, so it knows nothing about taint or
patterns. Adding a third kind is a class implementing `analyze(module)` plus one registry
entry: no traversal code changes, which `tests/test_rules.py` asserts directly. Two
analyzers ship:

- `analyzers/taint.py` is an abstract interpreter over the AST. Function summaries are
  computed on demand and memoised, so interprocedural flow works within a file and across
  files, with a recursion guard and a depth cap.
- `analyzers/pattern.py` walks assignments, dict literals and keyword arguments looking
  for literal values that match name globs and pass entropy, length and character-class
  filters.

**Reporting.** Findings are filtered by inline suppressions, deduplicated, sorted, and
fingerprinted, then rendered as SARIF 2.1.0 or as a table.

Taint is a tuple of flows. Each flow carries the set of rule ids it is dangerous for, its
origin, and every step it travelled. One traversal serves all taint rules at once, and a
sanitizer subtracts only its own rule's id. See DECISIONS.md.

## Rule format

```yaml
rules:
  - id: py.sql-injection
    severity: critical
    cwe: CWE-89
    message: "Untrusted input reaches a SQL query without parameterization"
    kind: taint
    sources:
      - pattern: flask.request.args.get
      - pattern: flask.request.form.*
    sinks:
      - pattern: "*.execute"
        arg: 0
      - pattern: subprocess.run
        arg: 0
        when: {kwarg: shell, equals: true}
    sanitizers:
      - pattern: myapp.db.quote_identifier
    guards:
      - pattern: myapp.security.is_safe_column
```

Patterns are dotted paths where `*` matches exactly one segment. `arg` selects the
dangerous argument by index, or `any` for all of them including keywords, or `receiver`
for the object a method is called on; omitting it means `any`. `receiver` exists because
some sinks take no arguments at all: in `Path(root + name).read_text()` the tainted value
is the `Path`, not an argument. It is opt-in, never folded into `any`, because a tainted
receiver is usually harmless: a Django `queryset` carrying a parameterized filter is
tainted and `queryset.extra(select=literals)` is not an injection. `when` gates a sink on a keyword argument, with `equals` for a literal value
or `absent: true` for a missing one, which is how `yaml.load` is dangerous only without a
`Loader`. Any rule may carry `paths: {include: [...], exclude: [...]}` to scope it to part
of the tree; that is handled by the engine and works for every kind.

`guards` names predicates that validate a value rather than transform it. A sanitizer
kills taint on the value it returns; a guard kills taint on the value it was asked about,
and only when the failing branch of the `if` exits.

Pattern rules take a `match` block with `assigned_to` name globs, `value: literal_string`,
`min_entropy`, `min_length`, `min_charset_classes`, `exclude` value globs, and
`exclude_identifier_path` to drop dotted import paths such as
`"myapp.secrets.backends.LocalFilesystemBackend"` assigned to a secret-shaped name.

`rules.yaml` ships seven rules covering SQL injection, command injection, path traversal,
SSRF, unsafe HTML rendering, insecure deserialization, and hard-coded secrets.

## What name resolution can and cannot follow

**Can:**

- `import os.path as p`, `from flask import request as rq`, and plain `import numpy as np`.
  Aliases are expanded to the canonical dotted path, so `rq.args.get` matches
  `flask.request.args.get`.
- Relative imports. `from .models import User` inside `pkg/views.py` resolves to
  `pkg.models.User`.
- Module-level rebinding of an imported name, such as `db = myapp.database`.
- Unqualified names that are module-level definitions in the same file. A bare
  `validate_url(...)` in module `app.security` resolves to `app.security.validate_url`, so
  a `*.validate_url` sanitizer matches it.
- Instance methods on a receiver whose type is unknown. An unresolvable prefix collapses
  to a single opaque segment, so `conn.cursor().execute` yields `?.execute` and matches
  `*.execute`. This is how sinks on database cursors work at all.
- Methods on `self` within a class, and on a local whose constructor call is visible in
  the same function (`repo = UserRepo()` then `repo.find(...)`), and on a constructor call
  used directly (`UserRepo(request).find(...)`).
- Inherited methods. A call resolves against the class's bases, transitively, including
  bases imported from another file. `class Runner(BaseRunner)` with `execute_now` defined
  only on `BaseRunner` resolves.
- `getattr` with a literal attribute name. `getattr(os, "system")(cmd)` resolves to
  `os.system`.
- Local aliasing of a callable. `f = os.system; f(cmd)` resolves to `os.system`.
- A parameter's identity when the call site passes something nameable. `read(request)`
  binds `source` to `flask.request` inside `def read(source)`, so `source.args.get` is
  recognised as a source there. The binding is part of the summary cache key, so the same
  helper called with two different objects gets two summaries. To keep that bounded, a
  binding is only recorded when the dotted name is a prefix of some rule's source pattern.

**Cannot:**

- Dynamic attribute access with a computed name. `getattr(os, "sys" + "tem")` and
  `globals()["system"]` resolve to nothing and are never sinks.
- Callables reached through a subscript. `HANDLERS["run"](cmd)` where `HANDLERS` is a dict
  of functions resolves to nothing. This is the worst false negative in BENCHMARK.md.
- Type inference. An object received as a parameter or returned from an unknown call has
  no known class, so `*.execute` style patterns are the only thing that will match its
  methods. This is deliberate and is why the shipped sink patterns lead with `*`.
- Overriding. Base-class methods are resolved, but the *most derived* definition wins only
  when it is on the class named at the call site. Resolution stops at the first base that
  defines the name, in `bases` order, so it approximates the MRO rather than computing it.
- Decorators. A decorated function is analysed as written; a decorator that rewraps or
  replaces it is ignored. Calls to the decorated name reach the undecorated body, which is
  usually right and is wrong for a decorator that sanitizes.
- Star imports. `from x import *` binds nothing.
- Re-exports through `__init__.py`. `from pkg import helper` finds `helper` only if
  `pkg/__init__.py` itself defines or imports it by name.

Function-level imports are collected into the module's alias table, so an import inside
one function is visible to the whole module. That over-approximates, and it is what makes
Django's common `from .models import X` inside a view resolve correctly.

## Where the analysis stops

Within a function the engine propagates taint through assignment chains, f-strings, `%`,
`.format`, concatenation, containers and object attributes, comprehensions, `with`,
walrus, `try`, `match`, container mutation (`parts.append(tainted)` taints `parts`), and
branch merges where taint on either side taints the result. It kills taint on reassignment
to a clean value, on a declared sanitizer, on value-killing builtins such as `int` and
`len`, on lookups into module-level constant containers, and on two forms of
path-sensitivity:

- A branch that always exits does not contribute its environment to the merge. Taint set
  inside `if x: raise` is not live afterwards.
- A validating guard whose failure branch exits kills the value it validated. After
  `if not HOSTNAME.fullmatch(host): raise`, `host` is clean. What counts as validating is
  a fixed set of predicates (`startswith`, `fullmatch`, `isdigit`, `in`/`not in` against a
  container, and friends) plus any pattern listed under a rule's optional `guards:` key,
  which accepts the same dotted-path syntax as `sanitizers:` and matches plain functions
  as well as methods.
  A bare presence check such as `if not name: raise` deliberately does not kill, because
  it validates nothing.

Beyond one function:

- **Interprocedural within a file: yes.** Summaries record which parameters reach the
  return value and which reach a sink, both with their step lists, so the reported path
  runs through the callee and back.
- **Across files: yes.** Callees are resolved through the module index and analysed on
  demand. Sanitizers in another module kill taint correctly.
- **Object fields and module globals across functions: partly.** A pre-pass records
  source-tainted writes to `self.attr` and to module-level containers, then seeds them
  into sibling methods and functions. It is flow-insensitive, so it does not care whether
  the writing function actually ran first.
- **Argument mutation: yes.** A summary records which parameter a callee writes into and
  from where, so `collect(parts, tainted)` where `collect` does `bucket.append(value)`
  taints `parts` at the call site.
- **Constructors: yes.** `__init__` is summarised, and the fields it taints are carried on
  the constructed value, tagged by field name. A later method call on that object only
  sees the fields that were actually tainted, so a clean field on a dirty object is not
  reported.
- **Lambdas assigned to a name: yes.** The body is re-evaluated with the call's arguments
  bound to its parameters.

**It stops at:** callables reached through a subscript; dynamic attribute access with a
computed name; decorators that replace the function; full MRO resolution; `global` writes
from a function to a name not already a module-level binding; recursion, which returns an
empty summary at the cycle; and any call chain deeper than six frames.

### Where findings are reported

At the **sink**, not at the entry point, and once per distinct (entry point, sink) pair.
One vulnerable helper called from twenty places produces findings on the helper's line,
one per distinct source, each carrying its own route. A suppression comment in the file
holding the sink covers all of them.

## Suppressions and baselines

A comment on the flagged line or directly above it suppresses the finding:

```python
cursor.execute(query)  # taintscan: ignore[py.sql-injection] column name is allowlisted
```

`# taintscan: ignore` with no bracket suppresses every rule on that line. A suppression with
no reason text is itself reported as a low-severity finding. `# codity: ignore` is accepted
as an alias of the same marker.

A baseline records the findings you have decided to live with, and `--baseline` reports
only what is new. A finding's identity is built from the rule, the file, the shape of the
sink expression with every identifier anonymised, and the origin, never from line or
column numbers, the enclosing function name, or the names of locals. Adding lines above a finding, renaming the function around it, reformatting
the call, renaming a local variable at the sink, or renaming the file all keep it out of
the new set. The scheme and its failure
modes are in DECISIONS.md.

## Performance

8,163 files of Sentry in 51 to 75 seconds; 7,995 files of Apache Airflow in 30 to 47
seconds; 2,932 files of Django in 10 to 14 seconds; 500 files with interprocedural flow in 0.24 to 0.39
seconds, asserted on every test run against a 60-second budget. What buys it: each file is parsed once
and walked once for every taint rule rather than once per rule; sink, source and sanitizer
patterns are indexed by their last dotted segment so a call site tests only the handful of
patterns that could match; dotted-name splitting and glob matching are memoised; function
summaries are computed on demand and cached per process, keyed by the call-site name
bindings so the cache stays correct without recomputation; `local_names` is memoised on
the function it describes instead of re-walking the body per analysis; pattern lookups are
memoised on the candidate-name tuple, which the profiler named as the hottest function; the second, sticky-state pass
runs only for modules that actually write to a field or global; imports and module-level
constants are collected in a single `ast.walk` rather than one each, which was 20% of the
time on a large repository; files are distributed across a process pool with `ProcessPoolExecutor.map`,
which preserves order while letting progress be reported as results arrive. Output is
sorted and serialized with sorted keys, so serial and parallel runs are byte-identical.

The cross-file module cache is the one thing that has to be bounded rather than made
fast. Resolving a call into another file parses that file, and on a large repository the
set of files reachable by import from somewhere is effectively the whole repository, so
an unbounded cache is a slow memory leak. It is an LRU, `MODULE_CACHE_SIZE` entries per
worker; smaller trades wall time for memory and larger trades it back. 512 was chosen by
measuring Sentry at both ends: 128 entries costs about 20% wall time for a 750 MB ceiling,
unbounded is 4.5 GB and rising.

## What I know is broken

- Real-repo precision is the honest number, not the corpus. The corpus scores 1.000 on
  both axes, so it is now a regression suite rather than a measurement. Across five public
  repositories precision is 0.815 per finding under a generous definition of correct, and
  roughly 0.01 under "would an engineer open a ticket". BENCHMARK.md has the breakdown.
- Autoescaped template output is the largest false-positive class.
  `HttpResponse(render_to_string(...))` is reported because the engine cannot see that the
  template engine escaped the value, and a sanitizer passed as a function, as in
  `map(conditional_escape, args)`, does not kill taint.
- Strings carry no constant-prefix information, so
  `requests.get(f"https://fixed-host.example/{tainted}")` is reported as SSRF even though
  the host cannot be steered. This is the first thing I would fix.
- Path-sensitivity is a heuristic, not an analysis. A guard kills taint only when one
  branch of the `if` always exits and the predicate is on a fixed list of validators or
  declared under the rule's `guards:` key. A project's own validator is invisible until
  someone lists it.
- Callables held in containers are invisible. `HANDLERS["run"](cmd)` is never a sink.
  This is the worst false negative in BENCHMARK.md.

## Two things the AI assistant got wrong that I caught

Both are in the parallel scan, and both passed every test until I asked what happens when
a worker goes down. DECISIONS.md lists two more from the analysis itself.

- **One bad file threw away the whole scan.** The assistant caught the errors it expected
  (unreadable file, syntax error, bad encoding, deep recursion) and nothing else. An
  unexpected exception in one file, such as a `MemoryError` or an analyzer bug on an
  unusual AST, came back through the pool and crashed the run, discarding the results for
  every file that had scanned fine. I had it wrap each file in its own `try/except
  Exception`, so the file is skipped with a `scanner: skipped <path>` warning on stderr
  and the rest of the scan completes.
- **A dead worker hung the scan forever.** It used `multiprocessing.Pool.imap`. When a
  worker process dies outright (OOM killer, `kill -9`, segfault), `Pool` quietly starts a
  replacement, but the batch of files the dead worker held is lost and `imap` waits for it
  indefinitely. In CI that is a job stuck until the runner's timeout, with no error. I had
  it switch to `concurrent.futures.ProcessPoolExecutor`, which raises `BrokenProcessPool`
  instead; the CLI reports that a worker died and exits with code 2.

Both are pinned by tests in `tests/test_engine.py`, and both tests fail against the old
code (the second one by hitting a 30 second alarm). The output on Django is byte-identical
before and after, and the scan time did not change (11.1s before, 10.6s after).

## If GitHub is down

A GitHub outage only stops you fetching new repos from GitHub. Everything else keeps
working. The scanner reads local directories and makes no network calls. `make scan-repo`
reuses clones already in `.repos/`, and it also accepts any git URL (GitLab, Codeberg, a
mirror) or a local path. Python projects can be fetched from PyPI with
`pip download --no-binary :all: --no-deps <package>` and scanned from the unpacked source.

To keep fetching during an outage, point git at a mirror. Git rewrites the URL natively,
so no scanner change is needed:

```
git config --global url."https://your-mirror.example/".insteadOf "https://github.com/"
```

Every `github.com` URL, including the ones `make scan-repo` builds from `org/name`, is then
fetched from the mirror (a self-hosted Gitea or GitLab mirroring the repos you scan, or a
company git proxy). Remove the setting when GitHub is back with
`git config --global --unset url."https://your-mirror.example/".insteadOf`.
