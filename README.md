# codity-scanner

A static taint analyzer for Python. It parses a codebase with Python's own `ast` module,
tracks untrusted values from where they enter to where they are dangerous, and reports
only the ones that connect, with the route they took.

Rules are data. Adding a vulnerability class means editing `rules.yaml`.

## Install, run, test

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
`--exclude DIR` (repeatable), `--root`, `-o/--output`.

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
```

Patterns are dotted paths where `*` matches exactly one segment. `arg` selects the
dangerous argument by index, or `any` for all of them including keywords; omitting it
means `any`. `when` gates a sink on a keyword argument, with `equals` for a literal value
or `absent: true` for a missing one, which is how `yaml.load` is dangerous only without a
`Loader`. Any rule may carry `paths: {include: [...], exclude: [...]}` to scope it to part
of the tree; that is handled by the engine and works for every kind.

Pattern rules take a `match` block with `assigned_to` name globs, `value: literal_string`,
`min_entropy`, `min_length`, `min_charset_classes` and `exclude` value globs.

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
  the same function (`repo = UserRepo()` then `repo.find(...)`).

**Cannot:**

- Dynamic attribute access. `getattr(os, "system")(cmd)` and `globals()["system"]` resolve
  to nothing and are never sinks.
- Type inference. An object received as a parameter or returned from an unknown call has
  no known class, so `*.execute` style patterns are the only thing that will match its
  methods. This is deliberate and is why the shipped sink patterns lead with `*`.
- Class hierarchies. A method is found on the class that literally defines it; inherited
  and overridden methods are not resolved, and neither is any dynamic dispatch.
- Decorators. A decorated function is analysed as written; a decorator that rewraps or
  replaces it is ignored.
- Star imports. `from x import *` binds nothing.
- Re-exports through `__init__.py`. `from pkg import helper` finds `helper` only if
  `pkg/__init__.py` itself defines or imports it by name.
- Local aliasing of a callable. `f = os.system; f(cmd)` is not tracked.

Function-level imports are collected into the module's alias table, so an import inside
one function is visible to the whole module. That over-approximates, and it is what makes
Django's common `from .models import X` inside a view resolve correctly.

## Where the analysis stops

Within a function the engine propagates taint through assignment chains, f-strings, `%`,
`.format`, concatenation, containers and object attributes, comprehensions, `with`,
walrus, `try`, `match`, and branch merges where taint on either side taints the result.
It kills taint on reassignment to a clean value, on a declared sanitizer, on value-killing
builtins such as `int` and `len`, and on lookups into module-level constant containers.

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

**It stops at:** mutation of arguments, so a helper that appends to a list you passed it
leaves that list clean, which is the worst false negative in BENCHMARK.md; `lambda` and
comprehension bodies as callees, though a lambda body is walked against the enclosing
scope so closure captures are still checked; class hierarchies and dynamic dispatch;
decorators; `global` writes from a function to a name not already a module-level binding;
recursion, which returns an empty summary at the cycle; and any call chain deeper than six
frames.

## Suppressions and baselines

A comment on the flagged line or directly above it suppresses the finding:

```python
cursor.execute(query)  # codity: ignore[py.sql-injection] column name is allowlisted
```

`# codity: ignore` with no bracket suppresses every rule on that line. A suppression with
no reason text is itself reported as a low-severity finding.

A baseline records the findings you have decided to live with, and `--baseline` reports
only what is new. A finding's identity is built from the rule, the file, the shape of the
sink expression and the origin, never from line or column numbers or the enclosing
function name. Adding lines above a finding, renaming the function around it, reformatting
the call, or renaming the file all keep it out of the new set. The scheme and its failure
modes are in DECISIONS.md.

## Performance

7,985 files of Apache Airflow in 31 seconds; 500 synthetic files with interprocedural
flow in 0.37 seconds, asserted on every test run. What buys it: each file is parsed once
and walked once for every taint rule rather than once per rule; sink, source and sanitizer
patterns are indexed by their last dotted segment so a call site tests only the handful of
patterns that could match; dotted-name splitting and glob matching are memoised; function
summaries are computed on demand and cached per process; the second, sticky-state pass
runs only for modules that actually write to a field or global; files are distributed
across a process pool with `Pool.map`, which preserves order. Output is sorted and
serialized with sorted keys, so serial and parallel runs are byte-identical.

## What I know is broken

- Both corpus false positives are inline validation the engine cannot see: a regex guard
  and a `startswith` path-containment check. Taint is a property of values and the engine
  has no path-sensitivity, so a checked value looks exactly like an unchecked one.
- Real-repo precision is far below corpus precision. A hand triage of 40 Airflow, Django
  and Saleor findings put it near 45%. BENCHMARK.md names the four residual false-positive
  classes.
- Container fields are not distinguished. `d["safe"]` is tainted once `d["bad"]` is.
- The baseline signature contains local variable names, so renaming a local variable used
  at the sink makes the finding look new.
- Cross-file findings are reported at the call site in the caller, not at the sink in the
  callee. One vulnerable helper reached from seven call sites produces seven findings.
- Scanning a single file gives that file its own module index of one, so cross-file flow
  is not resolved. Point the scanner at a directory to get interprocedural results.
- `scanner bench` compares against labels by line number, so a finding correct in
  substance but reported on a different line of a multi-line call counts as both a false
  positive and a false negative.
