# Decisions

## How taint is represented, and what I rejected

A tainted value is a tuple of `Flow` records. Each `Flow` carries the set of rule ids it
is dangerous for, an origin (a real source, or parameter *i* of the enclosing function),
and the ordered `Step`s it has travelled. The environment maps a variable path to that
tuple; absent and empty both mean clean.

Carrying rule ids inside the flow is the decision everything else hangs off. The
alternative was to run the whole interpreter once per rule, which is simpler to reason
about and roughly N times the work for N taint rules. Instead one traversal serves every
taint rule at once: a source contributes the ids of the rules that named it, a sanitizer
subtracts the ids of the rules that declared it, and a sink fires only if its own rule id
survived the trip. Rule-specific sanitization falls out for free, so `html.escape` kills
XSS without pretending to fix SQL injection.

Flows are immutable, which makes branch merging a set union with a deterministic
tie-break rather than a copy-and-patch. The join keeps one flow per `(origin, rule set)`
pair, preferring the shortest path, capped at six flows and twenty-four steps per value.
Those caps are the only reason loops terminate cheaply; without them a two-pass loop
body can grow paths without bound.

**Rejected: a points-to analysis.** Containers are field-insensitive per variable. A
tainted element taints `d["k"]` and `d` alike, and object attributes are tracked as
`obj.attr` keys with a fallback to `obj`. This is wrong in the direction of over-tainting
and it is what makes `d["safe"] = "x"; d["bad"] = tainted` treat both keys as tainted. A
real heap model would fix it and would have cost most of the time budget for a class of
bug my corpus barely contains.

**Rejected: a lattice with a separate "sanitized" value.** Sanitization is subtraction
from a rule set, not a third state. A value sanitized for one rule and not another has to
be representable, and a scalar lattice cannot do it.

**Rejected: SSA or a real CFG.** The engine is an abstract interpreter over the AST.
Loops run their body twice and merge with the pre-loop environment, which reaches a
fixpoint for the accumulation patterns that matter and is bounded by construction.
`try` merges the body environment into each handler because an exception can fire
anywhere inside the body.

## Finding identity for baselines

A fingerprint is `sha256(rule id, file path, signature, ordinal)`, where the signature for
a taint finding is the sink pattern, the origin label, and `ast.dump` of the sink call
after a round trip through `ast.unparse`. The ordinal disambiguates identical findings
within one file.

What is deliberately **not** in it: line numbers, column numbers, the enclosing function
name, and source formatting. So inserting twenty lines above a finding does not move it,
renaming the function containing it does not move it, and reformatting the call across
three lines does not move it. All three are tested in `tests/test_baseline.py`.

File renames are handled by a second, path-free fingerprint stored alongside the first.
It is consulted only when the baseline entry's file is absent from the current scan, so
moving `app.py` to `views.py` keeps the finding, while copy-pasting a vulnerable function
into a new file correctly reports a new one.

**What breaks it.** Editing the flagged statement itself, which is intended. Reordering
two byte-identical findings in one file, because the ordinal is positional. Changing a
local variable's name, because the variable appears in the dumped sink expression: this
one is a genuine wart, and the fix is to alpha-rename locals before dumping.

## The precision and recall trade-off

I chose recall inside the engine and precision inside the rules.

The engine over-approximates. An unknown call returns tainted if any argument or the
receiver is tainted, because the alternative loses every wrapper, every helper and every
`str.join`. Taint on either branch of an `if` taints the merge. This is the only way to
survive code that calls libraries the analyser has never heard of, which is all real code.

Precision is then bought back in rule data, because rule data is the part a user can
change without reading my source. Sinks carry an argument index so a parameterized query
is silent. Sinks carry an optional `when` guard so `subprocess.run` is dangerous with
`shell=True` and quiet without it, and `yaml.load` is dangerous only when the `Loader`
argument is absent. The secret rule is filtered by entropy, length and character-class
count. When triage on Airflow showed that `sys.argv` and `os.environ` produced 100% of
the path-traversal and SSRF noise, the fix was deleting two lines from a YAML anchor, not
touching the engine.

The exception, where I spent engine code on precision, is the "provably constant"
requirement. A module-level name bound exactly once to a literal container, never
rebound and never mutated, is constant, and lookups on it return clean. Allowlist
dictionaries are common enough in safe code that treating `ALLOWED.get(user_input)` as
tainted poisons an entire class of correct programs.

I would rather ship a scanner that misses the `getattr` dispatch case than one that
reports Django's number formatter. The 40-finding hand triage in BENCHMARK.md says I have
not fully succeeded: real-repo precision is near 45%.

## The rule I most wanted to write and could not

A rule that distinguishes a validated value from an unvalidated one, so that

```python
if not HOSTNAME.fullmatch(host):
    raise ValueError
os.system("ping " + host)
```

is silent while the same code without the guard is reported. Today the only way to
express "this value has been checked" is to declare a sanitizer function, which forces
the check into a named call and does nothing for the far more common inline guard. Both
of my corpus false positives are this shape.

The engine would need path-sensitivity: predicates evaluated in an `if` test would have
to be recorded as facts attached to the values they constrain, branches would have to
carry the predicate and its negation, and a control-flow edge that certainly raises or
returns would have to remove the failing branch from the merge. The rule surface would
then be something like `validators: [{pattern: "*.fullmatch", guards: arg 0}]`. That is
a real dataflow framework with a CFG underneath, which is the honest reason it is not
here.

## What I cut, and what another week would buy

Cut: mutation of arguments in function summaries, which is the worst false negative in
BENCHMARK.md; `lambda` and comprehension bodies as first-class callees, so taint entering
a lambda through its own parameter is lost; class hierarchies, so a method is resolved
only on `self` or on a variable whose constructor call is visible in the same function;
decorators, which are not followed; and `*args`/`**kwargs` splatting, which is unioned
rather than matched positionally.

With another week, in order: argument side effects in summaries, because it is the
cheapest recall win left and I know exactly where it goes. Then the `startswith` and
`in`-allowlist guard patterns as a narrow special case of path-sensitivity, because those
two shapes cover most of the inline-validation false positives without building a CFG.
Then alpha-renaming locals in the baseline signature. Then a cross-file call graph built
once per scan instead of resolved on demand, which would let summaries be computed
bottom-up and would cut the Airflow scan time.

## Two things the AI assistant got wrong that I caught

**Overlapping sink patterns produced duplicate findings.** The first benchmark run scored
0.600 precision on SSRF and unsafe HTML. The cause was not the analysis: `urllib.request.urlopen`
and `*.urlopen` both matched the same call, and each match emitted its own finding, so
every correctly-found vulnerability was reported twice and the duplicate counted as a
false positive. Sink matching now reports at most one finding per rule per call site, with
a dedupe in the engine as a backstop. The lesson is that a rule pack with redundant
patterns is normal and the engine has to be idempotent under it.

**A sanitizer for one rule silently disabled interprocedural analysis for all the others.**
A cross-file test failed where a `secure_filename` wrapper in another module should have
killed path-traversal taint. The wrapper was named `clean`, which matched the `*.clean`
sanitizer pattern belonging to the *unsafe HTML* rule. The call handler treated any
sanitizer match as a reason to return early, so it stripped the XSS rule and returned
before ever consulting the function summary, losing the path-traversal analysis entirely.
Sanitization is now applied to the result of full evaluation rather than short-circuiting
it, and the over-broad `*.clean` pattern is gone. A single failing test caught a bug that
was silently suppressing cross-file analysis on every call whose name happened to collide
with any sanitizer in any rule.
