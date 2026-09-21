# Decisions

## How taint is represented, and what I rejected

A tainted value is a tuple of `Flow` records. Each `Flow` carries the set of rule ids it
is dangerous for, an origin (a real source, or parameter *i* of the enclosing function),
the ordered `Step`s it has travelled, and an optional field tag naming which attribute of
an object the taint lives in. The environment maps a variable path to that
tuple; absent and empty both mean clean.

Carrying rule ids inside the flow is the decision everything else hangs off. The
alternative was to run the whole interpreter once per rule, which is simpler to reason
about and roughly N times the work for N taint rules. Instead one traversal serves every
taint rule at once: a source contributes the ids of the rules that named it, a sanitizer
subtracts the ids of the rules that declared it, and a sink fires only if its own rule id
survived the trip. Rule-specific sanitization falls out for free, so `html.escape` kills
XSS without pretending to fix SQL injection.

The field tag is what keeps constructor analysis honest. `Repo(request)` yields a value
whose flows are tagged `term`, because `__init__` assigned a source to `self.term`. A
later `repo.run()` that reads `self.other` filters those flows out and reports nothing,
while one that reads `self.term` reports. Without the tag the choice would have been
between ignoring constructors and treating every field of a dirty object as dirty.

Flows are immutable, which makes branch merging a set union with a deterministic
tie-break rather than a copy-and-patch. The join keeps one flow per
`(origin, rule set, field)` triple, preferring the shortest path, capped at six flows and
twenty-four steps per value.
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

**Accepted in place of a CFG: two syntactic approximations of control flow.** A branch
whose body always exits (`return`, `raise`, `break`, `continue`, or a call named `exit` or
`abort`) does not contribute its environment to the merge, which is the one CFG fact worth
the most and the cheapest to compute from the AST. On top of it, when exactly one branch
of an `if` exits, the values named in a validating predicate in the test are killed after
the statement. That is not path-sensitivity; it is a rule that says "code after a guard
that rejects has been guarded". It is wrong when a predicate validates one property and
the sink cares about another, and it was still worth it: it removed both remaining corpus
false positives and most of Airflow's command-injection noise.

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

Every identifier in that dump is rewritten to `_` first, so the signature describes the
*shape* of the sink call and its literals, not the names chosen around it. Renaming `name`
to `username`, or `cursor` to `conn`, keeps the finding.
`tests/test_baseline.py::test_finding_survives_a_local_variable_rename` pins it.

**What breaks it.** Editing the flagged statement itself, which is intended. Reordering
two byte-identical findings in one file, because the ordinal is positional. Anonymising
identifiers also means two findings that differ only by variable name now share a
signature and are separated only by the ordinal, so deleting the first makes the second
look new. That trade is deliberate: renaming a variable is common, deleting one of two
otherwise identical sinks is rare.

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

I would rather ship a scanner that misses a dispatch table than one that reports Django's
number formatter. The hand triage in BENCHMARK.md says I have partly succeeded:
real-repo precision is 0.855 under a generous reading, and the thing it still reports is
Django's number formatter.

The one place this trade was revisited: the guard rule above buys precision with engine
code, not rule data, which contradicts the paragraph above it. It earned the exception by
removing a false-positive class that no amount of rule editing could reach, since the
thing to suppress is a syntactic shape in the user's code rather than a name the user
could list.

## The rule I most wanted to write and could not

The inline-validation rule described in the previous revision of this document is now
built, as `guards:` plus the exiting-branch merge above, so the honest answer has moved on
to a harder one: **a rule that follows a callable held in data.**

```yaml
- id: py.command-injection
  sinks:
    - pattern: "*.system"
      arg: 0
```

does not fire on

```python
HANDLERS = {"run": os.system}
HANDLERS["run"]("echo " + request.args.get("cmd"))
```

and no rule I can write will make it fire, because the engine never learns that the value
at `HANDLERS["run"]` *is* `os.system`. Dispatch tables, plugin registries, Celery task
maps and `functools.partial` all have this shape, and they are exactly where a codebase
hides its dangerous operations.

The engine would need a second abstract domain alongside taint: for each environment key,
the set of dotted paths the value may name, propagated through assignment, containers and
returns, and consulted at every call site before pattern matching. It is not conceptually
hard and it is not small: every place that currently reads a taint tuple would need to
read a pair, and the constant-container detection that already exists would have to be
generalised from "is this literal" to "what does this name". A week of work, not an
afternoon, which is why it is not here.

## What I cut, and what another week would buy

Everything on the previous cut list is now built: argument mutation in summaries, lambda
bodies as callees, class hierarchies including bases in other files, constructors, guard
patterns, and alpha-renaming in the baseline signature. What remains cut:

Comprehension bodies as first-class callees. Decorators that replace the function, which
are analysed as if the decorator were absent. `*args`/`**kwargs` splatting, which is
unioned rather than matched positionally. Real MRO computation, so base resolution takes
the first base that defines a name. Container field-sensitivity, so `d["safe"]` is dirty
once `d["bad"]` is. And callables held in data, described above.

With another week, in order: the dotted-path domain, because it is the largest remaining
class of missed sinks and it also fixes decorators, `partial` and dispatch tables at once.
Then clustering the table output by sink, because the Django false positive appears three
times and one wrong conclusion should look like one line. Then a cross-file call graph
built once per scan instead of resolved on demand, which would let summaries be computed
bottom-up and would cut the Airflow scan time, currently 39s for 7,990 files. Then
container field-sensitivity, which is the last correctness gap I can name precisely.

## Five things the AI assistant got wrong that I caught

**A value filter that silently deleted real secrets.** To kill a false-positive class
where a dotted import path is assigned to a `*_KEY` name, the assistant added
`exclude_identifier_path`: drop any dot-separated value whose segments are all
identifiers. It worked on the four targets. It also dropped
`VAULT_TOKEN = "s.FnL7qg0YnHZDpf4zKKuFy0UK"`, a real Vault token shape, while keeping a
near-identical literal whose segment was one character longer, so the behaviour was both
wrong and inconsistent. Caught by diffing the Airflow findings before and after instead of
trusting the corpus, which still scored 1.000 throughout. The filter now requires three or
more segments, which no two-part token shape has, and
`tests/test_pattern.py::test_a_two_segment_vault_token_is_still_a_secret` pins it. The
lesson: a filter added to remove noise has to be measured against what it removes, not
only against what it was aimed at.

**A rule key that was dead on arrival.** The `guards:` key was implemented, documented and
shipped, and never worked for the case anyone would write. The lookup was nested inside an
`isinstance(node.func, ast.Attribute)` branch, so `HOSTNAME.fullmatch(host)` reached it and
`is_clean_host(host)` did not. The tests passed because every test used a method. Caught by
writing the example from the README and running it. There is now a test that asserts the
same YAML with and without the key produces a finding and no finding.

**A false negative that was not one.** Asked for the worst remaining gap, the assistant
produced a confident worked example of taint lost through a container in an object field,
and it was wrong: the engine finds it via the sticky field pre-pass. Caught by running the
snippet before publishing it. Every example in BENCHMARK.md is now executed first, and the
worst false negative it claims is verified missing.

**Overlapping sink patterns produced duplicate findings.** `urllib.request.urlopen` and
`*.urlopen` both matched one call and each emitted a finding, so every true positive was
reported twice and the duplicate counted as a false positive. Sink matching now reports at
most one finding per rule per call site. A rule pack with redundant patterns is normal and
the engine has to be idempotent under it.

**A sanitizer for one rule silently disabled interprocedural analysis for all the others.**
A wrapper named `clean` matched the `*.clean` sanitizer of the *unsafe HTML* rule, and the
call handler treated any sanitizer match as a reason to return early, so it never consulted
the function summary and lost path-traversal analysis entirely. Sanitization is now applied
to the result of full evaluation rather than short-circuiting it.
