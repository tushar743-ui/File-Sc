# Decisions

## How taint is represented, and what I rejected

A tainted value is a tuple of `Flow` records. Each carries the set of rule ids it is
dangerous for, an origin (a real source, or parameter *i* of the enclosing function), the
ordered `Step`s travelled, and an optional field tag naming which attribute of an object
holds it. The environment maps a variable path to that tuple; absent and empty both mean
clean.

Carrying rule ids inside the flow is the decision everything hangs off. The alternative
was running the interpreter once per rule: simpler, and N times the work for N rules.
Instead one traversal serves every taint rule at once. A source contributes the ids of the
rules that named it, a sanitizer subtracts the ids of the rules that declared it, and a
sink fires only if its own id survived the trip, so `html.escape` kills XSS without
pretending to fix SQL injection.

The field tag is what keeps constructor analysis honest. `Repo(request)` yields a value
whose flows are tagged `term`, because `__init__` assigned a source to `self.term`. A
later `repo.run()` reading `self.other` filters those flows out; one reading `self.term`
reports. Without the tag the choice was between ignoring constructors and treating every
field of a dirty object as dirty.

Flows are immutable, so merging branches is a set union with a deterministic tie-break.
The join keeps one flow per `(origin, rules, field)`, preferring the shortest path, capped
at six flows and twenty-four steps. Those caps are the only reason loops terminate
cheaply.

**Rejected: points-to analysis.** Containers are field-insensitive, so `d["safe"]` is
dirty once `d["bad"]` is. Wrong in the direction of over-tainting, and a real heap model
would have cost most of the budget for a bug class my corpus barely contains.

**Rejected: a lattice with a separate "sanitized" state.** Sanitization is subtraction
from a rule set. A value clean for one rule and dirty for another must be representable,
and a scalar lattice cannot do it.

**Rejected: SSA or a real CFG.** This is an abstract interpreter over the AST. Loops run
their body twice and merge with the pre-loop environment. In place of a CFG I took two
syntactic approximations: a branch that always exits does not contribute to the merge, and
when exactly one branch of an `if` exits, values named by a validating predicate in the
test are killed afterwards. That is not path-sensitivity, it is "code after a guard that
rejects has been guarded". It is wrong when the predicate checks a different property than
the sink cares about, and it still removed both remaining corpus false positives.

## Finding identity for baselines

A fingerprint is `sha256(rule id, file path, signature, ordinal)`. The signature is the
sink pattern, the origin label, and `ast.dump` of the sink call after a round trip through
`ast.unparse`, with every identifier rewritten to `_`. So it describes the *shape* of the
call and its literals, not the names around it.

Deliberately absent: line numbers, columns, the enclosing function name, formatting, and
local variable names. Inserting twenty lines above a finding, renaming the function around
it, reformatting the call, and renaming a local at the sink all keep it out of the new set.
Each is tested in `tests/test_baseline.py`. File renames are handled by a second, path-free
fingerprint consulted only when the baseline entry's file is absent from the scan, so
moving `app.py` to `views.py` keeps the finding while copy-pasting a vulnerable function
into a new file correctly reports a new one.

**What breaks it.** Editing the flagged statement, which is intended. Reordering two
byte-identical findings, because the ordinal is positional. And anonymising identifiers
means two findings differing only by variable name now share a signature, so deleting the
first makes the second look new. Renaming a variable is common; deleting one of two
otherwise identical sinks is rare. I took that trade knowingly.

## The precision and recall trade-off

Recall inside the engine, precision inside the rules.

The engine over-approximates: an unknown call returns tainted if any argument or the
receiver is tainted, and taint on either branch taints the merge. That is the only way to
survive code calling libraries the analyser has never heard of.

Precision is bought back in rule data, the part a user can change without reading my
source. Sinks carry an argument index, so a parameterized query is silent, and a `when`
guard, so `subprocess.run` is dangerous with `shell=True` and quiet without it.

The sharpest instance is severity by source. `flask.request.args.get` and `os.environ.get`
both reach `cursor.execute`, and only one is an attack: whoever can set your environment
already owns the machine, and does not need your SQL bug. Treating the two alike is what
made Airflow report six criticals nobody would act on. So the three rules accepting both
source sets became six, each pair identical but for `sources:`, the local half at medium.
Airflow went from six criticals to zero, the same 55 findings, none lost and none
reclassified as safe. YAML anchors keep one copy of each sink list. No engine change: the
severity of a finding is a property of where the data came from, and that lives in the
data, which is the clearest evidence the format does what Part 1 asked.

Two exceptions where I spent engine code on precision. Provably-constant containers, since
treating `ALLOWED.get(user_input)` as tainted poisons a class of correct programs. And the
guard rule above, which removed a false-positive class no rule edit could reach: the thing
to suppress is a shape in the user's code, not a name they could list.

I would rather miss a dispatch table than report Django's number formatter. Real-repo
precision is 0.815 per finding and 0.880 per sink, and the thing it still reports is
Django's number formatter.

That side was tested this revision. A summary bug dropped every flow into a sink argument
but the first, missing an interprocedural injection whenever the tainted argument was not
the first to appear. Fixing it cost four false positives, all autoescaped template output.
I took the recall: a rule cannot recover a flow the engine never recorded, whereas a
false-positive class is a rule edit away.

## The rule I most wanted to write and could not

A rule that follows a callable held in data. No rule I can write fires on

```python
HANDLERS = {"run": os.system}
HANDLERS["run"]("echo " + request.args.get("cmd"))
```

because the engine never learns that the value at `HANDLERS["run"]` *is* `os.system`.
Dispatch tables, plugin registries, Celery task maps and `functools.partial` all have this
shape, and they are where a codebase hides its dangerous operations.

It needs a second abstract domain beside taint: for each environment key, the set of
dotted paths the value may name, propagated through assignment, containers and returns,
and consulted at every call site before pattern matching. Not conceptually hard, but every
place that reads a taint tuple would read a pair. A week, not an afternoon.

## What I cut, and what another week would buy

Cut: comprehension bodies as callees; decorators that replace the function, analysed as if
absent; `*args`/`**kwargs`, unioned rather than matched positionally; real MRO, so base
resolution takes the first base defining a name; container field-sensitivity; and
callables held in data.

Another week, in order: the dotted-path domain, which also fixes decorators, `partial` and
dispatch tables at once. Then an argv-vector domain, since taint in a non-zeroth element of
a list handed to `os.spawnlp` or `os.execvp` cannot change which program runs, and that
shape is four of Airflow's five command-injection hits, leaving only the genuine
`shell=True` one. Then a call graph built once per scan instead of
resolved on demand, which would cut the 33s Airflow run. Then container field-sensitivity.

