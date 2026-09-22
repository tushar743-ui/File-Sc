# Benchmark

All numbers are reproducible from a clean checkout:

```bash
make bench
```

Ground truth lives in `corpus/labels.json`. Each entry maps a path relative to `corpus/`
to the findings a correct run must produce, as `(rule id, line)`. A finding counts as a
true positive when its rule matches and the labelled line falls inside the finding's
reported line range. Every finding in a file with no label for it is a false positive.

Findings are reported at the **sink**, so a flow that crosses files is labelled in the
file holding the sink, not in the file holding the entry point. One finding is produced
per distinct (entry point, sink) pair.

## Corpus

86 labelled files: 41 vulnerable, 42 safe-but-tempting, 3 shared helper modules imported
by both halves to exercise cross-file flow. 41 expected findings.

The safe half is the half that matters, so it contains the cases most likely to fool the
engine: parameterized and named-parameter queries, `subprocess` with an argument list
instead of a shell string, `shlex.quote`, `secure_filename` and `os.path.basename`,
taint killed by reassignment, `int()` coercion both inline and through a helper function,
allowlist lookups against module-level constant dicts and tuples, `yaml.load` with an
explicit `Loader`, `yaml.safe_load`, a Django `HttpResponse` carrying tainted JSON under
an explicit `application/json` content type, template rendering with autoescaping, secret-shaped
constants that are placeholders or low entropy, dotted import paths assigned to
secret-shaped names, and a cross-file pair where the helper sanitizes and its twin does
not.

## Results

| RULE | TP | FP | FN | PRECISION | RECALL | F1 |
|---|---|---|---|---|---|---|
| py.command-injection | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.hardcoded-secret | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.insecure-deserialization | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.path-traversal | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.sql-injection | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.ssrf | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.unsafe-html | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| **ALL** | **41** | **0** | **0** | **1.000** | **1.000** | **1.000** |

### Read this number sceptically

A perfect score on a corpus I wrote myself is close to meaningless as evidence, and it is
not the number to judge the scanner by. The honest description of how it happened: the
corpus contains nine `hard_*` files written specifically to break the engine, they all
failed for a while, and then the engine was extended until they passed. That is a
legitimate development loop, but it means the corpus has stopped discriminating. It now
serves as a regression suite, not as a measurement.

The numbers worth reading are the open-source ones below, on code nobody wrote for this
scanner.

## Open-source runs

Five public Python repositories, scanned with the shipped `rules.yaml` on a 4-core
laptop, with `--format summary`.

| repository | Python files | wall time | sinks | findings |
|---|---|---|---|---|
| getsentry/sentry | 8,163 | 51-75s | 76 | 83 |
| apache/airflow | 7,995 | 30-47s | 55 | 55 |
| django/django | 2,932 | 10-14s | 19 | 24 |
| pallets/flask | 83 | 0.3s | 0 | 0 |
| psf/requests | 37 | 0.3s | 0 | 0 |
| **total** | **19,210** | | **150** | **162** |

Each is one command: `make scan-repo REPO=getsentry/sentry FMT=summary`, which clones
shallow into `.repos/` and scans it. Times are a range across runs on an idle and a
loaded machine; finding counts do not move.

**Sinks and findings are different numbers and both matter.** One dangerous line reached
by three different entry points is three findings and one sink. The SARIF keeps them
apart, because a reviewer fixing the line wants every route that reaches it. The
`summary` format clusters them, because a reviewer triaging 8,000 files wants to know how
many lines need looking at. Sentry's 83 findings are 76 lines; one false positive in
`web/helpers.py` accounts for 6 of them on its own.

Flask and Requests returning nothing is the result worth stating. Both are widely audited
libraries with no web entry points of their own, so zero is the correct answer, and a
scanner that produced findings there would be producing noise.

### Triage

Airflow and Django were read finding by finding, except that the 48 Vault and Chime
credential literals in Airflow's provider tests were sampled rather than read line by
line, because they are homogeneous. All 7 of Sentry's non-secret sinks were read; its 69
secret findings were sampled, 12 read.

| group | n | true by the rule's definition | false |
|---|---|---|---|
| airflow, hard-coded secret, provider tests | 48 | 48 | 0 |
| airflow, hard-coded secret, library code | 1 | 0 | 1 |
| airflow, command injection | 5 | 1 | 4 |
| airflow, SQL injection | 1 | 1 | 0 |
| django, unsafe HTML, `numberformat.py` | 6 | 0 | 6 |
| django, unsafe HTML, `shortcuts.py` + `format_html` | 3 | 0 | 3 |
| django, unsafe HTML, test views | 10 | 10 | 0 |
| django, SSRF | 3 | 3 | 0 |
| django, hard-coded secret | 2 | 2 | 0 |
| sentry, hard-coded secret, test fixtures | 60 | 60 | 0 |
| sentry, hard-coded secret, library and docs | 9 | 6 | 3 |
| sentry, unsafe HTML | 10 | 0 | 10 |
| sentry, path traversal | 2 | 1 | 1 |
| sentry, SSRF | 2 | 0 | 2 |
| **total** | **162** | **132** | **30** |

**Precision on unseen real code: 0.815 per finding, 0.880 per sink.** The difference is
entirely the per-entry-point duplication of false positives, which is why the clustered
number is the fairer one to quote and the raw one is the one that is honest about how
much output a reviewer actually wades through. The previous revision of this engine
scored near 0.45 on airflow and django under the same convention.

"True by the rule's definition" is a deliberately generous bar and it is the same bar the
previous revision was measured against, so the two are comparable. It means the dataflow
or the literal is really what the rule describes. It does not mean a reviewer would act.
Under the stricter question, *would an engineer open a ticket for this*, only 2 of 162
survive: the two named below. Most of the rest are credential-shaped literals in test
fixtures, which are correctly identified and rarely interesting.

### Two findings I would act on

`providers/apache/hive/.../hooks/hive.py:958`, where `os.environ.get` flows through a
returned dict into `cur.execute(f"set {k}={v}")`, and
`task-sdk/.../execution_time/task_runner.py:1242`, where the `_AIRFLOW__STARTUP_MSG`
environment variable is parsed, read back as `run_as_user`, and reaches `os.execvp`
several hops later across two files. Neither is remotely exploitable by an anonymous
attacker, but both are real dataflows that a reviewer should see, and neither is findable
by grep.

### The bug this revision found, and what it cost

Testing against a hand-written file of known vulnerabilities, rather than against the
corpus, exposed a false negative in the summary machinery. `report()` appended the first
qualifying flow into a sink argument and then returned, so a callee whose sink expression
read more than one tainted value recorded only one of them. Which one survived was
decided by source position:

```python
def query(cursor, table, term):
    cursor.execute("SELECT * FROM " + table + " WHERE x = '" + term + "'")

query(cursor, "reports", request.args.get("q"))     # missed
query(cursor, request.args.get("q"), "reports")     # found
```

That is a textbook interprocedural SQL injection, and it was missed whenever the tainted
argument was not the first one to appear in the sink expression. The same cause hid
tainted `self` fields behind clean ones. Fixed by recording every flow;
`tests/test_taint.py::test_summary_keeps_every_param_flow_not_only_the_first` and its
field twin fail without the fix.

It cost 4 false positives: Django's `shortcuts.py:28` and `utils/html.py:145`, and
Sentry's `web/helpers.py:42`. All three are the same shape as the pre-existing
`numberformat.py` false positive, autoescaped template output reaching `HttpResponse` or
`mark_safe`, and `format_html`, which escapes through `map(conditional_escape, args)`, a
higher-order call the engine does not follow. Recall went up on the class of bug the
assignment is about; precision paid for it in a class already documented as broken. Given
that dropping all but one flow is a correctness hole rather than a tuning knob, that is
the right side of the trade.

### Rule coverage gaps closed in the same pass

The same file was silently clean on seven genuine vulnerabilities. Six were missing
sources or sinks, fixed in `rules.yaml` with no engine change:

| case | cause |
|---|---|
| `pickle.loads(request.get_data())` | `get_data` was not a source, only `request.data` |
| `yaml.load(request.get_data())` | same |
| `make_response("<p>" + c + "</p>")` | not a sink |
| `tarfile.open(root + name)` | not a sink |
| `shelve.open(root + name)` | not a sink, and it is both path traversal and deserialization |
| `Path(root + name).read_text()` | needed a new `arg: receiver` selector |
| `request.headers["X"]`, `request.files["x"]` | listed only as `headers.*`, which matches an attribute segment and never a subscript |

The last one is the interesting one. `arg` selects a call argument, but `read_text()`
takes none: the tainted value is the receiver. `arg: receiver` was added alongside the
integer and `any` forms, which is one line in the schema and three in the analyzer.

The first attempt also folded the receiver into `arg: any`, which was wrong. The brief
defines `any` as all arguments, and the broader reading immediately produced a false
positive on Sentry: `queryset.extra(select=select_extra)`, where `queryset` is tainted
only by a parameterized `Q(version__icontains=query)` ORM filter and `select_extra` holds
nothing but literals. Reverted to opt-in. These additions cost **zero** new findings
on Flask, Requests, Django and Airflow.

The subscript row is worth its own line. `request.args["cmd"]` was a source and
`request.headers["X-Cmd"]` was not, because `args` was listed both bare and as `args.*`
while `headers`, `files`, `cookies` and `values` were listed only as `.*`. Four of
Flask's seven request containers were sources under `.get()` and not under `[]`. Four
lines of `rules.yaml`.

## Worst false positive, Sentry

`sentry/utils/samples.py:174`. Sentry writes the containment check correctly:

```python
expected_commonpath = os.path.realpath(samples_root)
json_path = os.path.join(samples_root, json_file)
json_real_path = os.path.realpath(json_path)
if expected_commonpath != os.path.commonpath([expected_commonpath, json_real_path]):
    raise SuspiciousFileOperation("potential path traversal attack detected")
...
with open(json_path) as fp:
```

The engine does model guards that exit: `if not validator(x): raise` kills taint on `x`.
This one it cannot see, for two reasons. The guard tests `json_real_path`, a value derived
from `json_path`, not `json_path` itself, so the kill would have to propagate backwards
along the derivation. And the condition is an inequality between two computed expressions
rather than a predicate applied to the value, so there is no argument position to attach
the kill to. Recognising it needs the guard analysis to reason about which variables a
condition constrains rather than which variable it is called on, which is a small
alias/dependence analysis the engine does not have.

The same file shows the second-worst. `atlassian_connect.py:139`:

```python
key_response = requests.get(f"https://connect-install-keys.atlassian.com/{key_id}")
```

`key_id` is attacker-influenced, so the URL string is tainted and the SSRF rule fires
twice, once per entry point. But the scheme and host are literal, so no request can be
steered off `atlassian.com`. Ruling it out needs a constant-prefix domain on strings: if
the tainted part begins after a literal `scheme://host/`, it is a path injection, not an
SSRF. That is a genuinely useful domain to add and it is the first thing I would build
with more time.

## Worst false positive, Django

`django/utils/numberformat.py:29`, reported three times.

```python
def format(number, decimal_sep, decimal_pos=None, ...):
    if number is None or number == "":
        return mark_safe(number)
```

The engine follows `request.POST.get` through `ModelAdmin.get_object`, into a queryset
lookup, out through `str(obj)`, across two more files, and into `mark_safe`. Every hop is
a correct dataflow step. The conclusion is still wrong, for two reasons the engine cannot
see: the value that reaches `mark_safe` is a number, not the attacker's string, and
`mark_safe` on a number cannot produce markup. Fixing it needs type inference, which this
engine does not have.

It shows up three times because three admin views are distinct entry points into the same
sink. That is the intended behaviour, and here it makes one wrong conclusion look like
three. Clustering by sink in the table output would hide the noise without losing the
paths, and is the first thing I would add.

## Worst false negative

This was the multi-flow bug described above until this revision, which is a reminder that
the worst false negative is the one you have not looked for yet: it survived 110 passing
tests and a corpus scoring 1.000 because every corpus case happened to put the tainted
value first. What follows is the worst one remaining.

A callable stored in a container and dispatched out of it:

```python
HANDLERS = {"run": os.system}


def go():
    HANDLERS["run"]("echo " + request.args.get("cmd"))
```

The engine resolves a callable through a variable (`runner = os.system`) and through
`getattr(os, "system")`, because both bind a name to a dotted path it can name. It does
not resolve one through a subscript, because `HANDLERS["run"]` requires knowing the
container's contents at the index, and the value tracked for `HANDLERS` is taint, not
identity. The sink is never recognised as a sink, so no amount of correct taint
propagation helps.

The fix is a second, small abstract domain carried alongside taint: for each key, the set
of dotted paths the value may name. Constant containers are already detected for the
allowlist logic, so the information is within reach. The same domain would fix dispatch
tables, plugin registries and `functools.partial`, which is why it is the next thing I
would build.

Verified missing: `scanner scan` on that file reports nothing.

## Residual false-positive classes

1. **Long framework chains.** The `numberformat.py` case. The engine follows six call hops
   correctly and is wrong at the end of all six.
2. **`sys.argv` and `os.environ` in developer tooling.** `os.execl(sys.executable, *sys.argv)`
   in a reinstall helper is reported as command injection. Correct dataflow, useless
   finding. Four of Airflow's five command-injection findings are this.
3. **Hyphenated config keys on the secret rule.** `GCS_TOKEN_EXPIRES_AT_MS =
   "gcs.oauth2.token-expires-at"` survives the dotted-path filter because a hyphen is not
   an identifier character.
4. **Test fixtures.** Most surviving secret findings are JWT-shaped and Vault-shaped
   literals inside `tests/`. The rule behaves as written. `paths.exclude` on the rule
   removes them without touching the engine; it is deliberately not enabled by default,
   because a real secret committed to a test file is still a leaked secret.
5. **Autoescaped template output.** `HttpResponse(render_to_string(...))` and
   `mark_safe(format_string.format(*map(conditional_escape, args)))`. The tainted value
   really does reach the sink; what the engine cannot see is that the framework escaped
   it on the way, either inside the template engine or through a sanitizer passed as a
   function to `map`. This is now the largest single class: Django's `shortcuts.py`,
   `utils/html.py` and `numberformat.py`, and Sentry's `web/helpers.py`, which alone
   accounts for 6 of Sentry's 83 findings. Following sanitizers through higher-order
   calls would fix the `format_html` half; the template half needs the engine to treat
   a template renderer's return value as escaped, which is one line of `sanitizers:` per
   framework and is not shipped because it is wrong for `render_template_string`.

## What triage changed

| change | where | effect |
|---|---|---|
| `min_entropy` 3.5 to 4.0, `min_length` 8 to 12, new `min_charset_classes: 2` | `rules.yaml` | 837 secret findings to 128 |
| exclude values containing a space, a `://`, or a leading `/` | `rules.yaml` | 128 to 69 |
| `sys.argv` and `os.environ` removed as sources for path traversal, SSRF and unsafe HTML | `rules.yaml` | path traversal 77 to 0, SSRF 8 to 0 |
| local names no longer shadow builtin sources | `scanner/analyzers/taint.py` | removed 3 findings on `pickle.loads(input)` where `input` is a pytest parameter |
| validation guards that exit kill taint | `scanner/analyzers/taint.py` | both corpus false positives removed |
| base-class method resolution | `scanner/analyzers/taint.py` | no change on these two repos, large change on class-heavy code |
| `exclude_identifier_path` on the secret rule | `rules.yaml` + `pattern.py` | removed 3 dotted import paths assigned to `*_KEY` / `*SECRET*` names |

The `min_charset_classes` threshold was chosen by measuring, not by taste: it is the
setting that discards the most real-repo noise while keeping every true secret in the
corpus. Character classes are counted over the value with `_-./: ` removed, which is what
separates `sk_live_51H8xQ2KmZvR7tYbNp` from `attribute_by_page_id_and_attribute_slug`.

`exclude_identifier_path` has a cautionary history worth recording. The first version
excluded any dot-separated string whose segments were all identifiers. That silently
dropped `VAULT_TOKEN = "s.FnL7qg0YnHZDpf4zKKuFy0UK"`, a real Vault token shape, while
keeping a near-identical one whose segment was one character longer. It now requires at
least three segments, which no two-part token shape has.
`tests/test_pattern.py::test_a_two_segment_vault_token_is_still_a_secret` pins it.

## Performance

The 60-second budget is for 500 files. The engine does 500 files with interprocedural
flow in **0.35s to 0.54s** depending on machine load, 2,932 files of Django in 13.4s to
21s, 7,995 files of Airflow in 40s to 69s and 8,163 files of Sentry in 71s to 91s, all on
4 cores. `tests/test_engine.py::test_five_hundred_files_scan_within_the_budget` asserts
the budget on every run.

The capabilities added in an earlier revision cost roughly 2x throughput, from 0.24s to
0.54s on the 500-file tree. Two caches paid most of it back: `local_names` is memoised on
`FunctionInfo` instead of re-walking the body for every walker, and `PatternIndex.lookup`
memoises on the candidate-name tuple, which was the single hottest function in the
profile. What buys the rest of the headroom is described in README.md under Performance.

### Memory, which is what actually breaks at repository scale

Wall time was never the thing that would fail first. Resolving a call into another file
parses that file and holds the parsed module so the next resolution is cheap, and the
cache that held those modules was unbounded. On Sentry, 8,163 files and 333 MB, worker
memory climbed linearly through the scan and passed **4.5 GB** across eight workers
without levelling off. Nothing failed at that size, but nothing was stopping it either:
the ceiling was the repository, not the scanner.

The cache is now an LRU of `MODULE_CACHE_SIZE` parsed modules per worker, so peak memory
is flat in repository size. Measured on Sentry, sampling summed worker RSS every two
seconds:

| cache size | peak worker RSS | wall time |
|---|---|---|
| unbounded | 4.5 GB and rising | 77s |
| 128 | 753 MB | 99s |
| **512 (shipped)** | **1.2 GB** | **83s** |

512 was chosen off that table: it costs nothing measurable against unbounded and buys a
hard ceiling. Two other bounds were already in place and matter for the same reason:
files over `MAX_FILE_BYTES` (2 MB) are skipped rather than parsed, and a file that fails
to parse is skipped rather than failing the run.

Profiling the bounded engine showed `Resolver.__init__` walking each module's AST twice,
once for imports and once for module-level constants, at about 20% of scan time. Merged
into one walk. A 549-file Sentry subtree went from 12.1s to 5.2s single-process.

## Determinism

`scanner scan corpus --rules rules.yaml --format sarif` produces byte-identical output
across runs and between serial and 4-way parallel execution, verified with `cmp`.

The bounded module cache does not weaken this. Cache eviction changes only whether a file
is re-parsed, never what is found, so the same check on Django at 2,932 files, where
eviction actually happens, is also byte-identical between 1 worker and 8.
`tests/test_engine.py::test_module_cache_is_bounded_and_results_unchanged` pins both
halves: the cache never exceeds its bound, and the findings match an unbounded run.

The SARIF validates against the published 2.1.0 schema with zero errors. The schema is
vendored at `tests/sarif-schema-2.1.0.json` and the check is
`tests/test_sarif.py::test_document_validates_against_the_published_schema`. It needs a
JSON Schema validator, which is not a dependency of this project, so it skips on a plain
`make test` and runs under `make verify-sarif`, which installs one into the throwaway
`.deps/` directory. The rest of `tests/test_sarif.py` asserts every field the brief
requires without any dependency at all.
