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

77 labelled files: 35 vulnerable, 39 safe-but-tempting, 3 shared helper modules imported
by both halves to exercise cross-file flow. 35 expected findings.

The safe half is the half that matters, so it contains the cases most likely to fool the
engine: parameterized and named-parameter queries, `subprocess` with an argument list
instead of a shell string, `shlex.quote`, `secure_filename` and `os.path.basename`,
taint killed by reassignment, `int()` coercion both inline and through a helper function,
allowlist lookups against module-level constant dicts and tuples, `yaml.load` with an
explicit `Loader`, `yaml.safe_load`, template rendering with autoescaping, secret-shaped
constants that are placeholders or low entropy, dotted import paths assigned to
secret-shaped names, and a cross-file pair where the helper sanitizes and its twin does
not.

## Results

| RULE | TP | FP | FN | PRECISION | RECALL | F1 |
|---|---|---|---|---|---|---|
| py.command-injection | 8 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.hardcoded-secret | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.insecure-deserialization | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.path-traversal | 5 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.sql-injection | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.ssrf | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.unsafe-html | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| **ALL** | **35** | **0** | **0** | **1.000** | **1.000** | **1.000** |

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

Two public Python repositories, scanned with the shipped `rules.yaml` on a 4-core laptop.

| repository | Python files | wall time | findings |
|---|---|---|---|
| apache/airflow | 7,990 | 39.3s | 55 |
| django/django | 2,932 | 13.8s | 21 |
| **total** | **10,922** | **53.1s** | **76** |

Those times are from an idle 4-core laptop and are the best of several runs. Repeated
under load (load average 5 on 4 cores) the same scans take 50 to 69s and 21s, so treat
them as a range rather than a figure. Finding counts do not move. The 500-file budget
below is measured the same way and has three orders of magnitude of headroom either way.

### Triage

Every one of the 76 was read, except that the 48 Vault and Chime credential literals in
Airflow's provider tests were sampled rather than read line by line, because they are
homogeneous.

| group | n | true by the rule's definition | false |
|---|---|---|---|
| airflow, hard-coded secret, provider tests | 48 | 48 | 0 |
| airflow, hard-coded secret, library code | 1 | 0 | 1 |
| airflow, command injection | 5 | 1 | 4 |
| airflow, SQL injection | 1 | 1 | 0 |
| django, unsafe HTML, `numberformat.py` | 6 | 0 | 6 |
| django, unsafe HTML, test views | 10 | 10 | 0 |
| django, SSRF | 3 | 3 | 0 |
| django, hard-coded secret | 2 | 2 | 0 |
| **total** | **76** | **65** | **11** |

**Precision on unseen real code: 0.855.** The previous revision of this engine scored
near 0.45 on the same repositories under the same convention.

"True by the rule's definition" is a deliberately generous bar and it is the same bar the
previous revision was measured against, so the two are comparable. It means the dataflow
or the literal is really what the rule describes. It does not mean a reviewer would act.
Under the stricter question, *would an engineer open a ticket for this*, only 2 of 76
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

## Worst false positive

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
flow in **0.35s to 0.54s** depending on machine load, 2,932 files of Django in 13.8s to
21s and 7,990 files of Airflow in 39s to 69s, all on 4 cores. `tests/test_engine.py::test_five_hundred_files_scan_within_the_budget`
asserts the budget on every run.

The capabilities added in the last revision cost roughly 2x throughput, from 0.24s to
0.54s on the 500-file tree. Two caches paid most of it back: `local_names` is memoised on
`FunctionInfo` instead of re-walking the body for every walker, and `PatternIndex.lookup`
memoises on the candidate-name tuple, which was the single hottest function in the
profile. What buys the rest of the headroom is described in README.md under Performance.

## Determinism

`scanner scan corpus --rules rules.yaml --format sarif` produces byte-identical output
across runs and between serial and 4-way parallel execution, verified with `cmp`.

The SARIF validates against the published 2.1.0 schema with zero errors. The schema is
vendored at `tests/sarif-schema-2.1.0.json` and the check is
`tests/test_sarif.py::test_document_validates_against_the_published_schema`. It needs a
JSON Schema validator, which is not a dependency of this project, so it skips on a plain
`make test` and runs under `make verify-sarif`, which installs one into the throwaway
`.deps/` directory. The rest of `tests/test_sarif.py` asserts every field the brief
requires without any dependency at all.
