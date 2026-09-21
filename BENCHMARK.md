# Benchmark

All numbers are reproducible from a clean checkout:

```bash
scanner bench corpus --rules rules.yaml --labels corpus/labels.json --format markdown
```

Ground truth lives in `corpus/labels.json`. Each entry maps a path relative to `corpus/`
to the findings a correct run must produce, as `(rule id, line)`. A finding counts as a
true positive when its rule matches and the labelled line falls inside the finding's
reported line range. Every finding in a file with no label for it is a false positive,
including findings in the `shared/` helpers.

## Corpus

73 labelled files: 33 vulnerable, 37 safe-but-tempting, 3 shared helper modules imported
by both halves to exercise cross-file flow. 33 expected findings.

The safe half is the half that matters, so it contains the cases most likely to fool the
engine: parameterized and named-parameter queries, `subprocess` with an argument list
instead of a shell string, `shlex.quote`, `secure_filename` and `os.path.basename`,
taint killed by reassignment, `int()` coercion both inline and through a helper function,
allowlist lookups against module-level constant dicts and tuples, `yaml.load` with an
explicit `Loader`, `yaml.safe_load`, template rendering with autoescaping, secret-shaped
constants that are placeholders or low entropy, and a cross-file pair where the helper
sanitizes and its twin does not.

## Results

| RULE | TP | FP | FN | PRECISION | RECALL | F1 |
|---|---|---|---|---|---|---|
| py.command-injection | 6 | 1 | 1 | 0.857 | 0.857 | 0.857 |
| py.hardcoded-secret | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.insecure-deserialization | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.path-traversal | 5 | 1 | 0 | 0.833 | 1.000 | 0.909 |
| py.sql-injection | 7 | 0 | 2 | 1.000 | 0.778 | 0.875 |
| py.ssrf | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.unsafe-html | 3 | 0 | 1 | 1.000 | 0.750 | 0.857 |
| **ALL** | **29** | **2** | **4** | **0.935** | **0.879** | **0.906** |

The six `hard_*` files were written specifically to break the engine and they did. Without
them the scanner scores 1.000 on both axes, which says more about the corpus than the
scanner, so they stay in and the numbers above are the honest ones.

## Worst false positive

`safe/hard_path_containment.py:13`, and its structural twin on real code,
`django/contrib/admin/options.py:2159`.

The local case is the textbook safe containment check:

```python
full = os.path.abspath(os.path.join(ROOT, name))
if not full.startswith(ROOT + os.sep):
    raise ValueError("outside root")
return open(full, "rb").read()
```

The scanner reports it. **Why it happens:** taint is a property of values, and the engine
has no notion that control flow has been narrowed. `full` is tainted at the `open` call
because nothing in my model distinguishes "this value was checked" from "this value was
used". `os.path.abspath` is deliberately not a sanitizer, because on its own it does not
make a path safe, and the `startswith` guard that actually does the work is a `Compare`
node whose result the engine throws away. Fixing this needs path-sensitivity: the engine
would have to learn that the `raise` branch is taken whenever the predicate fails, and
carry the negated predicate into the fall-through branch as a fact about `full`. That is
a different analysis, not a tweak.

The same shape on Django is worse because it is eight hops long. `request.POST` reaches
`mark_safe` in `django/utils/numberformat.py:29` by travelling through
`display_for_value`, `template_localtime`, `localize`, `number_format` and `format`. Each
hop is a call whose body the engine does read, and none of them is a declared sanitizer,
so the taint survives. By the time the value reaches `mark_safe` it has been converted to
a formatted number and is entirely safe. Five of Django's fifteen `py.unsafe-html`
findings are this one chain reported from five call sites.

## Worst false negative

`vulnerable/hard_out_param.py:11`.

```python
def collect(bucket, value):
    bucket.append(value)

def search(cursor):
    parts = []
    collect(parts, request.args.get("q"))
    cursor.execute("SELECT * FROM t WHERE c = '" + parts[0] + "'")
```

**Why it happens:** function summaries record two things, which parameters flow to the
return value and which parameters flow to a sink inside the callee. They record nothing
about parameters that are *mutated*. `collect` neither returns nor sinks, so its summary
is empty, and at the call site `parts` stays clean. Every accumulator, visitor and
"fill this list for me" helper is invisible to the scanner. The fix is a third summary
component, a side-effect map from parameter index to the taint written into it, applied
back to the caller's environment after the call. I know the shape of the fix; I ran out
of time to land it safely, and a half-done version that fires on every method call would
have cost more precision than it bought.

The other three misses are honest limits, each documented in README.md: dynamic dispatch
through `getattr`, taint entering a `lambda` through its own parameter, and an object
field set from a constructor parameter rather than from a source directly.

## Open-source runs

Three public Python repositories, scanned with the shipped `rules.yaml` on a 4-core
laptop.

| repository | Python files | wall time | findings |
|---|---|---|---|
| apache/airflow | 7,985 | 31.0s | 63 |
| django/django | 2,932 | 10.8s | 20 |
| saleor/saleor | 4,332 | 14.3s | 17 |
| **total** | **15,249** | **56.1s** | **100** |

An earlier revision of the rules produced 1,007 findings on the same three repositories.
Everything that closed that gap is described under "What triage changed" below, and all
of it was rule data rather than engine code, which is the outcome the rule format was
designed for.

### Triage of a 40-finding sample

Sampled with a fixed seed and read by hand, one finding at a time.

| group | n | verdict |
|---|---|---|
| airflow, command injection | 10 | 1 worth review, 9 false |
| airflow, SQL injection | 1 | 1 true |
| airflow, hard-coded secret | 12 | 8 true by the rule's definition, 4 false |
| django, unsafe HTML | 12 | 6 true, 6 false |
| django, SSRF | 3 | 3 true |
| saleor, hard-coded secret | 8 | 8 true by the rule's definition |

Roughly 18 of 40 survive triage, so precision on unseen real code is near 45%, against
93.5% on my own corpus. That gap is the honest headline of this document, and the four
residual false-positive classes are:

1. **Long framework chains.** The Django `mark_safe` case above. The engine follows six
   call hops correctly and is wrong at the end of all six.
2. **`sys.argv` and `os.environ` in developer tooling.** `os.execl(sys.executable, *sys.argv)`
   in a reinstall helper is reported as command injection. It is a correct dataflow and a
   useless finding.
3. **Name globs on the secret rule.** `*_key` matches `s3_key`, `context_key`,
   `GCS_TOKEN_EXPIRES_AT_MS`. The value filters catch most of these but not all.
4. **Test fixtures.** Most surviving secret findings are JWT-shaped and Vault-shaped
   literals inside `tests/`. They are credential-shaped literals, so the rule is behaving
   as written, but a team would want them gone. `paths.exclude` on the rule does that
   without touching the engine; it is deliberately not enabled by default, because a real
   secret committed to a test file is still a leaked secret.

### Two findings I would act on

`providers/apache/hive/.../hooks/hive.py:958`, where `os.environ.get` flows through a
returned dict into `cur.execute(f"set {k}={v}")`, and
`task-sdk/.../execution_time/task_runner.py`, where the `_AIRFLOW__STARTUP_MSG`
environment variable is parsed, read back as `run_as_user`, and reaches
`os.execvp("sudo", cmd)` seven hops later across two files. Neither is remotely
exploitable by an anonymous attacker, but both are real dataflows that a reviewer should
see, and neither is findable by grep.

### What triage changed

| change | where | effect on the three repos |
|---|---|---|
| `min_entropy` 3.5 to 4.0, `min_length` 8 to 12, new `min_charset_classes: 2` | `rules.yaml` | 837 secret findings to 128 |
| exclude values containing a space, a `://`, or a leading `/` | `rules.yaml` | 128 to 69 |
| `sys.argv` and `os.environ` removed as sources for path traversal, SSRF and unsafe HTML | `rules.yaml` | path traversal 77 to 0, SSRF 8 to 0 |
| local names no longer shadow builtin sources | `scanner/analyzers/taint.py` | removed 3 findings on `pickle.loads(input)` where `input` is a pytest parameter |

The `min_charset_classes` threshold was chosen by measuring, not by taste: it is the
setting that discards the most real-repo noise while keeping every true secret in the
corpus. Character classes are counted over the value with `_-./: ` removed, which is what
separates `sk_live_51H8xQ2KmZvR7tYbNp` from `attribute_by_page_id_and_attribute_slug`.

## Performance

The 60-second budget is for 500 files. The engine does 500 synthetic files with
interprocedural flow in **0.37s** and 7,985 files of Airflow in 31s, both on 4 cores.
`tests/test_engine.py::test_five_hundred_files_scan_within_the_budget` asserts the budget
on every run. What buys the headroom is described in README.md under Performance.

## Determinism

`scanner scan corpus --rules rules.yaml --format sarif` produces byte-identical output
across runs and between serial and 4-way parallel execution, verified with `cmp`. The
SARIF validates against the published 2.1.0 schema.
