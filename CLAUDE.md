always remember to read CLAUDE.md before the starting on any session 


you are a top level software engineer with 15+ years of experience 


donot use em-dash in the entire codebase, donot add comments, donot commit, add/stage, push any code on your behalf, 


stack 
SCANNER LANGUAGE    Python
TARGET LANGUAGE     Python
PARSER              ast  (stdlib)
YAML                PyYAML
CLI                 argparse  (stdlib)
TESTS               pytest
SARIF OUTPUT        json  (stdlib)
TABLE OUTPUT        str.ljust()  (stdlib)
BASELINE            json + hashlib  (stdlib)
ENTROPY             math  (stdlib)
PARALLELISM         multiprocessing.Pool.map()  (stdlib)
PATTERN MATCHING    re  (stdlib — rule globs only, not analysis)

External installs: 2 — PyYAML + pytest

scanner/
├── scanner/
│   ├── __init__.py
│   ├── cli.py                 ← argparse subcommands: scan, baseline
│   ├── engine.py              ← KIND_REGISTRY dispatch
│   ├── rules.py               ← PyYAML loader + Rule dataclass
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── base.py            ← AbstractAnalyzer base class
│   │   ├── taint.py           ← taint propagation engine
│   │   └── pattern.py         ← re + math entropy matcher
│   ├── ast_utils/
│   │   ├── __init__.py
│   │   ├── visitor.py         ← base ast.NodeVisitor
│   │   ├── resolver.py        ← import alias resolution
│   │   └── scope.py           ← variable + scope tracking
│   ├── output/
│   │   ├── sarif.py           ← SARIF 2.1.0 via json stdlib
│   │   └── table.py           ← str.ljust() terminal table
│   ├── baseline.py            ← json + hashlib finding identity
│   └── suppression.py         ← ast comment node suppression
├── rules.yaml                 ← all 6 rule classes
├── corpus/
│   ├── vulnerable/            ← 20+ genuinely vulnerable files
│   ├── safe/                  ← 20+ safe-but-tempting files
│   └── labels.json            ← machine-readable ground truth
├── tests/
│   ├── test_taint.py
│   ├── test_pattern.py
│   ├── test_baseline.py
│   ├── test_suppression.py
│   └── test_sarif.py
├── BENCHMARK.md
├── DECISIONS.md
├── README.md
└── pyproject.toml             ← single install command


install anything needed if not in the system 


coding style guide:
1. Does this need to exist?   → no: skip it
2. Already in this codebase?  → reuse it, don't rewrite
3. Stdlib does it?            → use it
4. Native platform feature?   → use it
5. Installed dependency?      → use it
6. One line?                  → one line
7. Only then: the minimum that works



if somechange  can be done in 3-4 lines donot consume a lot of time in writing a 100 lines code


and remeber to make it in such a way that it can be easily tested on opensource repos like kubeedge, kubestellar etc and also make it in a way that it should be fuly scalable and should not have any flaws (use the best industry backend and software engineering practices )



description 
 Static Taint Analyzer
Context
A large part of what Codity does is read code it has never seen and decide whether it contains a security
vulnerability. The difficulty is not finding candidates. Grepping for execute( finds thousands. The difficulty is
that a scanner which cries wolf gets switched off in a week, so what matters is whether untrusted input can actually
reach a dangerous operation, and whether something on the way made it safe.
You are building a scanner that answers that question. It is a real static analysis engine, not a regex pass, and we will
measure it the way we measure our own: precision and recall against a corpus you have never seen.
What you build
A command-line security scanner that analyzes a codebase, tracks untrusted data from where it enters to where it is
dangerous, and reports the ones that connect.
scanner scan ./target --rules rules.yaml --format sarif
> results.sarif
scanner scan ./target --rules rules.yaml --format table
scanner scan ./target --rules rules.yaml --fail-on high
Pick one language to analyze: Python or TypeScript/JavaScript. Analyze it with the language's own parser (Python's
ast module, or the TypeScript compiler API or Babel). Do not write a parser. Do not use regular expressions as
your analysis: matching text is the thing this assignment exists to move past.
The scanner itself may be written in any of Python, TypeScript/Node, or Go, and it does not have to be the same
language it analyzes.
Part 1: The rule format
Rules are data, not code. A user must be able to add a new vulnerability class by editing YAML, with no changes to
your engine. Implement this schema:rules:
- id: py.sql-injection
severity: critical
cwe: CWE-89
message: "Untrusted input reaches a SQL query without parameterization"
kind: taint
sources:
- pattern: flask.request.args.get
- pattern: flask.request.form.*
- pattern: os.environ.get
sinks:
- pattern: "*.execute"
arg: 0
- pattern: "*.executescript"
arg: 0
sanitizers:
- pattern: myapp.db.quote_identifier
- id: py.hardcoded-secret
severity: high
cwe: CWE-798
message: "Hard-coded credential"
kind: pattern
match:
assigned_to: ["*_key", "*_secret", "*password*", "*token*"]
value: literal_string
min_entropy: 3.5
Two rule kinds, taint and pattern , and your engine must support both without special-casing either one
inside the core. If adding a third kind later would mean editing the traversal, your design is wrong. We will look at
this specifically.
Pattern syntax: dotted paths with * matching a single segment. arg selects which argument of a sink call is
dangerous, with arg: any meaning all of them.
Document precisely what your name resolution can and cannot follow, including what happens with aliased
imports, instance methods on objects whose type you do not know, and dynamic attribute access.
Part 2: Taint tracking
This is the core of the assignment. At minimum, within a single function, you must correctly propagate taint
through:Direct assignment, and chains of it
String concatenation, f-strings or template literals, .format() , %
Insertion into and retrieval from a list, dict, tuple, or object attribute
Passing a tainted value as an argument to a call whose return value is then used
Conditional branches, where taint on either branch means the merged value is tainted
And you must correctly kill taint on:
Reassignment of the variable to a clean value
Passage through a declared sanitizer
Values that are provably constant
Beyond a single function, go as far as you can and be explicit about where you stopped. Interprocedural analysis
within one file is expected. Across files is a strong submission. Whatever you do not implement, say so in the
README rather than letting us discover it.
When you report a finding, report the path: where the value entered, each step it travelled, and where it landed. A
finding that says only "line 88 is vulnerable" is worth a fraction of one that shows the route.
Part 3: Rule coverage
Ship rules for at least these six classes, written against real library APIs for your chosen language:
1. SQL injection
2. Command injection
3. Path traversal
4. Server-side request forgery, or unsafe HTML rendering
5. Insecure deserialization
6. Hard-coded secrets, as a pattern rule
Part 4: Output
Primary output is SARIF 2.1.0, because that is what security tooling consumes. It must validate against the
published schema. At minimum every result needs:
ruleId
level
message
a physicalLocation with file URI, line and column
the taint path expressed as codeFlows
Rule metadata including CWE goes in tool.driver.rules .Also provide a readable table format for humans at a terminal.
Part 5: Living with the results
A scanner that reports the same forty findings every run, forever, is unusable. Implement both of:
Inline suppression. A comment on or directly above the flagged line suppresses that finding:
cursor.execute(query)
# codity: ignore[py.sql-injection] query is built from an
allowlisted column name
A suppression with no reason text is itself reported, as a low-severity finding.
A baseline.
scanner baseline --rules rules.yaml ./target > .scanner-baseline.json
scanner scan --rules rules.yaml --baseline .scanner-baseline.json ./target
The second command reports only what is new.
Baselines are the interesting half. Findings must survive code moving. If a developer adds twenty lines at the top of
a file, every finding below shifts, and none of them are new. If a function is renamed, the finding inside it is not
new. Design an identity for a finding that is stable under edits that did not touch it, explain your scheme in
DECISIONS.md , and demonstrate it with a test.
Part 6: Measure yourself
Build a labelled corpus and report your own numbers.
At least 40 files you wrote, split between genuinely vulnerable and safe-but-tempting. The safe half is the half
that matters: parameterized queries, correctly sanitized paths, taint killed by reassignment, constants that look
like secrets. Write the cases you expect to trip your own scanner.
Additionally, run against at least two public open-source repositories of your choosing, and triage a sample
of what came back by hand.
BENCHMARK.md reports precision, recall, and F-score on your own corpus, the per-rule breakdown, and an
honest analysis of your worst false positive and your worst false negative, with the reason each one happens.
We will run your scanner against a corpus of ours that you have not seen.
Constraints
Standard library plus a parser plus a YAML reader. Do not use an existing static analysis framework: no
Semgrep, no CodeQL, no Bandit, no ESLint rule engine, no taint library. Using one is an automatic fail, andwe check.
A test runner and a CLI argument parser are fine.
Deterministic. The same input produces the same bytes out.
Must scan a 500-file repository in under 60 seconds on a normal laptop. Say what you did to get there.
One documented command installs it, one runs it, one runs your tests.
Deliverables
1. The scanner, in a git repository with real commit history. We read the history, and a single commit dumping
4,000 lines reads exactly as it looks.
2. rules.yaml with the six rule classes.
3. Your labelled corpus, with the labels in a machine-readable file so your numbers can be reproduced.
4. BENCHMARK.md , as specified in Part 6.
5. README.md : install, run, architecture in a few paragraphs, your name resolution limits, where your analysis
stops, and what you know is broken.
6. DECISIONS.md , two pages maximum:
How taint is represented, and what you rejected.
Your finding-identity scheme for baselines, and what breaks it.
The precision and recall trade-off you chose, and why you chose that side of it.
The rule you most wanted to write and could not, and what your engine would need.
What you cut, and what you would do with another week.
If you used an AI assistant, two specific things it got wrong that you caught.



also add the files names necessary to be ignored in the .gitignore file like CLAUDE.md, .env etc 


at the end of the session always remeber to mention in the last of claude.md that from the give description how much we have completed and how much is left 

================================================================
STATUS AGAINST THE ASSIGNMENT DESCRIPTION  (session of 2026-09-21)
================================================================

DONE

Part 1  Rule format
  rules.yaml drives everything. kind dispatch via KIND_REGISTRY in engine.py;
  the loader validates only the shared fields and passes the rest through as
  spec, so it knows nothing about taint vs pattern. A third kind = one class +
  one registry line, asserted by tests/test_rules.py.
  Pattern syntax: dotted paths, * = one segment, arg index or "any".
  Added beyond the spec: sink "when" guards (kwarg equals / absent) and a
  kind-agnostic paths.include / paths.exclude on any rule.
  Name resolution limits written up in README.md.

Part 2  Taint tracking
  All required intraprocedural propagation and all required kills, plus
  comprehensions, with, walrus, try, match, augassign.
  Interprocedural within a file: yes. Across files: yes (on-demand memoised
  summaries, recursion guard, depth cap 6).
  Extra: object fields and module globals across functions via a sticky pre-pass.
  Every finding carries the full route; rendered as SARIF codeFlows.

Part 3  Rule coverage
  7 rules: sql-injection, command-injection, path-traversal, ssrf,
  unsafe-html, insecure-deserialization, hardcoded-secret.

Part 4  Output
  SARIF 2.1.0, validated against the published schema. Table format for humans.

Part 5  Living with results
  Inline suppression with reason; reasonless suppression reported as low.
  Baseline survives line shifts, function renames, reformatting and file
  renames. Tested in tests/test_baseline.py.

Part 6  Measure yourself
  73 labelled files (33 vulnerable / 37 safe / 3 shared), corpus/labels.json.
  Precision 0.935, recall 0.879, F1 0.906.
  3 OSS repos scanned (airflow 7985, django 2932, saleor 4332 files),
  40 findings hand-triaged. BENCHMARK.md has per-rule breakdown, worst FP and
  worst FN with causes.

Constraints
  Stdlib + ast + PyYAML only. No analysis framework. Deterministic (serial and
  parallel produce identical bytes). 500 files in 0.37s against a 60s budget.
  One command each to install / run / test.

Deliverables present: rules.yaml, corpus + labels.json, BENCHMARK.md,
README.md, DECISIONS.md.

NOT DONE / LEFT

  1. Git history. Nothing is staged or committed (per your instruction). The
     work is laid out as 12 milestones in the plan file and should be committed
     as a sequence, not one dump: scaffold, rules, ast_utils, engine+pattern,
     intraprocedural taint, interprocedural, suppression+baseline, output+CLI,
     rules.yaml, corpus, OSS triage, docs.
  2. Argument mutation in function summaries. A helper that appends to a list
     you passed it leaves that list clean. Worst false negative.
  3. Path-sensitivity. Both corpus false positives are inline validation
     (regex guard, startswith containment check) that the engine cannot see.
  4. Dynamic dispatch (getattr), lambda parameters, class hierarchies,
     decorators, star imports, local aliasing of a callable.
  5. Real-repo precision is near 45% vs 93.5% on the corpus. Four residual FP
     classes named in BENCHMARK.md.
  6. Baseline signature contains local variable names, so renaming a local at
     the sink makes a finding look new.
  7. Cross-file findings are reported at the caller's call site, so one
     vulnerable helper reached from N call sites yields N findings.

NOTE ON THIS MACHINE
  python3-venv is not installed, so the documented
  "python3 -m venv .venv && .venv/bin/pip install -e .[dev]" cannot run here.
  Tests were run with pytest installed to a scratch dir via pip --target.
  Install python3.12-venv to use the documented path.
