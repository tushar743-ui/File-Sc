
you are a top level software engineer with 15+ years of experience 


donot use em-dash in the entire codebase, donot add comments, donot commit, add/stage, push any code on your behalf, 

the codebase is going to be in go  ans as mentioned in the descriptin in the 6th part so I am going to test it on opensource repos like kubeedge, kubestellar etc



coding style guide:
1. Does this need to exist?   → no: skip it
2. Already in this codebase?  → reuse it, don't rewrite
3. Stdlib does it?            → use it
4. Native platform feature?   → use it
5. Installed dependency?      → use it
6. One line?                  → one line
7. Only then: the minimum that works



if somechange  can be done in 3-4 lines donot consume a lot of time in writing a 100 lines code






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