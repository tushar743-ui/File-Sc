from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace
from typing import Iterator

from ..ast_utils.scope import FUNCTION_NODES, FunctionInfo, ModuleInfo
from ..ast_utils.visitor import location
from ..ast_utils.resolver import LOOKUP_METHODS, READONLY_METHODS
from ..rules import PatternIndex, PatternSpec, RuleError, parse_pattern_specs
from .base import AbstractAnalyzer, Finding, Step

MAX_FLOWS = 6
MAX_STEPS = 24
MAX_DEPTH = 6

VALUE_KILLING_CALLS = frozenset(
    {
        "int", "float", "bool", "complex", "len", "hash", "id", "ord",
        "round", "abs", "isinstance", "issubclass", "callable", "type",
    }
)


@dataclass(frozen=True)
class Flow:
    rules: frozenset
    param: int
    steps: tuple[Step, ...]

    def extend(self, step: Step) -> "Flow":
        if self.steps and self.steps[-1].line == step.line and self.steps[-1].file == step.file:
            return self
        if len(self.steps) >= MAX_STEPS:
            return self
        return replace(self, steps=self.steps + (step,))

    @property
    def order(self) -> tuple:
        return (self.param, len(self.steps), self.steps, tuple(sorted(self.rules)))


Taint = tuple
EMPTY: Taint = ()


def join(*taints: Taint) -> Taint:
    best: dict[tuple, Flow] = {}
    for taint in taints:
        for flow in taint:
            key = (flow.param, flow.rules)
            current = best.get(key)
            if current is None or flow.order < current.order:
                best[key] = flow
    if len(best) <= 1:
        return tuple(best.values())
    return tuple(sorted(best.values(), key=lambda f: f.order))[:MAX_FLOWS]


def strip_rules(taint: Taint, removed: frozenset) -> Taint:
    out = []
    for flow in taint:
        remaining = flow.rules - removed
        if remaining:
            out.append(replace(flow, rules=remaining))
    return tuple(out)


def extend_all(taint: Taint, step: Step) -> Taint:
    return tuple(flow.extend(step) for flow in taint)


@dataclass(frozen=True)
class SinkSpec:
    rule_id: str
    pattern: str
    arg: object
    when: dict = field(default_factory=dict, compare=False)


@dataclass
class Summary:
    params: tuple[str, ...]
    return_flows: tuple[tuple[int, frozenset, tuple[Step, ...]], ...] = ()
    return_taint: Taint = EMPTY
    sink_flows: tuple[tuple[SinkSpec, int, frozenset, tuple[Step, ...], tuple], ...] = ()
    self_fields: tuple[tuple[str, int, frozenset, tuple[Step, ...]], ...] = ()


EMPTY_SUMMARY = Summary(params=())


def _step(module: ModuleInfo, node: ast.AST, label: str) -> Step:
    line, col, end_line, end_col = location(node)
    return Step(module.rel_path, line, col, end_line, end_col, label, module.snippet(line))


class _Walker:
    def __init__(
        self,
        engine: "TaintAnalyzer",
        module: ModuleInfo,
        func: FunctionInfo | None,
        depth: int,
        record_summary: bool,
    ) -> None:
        self.engine = engine
        self.module = module
        self.resolver = module.resolver
        self.func = func
        self.depth = depth
        self.record_summary = record_summary
        self.env: dict[str, Taint] = {}
        self.types: dict[str, str] = {}
        self.findings: list[Finding] = []
        self.returns: list[Flow] = []
        self.sink_flows: list[tuple] = []
        self.field_flows: list[tuple] = []
        self.sticky_names: frozenset[str] = frozenset()
        self.sticky_writes: dict[str, Taint] = {}
        self.bound: frozenset[str] = (
            local_names(func.node) if func is not None else frozenset()
        )

    def run(self, body: list) -> None:
        self.exec_body(body)

    def key_of(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self.key_of(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Subscript):
            base = self.key_of(node.value)
            return f"{base}[]" if base else None
        return None

    def clear_subkeys(self, name: str) -> None:
        prefixes = (name + ".", name + "[")
        for key in [k for k in self.env if k.startswith(prefixes)]:
            del self.env[key]

    def set_key(self, key: str, taint: Taint, node: ast.AST | None = None) -> None:
        if node is not None and taint:
            taint = extend_all(taint, _step(self.module, node, f"{key} holds tainted data"))
        self.env[key] = taint
        base = key.split(".")[0].split("[")[0]
        if base == key:
            self.clear_subkeys(key)
        elif taint:
            self.env[base] = join(self.env.get(base, EMPTY), taint)
        if taint and base != key and (base == "self" or base in self.sticky_names):
            escaping = tuple(flow for flow in taint if flow.param < 0)
            if escaping:
                self.sticky_writes[key] = join(self.sticky_writes.get(key, EMPTY), escaping)

    def get_key(self, key: str) -> Taint:
        return self.env.get(key, EMPTY)

    def assign(self, target: ast.AST, taint: Taint, node: ast.AST) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.assign(element, taint, node)
            return
        if isinstance(target, ast.Starred):
            self.assign(target.value, taint, node)
            return
        key = self.key_of(target)
        if key is None:
            if isinstance(target, (ast.Attribute, ast.Subscript)):
                self.eval(target.value)
            return
        self.set_key(key, taint, node)
        if self.record_summary and isinstance(target, ast.Attribute):
            if isinstance(target.value, ast.Name) and target.value.id == "self":
                for flow in taint:
                    if flow.param >= 0:
                        self.field_flows.append(
                            (target.attr, flow.param, flow.rules, flow.steps)
                        )

    def exec_body(self, body: list) -> None:
        for statement in body:
            self.exec_stmt(statement)

    def exec_stmt(self, node: ast.AST) -> None:
        handler = getattr(self, "st_" + type(node).__name__, None)
        if handler is None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.eval(child)
            return
        handler(node)

    def branch(self, bodies: list[list]) -> None:
        before = dict(self.env)
        results = []
        for body in bodies:
            self.env = dict(before)
            self.exec_body(body)
            results.append(self.env)
        self.env = merge_envs(results) if results else before

    def st_Assign(self, node: ast.Assign) -> None:
        taint = self.eval(node.value)
        self.track_type(node)
        for target in node.targets:
            self.assign(target, taint, node)

    def st_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.assign(node.target, self.eval(node.value), node)

    def st_AugAssign(self, node: ast.AugAssign) -> None:
        key = self.key_of(node.target)
        taint = join(self.eval(node.value), self.get_key(key) if key else EMPTY)
        self.assign(node.target, taint, node)

    def st_Expr(self, node: ast.Expr) -> None:
        self.eval(node.value)

    def st_Return(self, node: ast.Return) -> None:
        if node.value is None:
            return
        taint = self.eval(node.value)
        if taint:
            step = _step(self.module, node, "value returned to the caller")
            self.returns.extend(extend_all(taint, step))

    def st_If(self, node: ast.If) -> None:
        self.eval(node.test)
        self.branch([node.body, node.orelse])

    def st_While(self, node: ast.While) -> None:
        self.eval(node.test)
        self.loop(node.body, node.orelse)

    def st_For(self, node: ast.For) -> None:
        taint = self.eval(node.iter)
        self.assign(node.target, taint, node)
        self.loop(node.body, node.orelse)

    st_AsyncFor = st_For

    def loop(self, body: list, orelse: list) -> None:
        before = dict(self.env)
        self.exec_body(body)
        self.exec_body(body)
        after = self.env
        self.env = merge_envs([before, after])
        if orelse:
            self.exec_body(orelse)

    def st_Try(self, node: ast.Try) -> None:
        before = dict(self.env)
        self.exec_body(node.body)
        body_env = self.env
        results = [body_env]
        for handler in node.handlers:
            self.env = merge_envs([before, body_env])
            if handler.name:
                self.env[handler.name] = EMPTY
            self.exec_body(handler.body)
            results.append(self.env)
        self.env = merge_envs(results)
        self.exec_body(node.orelse)
        self.exec_body(node.finalbody)

    st_TryStar = st_Try

    def st_With(self, node: ast.With) -> None:
        for item in node.items:
            taint = self.eval(item.context_expr)
            if item.optional_vars is not None:
                self.assign(item.optional_vars, taint, node)
        self.exec_body(node.body)

    st_AsyncWith = st_With

    def st_Match(self, node: ast.Match) -> None:
        self.eval(node.subject)
        self.branch([case.body for case in node.cases])

    def st_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            key = self.key_of(target)
            if key:
                self.env.pop(key, None)
                self.clear_subkeys(key)

    def st_FunctionDef(self, node: ast.AST) -> None:
        return

    st_AsyncFunctionDef = st_FunctionDef
    st_ClassDef = st_FunctionDef

    def st_Import(self, node: ast.AST) -> None:
        return

    st_ImportFrom = st_Import

    def st_Global(self, node: ast.AST) -> None:
        return

    st_Nonlocal = st_Global
    st_Pass = st_Global
    st_Break = st_Global
    st_Continue = st_Global

    def track_type(self, node: ast.Assign) -> None:
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return
        if not isinstance(node.value, ast.Call):
            return
        name = self.resolver.dotted(node.value.func)
        if name in self.module.classes:
            self.types[node.targets[0].id] = name

    def eval(self, node: ast.AST) -> Taint:
        handler = getattr(self, "ev_" + type(node).__name__, None)
        if handler is None:
            return self.ev_default(node)
        return handler(node)

    def ev_default(self, node: ast.AST) -> Taint:
        out = EMPTY
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                out = join(out, self.eval(child))
        return out

    def ev_Constant(self, node: ast.Constant) -> Taint:
        return EMPTY

    def ev_Name(self, node: ast.Name) -> Taint:
        taint = self.get_key(node.id)
        if taint:
            return taint
        return self.source_taint(node)

    def ev_Attribute(self, node: ast.Attribute) -> Taint:
        key = self.key_of(node)
        if key is not None and key in self.env:
            return self.env[key]
        source = self.source_taint(node)
        if source:
            return source
        return self.eval(node.value)

    def ev_Subscript(self, node: ast.Subscript) -> Taint:
        self.eval(node.slice)
        key = self.key_of(node)
        if key is not None and key in self.env:
            return self.env[key]
        source = self.source_taint(node)
        if source:
            return source
        return self.eval(node.value)

    def ev_BinOp(self, node: ast.BinOp) -> Taint:
        return join(self.eval(node.left), self.eval(node.right))

    def ev_BoolOp(self, node: ast.BoolOp) -> Taint:
        return join(*[self.eval(value) for value in node.values])

    def ev_Compare(self, node: ast.Compare) -> Taint:
        self.eval(node.left)
        for comparator in node.comparators:
            self.eval(comparator)
        return EMPTY

    def ev_UnaryOp(self, node: ast.UnaryOp) -> Taint:
        taint = self.eval(node.operand)
        return EMPTY if isinstance(node.op, ast.Not) else taint

    def ev_IfExp(self, node: ast.IfExp) -> Taint:
        self.eval(node.test)
        return join(self.eval(node.body), self.eval(node.orelse))

    def ev_JoinedStr(self, node: ast.JoinedStr) -> Taint:
        return join(*[self.eval(value) for value in node.values])

    def ev_FormattedValue(self, node: ast.FormattedValue) -> Taint:
        return self.eval(node.value)

    def ev_Lambda(self, node: ast.Lambda) -> Taint:
        saved = dict(self.env)
        for argument in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self.env[argument.arg] = EMPTY
        self.eval(node.body)
        self.env = saved
        return EMPTY

    def ev_NamedExpr(self, node: ast.NamedExpr) -> Taint:
        taint = self.eval(node.value)
        self.assign(node.target, taint, node)
        return taint

    def ev_Await(self, node: ast.Await) -> Taint:
        return self.eval(node.value)

    def ev_Yield(self, node: ast.AST) -> Taint:
        taint = self.eval(node.value) if node.value is not None else EMPTY
        if taint:
            self.returns.extend(
                extend_all(taint, _step(self.module, node, "value yielded to the caller"))
            )
        return EMPTY

    ev_YieldFrom = ev_Yield

    def comprehension(self, node: ast.AST, parts: list) -> Taint:
        for generator in node.generators:
            self.assign(generator.target, self.eval(generator.iter), node)
            for condition in generator.ifs:
                self.eval(condition)
        return join(*[self.eval(part) for part in parts])

    def ev_ListComp(self, node: ast.AST) -> Taint:
        return self.comprehension(node, [node.elt])

    ev_SetComp = ev_ListComp
    ev_GeneratorExp = ev_ListComp

    def ev_DictComp(self, node: ast.AST) -> Taint:
        return self.comprehension(node, [node.key, node.value])

    def source_taint(self, node: ast.AST) -> Taint:
        if isinstance(node, ast.Name) and node.id in self.bound:
            return EMPTY
        names = self.resolver.candidates_for(node)
        hits = self.engine.sources.lookup(names)
        if not hits:
            return EMPTY
        rules = frozenset(spec.payload for spec in hits)
        label = f"untrusted input from {hits[0].pattern}"
        return (Flow(rules, -1, (_step(self.module, node, label),)),)

    def ev_Call(self, node: ast.Call) -> Taint:
        names = self.resolver.candidates_for(node.func)
        receiver = EMPTY
        if isinstance(node.func, ast.Attribute):
            receiver = self.eval(node.func.value)
        elif not isinstance(node.func, ast.Name):
            receiver = self.eval(node.func)

        arg_taints = [self.eval(argument) for argument in node.args]
        kw_taints = [(keyword.arg, self.eval(keyword.value)) for keyword in node.keywords]

        self.check_sinks(node, names, arg_taints, kw_taints, receiver)

        sanitized = frozenset(
            spec.payload for spec in self.engine.sanitizers.lookup(names)
        )
        source = self.source_taint(node.func)
        if source:
            combined = join(source, *arg_taints, *[t for _, t in kw_taints])
        else:
            combined = join(receiver, *arg_taints, *[t for _, t in kw_taints])

        simple = names[0] if names else ""
        if simple in VALUE_KILLING_CALLS:
            result = EMPTY
        else:
            result = self.constant_lookup(node, arg_taints)
            if result is None:
                result = self.call_summary(node, arg_taints, kw_taints, receiver)
            if result is None:
                result = combined

        return strip_rules(result, sanitized) if sanitized else result

    def is_constant_name(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Name)
            and node.id in self.resolver.constants
            and node.id not in self.env
        )

    def constant_lookup(self, node: ast.Call, arg_taints: list) -> Taint | None:
        func = node.func
        if not isinstance(func, ast.Attribute) or not self.is_constant_name(func.value):
            return None
        if func.attr in LOOKUP_METHODS:
            return join(*arg_taints[1:]) if len(arg_taints) > 1 else EMPTY
        if func.attr in READONLY_METHODS:
            return EMPTY
        return None

    def sink_arguments(
        self,
        spec: SinkSpec,
        node: ast.Call,
        arg_taints: list,
        kw_taints: list,
    ) -> list[tuple[Taint, ast.AST]]:
        if spec.arg is None or spec.arg == "any":
            pairs = [(t, node.args[i]) for i, t in enumerate(arg_taints)]
            pairs += [
                (t, node.keywords[i].value) for i, (_, t) in enumerate(kw_taints)
            ]
            return pairs
        if isinstance(spec.arg, int) and 0 <= spec.arg < len(arg_taints):
            return [(arg_taints[spec.arg], node.args[spec.arg])]
        return []

    def condition_holds(self, spec: SinkSpec, node: ast.Call) -> bool:
        when = spec.when
        if not when:
            return True
        name = when.get("kwarg")
        if name is None:
            return True
        found = next((k for k in node.keywords if k.arg == name), None)
        if when.get("absent"):
            return found is None
        if found is None:
            return False
        if "equals" not in when:
            return True
        return isinstance(found.value, ast.Constant) and found.value.value == when["equals"]

    def check_sinks(
        self,
        node: ast.Call,
        names: tuple,
        arg_taints: list,
        kw_taints: list,
        receiver: Taint,
    ) -> None:
        hits = self.engine.sinks.lookup(names)
        if not hits:
            return
        reported: set[str] = set()
        for pattern_spec in hits:
            spec: SinkSpec = pattern_spec.payload
            if spec.rule_id in reported or not self.condition_holds(spec, node):
                continue
            for taint, argument in self.sink_arguments(spec, node, arg_taints, kw_taints):
                if self.report(spec, node, argument, taint):
                    reported.add(spec.rule_id)
                    break

    def report(self, spec: SinkSpec, node: ast.Call, argument: ast.AST, taint: Taint) -> bool:
        if not taint:
            return False
        sink_step = _step(
            self.module, node, f"reaches {spec.pattern} without neutralization"
        )
        for flow in sorted(taint, key=lambda f: f.order):
            if spec.rule_id not in flow.rules:
                continue
            if flow.param >= 0:
                if self.record_summary:
                    self.sink_flows.append(
                        (spec, flow.param, flow.rules, flow.steps + (sink_step,), ())
                    )
                    return True
                continue
            if self.record_summary:
                continue
            self.emit(spec, node, flow.steps + (sink_step,))
            return True
        return False

    def emit(self, spec: SinkSpec, node: ast.AST, steps: tuple[Step, ...]) -> None:
        rule = self.engine.rule_by_id[spec.rule_id]
        line, col, end_line, end_col = location(node)
        self.findings.append(
            Finding(
                rule_id=rule.id,
                severity=rule.severity,
                cwe=rule.cwe,
                message=rule.message,
                file=self.module.rel_path,
                line=line,
                col=col,
                end_line=end_line,
                end_col=end_col,
                signature=signature_for(spec, steps, node),
                path=steps,
                snippet=self.module.snippet(line),
            )
        )

    def call_summary(
        self,
        node: ast.Call,
        arg_taints: list,
        kw_taints: list,
        receiver: Taint,
    ) -> Taint | None:
        if self.depth >= MAX_DEPTH:
            return None
        target = self.engine.resolve_callee(self.module, self.func, self.types, node)
        if target is None:
            return None
        module, info = target
        summary = self.engine.summary_for(module, info, self.depth + 1)
        if summary is EMPTY_SUMMARY and not summary.params:
            return None

        bound = self.bind_arguments(info, summary, node, arg_taints, kw_taints, receiver)
        call_step = _step(self.module, node, f"passed into {info.qualname}()")

        for spec, index, remaining, steps, _ in summary.sink_flows:
            incoming = bound.get(index, EMPTY)
            for flow in sorted(incoming, key=lambda f: f.order):
                if spec.rule_id not in flow.rules or spec.rule_id not in remaining:
                    continue
                if flow.param >= 0:
                    if self.record_summary:
                        self.sink_flows.append(
                            (spec, flow.param, flow.rules & remaining,
                             flow.steps + (call_step,) + steps, ())
                        )
                    break
                if not self.record_summary:
                    self.emit(spec, node, flow.steps + (call_step,) + steps)
                break

        result = list(summary.return_taint)
        for index, remaining, steps in summary.return_flows:
            for flow in bound.get(index, EMPTY):
                rules = flow.rules & remaining
                if rules:
                    result.append(
                        Flow(rules, flow.param, flow.steps + (call_step,) + steps)
                    )
        return join(tuple(result))

    def bind_arguments(
        self,
        info: FunctionInfo,
        summary: Summary,
        node: ast.Call,
        arg_taints: list,
        kw_taints: list,
        receiver: Taint,
    ) -> dict[int, Taint]:
        bound: dict[int, Taint] = {}
        offset = 1 if info.is_method and not _is_direct_class_call(node, info) else 0
        if offset and receiver:
            bound[0] = receiver
        for position, taint in enumerate(arg_taints):
            index = position + offset
            if index < len(info.params) and taint:
                bound[index] = join(bound.get(index, EMPTY), taint)
        for name, taint in kw_taints:
            if name is None or not taint:
                continue
            index = info.param_index(name)
            if index >= 0:
                bound[index] = join(bound.get(index, EMPTY), taint)
        return bound


def _is_direct_class_call(node: ast.Call, info: FunctionInfo) -> bool:
    return False


def local_names(node: ast.AST) -> frozenset[str]:
    bound: set[str] = set()
    declared: set[str] = set()
    args = getattr(node, "args", None)
    if args is not None:
        bound.update(a.arg for a in args.posonlyargs + args.args + args.kwonlyargs)
        if args.vararg:
            bound.add(args.vararg.arg)
        if args.kwarg:
            bound.add(args.kwarg.arg)
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            bound.add(child.id)
        elif isinstance(child, (ast.Global, ast.Nonlocal)):
            declared.update(child.names)
        elif isinstance(child, ast.ExceptHandler) and child.name:
            bound.add(child.name)
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            for alias in child.names:
                bound.discard((alias.asname or alias.name).split(".")[0])
    return frozenset(bound - declared)


def module_level_names(tree: ast.Module) -> frozenset[str]:
    names: set[str] = set()
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        for target in targets:
            for child in ast.walk(target):
                if isinstance(child, ast.Name):
                    names.add(child.id)
    return frozenset(names)


def merge_envs(envs: list[dict[str, Taint]]) -> dict[str, Taint]:
    if len(envs) == 1:
        return dict(envs[0])
    keys: set[str] = set()
    for env in envs:
        keys.update(env)
    merged: dict[str, Taint] = {}
    for key in keys:
        merged[key] = join(*[env.get(key, EMPTY) for env in envs])
    return merged


def signature_for(spec: SinkSpec, steps: tuple[Step, ...], node: ast.AST) -> str:
    origin = steps[0].label if steps else ""
    shape = ast.dump(_strip(node))
    return f"{spec.pattern}|{origin}|{shape}"


def _strip(node: ast.AST) -> ast.AST:
    clone = ast.parse(ast.unparse(node), mode="eval").body
    return clone


class TaintAnalyzer(AbstractAnalyzer):
    kind = "taint"

    def __init__(self, rules, context) -> None:
        super().__init__(rules, context)
        self.rule_by_id = {rule.id: rule for rule in rules}
        self.sources = PatternIndex()
        self.sinks = PatternIndex()
        self.sanitizers = PatternIndex()
        for rule in rules:
            for spec in parse_pattern_specs(rule.spec.get("sources"), rule.id, rule.id):
                self.sources.add(spec)
            for spec in parse_pattern_specs(rule.spec.get("sanitizers"), rule.id, rule.id):
                self.sanitizers.add(spec)
            entries = rule.spec.get("sinks")
            if not entries:
                raise RuleError(f"rule '{rule.id}': taint rules need at least one sink")
            for spec in parse_pattern_specs(entries, rule.id):
                when = {}
                for entry in entries:
                    if isinstance(entry, dict) and entry.get("pattern") == spec.pattern:
                        when = entry.get("when") or {}
                        break
                self.sinks.add(
                    PatternSpec(
                        spec.pattern,
                        spec.arg,
                        SinkSpec(rule.id, spec.pattern, spec.arg, when),
                    )
                )
        self.summaries: dict[tuple[str, str], Summary] = {}
        self.in_progress: set[tuple[str, str]] = set()

    def analyze(self, module: ModuleInfo) -> Iterator[Finding]:
        findings, sticky = self._pass(module, {})
        if not sticky:
            return iter(findings)
        findings, _ = self._pass(module, sticky)
        return iter(findings)

    def _pass(self, module: ModuleInfo, seeds: dict) -> tuple[list[Finding], dict]:
        names = module_level_names(module.tree)
        findings: list[Finding] = []
        collected: dict[str, dict[str, Taint]] = {}

        def visit(info: FunctionInfo | None, body: list) -> None:
            scope = info.owner if info is not None else ""
            walker = _Walker(self, module, info, 0, False)
            walker.sticky_names = names
            for source_scope in ("", scope):
                for key, taint in seeds.get(source_scope, {}).items():
                    walker.env[key] = taint
                    base = key.split(".")[0].split("[")[0]
                    walker.env[base] = join(walker.env.get(base, EMPTY), taint)
            walker.run(body)
            findings.extend(walker.findings)
            for key, taint in walker.sticky_writes.items():
                target = scope if key.startswith("self.") or key.startswith("self[") else ""
                bucket = collected.setdefault(target, {})
                bucket[key] = join(bucket.get(key, EMPTY), taint)

        visit(None, module.tree.body)
        for qualname in sorted(module.functions):
            visit(module.functions[qualname], module.functions[qualname].node.body)
        return findings, collected

    def summary_for(self, module: ModuleInfo, info: FunctionInfo, depth: int) -> Summary:
        key = (module.path, info.qualname)
        cached = self.summaries.get(key)
        if cached is not None:
            return cached
        if key in self.in_progress or depth >= MAX_DEPTH:
            return Summary(params=info.params)
        self.in_progress.add(key)
        try:
            summary = self._build_summary(module, info, depth)
        finally:
            self.in_progress.discard(key)
        self.summaries[key] = summary
        return summary

    def _build_summary(self, module: ModuleInfo, info: FunctionInfo, depth: int) -> Summary:
        walker = _Walker(self, module, info, depth, True)
        all_rules = frozenset(self.rule_by_id)
        for index, name in enumerate(info.params):
            if index == 0 and info.is_method:
                continue
            step = _step(module, info.node, f"parameter '{name}' of {info.qualname}()")
            walker.env[name] = (Flow(all_rules, index, (step,)),)
        walker.run(info.node.body)

        return_flows = []
        return_taint = []
        for flow in walker.returns:
            if flow.param >= 0:
                return_flows.append((flow.param, flow.rules, flow.steps))
            else:
                return_taint.append(flow)
        return Summary(
            params=info.params,
            return_flows=tuple(return_flows),
            return_taint=join(tuple(return_taint)),
            sink_flows=tuple(walker.sink_flows),
            self_fields=tuple(walker.field_flows),
        )

    def resolve_callee(
        self,
        module: ModuleInfo,
        func: FunctionInfo | None,
        types: dict[str, str],
        node: ast.Call,
    ) -> tuple[ModuleInfo, FunctionInfo] | None:
        callee = node.func
        if isinstance(callee, ast.Name):
            local = module.functions.get(callee.id)
            if local is not None:
                return module, local
        if isinstance(callee, ast.Attribute) and isinstance(callee.value, ast.Name):
            base = callee.value.id
            if base == "self" and func is not None and func.owner:
                method = module.functions.get(f"{func.owner}.{callee.attr}")
                if method is not None:
                    return module, method
            owner = types.get(base)
            if owner:
                method = module.functions.get(f"{owner}.{callee.attr}")
                if method is not None:
                    return module, method
        return self.context.resolve_external(module, node)
