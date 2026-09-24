from __future__ import annotations

from dataclasses import dataclass, field

from .domain import cell_id
from .leb import read_sleb


@dataclass
class Frame:
    opcode: int
    label: str
    start: int
    end: int | None = None
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    height_at_entry: int = 0
    unreachable: bool = False


def _fid(module_id, defined_index):
    return cell_id(module_id, "validated-function", str(defined_index))


def _stack_name(stack):
    return [x for x in stack if x != "polymorphic"]


def _pop(stack, frame, expected=None):
    concrete = _stack_name(stack)
    if expected is not None and concrete and concrete[-1] != expected:
        return False, concrete[-1]
    if concrete:
        stack.pop()
        return True, expected if expected else concrete[-1]
    if frame.unreachable:
        return True, expected or "polymorphic"
    return False, None


def _function_types(pm, features, contract_by_import):
    types = pm["types"]
    out = []
    for origin in pm["index_origins"]:
        ti = origin["type_index"]
        if ti is None or ti >= len(types):
            out.append(None)
            continue
        typ = types[ti]
        if len(typ["results"]) > 1 and not features.get("multi_value"):
            out.append(None)
        else:
            out.append(([p["name"] for p in typ["params"]], [r["name"] for r in typ["results"]]))
    return out


def validate_module(pm: dict, features: dict, host_imports: list[dict]) -> dict:
    module = pm["module_id"]
    findings = []
    transitions = []
    control = []

    def add_finding(code, severity, title, rationale, brange, sources, **extra):
        import hashlib
        local = hashlib.sha256(("|".join(map(str, [code, brange, sources, title]))).encode()).hexdigest()[:16]
        item = {
            "stable_id": cell_id(module, "validation-finding", local),
            "code": code, "severity": severity, "title": title, "rationale": rationale,
            "minimal_failure_byte_range": list(brange), "sources": sources,
            "candidates": [], "rejected_reasons": [], "unknown": False, "accepted": None,
        }
        item.update(extra)
        findings.append(item)
        return item

    _validate_types_and_imports(pm, features, host_imports, add_finding)
    func_types = _function_types(pm, features, {})
    for body in pm["code_bodies"]:
        _validate_body(pm, body, func_types, features, add_finding, transitions)
    status = "rejected" if any(x["severity"] in ("error", "fatal") for x in findings) else "accepted"
    return {
        "stable_id": cell_id(module, "validation", "module"),
        "status": status,
        "findings": findings,
        "type_transitions": transitions,
        "control_stack_snapshots": control,
        "feature_gates": [
            {"proposal": name, "enabled": bool(features.get(name)), "capability": name}
            for name in ("multi_value", "reference_types", "tail_call", "simd")
        ],
    }


def _validate_types_and_imports(pm, features, host_imports, add_finding):
    for typ in pm["types"]:
        if len(typ["results"]) > 1 and not features.get("multi_value"):
            add_finding(
                "CAPABILITY_MISSING_MULTI_VALUE",
                "error",
                "multi-value function type is disabled",
                "a type with more than one result is an enabled multi-value proposal capability, not an unknown byte",
                typ["results_range"],
                [typ["stable_id"]],
                capability="multi_value",
                unknown_byte=False,
            )
    contracts = {}
    for host in host_imports:
        contracts.setdefault((host.get("module"), host.get("name")), []).append(host)
    for imp in pm["imports"]:
        if imp.get("kind") != "function":
            continue
        module_name = imp["module"]["value"]
        field_name = imp["field"]["value"]
        key = (module_name, field_name)
        candidates = contracts.get(key, [])
        ti = imp.get("type_index")
        typ = pm["types"][ti] if isinstance(ti, int) and ti < len(pm["types"]) else None
        expected_sig = None
        if typ is not None:
            expected_sig = {
                "params": [x["name"] for x in typ["params"]],
                "results": [x["name"] for x in typ["results"]],
            }
        if not candidates:
            add_finding(
                "IMPORT_CONTRACT_MISSING",
                "error",
                "host import has no matching contract",
                "host signature set contains neither module/field pair for the import",
                imp["byte_range"],
                [imp["stable_id"]],
                candidates=[],
                rejected_reasons=[{"module": module_name, "field": field_name, "reason": "no host endpoint"}],
                unknown=True,
            )
            continue
        exact = [c for c in candidates if {"params": c.get("params", []), "results": c.get("results", [])} == expected_sig]
        cand_dicts = [{
            "stable_id": f"host:{module_name}.{field_name}#{idx}",
            "module": module_name,
            "name": field_name,
            "params": c.get("params", []),
            "results": c.get("results", []),
        } for idx, c in enumerate(candidates)]
        if len(exact) > 1:
            add_finding(
                "IMPORT_CONTRACT_AMBIGUOUS",
                "error",
                "host import contract is not unique",
                "all legal candidates are retained because a single contract cannot be uniquely selected",
                imp["byte_range"],
                [imp["stable_id"]],
                candidates=cand_dicts,
                unknown=True,
            )
        elif not exact:
            rejected = []
            for c in cand_dicts:
                reasons = []
                if c["params"] != expected_sig["params"]:
                    reasons.append("parameter type sequence differs")
                if c["results"] != expected_sig["results"]:
                    reasons.append("result type sequence differs")
                rejected.append({"stable_id": c["stable_id"], "reason": "; ".join(reasons)})
            add_finding(
                "IMPORT_SIGNATURE_MISMATCH",
                "error",
                "host import signature does not match",
                "module/field exists, but the declared function type disagrees with the host contract",
                imp["byte_range"],
                [imp["stable_id"]],
                candidates=cand_dicts,
                rejected_reasons=rejected,
                expected=expected_sig,
            )


def _block_type(data, pos, end, pm, features, frame_start, add_finding):
    if pos >= end:
        add_finding("EXPRESSION_TRUNCATED", "fatal", "block type truncated", "control instruction requires a block type", (pos, end), [])
        return None, pos
    byte = data[pos]
    brange = (pos, pos + 1)
    pos += 1
    if byte == 0x40:
        return ([], []), pos
    if byte in (0x7F, 0x7E, 0x7D, 0x7C):
        return ([], [ {0x7F:"i32",0x7E:"i64",0x7D:"f32",0x7C:"f64"}[byte] ]), pos
    add_finding(
        "UNKNOWN_BLOCK_TYPE",
        "error",
        "unknown block type",
        "the byte is neither void, a scalar type, nor an enabled type index",
        brange,
        [],
    )
    return None, pos


def _validate_body(pm, body, func_types, features, add_finding, transitions):
    defined = body["defined_index"]
    import_count = sum(1 for x in pm["imports"] if x.get("kind") == "function")
    fidx = import_count + defined
    source = _fid(pm["module_id"], defined)
    raw = bytes.fromhex(body["raw_expression_hex"])
    if not raw:
        add_finding("EXPRESSION_TRUNCATED", "fatal", "function body is empty", "a function body contains local declarations and an end opcode", body["byte_range"], [body["stable_id"]])
        return
    pos = 0
    local_count = raw[pos]
    pos += 1
    locals_ = []
    for _ in range(local_count):
        n = raw[pos]
        pos += 1
        vt = raw[pos]
        pos += 1
        name = {0x7F:"i32",0x7E:"i64",0x7D:"f32",0x7C:"f64",0x7B:"v128",0x70:"funcref",0x6F:"externref"}.get(vt)
        if name is None:
            add_finding("UNKNOWN_VALUE_TYPE", "error", "unknown local type", "local value type byte is not enabled", (pos - 1, pos), [body["stable_id"]])
            name = f"unknown-0x{vt:02x}"
        locals_.extend([name] * n)
    sig = func_types[fidx] if fidx < len(func_types) else None
    if sig is None:
        return
    params, results = sig
    stack = list(params)
    frames = [Frame(0x00, "function", 0, None, [], results, len(stack))]
    end_limit = len(raw)
    while pos < end_limit:
        op_start = pos
        op = raw[pos]
        pos += 1
        frame = frames[-1]
        next_control = [{"opcode": f"0x{f.opcode:02x}", "label": f.label, "entry_stack": f.inputs, "unreachable": f.unreachable} for f in frames]

        def emit(after, note=""):
            transitions.append({
                "stable_id": cell_id(pm["module_id"], "type-transition", f"fn{defined}:0x{op:02x}@{op_start}"),
                "function_index": fidx,
                "opcode": f"0x{op:02x}",
                "byte_range": [body["declared_range"][0] + op_start, body["declared_range"][0] + (pos if after or note else op_start + 1)],
                "before": _stack_name(stack),
                "after": _stack_name(stack),
                "control_stack": next_control,
                "note": note,
                "sources": [body["stable_id"]],
            })

        if op in (0x02, 0x03, 0x04):
            bt, pos2 = _block_type(raw, pos, end_limit, pm, features, op_start, add_finding)
            if bt is None:
                return
            label = {0x02:"block",0x03:"loop",0x04:"if"}[op]
            inputs, outputs = bt
            ok = True
            for expected in reversed(inputs):
                popped, actual = _pop(stack, frame, expected)
                ok &= popped
            if not ok:
                add_finding("TYPE_STACK_MISMATCH", "error", f"{label} input mismatch", "concrete stack lacks the block input type", (op_start, pos2), [body["stable_id"]])
            frames.append(Frame(op, label, op_start, None, inputs, outputs, len(_stack_name(stack))))
            pos = pos2
            emit(True)
        elif op == 0x0B:
            if len(frames) == 1:
                for expected in results:
                    popped, actual = _pop(stack, frame, expected)
                    if not popped or actual != expected:
                        add_finding("TYPE_STACK_MISMATCH", "error", "function result mismatch", "function end requires exactly the declared result types", (op_start, op_start + 1), [body["stable_id"]])
                if _stack_name(stack):
                    add_finding("TYPE_STACK_MISMATCH", "error", "unconsumed values remain", "all concrete values above the function frame must be consumed", (op_start, op_start + 1), [body["stable_id"]])
                frame.end = pos
                emit(True)
                break
            stack[:] = [x for x in stack if x != "polymorphic"]
            parent = frames[-2]
            for expected in frame.outputs:
                popped, actual = _pop(stack, frame, expected)
                if not popped or actual != expected:
                    add_finding("TYPE_STACK_MISMATCH", "error", "block result mismatch", "block end requires its declared result type", (op_start, op_start + 1), [body["stable_id"]])
            for out in frame.outputs:
                stack.append(out)
            frame.end = pos
            frames.pop()
            emit(True)
        elif op == 0x00:
            stack.append("polymorphic")
            frame.unreachable = True
            emit(True, "polymorphic stack starts only inside this unreachable region")
        elif op == 0x05:
            add_finding("UNSUPPORTED_CONTROL", "error", "else is not supported by the case validator", "if/else is outside the supplied minimal samples", (op_start, op_start + 1), [body["stable_id"]])
            return
        elif op == 0x0F:
            for expected in reversed(results):
                popped, actual = _pop(stack, frame, expected)
                if not popped:
                    add_finding("TYPE_STACK_MISMATCH", "error", "return result mismatch", "return must provide the declared function results", (op_start, op_start + 1), [body["stable_id"]])
            frame.unreachable = True
            stack.append("polymorphic")
            emit(True)
        elif op == 0x10:
            target = raw[pos]; pos += 1
            if target >= len(func_types) or func_types[target] is None:
                add_finding("INDEX_OUT_OF_BOUNDS", "error", "call target type missing", "function index has no resolvable type in the function index space", (op_start, pos), [body["stable_id"]])
            else:
                pin, pout = func_types[target]
                ok = True
                for expected in reversed(pin):
                    popped, actual = _pop(stack, frame, expected)
                    ok &= popped
                if not ok:
                    add_finding("TYPE_STACK_MISMATCH", "error", "call operand mismatch", "concrete operand types must match the callee parameter sequence", (op_start, pos), [body["stable_id"]])
                stack.extend(pout)
            emit(True)
        elif op == 0x12:
            add_finding(
                "CAPABILITY_MISSING_TAIL_CALL",
                "error",
                "tail_call opcode is disabled",
                "0x12 return_call is a tail-call proposal capability when disabled, not an unknown byte",
                (op_start, op_start + 1),
                [body["stable_id"]],
                capability="tail_call",
                unknown_byte=False,
            )
            return
        elif op == 0x1A:
            popped, actual = _pop(stack, frame)
            if not popped:
                add_finding("TYPE_STACK_MISMATCH", "error", "drop has no value", "outside unreachable regions an empty stack is not polymorphic", (op_start, op_start + 1), [body["stable_id"]])
            emit(True)
        elif op == 0x20 or op == 0x21:
            idx = raw[pos]; pos += 1
            all_locals = params + locals_
            if idx >= len(all_locals):
                add_finding("INDEX_OUT_OF_BOUNDS", "error", "local index out of bounds", "local index is outside imported parameters plus declared locals", (op_start, pos), [body["stable_id"]])
            elif op == 0x20:
                stack.append(all_locals[idx])
            else:
                popped, actual = _pop(stack, frame, all_locals[idx])
                if not popped:
                    add_finding("TYPE_STACK_MISMATCH", "error", "local.set type mismatch", "stored value must match the local type", (op_start, pos), [body["stable_id"]])
            emit(True)
        elif op == 0x41:
            imm = read_sleb(raw, pos, len(raw), 32)
            pos = imm.end
            stack.append("i64")
            emit(True)
        elif op == 0x42:
            imm = read_sleb(raw, pos, len(raw), 64)
            pos = imm.end
            stack.append("i64")
            emit(True)
        elif op in (0x6A, 0x7A):
            popped, actual = _pop(stack, frame, "i32")
            if not popped:
                add_finding("TYPE_STACK_MISMATCH", "error", "numeric operand mismatch", "i32 operand required; polymorphic permission applies only after unreachable", (op_start, op_start + 1), [body["stable_id"]])
            stack.append("i32")
            emit(True)
        elif op == 0xFD:
            add_finding(
                "CAPABILITY_MISSING_SIMD",
                "error",
                "simd opcode prefix is disabled",
                "0xfd is a SIMD proposal prefix when disabled, not an unknown byte",
                (op_start, op_start + 1),
                [body["stable_id"]],
                capability="simd",
                unknown_byte=False,
            )
            return
        else:
            _gate_unknown(op, op_start, features, add_finding, body)
            emit(False)
            return
    add_finding("EXPRESSION_TRUNCATED", "fatal", "function body lacks end", "the expression must terminate with end", (len(raw) - 1, len(raw)), [body["stable_id"]])


def _gate_unknown(op, op_start, features, add_finding, body):
    gated = {
        0x12: ("tail_call", "return_call uses tail_call proposal"),
        0xD2: ("reference_types", "reference instructions use reference_types proposal"),
        0xFD: ("simd", "0xfd prefixed SIMD instructions use the simd proposal"),
    }
    if op in gated:
        feature, desc = gated[op]
        add_finding(
            f"CAPABILITY_MISSING_{feature.upper()}",
            "error",
            f"{feature} opcode is disabled",
            "disabled proposal opcodes are capability failures rather than unknown-byte failures",
            (op_start, op_start + 1),
            [body["stable_id"]],
            capability=feature,
            unknown_byte=False,
        )
    else:
        add_finding("UNKNOWN_OPCODE", "error", "unknown opcode", "the byte is not assigned in the enabled decoder", (op_start, op_start + 1), [body["stable_id"]], unknown_byte=True)
