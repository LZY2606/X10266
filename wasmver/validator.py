"""Function-body type validation with an explicit polymorphic stack.

The two subtle rules live here and are unit-tested directly:

* polymorphic typing applies **only** to the region following an
  ``unreachable`` (propagating into nested blocks); the same underflowing
  sequence before any unreachable is a real type-stack fault.
* an opcode known to a disabled proposal yields ``capability-missing``
  together with concrete candidates (enable proposal / remove instruction);
  a byte belonging to no known proposal yields ``unknown-opcode``.
"""

from __future__ import annotations

from .leb import decode_u, decode_s
from .opcodes import TABLE, PREFIX_FC, PREFIX_FD, PREFIX_PROPOSAL
from .types import VALUE_TYPES, VALUE_TYPE_PROPOSALS, FuncType
from .model import byte_range, finding, candidate


class _Cursor:
    def __init__(self, data: bytes, base: int):
        self.data = data
        self.base = base
        self.pos = 0
        self.findings: list[dict] = []

    @property
    def abs(self) -> int:
        return self.base + self.pos

    def u8(self):
        if self.pos >= len(self.data):
            return None
        b = self.data[self.pos]
        self.pos += 1
        return b

    def u32(self):
        v = decode_u(self.data, self.pos, 32)
        self.pos = min(v.end, len(self.data))
        if v.status != "ok":
            self.findings.append(finding(
                f"leb128-{v.status}", v.reason or "",
                byte_range(self.base + v.start, self.base + v.end),
                leb=v.as_dict()))
        return v

    def s32(self):
        v = decode_s(self.data, self.pos, 32)
        self.pos = min(v.end, len(self.data))
        if v.status != "ok":
            self.findings.append(finding(
                f"leb128-{v.status}", v.reason or "",
                byte_range(self.base + v.start, self.base + v.end),
                leb=v.as_dict()))
        return v

    def s64(self):
        v = decode_s(self.data, self.pos, 64)
        self.pos = min(v.end, len(self.data))
        if v.status != "ok":
            self.findings.append(finding(
                f"leb128-{v.status}", v.reason or "",
                byte_range(self.base + v.start, self.base + v.end),
                leb=v.as_dict()))
        return v


class _Frame:
    def __init__(self, kind, params, results, height, op_range,
                 polymorphic=False):
        self.kind = kind          # block | loop | if | else | function
        self.params = list(params)
        self.results = list(results)
        self.height = height
        self.op_range = op_range
        self.polymorphic = polymorphic


def _resolve_opcode(cur: _Cursor, b: int):
    """Return (OpInfo|None, sub byte range|None, proposal_hint)."""
    if b in (0xFC, 0xFD):
        sub_start = cur.pos
        sub = cur.u32()
        sub_range = byte_range(cur.base + sub_start, cur.pos + cur.base)
        table = PREFIX_FC if b == 0xFC else PREFIX_FD
        info = table.get(sub.value if sub.value is not None else -1)
        hint = PREFIX_PROPOSAL[b]
        return info, sub_range, hint
    if b in (0xFB, 0xFE):
        sub_start = cur.pos
        sub = cur.u32()
        sub_range = byte_range(cur.base + sub_start, cur.pos + cur.base)
        return None, sub_range, PREFIX_PROPOSAL[b]
    return TABLE.get(b), None, None


def _read_blocktype(cur: _Cursor):
    start = cur.abs
    b = cur.u8()
    if b is None:
        return {"kind": "truncated", "params": [], "results": [],
                "range": byte_range(start, cur.abs)}
    if b == 0x40:
        return {"kind": "empty", "params": [], "results": [],
                "range": byte_range(start, cur.abs)}
    if b in VALUE_TYPES:
        return {"kind": "value", "params": [],
                "results": [VALUE_TYPES[b]],
                "value_proposal": VALUE_TYPE_PROPOSALS.get(b),
                "range": byte_range(start, cur.abs)}
    if b == 0x80:
        v = cur.s32()
        return {"kind": "typeidx", "type_index": v.value,
                "leb": v.as_dict(),
                "params": [], "results": [],
                "range": byte_range(start, cur.abs)}
    return {"kind": "bad", "byte": f"0x{b:02x}", "params": [],
            "results": [], "range": byte_range(start, cur.abs)}


def _read_operand(cur: _Cursor, shape):
    if shape == "u32":
        v = cur.u32()
        return {"shape": "u32", "leb": v.as_dict(), "value": v.value}
    if shape == "s32":
        v = cur.s32()
        return {"shape": "s32", "leb": v.as_dict(), "value": v.value}
    if shape == "s64":
        v = cur.s64()
        return {"shape": "s64", "leb": v.as_dict(), "value": v.value}
    if shape == "f32":
        start = cur.pos
        raw = cur.data[cur.pos:cur.pos + 4]
        cur.pos = min(cur.pos + 4, len(cur.data))
        return {"shape": "f32", "raw_hex": raw.hex(),
                "range": byte_range(cur.base + start, cur.abs)}
    if shape == "f64":
        start = cur.pos
        raw = cur.data[cur.pos:cur.pos + 8]
        cur.pos = min(cur.pos + 8, len(cur.data))
        return {"shape": "f64", "raw_hex": raw.hex(),
                "range": byte_range(cur.base + start, cur.abs)}
    if shape == "memarg":
        align = cur.u32()
        offset = cur.u32()
        return {"shape": "memarg", "align": align.as_dict(),
                "offset": offset.as_dict()}
    if shape == "reserved_zero":
        start = cur.pos
        r = cur.u8()
        return {"shape": "reserved_zero", "byte": r,
                "range": byte_range(cur.base + start, cur.abs)}
    if shape == "v128":
        start = cur.pos
        raw = cur.data[cur.pos:cur.pos + 16]
        cur.pos = min(cur.pos + 16, len(cur.data))
        return {"shape": "v128", "raw_hex": raw.hex(),
                "range": byte_range(cur.base + start, cur.abs)}
    if shape in ("dataidx_zero", "one_zero"):
        idx = cur.u32()
        r = cur.u8()
        return {"shape": shape, "index": idx.as_dict(), "reserved": r}
    if shape == "two_zero":
        r1, r2 = cur.u8(), cur.u8()
        return {"shape": "two_zero", "reserved": [r1, r2]}
    if shape == "call_indirect":
        ti = cur.u32()
        table = cur.u8()
        return {"shape": "call_indirect", "type_index": ti.as_dict(),
                "table_byte": table}
    if shape == "br_table":
        count = cur.u32()
        labels = [cur.u32() for _ in range(count.value or 0)]
        default = cur.u32()
        return {"shape": "br_table",
                "labels": [x.as_dict() for x in labels],
                "default": default.as_dict()}
    return {"shape": shape}


def validate_function(code: bytes, code_base: int, func_type: FuncType,
                      local_types: list[str], context: dict,
                      caps) -> dict:
    """Type-check one function body.

    ``code`` excludes the local-declaration vector; ``code_base`` is the
    absolute module offset of its first byte, so every recorded range is a
    real module coordinate.
    """
    cur = _Cursor(code, code_base)
    stack: list[str] = []
    frames: list[_Frame] = [_Frame("function", [], list(func_type.results),
                                   0, byte_range(code_base, code_base + 1))]
    steps: list[dict] = []
    findings: list[dict] = []
    candidates: list[dict] = []

    def poly() -> bool:
        return any(f.polymorphic for f in frames)

    def record(op_name, op_range, operand, status, extra=None):
        depth = len(frames) - 1
        steps.append({
            "op": op_name,
            "range": op_range,
            "operand": operand,
            "before_depth": depth,
            "before_stack": list(stack),
            "polymorphic": poly(),
            "frame_kind": frames[-1].kind if frames else None,
            "status": status,
            **(extra or {}),
        })

    def pop(expected: str | None, op_range, op_name,
            what: str) -> str | None:
        frame = frames[-1]
        if len(stack) > frame.height:
            actual = stack.pop()
            if expected is not None and actual != expected and actual not in \
                    ("unknown",) and expected != "unknown":
                findings.append(finding(
                    "type-mismatch",
                    f"{op_name}: expected {expected} on stack for {what}, "
                    f"found {actual}", op_range,
                    expected=expected, actual=actual))
            return actual
        if frame.polymorphic:
            return expected  # polymorphic synthesis: any type allowed
        findings.append(finding(
            "stack-underflow",
            f"{op_name}: stack empty while expecting {expected} for {what}",
            op_range, expected=expected))
        return expected

    def ft_at(index: int) -> FuncType | None:
        types = context.get("types", [])
        if index is None or index < 0 or index >= len(types):
            return None
        return types[index]

    while True:
        op_start = cur.abs
        b = cur.u8()
        if b is None:
            findings.append(finding(
                "code-truncated", "function body ended before final 0x0B",
                byte_range(op_start, op_start + 1)))
            break
        op_range = byte_range(op_start, cur.abs)
        if b == 0x0B:
            frame = frames[-1]
            status = "ok"
            for t in reversed(frame.results):
                got = pop(t, op_range, "end", "block result")
                if got != t and got is not None:
                    status = "error"
            while len(stack) > frame.height:
                stack.pop()
            record(frame.kind + ":end", op_range, None, status,
                   {"block_results": list(frame.results)})
            was_poly = frame.polymorphic
            if frame.kind == "function":
                frames.pop()
                break
            frames.pop()
            for t in frame.results:
                stack.append(t)
            if was_poly and frames:
                frames[-1].polymorphic = True
                del stack[frames[-1].height:]
            continue

        info, sub_range, prefix_hint = _resolve_opcode(cur, b)
        operand = None
        structural = (
            info is not None and info.effect[0] == "control"
            and info.effect[1] in ("block", "loop", "if"))
        if info is not None and not structural:
            operand = _read_operand(cur, info.operand)
        full_range = byte_range(op_start, cur.abs)

        # 1) gating: known proposal opcode with proposal disabled.
        proposal = info.proposal if info else prefix_hint
        if info is not None and proposal and not caps.has(proposal):
            rng = sub_range or op_range
            findings.append(finding(
                "capability-missing",
                f"{info.name} belongs to proposal '{proposal}', which is "
                f"not enabled; this is not an unknown byte",
                full_range, proposal=proposal, opcode=info.name))
            candidates.append(candidate(
                f"enable-{proposal}", f"enable proposal '{proposal}'",
                "proposal set is a direct input; enabling it re-runs only "
                "capability-dependent results", rng,
                action="enable-proposal", proposal=proposal))
            candidates.append(candidate(
                "remove-instruction", f"remove {info.name}",
                "drop the gated instruction from this function body",
                full_range, action="edit-bytes"))
            record(info.name, full_range, operand, "capability-missing")
            _apply_effect(info, operand, stack, pop, full_range,
                          findings, context, local_types, cur)
            continue

        # 2) truly unknown byte.
        if info is None:
            if b in PREFIX_PROPOSAL and prefix_hint and not caps.has(prefix_hint):
                findings.append(finding(
                    "capability-missing",
                    f"0x{b:02x} sub-opcode family belongs to proposal "
                    f"'{prefix_hint}', which is not enabled",
                    full_range, proposal=prefix_hint,
                    opcode=f"0x{b:02x} prefix"))
                candidates.append(candidate(
                    f"enable-{prefix_hint}",
                    f"enable proposal '{prefix_hint}'",
                    "prefix maps to a known gated proposal family",
                    sub_range or op_range,
                    action="enable-proposal", proposal=prefix_hint))
                record(f"0x{b:02x} prefix", full_range, operand,
                       "capability-missing")
                continue
            findings.append(finding(
                "unknown-opcode",
                f"byte 0x{b:02x} is not defined by any enabled or known "
                f"proposal catalogue",
                op_range, byte=f"0x{b:02x}"))
            record(f"0x{b:02x}", full_range, operand, "unknown-opcode")
            continue

        # 3) structural opcodes need frame manipulation.
        if info.effect[0] == "control" and info.effect[1] in ("block", "loop"):
            operand = _read_blocktype(cur)
            full_range = byte_range(op_start, cur.abs)
            _enter_block(info.effect[1], operand, stack, frames, cur,
                         full_range, findings, candidates, caps, ft_at)
            record(info.name, full_range, operand,
                   "error" if any(f["code"].startswith(("type", "capability"))
                                  for f in findings[-2:]) else "ok",
                   {"block_results": list(frames[-1].results)})
            continue
        if info.effect[0] == "control" and info.effect[1] == "if":
            operand = _read_blocktype(cur)
            cond = pop("i32", full_range, "if", "condition")
            _enter_block("if", operand, stack, frames, cur, full_range,
                         findings, candidates, caps, ft_at)
            record("if", full_range, operand, "ok",
                   {"block_results": list(frames[-1].results)})
            continue
        if info.name == "else":
            _do_else(frames, stack, op_range, findings)
            record("else", full_range, operand, "ok")
            continue
        if info.name == "unreachable":
            frames[-1].polymorphic = True
            del stack[frames[-1].height:]
            findings.append(finding(
                "unreachable-reached",
                "static unreachable: the operand stack is polymorphic from "
                "this point until the block end; underflow here is allowed",
                op_range, severity="info"))
            record("unreachable", full_range, operand, "ok",
                   {"polymorphic_from": op_start})
            continue
        if info.name in ("br", "br_if"):
            depth_v = operand["leb"]["value"]
            if info.name == "br_if":
                pop("i32", full_range, "br_if", "condition")
            _branch(depth_v, info.name == "br", frames, stack, pop,
                    full_range, findings)
            record(info.name, full_range, operand, "ok")
            continue
        if info.name == "br_table":
            _br_table(operand, frames, stack, pop, full_range, findings)
            record("br_table", full_range, operand, "ok")
            continue
        if info.name in ("call", "return_call"):
            _do_call(operand, context, stack, pop, full_range, findings,
                     info.name)
            record(info.name, full_range, operand, "ok")
            continue
        if info.name in ("call_indirect", "return_call_indirect"):
            _do_call_indirect(operand, context, stack, pop, full_range,
                              findings, info.name, caps)
            record(info.name, full_range, operand, "ok")
            continue

        status = _apply_effect(info, operand, stack, pop, full_range,
                               findings, context, local_types, cur)
        record(info.name, full_range, operand,
               "error" if findings and findings[-1]["range"] == full_range
               else "ok")

    for f in cur.findings:
        findings.append(f)

    return {
        "steps": steps,
        "findings": findings,
        "candidates": candidates,
        "final_stack": stack,
        "control_stack_height_trace":
            [{"after_op": s["op"], "depth": s["before_depth"],
              "polymorphic": s["polymorphic"],
              "frame_kind": s["frame_kind"]} for s in steps],
    }
