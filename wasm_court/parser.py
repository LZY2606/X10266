import hashlib
from dataclasses import dataclass, field

from .leb import LebResult, read_s32_leb, read_u32_leb

MAGIC = b"\x00asm"
VERSION = b"\x01\x00\x00\x00"

KNOWN_SECTIONS = {
    1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
    6: "global", 7: "export", 8: "start", 9: "element", 10: "code",
    11: "data", 12: "datacount",
}

VALTYPE = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64"}

PROPOSAL_OPCODES = {
    0x12: "tail-call",
    0xD0: "reference-types",
    0xFD: "simd",
}


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def stable_id(version: int, kind: str, ordinal: int) -> str:
    return f"s{version}.{kind}.{ordinal}"


@dataclass
class ControlFrame:
    frame_id: str
    opcode: str
    start_types: list[str]
    end_types: list[str]
    original_stack_height: int
    unreachable: bool = False


@dataclass
class ParseResult:
    sha256: str
    sections: list[dict] = field(default_factory=list)
    lebs: list[dict] = field(default_factory=list)
    indices: list[dict] = field(default_factory=list)
    functions: list[dict] = field(default_factory=list)
    types: list[dict] = field(default_factory=list)
    imports: list[dict] = field(default_factory=list)
    custom_sections: list[dict] = field(default_factory=list)
    code_steps: list[dict] = field(default_factory=list)
    control_states: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def byte(self, label: str) -> tuple[int, dict | None]:
        start = self.pos
        if self.pos >= len(self.data):
            return -1, {
                "kind": "format_error", "code": "unexpected_end", "severity": "error",
                "message": f"missing {label}", "range": [start, min(start + 1, len(self.data))],
                "candidates": [], "unknown": False,
            }
        value = self.data[self.pos]
        self.pos += 1
        return value, None

    def u32(self) -> tuple[int | None, LebResult]:
        result, self.pos = read_u32_leb(self.data, self.pos)
        return result.value, result

    def s32(self):
        result, self.pos = read_s32_leb(self.data, self.pos)
        return result.value, result

    def take(self, count: int | None):
        if count is None or count < 0:
            return None
        end = self.pos + count
        if end > len(self.data):
            value = self.data[self.pos:]
            self.pos = len(self.data)
            return value
        value = self.data[self.pos:end]
        self.pos = end
        return value


def _finding(fid, code, severity, message, rng, category, source_refs=None, feature=None,
             candidates=None, adopted=True, rejection_reason=None, unknown=False):
    return {
        "id": fid,
        "kind": "finding",
        "findingId": fid,
        "code": code,
        "category": category,
        "severity": severity,
        "status": "accepted" if adopted else "rejected",
        "message": message,
        "minimumFailureRange": {"start": rng[0], "end": rng[1], "unit": "byte",
                               "coordinateBasis": "zero-based-half-open"},
        "sourceRefs": source_refs or [],
        "requiredFeature": feature,
        "candidateIds": candidates or [],
        "rejectionReason": rejection_reason,
        "unknown": unknown,
    }


def _candidate(cid, value, status, reason=None, source_refs=None):
    return {
        "id": cid,
        "kind": "candidate",
        "candidateId": cid,
        "value": value,
        "status": status,
        "reason": reason,
        "sourceRefs": source_refs or [],
    }


def _record_leb(result: ParseResult, version: int, leb: LebResult, purpose: str, counter: dict) -> str:
    counter["leb"] += 1
    lid = stable_id(version, "leb", counter["leb"])
    event = leb.as_event(lid, False, 32, purpose)
    result.lebs.append(event)
    if leb.status == "noncanonical":
        fid = f"{lid}.finding"
        result.findings.append(_finding(
            fid, "noncanonical_leb128", "warning",
            "LEB128 value is numerically decodable but uses a non-minimal encoding",
            (leb.start, leb.end), "leb128", [lid],
            candidates=[f"{lid}.candidate.decode", f"{lid}.candidate.reject"]))
        result.candidates.append(_candidate(f"{lid}.candidate.decode", {"value": leb.value},
                                            "legal_candidate", "decode but mark non-canonical", [lid]))
        result.candidates.append(_candidate(f"{lid}.candidate.reject", {"value": None},
                                            "legal_candidate", "reject under strict canonical rule", [lid]))
    if leb.status == "range_error":
        result.findings.append(_finding(
            f"{lid}.range", "numeric_out_of_range", "error",
            "LEB128 numeric range is outside u32; not reported as mere non-canonical padding",
            (leb.start, leb.end), "leb128", [lid]))
    if leb.status in {"truncated", "malformed"}:
        result.findings.append(_finding(f"{lid}.malformed", "malformed_leb128", "error",
                                        leb.diagnostic or "malformed LEB128", (leb.start, leb.end),
                                        "leb128", [lid]))
    return lid


def _read_name(reader: Reader, result: ParseResult, version: int, counter: dict, purpose: str):
    count, leb = reader.u32()
    lid = _record_leb(result, version, leb, f"{purpose} name length", counter)
    start = reader.pos
    raw = reader.take(count)
    if raw is None or len(raw) != count:
        return None, lid, [start, len(reader.data)]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        value = raw.hex()
    return value, lid, [start, reader.pos]


def _parse_type_section(reader, result, version, end, counter):
    count, leb = reader.u32()
    _record_leb(result, version, leb, "type count", counter)
    for type_index in range(count or 0):
      form, err = reader.byte("function type form")
      if err:
          result.findings.append(_finding(stable_id(version, "finding", counter["finding"] + 1),
                                           err["code"], "error", err["message"], tuple(err["range"]),
                                           "type"))
          counter["finding"] += 1
          return
      param_count, param_leb = reader.u32()
      _record_leb(result, version, param_leb, f"type {type_index} parameter count", counter)
      params = []
      for _ in range(param_count or 0):
          code, bad = reader.byte("parameter type")
          if bad:
              break
          params.append(VALTYPE.get(code, f"unknown:0x{code:02x}"))
      result_count, result_leb = reader.u32()
      _record_leb(result, version, result_leb, f"type {type_index} result count", counter)
      results = []
      for _ in range(result_count or 0):
          code, bad = reader.byte("result type")
          if bad:
              break
          results.append(VALTYPE.get(code, f"unknown:0x{code:02x}"))
      counter["type"] += 1
      tid = stable_id(version, "type", counter["type"])
      result.types.append({
          "id": tid, "kind": "functionType", "typeId": tid,
          "index": type_index, "indexSpace": "type", "params": params, "results": results,
          "sourceRefs": [], "multiValue": len(results) > 1,
      })


def _parse_import_section(reader, result, version, end, counter):
    count, leb = reader.u32()
    _record_leb(result, version, leb, "import count", counter)
    for import_index in range(count or 0):
        module, _, module_range = _read_name(reader, result, version, counter, "import module")
        name, _, name_range = _read_name(reader, result, version, counter, "import field")
        kind, bad = reader.byte("import kind")
        signature = None
        type_index = None
        if not bad and kind == 0:
            type_index, type_leb = reader.u32()
            type_ref = _record_leb(result, version, type_leb, f"import {import_index} function type", counter)
            signature_ref = None
            if type_index is not None and type_index < len(result.types):
                signature_ref = result.types[type_index]["id"]
            signature = {"kind": "func", "typeIndex": type_index, "typeRef": signature_ref}
            counter["index"] += 1
            fid = stable_id(version, "index", counter["index"])
            result.indices.append({
                "id": fid, "kind": "index", "indexId": fid, "space": "function",
                "index": import_index, "origin": "import", "signatureRef": signature_ref,
                "sourceRefs": [type_ref],
            })
        elif not bad:
            reader.pos += 1
        counter["import"] += 1
        iid = stable_id(version, "import", counter["import"])
        result.imports.append({
            "id": iid, "kind": "import", "importId": iid, "index": import_index,
            "module": module, "name": name, "importKind": kind,
            "contract": signature, "byteRange": {"start": module_range[0], "end": reader.pos, "unit": "byte"},
            "rawRepresentation": {"module": module, "field": name, "kind": kind},
        })


def _parse_function_section(reader, result, version, end, counter):
    count, leb = reader.u32()
    _record_leb(result, version, leb, "function count", counter)
    imported = len([i for i in result.indices if i["space"] == "function" and i["origin"] == "import"])
    for local_index in range(count or 0):
        type_index, type_leb = reader.u32()
        ref = _record_leb(result, version, type_leb, f"function {imported + local_index} type", counter)
        signature_ref = None
        if type_index is not None and type_index < len(result.types):
            signature_ref = result.types[type_index]["id"]
        counter["index"] += 1
        iid = stable_id(version, "index", counter["index"])
        result.indices.append({
            "id": iid, "kind": "index", "indexId": iid, "space": "function",
            "index": imported + local_index, "origin": "defined",
            "typeIndex": type_index, "signatureRef": signature_ref, "sourceRefs": [ref],
        })
        counter["function"] += 1
        fid = stable_id(version, "function", counter["function"])
        result.functions.append({
            "id": fid, "kind": "function", "functionId": fid,
            "functionIndex": imported + local_index, "indexRef": iid,
            "typeRef": signature_ref, "bodyRange": None,
        })


def _resolve_blocktype(code):
    if code == 0x40:
        return [], []
    if code in VALTYPE:
        return [], [VALTYPE[code]]
    return [], [f"blocktype:0x{code:02x}"]


def _add_transition(result, version, counter, fn_id, op, start, end, before, after,
                    frame_ids, status="ok", diagnostic=None):
    counter["step"] += 1
    sid = stable_id(version, "transition", counter["step"])
    result.code_steps.append({
        "id": sid,
        "kind": "typeTransition",
        "transitionId": sid,
        "functionRef": fn_id,
        "opcode": op,
        "byteRange": {"start": start, "end": end, "unit": "byte"},
        "beforeStack": list(before),
        "afterStack": list(after),
        "controlFrames": list(frame_ids),
        "status": status,
        "diagnostic": diagnostic,
        "sourceRefs": [],
    })
    return sid


def _record_stack_finding(result, version, counter, code, message, rng, fn_id,
                          refs=None, feature=None, unknown=False, candidates=None):
    counter["finding"] += 1
    fid = stable_id(version, "finding", counter["finding"])
    finding = _finding(fid, code, "error", message, rng, "type_stack", refs or [],
                       feature=feature, unknown=unknown, candidates=candidates)
    finding["functionRef"] = fn_id
    result.findings.append(finding)
    return fid


def _pop(stack, frame: ControlFrame):
    if len(stack) == frame.original_stack_height:
        if frame.unreachable:
            return "unreachable"
        return None
    return stack.pop()


def _expect(result, version, counter, stack, frame, expected, rng, fn_id, op, opcode_ref,
            polymorphic_errors, fn_index):
    actual = _pop(stack, frame)
    if actual is None:
        if frame.unreachable:
            polymorphic_errors.append((rng, f"{op} has no operand in unreachable polymorphic region"))
            return True
        _record_stack_finding(
            result, version, counter, "stack_underflow",
            f"{op} requires {expected} but the operand stack is empty outside unreachable code",
            rng, fn_id, [opcode_ref])
        return False
    if actual == "unreachable":
        return True
    if actual != expected:
        _record_stack_finding(
            result, version, counter, "type_mismatch",
            f"{op} requires {expected} but found {actual}", rng, fn_id, [opcode_ref])
        return False
    return True


def _validate_function_body(result, version, counter, fn_record, body, body_range, features, fn_index):
    reader = Reader(body)
    local_types = []
    local_groups, local_leb = reader.u32()
    group_leb = None
    for _ in range(local_groups or 0):
        group_count, count_leb = reader.u32()
        code, bad = reader.byte("local type")
        local_types.extend([VALTYPE.get(code, "unknown") for _ in range(group_count or 0)])
        group_leb = count_leb
    fn_id = fn_record["id"]
    fn_record["bodyRange"] = {"start": body_range[0] + 0, "end": body_range[1], "unit": "byte"}
    fn_record["locals"] = local_types
    stack: list[str] = []
    frames: list[ControlFrame] = []
    polymorphic_errors: list[tuple[tuple[int, int], str]] = []
    type_ref = fn_record.get("typeRef")
    ftype = next((t for t in result.types if t["id"] == type_ref), None)
    root = ControlFrame(stable_id(version, "control", 0), "root", [], ftype["results"] if ftype else [], 0)
    frames.append(root)

    def snapshot_state(status="active"):
        counter["control"] += 1
        cid = stable_id(version, "control", counter["control"] + 0)
        result.control_states.append({
            "id": cid,
            "kind": "controlState",
            "controlId": cid,
            "functionRef": fn_id,
            "stack": list(stack),
            "frames": [
                {"id": fr.frame_id, "opcode": fr.opcode, "startTypes": fr.start_types,
                 "endTypes": fr.end_types, "unreachable": fr.unreachable,
                 "originalStackHeight": fr.original_stack_height}
                for fr in frames
            ],
            "polymorphic": any(fr.unreachable for fr in frames),
            "status": status,
        })

    while reader.pos < len(body):
        start = body_range[0] + reader.pos
        opcode, bad = reader.byte("opcode")
        end = body_range[0] + reader.pos
        opcode_ref = _add_transition(result, version, counter, fn_id, f"0x{opcode:02x}",
                                     start, end, stack, stack, [f.frame_id for f in frames])
        frame = frames[-1]
        if bad:
            _record_stack_finding(result, version, counter, bad["code"], bad["message"],
                                  (start, end), fn_id)
            return
        if opcode in PROPOSAL_OPCODES and not features.get(PROPOSAL_OPCODES[opcode], False):
            _record_stack_finding(
                result, version, counter, "capability_missing",
                f"opcode 0x{opcode:02x} requires enabled proposal '{PROPOSAL_OPCODES[opcode]}' "
                "instead of being reported as an unknown byte",
                (start, end), fn_id, [opcode_ref], feature=PROPOSAL_OPCODES[opcode])
            return
        if opcode not in {0x00, 0x01, 0x02, 0x04, 0x05, 0x0B, 0x0D, 0x0E, 0x0F, 0x10,
                          0x1A, 0x20, 0x21, 0x23, 0x24, 0x41, 0x42, 0x6A, 0x6B, 0x1B,
                          *PROPOSAL_OPCODES}:
            _record_stack_finding(
                result, version, counter, "unknown_opcode",
                f"opcode 0x{opcode:02x} is not known to this validator",
                (start, end), fn_id, [opcode_ref], unknown=True)
            return
        if opcode == 0x00:
            frame.unreachable = True
            del stack[frame.original_stack_height:]
        elif opcode == 0x01:
            pass
        elif opcode in {0x02, 0x03, 0x04}:
            bt, bad_byte = reader.byte("blocktype")
            starts, ends = _resolve_blocktype(bt)
            for typ in starts:
                stack.append(typ)
            counter["control"] += 1
            cframe = ControlFrame(stable_id(version, "control", counter["control"]),
                                  {0x02: "block", 0x03: "loop", 0x04: "if"}[opcode], starts, ends,
                                  len(stack) - len(starts))
            if opcode == 0x04:
                _expect(result, version, counter, stack, frame, "i32", (start, end), fn_id,
                        "if", opcode_ref, polymorphic_errors, fn_index)
            frames.append(cframe)
        elif opcode == 0x05:
            frame.unreachable = False
            frame.original_stack_height = len(stack)
        elif opcode == 0x0B:
            if len(frames) == 1:
                break
            closed = frames.pop()
            for typ in closed.end_types:
                stack.append(typ)
        elif opcode in {0x0D, 0x0E, 0x0F}:
            target, target_leb = reader.u32()
            _record_leb(result, version, target_leb, "branch label index", counter)
            frame.unreachable = True
            del stack[frame.original_stack_height:]
        elif opcode == 0x10:
            callee, call_leb = reader.u32()
            call_ref = _record_leb(result, version, call_leb, "call function index", counter)
            target_index = result.indices[callee] if callee is not None and callee < len(result.indices) else None
            target_type = None
            if target_index and target_index.get("signatureRef"):
                target_type = next(t for t in result.types if t["id"] == target_index["signatureRef"])
            if target_type:
                for typ in reversed(target_type["params"]):
                    _expect(result, version, counter, stack, frame, typ, (start, end), fn_id,
                            f"call {callee}", call_ref, polymorphic_errors, fn_index)
                for typ in target_type["results"]:
                    stack.append(typ)
            else:
                _record_stack_finding(result, version, counter, "unknown_index",
                                      f"call targets undefined function index {callee}",
                                      (start, end), fn_id, [call_ref], unknown=True)
                return
        elif opcode == 0x12:
            callee, call_leb = reader.u32()
            _record_leb(result, version, call_leb, "return_call function index", counter)
            frame.unreachable = True
            del stack[frame.original_stack_height:]
        elif opcode in {0x20, 0x21}:
            local_index, local_leb = reader.u32()
            local_ref = _record_leb(result, version, local_leb, "local index", counter)
            typ = local_types[local_index] if local_index is not None and local_index < len(local_types) else None
            if typ is None:
                _record_stack_finding(result, version, counter, "unknown_index",
                                      f"local index {local_index} is not defined",
                                      (start, end), fn_id, [local_ref], unknown=True)
                return
            if opcode == 0x20:
                stack.append(typ)
            else:
                _expect(result, version, counter, stack, frame, typ, (start, end), fn_id,
                        "local.set", local_ref, polymorphic_errors, fn_index)
        elif opcode in {0x23, 0x24}:
            global_index, global_leb = reader.u32()
            gref = _record_leb(result, version, global_leb, "global index", counter)
            typ = "i32" if global_index == 0 else "i64"
            if opcode == 0x23:
                stack.append(typ)
            else:
                _expect(result, version, counter, stack, frame, typ, (start, end), fn_id,
                        "global.set", gref, polymorphic_errors, fn_index)
        elif opcode in {0x41, 0x42}:
            _, value_leb = reader.s32() if opcode == 0x41 else reader.u32()
            _record_leb(result, version, value_leb, "constant", counter)
            stack.append("i32" if opcode == 0x41 else "i64")
        elif opcode in {0x6A, 0x6B, 0x1A, 0x1B}:
            if opcode == 0x1A:
                _expect(result, version, counter, stack, frame, "i32", (start, end), fn_id,
                        "drop", opcode_ref, polymorphic_errors, fn_index)
            elif opcode == 0x1B:
                _expect(result, version, counter, stack, frame, "i32", (start, end), fn_id,
                        "select", opcode_ref, polymorphic_errors, fn_index)
                _expect(result, version, counter, stack, frame, "i32", (start, end), fn_id,
                        "select", opcode_ref, polymorphic_errors, fn_index)
                _expect(result, version, counter, stack, frame, "i32", (start, end), fn_id,
                        "select condition", opcode_ref, polymorphic_errors, fn_index)
                stack.append("i32")
            else:
                typ = "i32" if opcode == 0x6A else "i64"
                _expect(result, version, counter, stack, frame, typ, (start, end), fn_id,
                        "add", opcode_ref, polymorphic_errors, fn_index)
                _expect(result, version, counter, stack, frame, typ, (start, end), fn_id,
                        "add", opcode_ref, polymorphic_errors, fn_index)
                stack.append(typ)
        snapshot_state()
    if ftype:
        for expected in reversed(ftype["results"]):
            _expect(result, version, counter, stack, root, expected,
                    (max(0, len(body) - 1), len(body)), fn_id, "function return",
                    fn_record.get("id"), polymorphic_errors, fn_index)


def _parse_code_section(reader, result, version, end, counter, features):
    count, count_leb = reader.u32()
    count_ref = _record_leb(result, version, count_leb, "code body count", counter)
    defined = [f for f in result.functions]
    if count != len(defined):
        counter["finding"] += 1
        fid = stable_id(version, "finding", counter["finding"])
        result.findings.append(_finding(
            fid, "code_function_count_mismatch", "error",
            f"function section declares {len(defined)} bodies but code section contains {count}",
            (count_leb.start, count_leb.end), "index_space", [count_ref]))
    for body_index in range(count or 0):
        body_start = reader.pos
        size, size_leb = reader.u32()
        size_ref = _record_leb(result, version, size_leb, f"function body {body_index} size", counter)
        body_abs_start = reader.pos
        body_abs_end = body_abs_start + (size or 0)
        raw_body = reader.take(size)
        if raw_body is None or len(raw_body) != (size or 0):
            counter["finding"] += 1
            fid = stable_id(version, "finding", counter["finding"])
            result.findings.append(_finding(
                fid, "truncated_function_body", "error", "function body runs past module bytes",
                (size_leb.start, len(reader.data)), "code", [size_ref]))
            return
        fn_record = defined[body_index] if body_index < len(defined) else None
        if fn_record is None:
            counter["finding"] += 1
            fid = stable_id(version, "finding", counter["finding"])
            result.findings.append(_finding(
                fid, "extra_function_body", "error", "code body has no function-section declaration",
                (body_start, body_abs_end), "code", [size_ref]))
            continue
        _validate_function_body(result, version, counter, fn_record, raw_body,
                                (body_abs_start, body_abs_end), features,
                                fn_record["functionIndex"])


def _parse_custom_section(reader, result, version, section_end, counter, section_id,
                          section_start, size_leb):
    name_start = reader.pos
    name, name_ref, name_range = _read_name(reader, result, version, counter, "custom section")
    payload_start = reader.pos
    payload = reader.data[payload_start:section_end]
    reader.pos = section_end
    counter["custom"] += 1
    cid = stable_id(version, "custom", counter["custom"])
    result.custom_sections.append({
        "id": cid,
        "kind": "customSection",
        "customId": cid,
        "name": name,
        "nameRange": {"start": name_range[0], "end": name_range[1], "unit": "byte"},
        "payloadRange": {"start": payload_start, "end": section_end, "unit": "byte"},
        "payloadHex": payload.hex(),
        "payloadLength": {"value": len(payload), "unit": "byte"},
        "rawRepresentation": payload.hex(),
        "sourceRefs": [section_id, name_ref or ""],
    })


def parse_module(data: bytes, version: int = 1, features: dict | None = None) -> ParseResult:
    features = features or {}
    result = ParseResult(sha256=sha256_hex(data))
    counter = {"leb": 0, "finding": 0, "type": 0, "import": 0, "index": 0,
               "function": 0, "step": 0, "control": 0, "custom": 0}
    reader = Reader(data)
    if len(data) < 8 or data[:4] != MAGIC or data[4:8] != VERSION:
        result.findings.append(_finding(
            stable_id(version, "finding", 1), "invalid_module_header", "error",
            "module must begin with WebAssembly magic 00 61 73 6d and version 01 00 00 00",
            (0, min(8, len(data))), "header"))
        return result
    reader.pos = 8
    last_standard_id = 0
    seen_standard = set()
    ordinal = 0
    while reader.pos < len(data):
        ordinal += 1
        section_start = reader.pos
        section_id, bad = reader.byte("section id")
        if bad:
            result.findings.append(_finding(stable_id(version, "finding", counter["finding"] + 1),
                                            bad["code"], "error", bad["message"],
                                            tuple(bad["range"]), "section"))
            counter["finding"] += 1
            return result
        size, size_leb = reader.u32()
        size_ref = _record_leb(result, version, size_leb, f"section {ordinal} size", counter)
        section_end = reader.pos + (size or 0)
        if section_end > len(data):
            counter["finding"] += 1
            result.findings.append(_finding(
                stable_id(version, "finding", counter["finding"]), "section_size_overflow",
                "error", "section size extends past the end of the module",
                (section_start, len(data)), "section", [size_ref]))
            return result
        sid = stable_id(version, "section", ordinal)
        section_event = {
            "id": sid,
            "kind": "section",
            "sectionId": sid,
            "ordinal": ordinal,
            "sectionCode": section_id,
            "name": "custom" if section_id == 0 else KNOWN_SECTIONS.get(section_id, f"unknown:{section_id}"),
            "byteRange": {"start": section_start, "end": section_end, "unit": "byte",
                          "coordinateBasis": "zero-based-half-open"},
            "headerRange": {"start": section_start, "end": reader.pos, "unit": "byte"},
            "payloadRange": {"start": reader.pos, "end": section_end, "unit": "byte"},
            "declaredSize": {"value": size, "unit": "byte"},
            "actualSize": {"value": section_end - reader.pos, "unit": "byte"},
            "rawBytesHex": data[section_start:section_end].hex(),
            "sourceRefs": [size_ref],
            "adopted": True,
        }
        result.sections.append(section_event)
        if section_id == 0:
            _parse_custom_section(reader, result, version, section_end, counter, sid,
                                  section_start, size_ref)
        else:
            if section_id in seen_standard:
                counter["finding"] += 1
                result.findings.append(_finding(
                    stable_id(version, "finding", counter["finding"]), "duplicate_section", "error",
                    f"{KNOWN_SECTIONS.get(section_id, section_id)} section appears more than once",
                    (section_start, section_end), "section_order", [sid],
                    candidates=[f"{sid}.candidate.keep-first", f"{sid}.candidate.keep-last"]))
                result.candidates.append(_candidate(f"{sid}.candidate.keep-first",
                                                    {"adoptedSection": "first"}, "legal_candidate",
                    "WebAssembly 1.0 requires one known section; retain first and reject duplicate",
                    [sid]))
                result.candidates.append(_candidate(f"{sid}.candidate.keep-last",
                    {"adoptedSection": "last"}, "rejected_candidate",
                    "keeping the last duplicate would silently overwrite an indexed source", [sid]))
                section_event["adopted"] = False
            if section_id in KNOWN_SECTIONS and section_id < last_standard_id:
                counter["finding"] += 1
                result.findings.append(_finding(
                    stable_id(version, "finding", counter["finding"]), "section_out_of_order",
                    "error", "known sections must occur in ascending section-id order",
                    (section_start, section_end), "section_order", [sid]))
            if section_id not in KNOWN_SECTIONS:
                counter["finding"] += 1
                result.findings.append(_finding(
                    stable_id(version, "finding", counter["finding"]), "unknown_section",
                    "error", f"section id {section_id} is not assigned in the active specification",
                    (section_start, section_end), "section_order", [sid], unknown=True))
            if section_id in KNOWN_SECTIONS:
                last_standard_id = max(last_standard_id, section_id)
                seen_standard.add(section_id)
            if section_id == 1:
                _parse_type_section(reader, result, version, section_end, counter)
            elif section_id == 2:
                _parse_import_section(reader, result, version, section_end, counter)
            elif section_id == 3:
                _parse_function_section(reader, result, version, section_end, counter)
            elif section_id == 10:
                _parse_code_section(reader, result, version, section_end, counter, features)
            else:
                reader.pos = section_end
        reader.pos = section_end
    for type_event in result.types:
        if type_event["multiValue"] and not features.get("multi_value", False):
            counter["finding"] += 1
            fid = stable_id(version, "finding", counter["finding"])
            result.findings.append(_finding(
                fid, "capability_missing", "error",
                "multiple result values require enabled proposal 'multi_value'",
                (0, 0), "capability", [type_event["id"]], feature="multi_value"))
    return result
