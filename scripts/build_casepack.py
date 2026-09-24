from __future__ import annotations

import base64
import json
from pathlib import Path

from wasmverify.domain import FEATURES
from wasmverify.engine import Engine
from wasmverify.leb import sleb_bytes, uleb_bytes
from wasmverify.store import Store, normalize_config


HEADER = b"\x00asm\x01\x00\x00\x00"


def name(value: str) -> bytes:
    raw = value.encode("utf-8")
    return uleb_bytes(len(raw)) + raw


def section(sid: int, payload: bytes, size_override: bytes | None = None) -> bytes:
    return bytes([sid]) + (size_override or uleb_bytes(len(payload))) + payload


def functype(params: list[int], results: list[int]) -> bytes:
    return b"\x60" + uleb_bytes(len(params)) + bytes(params) + uleb_bytes(len(results)) + bytes(results)


def type_section(types: list[bytes]) -> bytes:
    return section(1, uleb_bytes(len(types)) + b"".join(types))


def function_import(module: str, field: str, type_index: int) -> bytes:
    return name(module) + name(field) + b"\x00" + uleb_bytes(type_index)


def import_section(items: list[bytes]) -> bytes:
    return section(2, uleb_bytes(len(items)) + b"".join(items))


def function_section(indices: list[int]) -> bytes:
    return section(3, uleb_bytes(len(indices)) + b"".join(uleb_bytes(i) for i in indices))


def export_function(export_name: str, index: int) -> bytes:
    return name(export_name) + b"\x00" + uleb_bytes(index)


def export_section(items: list[bytes]) -> bytes:
    return section(7, uleb_bytes(len(items)) + b"".join(items))


def code_section(bodies: list[bytes]) -> bytes:
    payload = uleb_bytes(len(bodies))
    for expr in bodies:
        body = b"\x00" + expr + b"\x0b"
        payload += uleb_bytes(len(body)) + body
    return section(10, payload)


def custom_section(section_name: str, payload: bytes) -> bytes:
    return section(0, name(section_name) + payload)


I32, I64 = 0x7F, 0x7E


def build_modules() -> dict[str, bytes]:
    baseline = HEADER
    baseline += type_section([functype([], [I32]), functype([], [I32])])
    baseline += import_section([function_import("env", "increment", 0)])
    baseline += function_section([1])
    baseline += export_section([export_function("answer", 1)])
    baseline += code_section([b"\x10\x00"])
    baseline += custom_section("court.note", b"baseline: preserved custom evidence")

    multi = HEADER + type_section([functype([], [I32, I64])]) + function_section([0]) + code_section([b"\x41\x00\x42\x00"])

    noncanon_type_payload = b"\x81\x00" + functype([], [I32])
    noncanon = HEADER + section(1, noncanon_type_payload) + function_section([0]) + code_section([b"\x41\x00"])

    overflow = HEADER + b"\x01\x80\x80\x80\x80\x10"

    unreachable = HEADER + type_section([functype([], [])]) + function_section([0]) + code_section([b"\x1a\x00\x1a"])

    tail = HEADER + type_section([functype([], [])]) + function_section([0]) + code_section([b"\x12\x00"])

    unknown = HEADER + type_section([functype([], [])]) + function_section([0]) + code_section([b"\xef"])

    mismatch = HEADER + type_section([functype([I32], [I32])]) + import_section([function_import("env", "increment", 0)])

    empty_type = type_section([])
    bad_order = HEADER + empty_type + code_section([]) + empty_type

    custom_revision = HEADER
    custom_revision += type_section([functype([], [I32]), functype([], [I32])])
    custom_revision += import_section([function_import("env", "increment", 0)])
    custom_revision += function_section([1])
    custom_revision += export_section([export_function("answer", 1)])
    custom_revision += code_section([b"\x10\x00"])
    custom_revision += custom_section("court.note", b"local revision: only custom payload changed")

    ambiguous = HEADER + type_section([functype([], [I32])]) + import_section([function_import("env", "increment", 0)])

    return {
        "01_baseline.wasm": baseline,
        "02_multivalue_disabled.wasm": multi,
        "03_noncanonical_leb.wasm": noncanon,
        "04_numeric_overflow_leb.wasm": overflow,
        "05_unreachable_polymorphic.wasm": unreachable,
        "06_tail_call_disabled.wasm": tail,
        "07_unknown_opcode.wasm": unknown,
        "08_import_signature_mismatch.wasm": mismatch,
        "09_duplicate_out_of_order.wasm": bad_order,
        "10_custom_local_revision.wasm": custom_revision,
        "11_import_ambiguous.wasm": ambiguous,
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    out = root / "casepack"
    moddir = out / "modules"
    moddir.mkdir(parents=True, exist_ok=True)
    modules = build_modules()
    for filename, data in modules.items():
        (moddir / filename).write_bytes(data)

    store = Store(":memory:", virtual_clock=lambda: "2026-09-25T00:00:00Z")
    project_id = "module-boundary-court"
    project = store.add_project(project_id, "模块边界庭：WebAssembly 段索引、类型栈与提案能力验证", "2026-09-25T00:00:01Z")
    stamps = [
        ("module", "01_baseline.wasm", "初始基线：完整保留 section/LEB/索引/import/custom"),
        ("config", "baseline", "MVP 能力与 env.increment: () -> i32"),
        ("module", "02_multivalue_disabled.wasm", "边界：多值返回在 proposal 关闭时提交"),
        ("config", "multi_enabled", "参数修订：启用 multi_value"),
        ("module", "03_noncanonical_leb.wasm", "边界：非规范 LEB128"),
        ("module", "04_numeric_overflow_leb.wasm", "边界：数值越界与非规范编码分离"),
        ("module", "05_unreachable_polymorphic.wasm", "边界：unreachable 前具体栈失败，其后多态"),
        ("module", "06_tail_call_disabled.wasm", "边界：tail_call proposal 关闭"),
        ("module", "07_unknown_opcode.wasm", "边界：真正未知字节"),
        ("module", "08_import_signature_mismatch.wasm", "边界：host import 签名不匹配"),
        ("module", "09_duplicate_out_of_order.wasm", "边界：section 重复与乱序"),
        ("module", "10_custom_local_revision.wasm", "局部源数据修订：只改变自定义段"),
        ("config", "ambiguous_contracts", "参数修订：增加无法唯一定位的重复合法 host 候选"),
        ("module", "11_import_ambiguous.wasm", "边界：全部合法 import 候选保留"),
    ]
    second = 2
    engine = Engine(store)
    noncanon_event = None
    for kind, key, label in stamps:
        second += 1
        ts = f"2026-09-25T00:00:{second:02d}Z"
        if kind == "module":
            event = store.add_module(project_id, modules[key], label, ts)
            if key == "03_noncanonical_leb.wasm":
                noncanon_event = event
        else:
            features = {name: False for name in FEATURES}
            contracts = [{"module": "env", "name": "increment", "params": [], "results": ["i32"]}]
            if key == "multi_enabled":
                features["multi_value"] = True
            if key == "ambiguous_contracts":
                features["multi_value"] = True
                contracts.append({"module": "env", "name": "increment", "params": [], "results": ["i32"]})
            store.add_config(project_id, {"features": features, "host_imports": contracts}, label, ts)

    parse_result, _ = engine.parse_event(noncanon_event)
    target = next(f["stable_id"] for f in parse_result["value"]["findings"] if f["code"] == "NONCANONICAL_LEB128")
    store.add_decision(project_id, target, True, "第一次人工决定：暂接受该非规范编码以继续审查", "2026-09-25T00:00:17Z")
    store.add_decision(project_id, target, False, "冲突人工决定：按规范 LEB128 规则否定；旧决定保留且不被覆盖", "2026-09-25T00:00:18Z")

    archive = store.export_project(project_id)
    archive["casepack_manifest"] = {
        "title": project["title"],
        "seed": 20260925,
        "time_base": "virtual UTC timestamps embedded in the event log",
        "network": "offline",
        "modules_dir": "casepack/modules",
        "required_paths": [
            "section duplicate/out-of-order", "non-canonical LEB128", "numeric LEB overflow",
            "polymorphic unreachable stack", "multi-value", "disabled proposal opcode",
            "import mismatch", "ambiguous import candidates", "custom section fidelity",
        ],
    }
    (out / "module-boundary-court.json").write_text(json.dumps(archive, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
