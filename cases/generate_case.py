from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "module-boundary-court"

def uleb(n):
    out=[]
    while True:
        b=n&0x7f; n >>=7
        if n: out.append(b|0x80)
        else: out.append(b); return bytes(out)

def vec(items):
    if isinstance(items, bytes):
        return uleb(len(items)) + items
    return uleb(len(items)) + b''.join(items)

def section(sid, payload):
    return bytes([sid]) + uleb(len(payload)) + payload

def custom(name, data=b''):
    raw=uleb(len(name))+name.encode()+data
    return section(0, raw)

def type_section(results=()):
    return section(1, vec([b'\x60' + vec([]) + vec(bytes(0x7f if x=='i32' else 0x7e for x in results))]))

def import_section():
    name=uleb(3)+b'env'+uleb(3)+b'log'
    return section(2, vec([name + b'\x00' + uleb(0)]))

def function_section(n=1):
    return section(3, vec([uleb(0) for _ in range(n)]))

def code_section(body):
    body_with_locals=uleb(0)+body
    return section(10, vec([uleb(len(body_with_locals))+body_with_locals]))

def module(sections):
    return b'\x00asm\x01\x00\x00\x00' + b''.join(sections)

NOTE=custom('court.note', b'{"retention":"custom-section-preserved"}')
INITIAL=module([type_section(('i32',)), import_section(), function_section(), code_section(bytes([0x41,0x01,0x0B])), NOTE])
NONCANON_BODY=bytes([0x80,0x00,0xD0,0x70,0x0B])
NONCANON=module([type_section(), import_section(), function_section(), section(10, vec([uleb(len(NONCANON_BODY))+NONCANON_BODY])), NOTE])
UNREACH=module([type_section(('i32',)), import_section(), function_section(), code_section(bytes([0x00,0x6A,0x0B])), NOTE])
DUP=module([type_section(('i32',)), import_section(), type_section(('i32',)), function_section(), code_section(bytes([0x41,0x01,0x0B])), NOTE])
MULTI=module([type_section(('i32','i32')), import_section(), function_section(), code_section(bytes([0x41,1,0x41,2,0x0B])), NOTE])
BASE_PARAMS={"proposals":{"multi_value":False,"reference_types":False,"sign_extension":False,"bulk_memory":False},"host_imports":{"imports":[{"module":"env","name":"log","desc":{"kind":"function","type_index":0}}]}}
ENABLED=dict(BASE_PARAMS); ENABLED["proposals"]={**ENABLED["proposals"],"reference_types":True}
MISMATCH=json.loads(json.dumps(BASE_PARAMS)); MISMATCH["host_imports"]["imports"][0]["desc"]={"kind":"function","type_index":1}

steps=[
 {"kind":"import","label":"r1 initial baseline with retained custom section","binary_hex":INITIAL.hex(),"params":BASE_PARAMS,"actor":"runtime-team"},
 {"kind":"parameter_adjustment","label":"r2 enable reference_types proposal","params":ENABLED,"actor":"runtime-team"},
 {"kind":"source_revision","label":"r3 noncanonical function local-count LEB128","binary_hex":NONCANON.hex(),"params":ENABLED,"actor":"runtime-team"},
 {"kind":"parameter_adjustment","label":"r4 close reference_types to distinguish capability from unknown byte","params":BASE_PARAMS,"actor":"runtime-team"},
 {"kind":"source_revision","label":"r5 unreachable region with polymorphic i32.add","binary_hex":UNREACH.hex(),"params":BASE_PARAMS,"actor":"runtime-team"},
 {"kind":"source_revision","label":"r6 duplicate and out-of-order type section","binary_hex":DUP.hex(),"params":BASE_PARAMS,"actor":"runtime-team"},
 {"kind":"source_revision","label":"r7 disabled multi-value function result","binary_hex":MULTI.hex(),"params":BASE_PARAMS,"actor":"runtime-team"},
 {"kind":"parameter_adjustment","label":"r8 host import signature mismatch","params":MISMATCH,"actor":"runtime-team"},
]
case={
 "case_id":"module-boundary-court",
 "title":"模块边界庭：WebAssembly 段索引、类型栈与提案能力验证",
 "seed":20260925,
 "virtual_time_base":"2026-09-25T00:00:00Z",
 "steps":steps,
 "conflict":{"finding_status":"candidate","decision_a":"accepted","decision_b":"rejected","rationale_a":"accept bounded polymorphic candidate for exploratory review","rationale_b":"reject after host team says exploratory repair cannot ship"},
 "expected_codes":["duplicate_section","section_out_of_order","noncanonical_leb","unreachable_stack","capability_missing","import_mismatch"],
 "coordinate_basis":{"byte_offset":"zero_based_inclusive_start_exclusive_end","leb128":"unsigned_leb128_bytes","stack":"function_frame_bottom_to_top","custom_sections":"raw_payload_retained"}
}
(ROOT/'case.json').write_text(json.dumps(case,ensure_ascii=False,indent=2),encoding='utf-8')
for name,data in [('initial.wasm',INITIAL),('noncanonical-local-count.wasm',NONCANON),('unreachable-poly.wasm',UNREACH),('duplicate-ordered-type.wasm',DUP),('multi-value-disabled.wasm',MULTI)]:
    (ROOT/name).write_bytes(data)
(ROOT/'README.md').write_text('''# 模块边界庭离线案例\n\n固定 seed 为 20260925，虚拟时间从 `2026-09-25T00:00:00Z` 开始。案例按父子修订重放 section 重复/乱序、非规范 LEB128、unreachable polymorphic stack、多值返回、提案关闭、host import 不匹配和自定义段保真。\n\n`case.json` 是机器可读的重放档案；`*.wasm` 是可复制的小型原始样例。所有字节坐标均为从 0 开始、左闭右开。\n''',encoding='utf-8')
print(ROOT)

ROOT.mkdir(parents=True, exist_ok=True)
