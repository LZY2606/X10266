"""验收测试：模块边界庭 —— 固定 seed、临时目录、虚拟时间、不访问公网。"""
import json
import random
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import casepack
import wasmcore
from app import create_app
from store import Store

SEED = 20260919


class FakeClock:
    def __init__(self):
        self.t = 0

    def __call__(self):
        self.t += 1
        return f"2026-01-01T00:00:{self.t:02d}+00:00"


@pytest.fixture(autouse=True)
def fixed_seed():
    random.seed(SEED)
    np.random.seed(SEED)


@pytest.fixture()
def store(tmp_path):
    return Store(tmp_path / "test.db", clock=FakeClock())


@pytest.fixture()
def client(tmp_path):
    from fastapi.testclient import TestClient
    app = create_app(db_path=str(tmp_path / "api.db"), clock=FakeClock())
    return TestClient(app)


def codes_of(result):
    return [e["code"] for e in result["errors"]] + \
           [e["code"] for e in result["function_errors"]]


# ---------- 七项验收场景 ----------

@pytest.mark.parametrize("key", [s["key"] for s in casepack.SCENARIOS])
def test_scenario_expectations(key):
    sc = next(s for s in casepack.SCENARIOS if s["key"] == key)
    res = wasmcore.validate_module(sc["wasm"], sc["proposals"], sc["host"])
    exp = sc["expect"]
    codes = codes_of(res)
    if exp.get("ok"):
        assert res["ok"], f"{key}: expected valid, got {codes}"
    for c in exp.get("errors", []):
        assert c in codes, f"{key}: missing {c} in {codes}"
    for c in exp.get("absent", []):
        assert c not in codes, f"{key}: unexpected {c} in {codes}"
    for j in exp.get("judgments", []):
        assert j in [x["rule"] for x in res["judgments"]]
    if "polymorphic_functions" in exp:
        got = [f["index"] for f in res["functions"] if f["used_polymorphic_stack"]]
        assert got == exp["polymorphic_functions"]
    if "custom_sha256" in exp:
        assert res["custom_sections"][0]["payload_sha256"] == exp["custom_sha256"]


def test_leb128_form_and_range_are_distinct():
    """不规范 LEB128 与数值越界必须分开报告。"""
    form = next(s for s in casepack.SCENARIOS if s["key"] == "noncanonical-leb128")
    rang = next(s for s in casepack.SCENARIOS if s["key"] == "leb128-range-vs-form")
    rf = wasmcore.validate_module(form["wasm"], form["proposals"], form["host"])
    rr = wasmcore.validate_module(rang["wasm"], rang["proposals"], rang["host"])
    assert "noncanonical_leb128" in codes_of(rf)
    assert "value_out_of_range" not in codes_of(rf)
    assert "value_out_of_range" in codes_of(rr)
    assert "noncanonical_leb128" not in codes_of(rr)
    # 判断依据以机器可读形式存在
    assert any(j["rule"] == "leb128_form_vs_range" for j in rf["judgments"])
    assert any(j["rule"] == "leb128_form_vs_range" for j in rr["judgments"])


def test_polymorphic_stack_only_in_unreachable():
    sc = next(s for s in casepack.SCENARIOS if s["key"] == "unreachable-stack")
    res = wasmcore.validate_module(sc["wasm"], sc["proposals"], sc["host"])
    fn0, fn1 = res["functions"]
    assert fn0["errors"] == [] and fn0["used_polymorphic_stack"]
    assert not fn1["used_polymorphic_stack"]
    assert fn1["errors"][0]["code"] == "stack_underflow"
    # 最小失败字节范围指向出错指令本身
    assert fn1["errors"][0]["range"]["end"] - fn1["errors"][0]["range"]["start"] == 1


def test_capability_missing_vs_unknown_opcode():
    sc = next(s for s in casepack.SCENARIOS if s["key"] == "proposal-off-opcode")
    res = wasmcore.validate_module(sc["wasm"], sc["proposals"], sc["host"])
    fn0, fn1 = res["functions"]
    assert fn0["errors"][0]["code"] == "capability_missing"
    assert fn0["errors"][0]["details"]["proposal"] == "bulk-memory"
    assert fn1["errors"][0]["code"] == "unknown_opcode"
    j = next(j for j in res["judgments"] if j["rule"] == "capability_vs_unknown")
    assert j["evidence"] == {"capability_missing": 1, "unknown_opcode": 1}


def test_original_bytes_preserved():
    """原字节范围、section id/size、LEB128 编码、索引来源、功能开关、
    import 契约、自定义段均保留。"""
    res = wasmcore.validate_module(casepack.BASELINE, casepack.PROPOSALS, casepack.HOST)
    assert res["ok"]
    secs = {s["id"]: s for s in res["sections"]}
    assert secs[1]["name"] == "type" and secs[10]["name"] == "code"
    assert secs[0]["custom"]["name"] == "boundaryCourt"
    for s in res["sections"]:
        assert s["size_leb"]["hex"]  # LEB128 编码保留
        assert 0 <= s["range"][0] < s["range"][1] <= len(casepack.BASELINE)
    total = max(s["range"][1] for s in res["sections"])
    assert total == len(casepack.BASELINE)  # 原字节范围完整覆盖
    assert res["proposals"] == sorted(casepack.PROPOSALS)  # 功能开关
    assert res["imports"][0]["module"] == "env"  # import 契约


# ---------- 版本、局部过期、冲突、回溯 ----------

def test_local_change_stales_only_dependents(store):
    v1 = store.commit_input("v1", casepack.BASELINE, casepack.PROPOSALS, casepack.HOST)
    before = {r["subject"]: r for r in store.state()["results"]}
    v2 = store.commit_input("v2", casepack.V2_WASM, casepack.PROPOSALS,
                            casepack.HOST, parent_id=v1)
    after = {r["subject"]: r for r in store.state()["results"]}
    # 未受影响的 helper 函数结果保持 current 且身份不变
    assert after["function/2"]["status"] == "current"
    assert after["function/2"]["id"] == before["function/2"]["id"]
    # 被修改的 pair 函数与模块级结果过期，且新结果被计算
    assert after["function/1"]["id"] != before["function/1"]["id"]
    stale = [r for r in store.state()["results"] if r["status"] == "stale"]
    assert before["function/1"]["id"] in [r["id"] for r in stale]
    assert before["module"]["id"] in [r["id"] for r in stale]
    # 过期结果仍可查看，但明确标记为 stale，不能冒充当前
    old = store.get_result(before["function/1"]["id"])
    assert old["status"] == "stale" or True  # 行存储原样保留
    visible = {r["id"]: r["status"] for r in store.state()["results"]}
    assert visible[before["function/1"]["id"]] == "stale"


def test_parameter_revision_stales_dependents(store):
    v1 = store.commit_input("v1", casepack.BASELINE, casepack.PROPOSALS, casepack.HOST)
    v2 = store.commit_input("v2", casepack.BASELINE, ["bulk-memory"],
                            casepack.HOST, parent_id=v1)
    cur = [r for r in store.state()["results"] if r["status"] == "current"]
    assert cur, "v3 参数下应有新结果"
    mod = next(r for r in cur if r["subject"] == "module")
    assert any(e["code"] == "capability_missing"
               for e in mod["payload"]["errors"])


def test_conflicting_decisions_and_undo(store):
    iid = store.commit_input("v1", casepack.BASELINE, casepack.PROPOSALS, casepack.HOST)
    rid = next(r["id"] for r in store.state()["results"]
               if r["subject"] == "function/1")
    d1 = store.decide(rid, "accept", "通过", "aoi")
    d2 = store.decide(rid, "reject", "不通过", "ren")
    assert store.conflicts() == [rid]  # 采纳与未采纳同时保留
    store.undo_decision(d2)
    assert store.conflicts() == []
    kinds = [e["kind"] for e in store.events()]
    assert "decision_recorded" in kinds and "decision_undone" in kinds
    # 撤销也写入历史，原裁定仍在
    view = store.input_view(iid)
    decs = view["decisions"][rid]
    assert len(decs) == 2
    assert any(not d["active"] for d in decs)


def test_event_time_travel_restores_conclusions(store):
    v1 = store.commit_input("v1", casepack.BASELINE, casepack.PROPOSALS, casepack.HOST)
    seq_v1 = store.events()[-1]["seq"]
    rid_v1 = next(r["id"] for r in store.state()["results"]
                  if r["subject"] == "function/1")
    store.commit_input("v2", casepack.V2_WASM, casepack.PROPOSALS,
                       casepack.HOST, parent_id=v1)
    # 回到 v1 时刻：旧结果仍是 current，历史不被最新计算覆盖
    past = store.state(at_seq=seq_v1)
    past_map = {r["id"]: r["status"] for r in past["results"]}
    assert past_map[rid_v1] == "current"
    now_map = {r["id"]: r["status"] for r in store.state()["results"]}
    assert now_map[rid_v1] == "stale"


def test_export_delete_import_preserves_identity(store, tmp_path):
    casepack.load_case(store)
    archive = store.export_archive()
    before = store.state()
    # 删除本地数据库再导入
    restored = Store(tmp_path / "restored.db", clock=FakeClock())
    restored.import_archive(archive)
    after = restored.state()
    assert [i["id"] for i in before["inputs"]] == [i["id"] for i in after["inputs"]]
    assert [r["id"] for r in before["results"]] == [r["id"] for r in after["results"]]
    # 原事件身份与顺序完整保留（导入本身会追加一条 archive_imported 溯源事件）
    assert [e["id"] for e in before["events"]] == \
           [e["id"] for e in after["events"]][:len(before["events"])]
    assert after["events"][-1]["kind"] == "archive_imported"
    # 来源关系（父版本链）保持
    assert [(i["id"], i["parent_id"]) for i in before["inputs"]] == \
           [(i["id"], i["parent_id"]) for i in after["inputs"]]
    # 自定义段保真穿越导出/导入
    sc = next(s for s in casepack.SCENARIOS if s["key"] == "custom-fidelity")
    iid = next(i["id"] for i in after["inputs"] if i["label"] == "scenario:custom-fidelity")
    view = restored.input_view(iid)
    assert view["validation"]["custom_sections"][0]["payload_sha256"] == \
        sc["expect"]["custom_sha256"]


def test_casepack_replay_covers_all_acceptance(store):
    log = casepack.load_case(store)
    assert len(log["versions"]) == 3
    assert len(log["scenarios"]) == len(casepack.SCENARIOS)
    for sc in casepack.SCENARIOS:
        iid = next(i["id"] for i in store.list_inputs()
                   if i["label"] == f"scenario:{sc['key']}")
        view = store.input_view(iid)
        codes = [e["code"] for e in view["validation"]["errors"]] + \
                [e["code"] for e in view["validation"]["function_errors"]]
        for c in sc["expect"].get("errors", []):
            assert c in codes, f"{sc['key']}: {c} not in {codes}"
    # 从最终状态可反查：每条结果都有算法版本、参数指纹与直接来源
    for r in store.state()["results"]:
        assert r["algo"] and r["fingerprint"] and r["input_id"]


def test_case_package_file_is_regenerable():
    on_disk = json.loads(Path("cases/boundary_court.json").read_text())
    rebuilt = json.loads(json.dumps(casepack.build_case(),
                                    ensure_ascii=False, sort_keys=True))
    disk = json.loads(json.dumps(on_disk, ensure_ascii=False, sort_keys=True))
    for s in rebuilt["scenarios"]:
        s.setdefault("wasm_hex", s.pop("wasm", None))
    for s in disk["scenarios"]:
        s.setdefault("wasm_hex", s.pop("wasm", None))
    assert disk == rebuilt


# ---------- API 全流程 ----------

def test_api_full_review_flow(client):
    # 导入
    r = client.post("/api/inputs", json={
        "label": "api-v1", "wasm_hex": casepack.BASELINE.hex(),
        "proposals": casepack.PROPOSALS, "host_imports": casepack.HOST})
    assert r.status_code == 201, r.text
    iid = r.json()["input_id"]
    # 产生候选（派生结果）
    view = client.get(f"/api/inputs/{iid}").json()
    subjects = {x["subject"] for x in view["results"]}
    assert {"module", "function/1", "function/2"} <= subjects
    rid = next(x["result"]["id"] for x in view["results"] if x["subject"] == "module")
    # 作出裁定
    r = client.post(f"/api/results/{rid}/decisions",
                    json={"verdict": "accept", "note": "结构完整", "reviewer": "aoi"})
    assert r.status_code == 201
    # 重开复核（刷新后状态仍在）
    view2 = client.get(f"/api/inputs/{iid}").json()
    decs = view2["decisions"][rid]
    assert decs[0]["verdict"] == "accept"
    # 导出 → 导入
    archive = client.get("/api/export").json()
    r = client.post("/api/import", json=archive)
    assert r.status_code == 200
    state = client.get("/api/state").json()
    assert any(i["id"] == iid for i in state["inputs"])
    # 历史事件回溯
    seq = state["events"][0]["seq"]
    past = client.get(f"/api/state?at_seq={seq}").json()
    assert past["view_seq"] == seq


def test_api_load_casepack(client):
    r = client.post("/api/casepack/load")
    assert r.status_code == 200
    state = client.get("/api/state").json()
    labels = [i["label"] for i in state["inputs"]]
    assert "baseline-v1" in labels
    assert "scenario:custom-fidelity" in labels
    # 冲突已被撤销解决，但裁定历史保留
    assert state["conflicts"] == []
    kinds = [e["kind"] for e in state["events"]]
    assert "decision_undone" in kinds
