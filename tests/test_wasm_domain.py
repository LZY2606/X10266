from pathlib import Path
from app.wasm import parse_module, compare_import_contract

CASE = Path(__file__).resolve().parents[1] / "cases" / "module-boundary-court"


def binary_at(case_data, target_index):
    binary = b""
    for index, step in enumerate(case_data["steps"]):
        if index > target_index:
            break
        if "binary_hex" in step:
            binary = bytes.fromhex(step["binary_hex"])
    return binary


def codes(case_data, index):
    step = case_data["steps"][index]
    data = binary_at(case_data, index)
    parsed = parse_module(data, proposals=step["params"]["proposals"])
    found = {x["code"] for x in parsed["findings"]} | {x["code"] for x in compare_import_contract(parsed["import_contract"], step["params"]["host_imports"])}
    return data, parsed, found


def test_initial_baseline_preserves_custom_and_has_no_diagnostic(case_data):
    _, parsed, found = codes(case_data, 0)
    assert found == set()
    custom = [s for s in parsed["sections"] if s["section_id"] == 0]
    assert custom[0]["custom_name"] == "court.note"
    assert parsed["header"]["span"] == {"start": 0, "end": 8, "label": "wasm header"}


def test_noncanonical_leb_is_distinct_from_numeric_overflow(case_data):
    _, parsed, found = codes(case_data, 2)
    assert "noncanonical_leb" in found
    assert "value_out_of_bounds" not in found
    leb = next(x for x in parsed["leb128"] if x["raw"] == [128, 0])
    assert leb["canonical"] is False and leb["overflow"] is False and leb["value"] == 0


def test_polymorphic_stack_is_bounded_to_unreachable_region(case_data):
    _, parsed, found = codes(case_data, 4)
    assert "unreachable_stack" in found
    instr = parsed["functions"][0]["type_transfers"]
    assert instr[0]["name"] == "unreachable" and instr[0]["polymorphic"] is False
    assert instr[1]["name"] == "i32.add" and instr[1]["polymorphic"] is True


def test_disabled_known_proposal_opcode_is_capability_not_unknown(case_data):
    _, _, found = codes(case_data, 3)
    assert "capability_missing" in found
    assert "unknown_byte" not in found


def test_unknown_byte_is_reported_as_unknown():
    bad = bytes.fromhex("0061736d01000000010401600000030201000a04010200fe00")
    parsed = parse_module(bad, proposals={})
    assert "unknown_byte" in {x["code"] for x in parsed["findings"]}


def test_multi_value_gated_by_proposal(case_data):
    step = case_data["steps"][6]
    data = binary_at(case_data, 6)
    disabled = parse_module(data, proposals=step["params"]["proposals"])
    enabled = parse_module(data, proposals={**step["params"]["proposals"], "multi_value": True})
    assert any(x["code"] == "capability_missing" for x in disabled["findings"])
    assert not any(x["code"] == "capability_missing" for x in enabled["findings"])


def test_duplicate_and_out_of_order_sections(case_data):
    _, _, found = codes(case_data, 5)
    assert {"duplicate_section", "section_out_of_order"} <= found


def test_import_mismatch_keeps_both_candidates(case_data):
    step = case_data["steps"][7]
    data = binary_at(case_data, 7)
    parsed = parse_module(data, proposals=step["params"]["proposals"])
    mismatch = next(x for x in compare_import_contract(parsed["import_contract"], step["params"]["host_imports"]) if x["code"] == "import_mismatch")
    assert mismatch["candidates"][0]["required"] == {"kind": "function", "type_index": 0}
    assert mismatch["candidates"][1]["host"] == {"kind": "function", "type_index": 1}


def test_custom_section_is_retained_across_every_source(case_data):
    for index, step in enumerate(case_data["steps"]):
        data = binary_at(case_data, index)
        parsed, _ = parse_module(data, proposals=step["params"]["proposals"]), None
        assert any(s["custom_name"] == "court.note" and s["payload_end"] == len(data) for s in parsed["sections"])
