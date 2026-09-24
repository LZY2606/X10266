from __future__ import annotations

import hashlib

import numpy as np

from . import ALGORITHM_VERSION
from .domain import cell_id
from .parser import as_dict, parse_module
from .store import canonical_json, normalize_config, sha256_json
from .validator import validate_module


def _structural_fingerprint(parsed: dict) -> str:
    chunks = [b"\x00asm\x01\x00\x00\x00"]
    for section in parsed["sections"]:
        if section["id"] != 0:
            chunks.append(bytes.fromhex(section["raw_hex"]))
    return hashlib.sha256(b"".join(chunks)).hexdigest()


def _custom_fingerprint(parsed: dict) -> str:
    customs = []
    for section in parsed["sections"]:
        if section["id"] == 0:
            customs.append({"ordinal": section["ordinal"], "range": section["raw_range"], "raw_hex": section["raw_hex"]})
    return sha256_json(customs)


def _content_module_id(sha256: str) -> str:
    return f"module@sha256:{sha256[:32]}"


def _layout(parsed: dict):
    sections = parsed["sections"]
    total = parsed["raw"]["length"]["value"] or 1
    bounds = np.array([[s["raw_range"][0], s["raw_range"][1]] for s in sections], dtype=float)
    if len(bounds):
        x = (bounds[:, 0] / total * 1000).round(2)
        widths = np.maximum(2, ((bounds[:, 1] - bounds[:, 0]) / total * 1000).round(2))
    else:
        x = widths = np.array([])
    bars = []
    for i, section in enumerate(sections):
        bars.append({
            "stable_id": f"{section['stable_id']};layout-bar",
            "section_id": section["stable_id"],
            "x": float(x[i]) if len(bounds) else 0,
            "width": float(widths[i]) if len(bounds) else 0,
            "coordinate_base": "1000-unit horizontal module byte map",
            "unit": "normalized/1000",
        })
    return {"stable_id": cell_id(parsed["module_id"], "layout", "section-map"), "bars": bars, "total_bytes": total}


def _basis(code: str, evidence: list[str], byte_range: list[int], feature=None) -> dict:
    return {
        "stable_id": f"basis:{code}:{hashlib.sha256(canonical_json([evidence, byte_range]).encode()).hexdigest()[:16]}",
        "rule_id": code,
        "predicate": {
            "NONCANONICAL_LEB128": "encoding has unnecessary LEB128 continuation but numeric value remains in range",
            "NUMERIC_OUT_OF_RANGE": "decoded integer exceeds the declared bit width",
            "TYPE_STACK_MISMATCH": "concrete stack disagrees outside an active polymorphic region",
            "CAPABILITY_MISSING_MULTI_VALUE": "opcode/type requires multi_value and feature is disabled",
            "CAPABILITY_MISSING_TAIL_CALL": "opcode requires tail_call and feature is disabled",
            "CAPABILITY_MISSING_SIMD": "opcode prefix requires simd and feature is disabled",
            "UNKNOWN_OPCODE": "byte has no assignment in the enabled decoder",
        }.get(code, "module grammar or host contract predicate"),
        "evidence_source_ids": evidence,
        "minimal_failure_byte_range": byte_range,
        "required_capability": feature,
        "classification": {
            "noncanonical_leb_distinct_from_numeric_overflow": code == "NONCANONICAL_LEB128",
            "numeric_overflow": code == "NUMERIC_OUT_OF_RANGE",
            "polymorphic_stack_limited_to_unreachable_region": code in ("TYPE_STACK_MISMATCH", "UNREACHABLE_STACK"),
            "missing_capability_not_unknown_byte": code.startswith("CAPABILITY_MISSING"),
        },
    }


class Engine:
    def __init__(self, store):
        self.store = store

    def parse_event(self, event):
        import base64
        payload = event["payload"]
        digest = payload["binary_sha256"]
        raw = self.store.get_blob(digest)
        if raw is None:
            raw = base64.b64decode(payload["original_base64"])
        content_module = _content_module_id(digest)
        parsed = as_dict(parse_module(raw, content_module))
        structural = _structural_fingerprint(parsed)
        customs = _custom_fingerprint(parsed)
        sources = [f"event:{event['id']}", parsed["raw"]["stable_id"]]
        parse_result = self.store.put_derived(
            event["project_id"], "core_parse", structural, "none", sources, parsed, event["seq"], event["timestamp"],
            stable_id=f"result:{ALGORITHM_VERSION};core_parse;sha256:{structural[:32]}",
        )
        custom_items = [s for s in parsed["sections"] if s["id"] == 0]
        custom_result = self.store.put_derived(
            event["project_id"], "custom_inventory", customs, "none",
            sources + [s["stable_id"] for s in custom_items],
            {"sections": custom_items, "preserved": True}, event["seq"], event["timestamp"],
            stable_id=f"result:{ALGORITHM_VERSION};custom_inventory;sha256:{customs[:32]}",
        )
        return parse_result, custom_result

    def state(self, project_id: str, at_seq: int | None = None):
        events = self.store.events(project_id, at_seq)
        module_event = next((e for e in reversed(events) if e["type"] == "module_submitted"), None)
        config_event = next((e for e in reversed(events) if e["type"] == "config_submitted"), None)
        decision_events = [e for e in events if e["type"] == "decision_made"]
        if not module_event:
            return {"project_id": project_id, "at_seq": at_seq, "events": events, "ready": False}
        parse_result, custom_result = self.parse_event(module_event)
        parsed = parse_result["value"]
        config_payload = config_event["payload"] if config_event else normalize_config({})
        config = normalize_config({"features": config_payload.get("features", {}), "host_imports": config_payload.get("host_imports", [])})
        config_fp = sha256_json(config)
        decision_fp = sha256_json([
            {"target": e["payload"]["target_stable_id"], "accepted": e["payload"]["accepted"], "seq": e["seq"]}
            for e in decision_events
        ])
        validation = validate_module(parsed, config["features"], config["host_imports"])
        source_hash = sha256_json({"core": parse_result["source_hash"], "config": config_fp, "decisions": decision_fp})
        sources = [parse_result["stable_id"], custom_result["stable_id"], f"event:{module_event['id']}"]
        if config_event:
            sources.append(f"event:{config_event['id']}")
        sources.extend(f"event:{e['id']}" for e in decision_events)
        findings = list(parsed["findings"]) + list(validation["findings"])
        decision_by_target = {}
        for event in decision_events:
            payload = event["payload"]
            decision_by_target.setdefault(payload["target_stable_id"], []).append(event)
        for finding in findings:
            decisions = decision_by_target.get(finding["stable_id"], [])
            if decisions:
                latest = decisions[-1]
                finding["accepted"] = latest["payload"]["accepted"]
                finding["decision_event_id"] = latest["id"]
                if len(decisions) > 1:
                    finding["conflicting_decisions"] = [e["id"] for e in decisions]
        bases = [_basis(f["code"], f["sources"], f["minimal_failure_byte_range"], f.get("capability")) for f in findings]
        layout = _layout(parsed)
        value = {
            "project_id": project_id,
            "at_seq": at_seq or events[-1]["seq"],
            "ready": True,
            "events": events,
            "current_module_event_id": module_event["id"],
            "current_config_event_id": config_event["id"] if config_event else None,
            "module_version": module_event["payload"],
            "config": config,
            "parameter_fingerprint": config_fp,
            "raw": parsed["raw"],
            "section_map": layout,
            "sections": parsed["sections"],
            "index_table": parsed["index_origins"],
            "types": parsed["types"],
            "imports": parsed["imports"],
            "functions": parsed["functions"],
            "exports": parsed["exports"],
            "code_bodies": parsed["code_bodies"],
            "cells": parsed["cells"] + [bar for bar in layout["bars"]],
            "control_stack": [t for t in validation["type_transitions"]],
            "type_transitions": validation["type_transitions"],
            "feature_gates": validation["feature_gates"],
            "custom_sections": custom_result["value"],
            "findings": findings,
            "judgment_basis_events": bases,
            "accepted_results": [f for f in findings if f.get("accepted") is True],
            "rejected_results": [f for f in findings if f.get("accepted") is False],
            "unknown_results": [f for f in findings if f.get("unknown")],
            "algorithm_version": ALGORITHM_VERSION,
        }
        result = self.store.put_derived(
            project_id, "analysis_bundle", source_hash, config_fp, sources, value, events[-1]["seq"], events[-1]["timestamp"],
            stable_id=f"result:{ALGORITHM_VERSION};analysis_bundle;sha256:{source_hash[:32]}",
        )
        value["stable_id"] = result["stable_id"]
        return value

    def current_state(self, project_id):
        return self.state(project_id)

    def expire_after_event(self, event):
        if event["type"] == "config_submitted":
            self.store.expire_kind_prefix(event["project_id"], "analysis_bundle", f"event:{event['id']}", event["seq"], event["timestamp"])
        elif event["type"] == "decision_made":
            self.store.expire_kind_prefix(event["project_id"], "analysis_bundle", f"event:{event['id']}", event["seq"], event["timestamp"])
