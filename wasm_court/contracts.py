DEFAULT_HOST_CONTRACTS = {
    "env.log": {
        "module": "env",
        "name": "log",
        "kind": "func",
        "params": ["i32"],
        "results": [],
    },
    "env.add": {
        "module": "env",
        "name": "add",
        "kind": "func",
        "params": ["i32", "i32"],
        "results": ["i32"],
    },
}


def evaluate_import_contracts(parse_result, host_contracts: dict, version: int) -> list[dict]:
    findings = []
    for ordinal, item in enumerate(parse_result.imports, 1):
        key = f"{item['module']}.{item['name']}"
        fid = f"s{version}.contract.{ordinal}"
        contract = host_contracts.get(key)
        if contract is None:
            findings.append({
                "id": fid,
                "kind": "finding",
                "findingId": fid,
                "code": "import_not_offered",
                "category": "import_contract",
                "severity": "error",
                "status": "accepted",
                "message": f"host does not offer import {key}",
                "minimumFailureRange": item["byteRange"],
                "sourceRefs": [item["id"]],
                "requiredFeature": None,
                "candidateIds": [],
                "rejectionReason": None,
                "unknown": False,
                "importRef": item["id"],
            })
            continue
        wanted = item.get("contract") or {}
        type_ref = wanted.get("typeRef")
        declared = next((t for t in parse_result.types if t["id"] == type_ref), None)
        if declared is None:
            mismatch = "imported function has no resolvable type index"
        else:
            mismatch = None
            if declared["params"] != contract.get("params", []):
                mismatch = "parameter types do not match host signature"
            if declared["results"] != contract.get("results", []):
                mismatch = "result types do not match host signature"
            if contract.get("kind", "func") != "func":
                mismatch = "host object kind is not callable"
        if mismatch:
            findings.append({
                "id": fid,
                "kind": "finding",
                "findingId": fid,
                "code": "import_signature_mismatch",
                "category": "import_contract",
                "severity": "error",
                "status": "accepted",
                "message": f"{key}: {mismatch}",
                "minimumFailureRange": item["byteRange"],
                "sourceRefs": [item["id"], type_ref] if type_ref else [item["id"]],
                "requiredFeature": None,
                "candidateIds": [f"{fid}.candidate.module-type", f"{fid}.candidate.host-signature"],
                "rejectionReason": None,
                "unknown": False,
                "importRef": item["id"],
            })
    return findings
