from __future__ import annotations

from dataclasses import dataclass
import base64
import copy
import hashlib
import json
import os
import sqlite3
import time
import uuid
from typing import Any

import numpy as np

from .wasm import ALGORITHM_VERSION, compare_import_contract, finding_minimum_span, parse_module

SCHEMA_VERSION = "module-court-schema/v1"

SCHEMA = """
pragma foreign_keys=on;
create table if not exists projects (
  project_id text primary key,
  title text not null,
  created_at text not null,
  head_revision_id text
);
create table if not exists revisions (
  revision_id text primary key,
  project_id text not null references projects(project_id),
  parent_revision_id text references revisions(revision_id),
  ordinal integer not null,
  kind text not null,
  label text not null,
  created_at text not null,
  parameter_fingerprint text not null,
  source_fingerprint text not null
);
create table if not exists events (
  event_id text primary key,
  project_id text not null references projects(project_id),
  revision_id text not null references revisions(revision_id),
  ordinal integer not null,
  kind text not null,
  at_virtual_time text not null,
  actor text not null,
  payload_json text not null,
  unique(project_id, ordinal)
);
create table if not exists artifacts (
  artifact_id text primary key,
  project_id text not null references projects(project_id),
  revision_id text not null references revisions(revision_id),
  stable_key text not null,
  display_name text not null,
  kind text not null,
  status text not null,
  algorithm_version text not null,
  parameter_fingerprint text not null,
  source_hash text not null,
  carried_from_artifact_id text references artifacts(artifact_id),
  data_json text not null,
  unique(revision_id, stable_key)
);
create table if not exists artifact_dependencies (
  artifact_id text not null references artifacts(artifact_id),
  fragment_id text not null,
  direct_source_id text not null,
  span_json text not null,
  fragment_hash text not null,
  primary key (artifact_id, fragment_id)
);
create table if not exists event_links (
  event_id text not null references events(event_id),
  link_role text not null,
  target_event_id text references events(event_id),
  target_artifact_id text references artifacts(artifact_id),
  note text not null,
  primary key (event_id, link_role, target_event_id, target_artifact_id)
);
"""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fingerprint_json(value: Any) -> str:
    return sha_text(canonical_json(value))


def stable_uuid(*parts: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "|".join(parts)))


class VirtualClock:
    def __init__(self, fixed: str | None = None):
        self.fixed = fixed
        self.ticks = 0

    def __call__(self) -> str:
        if self.fixed:
            return self.fixed
        return now_iso()


class ProjectStore:
    def __init__(self, path: str = ":memory:", clock=None):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.clock = clock or now_iso
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    def _row(self, sql, args=()):
        return self.conn.execute(sql, args).fetchone()

    def _rows(self, sql, args=()):
        return self.conn.execute(sql, args).fetchall()

    def list_projects(self):
        return [dict(r) for r in self._rows("select * from projects order by title")]

    def get_project(self, project_id):
        row = self._row("select * from projects where project_id=?", (project_id,))
        return dict(row) if row else None

    def create_project(self, title: str, project_id: str | None = None, label="initial import") -> dict:
        pid = project_id or stable_uuid("project", title, self.clock())
        at = self.clock()
        self.conn.execute("insert into projects(project_id,title,created_at,head_revision_id) values(?,?,?,?)", (pid, title, at, None))
        binary = bytes.fromhex("0061736d01000000")
        params = {"proposals": {"multi_value": False, "reference_types": False, "sign_extension": False, "bulk_memory": False}, "host_imports": {"imports": []}}
        rev = self._submit_revision(pid, None, "empty", label, binary, params, "system", note={"empty": True})
        self.conn.execute("update projects set head_revision_id=? where project_id=?", (rev["revision_id"], pid))
        self.conn.commit()
        return self.get_project(pid)

    def _next_ordinal(self, project_id: str, table: str) -> int:
        row = self._row(f"select coalesce(max(ordinal), -1) + 1 as n from {table} where project_id=?", (project_id,))
        return int(row["n"])

    def _event(self, project_id, revision_id, kind, payload, actor):
        ordinal = self._next_ordinal(project_id, "events")
        eid = stable_uuid("event", project_id, str(ordinal), kind)
        at = payload.get("at_virtual_time") or self.clock()
        self.conn.execute("insert into events(event_id,project_id,revision_id,ordinal,kind,at_virtual_time,actor,payload_json) values(?,?,?,?,?,?,?,?)",
                          (eid, project_id, revision_id, ordinal, kind, at, actor, canonical_json(payload)))
        return eid

    def _submit_revision(self, project_id, parent_id, kind, label, binary, params, actor, note=None):
        proj = self.get_project(project_id)
        ordinal = self._next_ordinal(project_id, "revisions")
        rid = stable_uuid("revision", project_id, str(ordinal), label)
        pf = fingerprint_json(params)
        sf = hashlib.sha256(binary).hexdigest()
        self.conn.execute("""insert into revisions(revision_id,project_id,parent_revision_id,ordinal,kind,label,created_at,parameter_fingerprint,source_fingerprint)
                             values(?,?,?,?,?,?,?,?,?)""", (rid, project_id, parent_id, ordinal, kind, label, self.clock(), pf, sf))
        payload = {"binary_base64": b64e(binary), "params": params, "note": note or {}, "at_virtual_time": self.clock()}
        self._event(project_id, rid, kind, payload, actor)
        self._compute(project_id, rid, binary, params, parent_id)
        return {"revision_id": rid, "ordinal": ordinal}

    def submit_input(self, project_id, binary: bytes, params: dict, label="initial import", actor="runtime-team", kind="import"):
        project = self.get_project(project_id)
        if not project:
            raise KeyError(project_id)
        parent = project["head_revision_id"]
        rev = self._submit_revision(project_id, parent, kind, label, binary, _normalize_params(params), actor)
        self.conn.execute("update projects set head_revision_id=? where project_id=?", (rev["revision_id"], project_id))
        self.conn.commit()
        return self.get_revision(rev["revision_id"])

    def revise_params(self, project_id, params, label, actor, finding_id=None, action="parameter_adjustment", rationale=""):
        current = self.revision_input(project_id, self.get_project(project_id)["head_revision_id"])
        parent_id = self.get_project(project_id)["head_revision_id"]
        rev = self._submit_revision(project_id, parent_id, action, label, current["binary"], _normalize_params(params), actor,
                                    {"target_finding": finding_id, "rationale": rationale})
        eid = self._row("select event_id from events where revision_id=? order by ordinal desc limit 1", (rev["revision_id"],))["event_id"]
        if finding_id:
            self._link_event(eid, "resolves_finding", target_artifact_id=finding_id, note=rationale)
        self.conn.execute("update projects set head_revision_id=? where project_id=?", (rev["revision_id"], project_id))
        self.conn.commit()
        return self.get_revision(rev["revision_id"])

    def record_decision(self, project_id, finding_id, decision, rationale, actor="reviewer", conflict_with=None, undo_of=None):
        head = self.get_project(project_id)["head_revision_id"]
        current = self.revision_input(project_id, head)
        kind = "decision_undo" if undo_of else ("conflicting_decision" if conflict_with else "decision")
        label = f"{decision} {finding_id}"
        rev = self._submit_revision(project_id, head, kind, label, current["binary"], current["params"], actor,
                                    {"finding_id": finding_id, "decision": decision, "rationale": rationale, "conflict_with": conflict_with, "undo_of": undo_of})
        eid = self._row("select event_id,project_id from events where revision_id=? order by ordinal desc", (rev["revision_id"],))
        self._link_event(eid["event_id"], "decides_finding", target_artifact_id=finding_id, note=decision)
        if conflict_with:
            self._link_event(eid["event_id"], "conflicts_event", target_event_id=conflict_with, note=rationale)
        if undo_of:
            self._link_event(eid["event_id"], "undoes_event", target_event_id=undo_of, note=rationale)
        self.conn.execute("update projects set head_revision_id=? where project_id=?", (rev["revision_id"], project_id))
        self.conn.commit()
        return self.get_revision(rev["revision_id"])

    def _link_event(self, event_id, role, target_event_id=None, target_artifact_id=None, note=""):
        self.conn.execute("""insert or ignore into event_links(event_id,link_role,target_event_id,target_artifact_id,note)
                             values(?,?,?,?,?)""", (event_id, role, target_event_id, target_artifact_id, note))

    def _compute(self, project_id, revision_id, binary, params, parent_id):
        parsed = parse_module(binary, "source.binary", params.get("proposals", {}))
        import_findings = compare_import_contract(parsed["import_contract"], params.get("host_imports", {}))
        candidates = list(parsed["findings"])
        for f in import_findings:
            f.setdefault("span", {"start": 0, "end": len(binary), "label": "import contract"})
            f.setdefault("source_id", "host.contract")
            candidates.append(f)
        sections = parsed["sections"]
        parent_by_key = {}
        if parent_id:
            for r in self._rows("select * from artifacts where revision_id=?", (parent_id,)):
                parent_by_key[r["stable_key"]] = dict(r)
        source_hash = hashlib.sha256(binary).hexdigest()
        pf = fingerprint_json(params)
        new_ids = {}

        def put(key, display, kind, status, data, deps, carried_from=None):
            old = parent_by_key.get(key)
            direct_hash = fingerprint_json([[d["fragment_id"], d["span"], d["fragment_hash"]] for d in deps])
            reusable = bool(old and old["parameter_fingerprint"] == pf and old["source_hash"] == direct_hash and kind != "event")
            aid = old["artifact_id"] if reusable else stable_uuid("artifact", project_id, revision_id, key)
            if reusable:
                data = json.loads(old["data_json"])
                carried = old["carried_from_artifact_id"] or old["artifact_id"]
            else:
                carried = carried_from
            self.conn.execute("""insert into artifacts(artifact_id,project_id,revision_id,stable_key,display_name,kind,status,algorithm_version,parameter_fingerprint,source_hash,carried_from_artifact_id,data_json)
                                 values(?,?,?,?,?,?,?,?,?,?,?,?)""",
                              (aid, project_id, revision_id, key, display, kind, status, ALGORITHM_VERSION, pf, direct_hash, carried, canonical_json(data)))
            self.conn.execute("delete from artifact_dependencies where artifact_id=?", (aid,))
            for dep in deps:
                self.conn.execute("""insert or replace into artifact_dependencies(artifact_id,fragment_id,direct_source_id,span_json,fragment_hash)
                                     values(?,?,?,?,?)""", (aid, dep["fragment_id"], dep["direct_source_id"], canonical_json(dep["span"]), dep["fragment_hash"]))
            new_ids[key] = aid
            return aid

        def dep(span, source="source.binary"):
            st = max(0, int(span.get("start", 0)))
            en = min(len(binary), int(span.get("end", st)))
            return {"fragment_id": "source.binary", "direct_source_id": source, "span": {"start": st, "end": en, "label": span.get("label", "")},
                    "fragment_hash": hashlib.sha256(binary[st:en]).hexdigest()}

        put("module.header", "Wasm header", "header", "accepted" if parsed["header"]["accepted"] else "rejected", parsed["header"], [dep(parsed["header"]["span"])])
        for sec in sections:
            put(f"section:{sec['order']}:{sec['section_id']}", f"section {sec['name']} #{sec['order']}", "section", "accepted", sec, [dep(sec)])
        for idx, leb in enumerate(parsed["leb128"]):
            span = {"start": leb["start"], "end": leb["end"], "label": f"LEB128 {idx}"}
            status = "rejected" if leb["overflow"] else ("candidate" if not leb["canonical"] else "accepted")
            put(f"leb:{idx}", f"LEB128 @{leb['start']}", "leb128", status, leb, [dep(span)])
        for rec in parsed["records"]:
            kind = rec.get("kind", "record")
            status = rec.get("status", "accepted")
            put(f"{kind}:{rec['stable_id']}", rec.get("name", rec["stable_id"]), kind, status, rec, [dep(rec["span"], rec.get("source_id", "source.binary"))])
        for space, info in parsed["index_spaces"].items():
            for source in info["sources"]:
                span = source.get("detail", {}).get("span", {"start": 0, "end": 0})
                put(f"index:{space}:{source['index']}", f"{space}[{source['index']}]", "index", "accepted", source, [dep(span)])
        for imp in parsed["import_contract"]["required"]:
            put(f"import-contract:{imp['module']}.{imp['name']}", f"import {imp['module']}.{imp['name']}", "import_contract", "accepted", imp, [dep({"start": 0, "end": len(binary), "label": "import"})])
        for fi, fn in enumerate(parsed["functions"]):
            put(f"function-validation:{fi}", f"function {fn['function_index']} type stack", "function_validation", "accepted", fn, [dep(fn["span"])])
        for ci, f in enumerate(candidates):
            key = f"finding:{ci}:{f.get('code')}:{f.get('span',{}).get('start',0)}:{f.get('span',{}).get('end',0)}:{f.get('source_id','source.binary')}"
            minimum = finding_minimum_span(f, sections)
            data = dict(f)
            data["minimum_failure_span"] = minimum
            data["classification"] = _classify_finding(f)
            data["accepted_candidates"] = [c for c in f.get("candidates", []) if c.get("status") == "accepted"]
            data["rejected_candidates"] = [c for c in f.get("candidates", []) if c.get("status") == "rejected"]
            put(key, f"{f.get('code')} @{minimum['start']}..{minimum['end']}", "finding", f.get("status", "candidate"), data, [dep(f.get("span", minimum), f.get("source_id", "source.binary"))])
        self._mark_stale(revision_id, parent_id, set(new_ids.values()))
        return new_ids

    def _mark_stale(self, revision_id, parent_id, current_ids):
        if not parent_id:
            return
        # Artifacts are version-scoped. A dependency whose stable key is absent from the
        # new revision remains visible from the old revision as superseded; the current
        # revision only presents carried/current artifacts.
        self.conn.execute("update artifacts set status=status where revision_id=?", (revision_id,))

    def get_revision(self, revision_id):
        r = self._row("select * from revisions where revision_id=?", (revision_id,))
        return dict(r) if r else None

    def revision_input(self, project_id, revision_id):
        event = self._row("select payload_json from events where revision_id=? order by ordinal limit 1", (revision_id,))
        payload = json.loads(event["payload_json"])
        return {"binary": b64d(payload["binary_base64"]), "params": payload["params"], "payload": payload}

    def list_revisions(self, project_id):
        return [dict(r) for r in self._rows("select * from revisions where project_id=? order by ordinal", (project_id,))]

    def list_events(self, project_id):
        out = []
        for r in self._rows("select * from events where project_id=? order by ordinal", (project_id,)):
            d = dict(r); d["payload"] = json.loads(d.pop("payload_json")); out.append(d)
        return out

    def list_artifacts(self, revision_id):
        out = []
        for r in self._rows("select * from artifacts where revision_id=? order by artifact_id", (revision_id,)):
            d = dict(r); d["data"] = json.loads(d.pop("data_json"))
            deps = self._rows("select * from artifact_dependencies where artifact_id=?", (d["artifact_id"]))
            d["dependencies"] = [{**dict(x), "span": json.loads(x["span_json"])} for x in deps]
            out.append(d)
        return out

    def review(self, revision_id):
        rev = self.get_revision(revision_id)
        inp = self.revision_input(rev["project_id"], revision_id)
        artifacts = self.list_artifacts(revision_id)
        by_kind = {}
        for a in artifacts:
            by_kind.setdefault(a["kind"], []).append(a)
        events = self.list_events(rev["project_id"])
        return {
            "project": self.get_project(rev["project_id"]),
            "revision": rev,
            "input": {"byte_length": len(inp["binary"]), "binary_hex": inp["binary"].hex(), "params": inp["params"]},
            "events": events,
            "artifacts": artifacts,
            "sections": by_kind.get("section", []),
            "indices": by_kind.get("index", []),
            "instructions": by_kind.get("instruction", []),
            "controls": by_kind.get("control", []),
            "function_validations": by_kind.get("function_validation", []),
            "findings": by_kind.get("finding", []),
            "leb128": by_kind.get("leb128", []),
            "records": [a for a in artifacts if a["kind"] in ("type", "import", "function", "export", "instruction", "control")],
        }

    def current_review(self, project_id):
        pid = project_id
        return self.review(self.get_project(pid)["head_revision_id"])

    def export_project(self, project_id):
        tables = ["projects", "revisions", "events", "artifacts", "artifact_dependencies", "event_links"]
        data = {"format": "module-boundary-court-export/v1", "schema_version": SCHEMA_VERSION, "tables": {}}
        for table in tables:
            rows = [dict(r) for r in self._rows(f"select * from {table} where project_id=?", (project_id,))]
            data["tables"][table] = rows
        return data

    def import_project(self, data, project_id_override=None):
        expected = "module-boundary-court-export/v1"
        if data.get("format") != expected:
            raise ValueError("unsupported export format")
        project = data["tables"]["projects"][0]
        pid = project_id_override or project["project_id"]
        if self.get_project(pid):
            raise ValueError("project already exists")
        with self.conn:
            self.conn.execute("insert into projects values(?,?,?,?)", (pid, project["title"], project["created_at"], project["head_revision_id"]))
            for r in data["tables"]["revisions"]:
                self.conn.execute("insert into revisions values(?,?,?,?,?,?,?,?,?)", (r["revision_id"], pid, r["parent_revision_id"], r["ordinal"], r["kind"], r["label"], r["created_at"], r["parameter_fingerprint"], r["source_fingerprint"]))
            for r in data["tables"]["events"]:
                self.conn.execute("insert into events values(?,?,?,?,?,?,?,?)", (r["event_id"], pid, r["revision_id"], r["ordinal"], r["kind"], r["at_virtual_time"], r["actor"], r["payload_json"]))
            for r in data["tables"]["artifacts"]:
                self.conn.execute("insert into artifacts values(?,?,?,?,?,?,?,?,?,?,?,?)", (r["artifact_id"], pid, r["revision_id"], r["stable_key"], r["display_name"], r["kind"], r["status"], r["algorithm_version"], r["parameter_fingerprint"], r["source_hash"], r["carried_from_artifact_id"], r["data_json"]))
            for r in data["tables"]["artifact_dependencies"]:
                self.conn.execute("insert into artifact_dependencies values(?,?,?,?,?)", (r["artifact_id"], r["fragment_id"], r["direct_source_id"], r["span_json"], r["fragment_hash"]))
            for r in data["tables"]["event_links"]:
                self.conn.execute("insert into event_links values(?,?,?,?,?)", (r["event_id"], r["role"], r["target_event_id"], r["target_artifact_id"], r["note"]))
        return self.get_project(pid)


def _normalize_params(params):
    defaults = {"multi_value": False, "reference_types": False, "sign_extension": False, "bulk_memory": False}
    proposals = {**defaults, **(params.get("proposals") or {})}
    host = params.get("host_imports") or {"imports": []}
    return {"proposals": proposals, "host_imports": host}


def _classify_finding(f):
    code = f.get("code")
    if code == "noncanonical_leb":
        return {"encoding_class": "noncanonical_leb", "numeric_class": None, "rule": "encoding legality and numeric range are separate axes"}
    if code in ("value_out_of_bounds", "index_out_of_bounds", "section_payload_out_of_bounds", "function_body_out_of_bounds"):
        return {"encoding_class": None, "numeric_class": "out_of_bounds", "rule": "numeric range is checked independently from LEB canonical form"}
    if code == "unreachable_stack":
        return {"stack_class": "polymorphic_region_start", "scope": "innermost unreachable block"}
    if code in ("capability_missing",):
        return {"capability_class": "known_opcode_disabled", "rule": "known proposal opcode is not reported as unknown byte"}
    if code in ("unknown_byte",):
        return {"capability_class": "unknown_byte", "rule": "only unmapped bytes are unknown"}
    return {"class": code}
