from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import time
from typing import Any

from . import ALGORITHM_VERSION
from .domain import config_id, decision_id, module_id


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class Store:
    def __init__(self, path: str = ":memory:", virtual_clock=None):
        self.path = path
        self.virtual_clock = virtual_clock or time.time
        parent = os.path.dirname(os.path.abspath(path)) if path != ":memory:" else ""
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
              id TEXT PRIMARY KEY,
              title TEXT NOT NULL,
              created_seq INTEGER NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
              id TEXT PRIMARY KEY,
              project_id TEXT NOT NULL,
              seq INTEGER NOT NULL,
              type TEXT NOT NULL,
              timestamp TEXT NOT NULL,
              parent_event_id TEXT,
              payload TEXT NOT NULL,
              UNIQUE(project_id, seq)
            );
            CREATE TABLE IF NOT EXISTS blobs (
              sha256 TEXT PRIMARY KEY,
              content BLOB NOT NULL,
              original_encoding TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS derived (
              stable_id TEXT PRIMARY KEY,
              project_id TEXT NOT NULL,
              kind TEXT NOT NULL,
              source_hash TEXT NOT NULL,
              algorithm_version TEXT NOT NULL,
              parameter_fingerprint TEXT NOT NULL,
              direct_sources TEXT NOT NULL,
              value TEXT NOT NULL,
              state TEXT NOT NULL,
              created_event_seq INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              expired_event_seq INTEGER,
              expired_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_project ON events(project_id, seq);
            CREATE INDEX IF NOT EXISTS idx_derived_project ON derived(project_id, kind, state);
            """
        )
        self.conn.commit()

    def now(self) -> str:
        value = self.virtual_clock()
        return value if isinstance(value, str) else f"2026-01-01T00:00:{value:09.6f}Z"

    def list_projects(self):
        return [dict(r) for r in self.conn.execute("SELECT * FROM projects ORDER BY created_seq")]

    def project(self, project_id: str):
        row = self.conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        return dict(row) if row else None

    def events(self, project_id: str, at_seq: int | None = None):
        sql = "SELECT * FROM events WHERE project_id=?"
        args: list[Any] = [project_id]
        if at_seq is not None:
            sql += " AND seq<=?"
            args.append(at_seq)
        sql += " ORDER BY seq"
        return [self._event_row(r) for r in self.conn.execute(sql, args)]

    def _event_row(self, row):
        item = dict(row)
        item["payload"] = json.loads(item["payload"])
        return item

    def event(self, event_id: str):
        row = self.conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        return self._event_row(row) if row else None

    def next_seq(self, project_id: str) -> int:
        row = self.conn.execute("SELECT COALESCE(MAX(seq), 0) AS n FROM events WHERE project_id=?", (project_id,)).fetchone()
        return int(row["n"]) + 1

    def add_project(self, project_id: str, title: str, timestamp: str | None = None):
        seq = 1
        eid = f"p:{project_id};e{seq}"
        ts = timestamp or self.now()
        self.conn.execute(
            "INSERT INTO projects(id,title,created_seq,created_at) VALUES(?,?,?,?)",
            (project_id, title, seq, ts),
        )
        self.conn.execute(
            "INSERT INTO events(id,project_id,seq,type,timestamp,parent_event_id,payload) VALUES(?,?,?,?,?,?,?)",
            (eid, project_id, seq, "project_created", ts, None, canonical_json({"title": title})),
        )
        self.conn.commit()
        return self.event(eid)

    def add_event(self, project_id, typ, payload, parent_event_id=None, event_id=None, seq=None, timestamp=None, blob: bytes | None = None):
        seq = seq or self.next_seq(project_id)
        eid = event_id or f"p:{project_id};e{seq}"
        ts = timestamp or self.now()
        if blob is not None:
            digest = hashlib.sha256(blob).hexdigest()
            payload = dict(payload)
            payload["binary_sha256"] = digest
            payload["original_encoding"] = payload.get("original_encoding", "base64")
            self.conn.execute(
                "INSERT OR IGNORE INTO blobs(sha256,content,original_encoding) VALUES(?,?,?)",
                (digest, blob, payload["original_encoding"]),
            )
        self.conn.execute(
            "INSERT INTO events(id,project_id,seq,type,timestamp,parent_event_id,payload) VALUES(?,?,?,?,?,?,?)",
            (eid, project_id, seq, typ, ts, parent_event_id, canonical_json(payload)),
        )
        self.conn.commit()
        return self.event(eid)

    def put_blob(self, content: bytes, encoding: str = "base64") -> str:
        digest = hashlib.sha256(content).hexdigest()
        self.conn.execute("INSERT OR IGNORE INTO blobs(sha256,content,original_encoding) VALUES(?,?,?)", (digest, content, encoding))
        self.conn.commit()
        return digest

    def get_blob(self, digest: str) -> bytes | None:
        row = self.conn.execute("SELECT content FROM blobs WHERE sha256=?", (digest,)).fetchone()
        return row["content"] if row else None

    def latest(self, project_id: str, typ: str, at_seq: int | None = None):
        events = [e for e in self.events(project_id, at_seq) if e["type"] == typ]
        return events[-1] if events else None

    def add_module(self, project_id, data, label, timestamp=None):
        parent = self.latest(project_id, "module_submitted")
        seq = self.next_seq(project_id)
        payload = {
            "module_id": module_id(project_id, seq),
            "label": label,
            "original_base64": base64.b64encode(data).decode("ascii"),
            "immutable": True,
        }
        return self.add_event(project_id, "module_submitted", payload, parent["id"] if parent else None, seq=seq, timestamp=timestamp, blob=data)

    def add_config(self, project_id, config, label, timestamp=None):
        parent = self.latest(project_id, "config_submitted")
        seq = self.next_seq(project_id)
        normalized = normalize_config(config)
        payload = {
            "config_id": config_id(project_id, seq),
            "label": label,
            "features": normalized["features"],
            "host_imports": normalized["host_imports"],
            "parameter_fingerprint": sha256_json(normalized),
            "raw_representation": config,
        }
        return self.add_event(project_id, "config_submitted", payload, parent["id"] if parent else None, seq=seq, timestamp=timestamp)

    def add_decision(self, project_id, target_stable_id, accepted, rationale, timestamp=None):
        prior_events = [e for e in self.events(project_id) if e["type"] == "decision_made"]
        prior = prior_events[-1] if prior_events else None
        conflicting = None
        if prior and prior["payload"].get("target_stable_id") == target_stable_id:
            old_accepted = prior["payload"].get("accepted")
            if old_accepted is not None and bool(old_accepted) != bool(accepted):
                conflicting = prior["id"]
        seq = self.next_seq(project_id)
        payload = {
            "decision_id": decision_id(project_id, seq),
            "target_stable_id": target_stable_id,
            "accepted": accepted,
            "rationale": rationale,
            "conflicts_with_event_id": conflicting,
        }
        return self.add_event(project_id, "decision_made", payload, prior["id"] if prior else None, seq=seq, timestamp=timestamp)

    def get_derived(self, stable_id):
        row = self.conn.execute("SELECT * FROM derived WHERE stable_id=?", (stable_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        for key in ("direct_sources", "value"):
            item[key] = json.loads(item[key])
        return item

    def put_derived(self, project_id, kind, source_hash, params_fp, sources, value, event_seq, timestamp, stable_id=None):
        stable_id = stable_id or f"result:{ALGORITHM_VERSION};{kind};sha256:{source_hash[:32]};params:{params_fp[:16]}"
        existing = self.get_derived(stable_id)
        if existing:
            return existing
        self.conn.execute(
            """INSERT INTO derived(stable_id,project_id,kind,source_hash,algorithm_version,parameter_fingerprint,
               direct_sources,value,state,created_event_seq,created_at)
               VALUES(?,?,?,?,?,?,?,?, 'active', ?,?)""",
            (stable_id, project_id, kind, source_hash, ALGORITHM_VERSION, params_fp,
             canonical_json(sources), canonical_json(value), event_seq, timestamp),
        )
        self.conn.commit()
        return self.get_derived(stable_id)

    def expire_kind_prefix(self, project_id, kind, source_id, event_seq, timestamp):
        rows = self.conn.execute(
            "SELECT stable_id, direct_sources FROM derived WHERE project_id=? AND kind=? AND state='active'",
            (project_id, kind),
        ).fetchall()
        for row in rows:
            sources = json.loads(row["direct_sources"])
            if source_id in sources:
                self.conn.execute(
                    "UPDATE derived SET state='stale', expired_event_seq=?, expired_at=? WHERE stable_id=?",
                    (event_seq, timestamp, row["stable_id"]),
                )
        self.conn.commit()

    def derived_list(self, project_id, include_stale=True):
        sql = "SELECT * FROM derived WHERE project_id=?"
        if not include_stale:
            sql += " AND state='active'"
        return [self.get_derived(r["stable_id"]) for r in self.conn.execute(sql, (project_id,))]

    def mark_current_analysis(self, project_id: str, stable_id: str):
        self.conn.execute(
            "UPDATE derived SET state='stale' WHERE project_id=? AND kind='analysis_bundle'",
            (project_id,),
        )
        self.conn.execute(
            "UPDATE derived SET state='current' WHERE project_id=? AND stable_id=?",
            (project_id, stable_id),
        )
        self.conn.commit()

    def export_project(self, project_id):
        events = self.events(project_id)
        blobs = []
        seen = set()
        for event in events:
            digest = event["payload"].get("binary_sha256")
            if digest and digest not in seen:
                raw = self.get_blob(digest)
                blobs.append({"sha256": digest, "content_base64": base64.b64encode(raw).decode("ascii"), "original_encoding": "base64"})
                seen.add(digest)
        return {
            "archive_format": "module-boundary-court/event-log/v1",
            "algorithm_version": ALGORITHM_VERSION,
            "project": self.project(project_id),
            "events": events,
            "blobs": blobs,
            "derived": self.derived_list(project_id),
        }

    def import_archive(self, archive: dict, replace: bool = True):
        if replace:
            self.conn.executescript("DELETE FROM derived; DELETE FROM events; DELETE FROM projects; DELETE FROM blobs;")
        project = archive["project"]
        self.conn.execute("INSERT OR REPLACE INTO projects VALUES(?,?,?,?)", (project["id"], project["title"], project["created_seq"], project["created_at"]))
        for blob in archive.get("blobs", []):
            self.conn.execute(
                "INSERT OR REPLACE INTO blobs(sha256,content,original_encoding) VALUES(?,?,?)",
                (blob["sha256"], base64.b64decode(blob["content_base64"]), blob.get("original_encoding", "base64")),
            )
        for event in archive["events"]:
            self.conn.execute(
                "INSERT OR REPLACE INTO events(id,project_id,seq,type,timestamp,parent_event_id,payload) VALUES(?,?,?,?,?,?,?)",
                (event["id"], event["project_id"], event["seq"], event["type"], event["timestamp"], event.get("parent_event_id"), canonical_json(event["payload"])),
            )
        for derived in archive.get("derived", []):
            self.conn.execute(
                """INSERT OR REPLACE INTO derived(stable_id,project_id,kind,source_hash,algorithm_version,
                   parameter_fingerprint,direct_sources,value,state,created_event_seq,created_at,
                   expired_event_seq,expired_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (derived["stable_id"], derived["project_id"], derived["kind"], derived["source_hash"],
                 derived["algorithm_version"], derived["parameter_fingerprint"], canonical_json(derived["direct_sources"]),
                 canonical_json(derived["value"]), derived["state"], derived["created_event_seq"],
                 derived["created_at"], derived.get("expired_event_seq"), derived.get("expired_at")),
            )
        self.conn.commit()
        return project


def normalize_config(config: dict) -> dict:
    features = {name: bool(config.get("features", {}).get(name, False)) for name in ("multi_value", "reference_types", "tail_call", "simd")}
    imports = []
    for item in config.get("host_imports", []):
        imports.append({
            "module": item["module"],
            "name": item["name"],
            "params": list(item.get("params", [])),
            "results": list(item.get("results", [])),
        })
    imports.sort(key=lambda x: canonical_json(x))
    return {"features": features, "host_imports": imports}
