import json
import sqlite3
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    parent_event_id TEXT,
    payload_json TEXT NOT NULL,
    UNIQUE(project_id, seq)
);
CREATE INDEX IF NOT EXISTS events_project_seq ON events(project_id, seq);
CREATE TABLE IF NOT EXISTS exports (
    export_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
"""


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class EventStore:
    def __init__(self, path: str | Path = ":memory:", clock: Callable[[], str] | None = None,
                 id_factory: Callable[[], str] | None = None):
        self.path = str(path)
        self.clock = clock or utc_now
        self.id_factory = id_factory or (lambda: str(uuid.uuid4()))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    def next_seq(self, project_id: str) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(seq), 0) AS max_seq FROM events WHERE project_id = ?",
            (project_id,),
        ).fetchone()
        return int(row["max_seq"]) + 1

    def append(self, project_id: str, kind: str, payload: dict,
               parent_event_id: str | None = None, actor: str = "runtime-reviewer",
               event_id: str | None = None, occurred_at: str | None = None) -> dict:
        seq = self.next_seq(project_id)
        event = {
            "eventId": event_id or self.id_factory(),
            "projectId": project_id,
            "seq": seq,
            "kind": kind,
            "occurredAt": occurred_at or self.clock(),
            "actor": actor,
            "parentEventId": parent_event_id,
            "payload": payload,
        }
        self.conn.execute(
            """INSERT INTO events(event_id, project_id, seq, kind, occurred_at, actor,
                                  parent_event_id, payload_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (event["eventId"], project_id, seq, kind, event["occurredAt"], actor,
             parent_event_id, json.dumps(payload, ensure_ascii=False, sort_keys=True)),
        )
        self.conn.commit()
        return event

    def events(self, project_id: str, seq_limit: int | None = None) -> list[dict]:
        sql = "SELECT * FROM events WHERE project_id = ?"
        args: list = [project_id]
        if seq_limit is not None:
            sql += " AND seq <= ?"
            args.append(seq_limit)
        sql += " ORDER BY seq"
        rows = self.conn.execute(sql, args).fetchall()
        return [
            {
                "eventId": row["event_id"],
                "projectId": row["project_id"],
                "seq": row["seq"],
                "kind": row["kind"],
                "occurredAt": row["occurred_at"],
                "actor": row["actor"],
                "parentEventId": row["parent_event_id"],
                "payload": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def projects(self) -> list[dict]:
        rows = self.conn.execute(
            """SELECT project_id, MIN(seq) AS first_seq, MAX(seq) AS last_seq,
                      MIN(occurred_at) AS created_at, MAX(occurred_at) AS updated_at
               FROM events GROUP BY project_id ORDER BY MIN(seq)"""
        ).fetchall()
        projects = []
        for row in rows:
            first = self.conn.execute(
                "SELECT payload_json FROM events WHERE project_id=? ORDER BY seq LIMIT 1",
                (row["project_id"],),
            ).fetchone()
            payload = json.loads(first["payload_json"]) if first else {}
            projects.append({
                "projectId": row["project_id"],
                "name": payload.get("name", row["project_id"]),
                "firstSeq": row["first_seq"],
                "lastSeq": row["last_seq"],
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            })
        return projects

    def export_project(self, project_id: str) -> dict:
        events = self.events(project_id)
        return {
            "format": "wasm-court-event-log/1",
            "projectId": project_id,
            "exportedAt": self.clock(),
            "events": events,
        }

    def import_project(self, archive: dict, preserve_ids: bool = True) -> int:
        if archive.get("format") != "wasm-court-event-log/1":
            raise ValueError("unsupported archive format")
        project_id = archive["projectId"]
        count = 0
        for event in archive["events"]:
            if event.get("projectId") != project_id:
                raise ValueError("archive contains foreign project event")
            self.conn.execute(
                """INSERT OR IGNORE INTO events(event_id, project_id, seq, kind, occurred_at,
                                                actor, parent_event_id, payload_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (event["eventId"], project_id, event["seq"], event["kind"], event["occurredAt"],
                 event.get("actor", "imported"), event.get("parentEventId"),
                 json.dumps(event["payload"], ensure_ascii=False, sort_keys=True)),
            )
            count += self.conn.total_changes and 1
        self.conn.commit()
        return len(archive["events"])
