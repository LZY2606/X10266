"""SQLite-backed versioned store.

- inputs: immutable original submissions; revisions are new rows with parent_id
- results: derived values carrying algo version, parameter fingerprint and
  direct source hash; local input changes only stale the results that depend
  on them; stale results stay readable but never masquerade as current
- events: append-only machine-readable log; every accept/reject/adjust/undo
  is an event; viewing an old event restores the dependency versions and
  conclusions visible at that time
- decisions: human rulings attached to results; conflicting rulings coexist
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

import wasmcore

SCHEMA = """
CREATE TABLE IF NOT EXISTS inputs(
  id TEXT PRIMARY KEY, seq INTEGER, parent_id TEXT, label TEXT,
  wasm BLOB, proposals TEXT, host_imports TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS results(
  id TEXT PRIMARY KEY, input_id TEXT, subject TEXT, algo TEXT,
  fingerprint TEXT UNIQUE, params TEXT, source_hash TEXT,
  status TEXT, payload TEXT, created_seq INTEGER, superseded_seq INTEGER);
CREATE TABLE IF NOT EXISTS decisions(
  id TEXT PRIMARY KEY, result_id TEXT, verdict TEXT, note TEXT,
  reviewer TEXT, created_seq INTEGER, undone_seq INTEGER);
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT, ts TEXT, kind TEXT, payload TEXT);
"""


def _now():
    return datetime.now(timezone.utc).isoformat()


def fingerprint(subject, params, source_hash):
    blob = json.dumps({"algo": wasmcore.ALGO_VERSION, "subject": subject,
                       "params": params, "source": source_hash},
                      sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:24]


def _slug(subject):
    return subject.replace("/", "-").replace("module", "mod")


class Store:
    def __init__(self, path, clock=None):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.clock = clock or _now
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---------- events ----------
    def _event(self, kind, payload):
        cur = self.conn.execute(
            "INSERT INTO events(ts, kind, payload) VALUES(?,?,?)",
            (self.clock(), kind, json.dumps(payload, sort_keys=True)))
        seq = cur.lastrowid
        eid = f"ev-{seq:04d}"
        self.conn.execute("UPDATE events SET id=? WHERE seq=?", (eid, seq))
        self.conn.commit()
        return seq, eid

    def events(self, at_seq=None):
        q = "SELECT * FROM events"
        args = ()
        if at_seq is not None:
            q += " WHERE seq<=?"
            args = (at_seq,)
        q += " ORDER BY seq"
        return [dict(r) | {"payload": json.loads(r["payload"])}
                for r in self.conn.execute(q, args)]

    # ---------- inputs ----------
    def commit_input(self, label, wasm, proposals, host_imports, parent_id=None):
        if parent_id and not self.conn.execute(
                "SELECT 1 FROM inputs WHERE id=?", (parent_id,)).fetchone():
            raise KeyError(f"unknown parent input {parent_id}")
        unknown = set(proposals) - set(wasmcore.KNOWN_PROPOSALS)
        if unknown:
            raise ValueError(f"unknown proposals: {sorted(unknown)}")
        seq, eid = self._event("input_committed", {
            "label": label, "parent_id": parent_id,
            "wasm_sha256": hashlib.sha256(wasm).hexdigest(),
            "wasm_len": len(wasm), "proposals": sorted(proposals)})
        iid = f"in-{seq:04d}"
        self.conn.execute(
            "INSERT INTO inputs VALUES(?,?,?,?,?,?,?,?)",
            (iid, seq, parent_id, label, wasm,
             json.dumps(sorted(proposals)), json.dumps(host_imports), self.clock()))
        self.conn.commit()
        self._derive(iid, seq)
        return iid

    def _derive(self, iid, seq):
        row = self.conn.execute("SELECT * FROM inputs WHERE id=?", (iid,)).fetchone()
        wasm = bytes(row["wasm"])
        proposals = json.loads(row["proposals"])
        host_imports = json.loads(row["host_imports"])
        res = wasmcore.validate_module(wasm, proposals, host_imports)
        params = {"proposals": sorted(proposals), "host_imports": host_imports}
        params_json = json.dumps(params, sort_keys=True)

        subjects = []
        mod_src = hashlib.sha256(wasm).hexdigest()
        subjects.append(("module", mod_src, {
            "ok": res["ok"], "errors": res["errors"],
            "function_errors": res["function_errors"],
            "sections": res["sections"], "index_spaces": res["index_spaces"],
            "imports": res["imports"], "exports": res["exports"],
            "custom_sections": res["custom_sections"],
            "judgments": res["judgments"], "histogram": res["histogram"],
        }))
        for fn in res["functions"]:
            src = hashlib.sha256(
                (fn["body_sha256"] + json.dumps(fn["type"], sort_keys=True)).encode()
            ).hexdigest()
            subjects.append((f"function/{fn['index']}", src, {
                "ok": not fn["errors"], "index": fn["index"],
                "type_index": fn["type_index"], "type": fn["type"],
                "body_range": fn["body_range"], "body_sha256": fn["body_sha256"],
                "locals": fn["locals"], "control_trace": fn["control_trace"],
                "type_transitions": fn["type_transitions"], "errors": fn["errors"],
                "used_polymorphic_stack": fn["used_polymorphic_stack"],
            }))

        new_fps = {}
        for subject, src, payload in subjects:
            new_fps[fingerprint(subject, params, src)] = (subject, src, payload)

        staled = []
        for r in self.conn.execute(
                "SELECT id, fingerprint FROM results WHERE status='current'"):
            if r["fingerprint"] not in new_fps:
                self.conn.execute(
                    "UPDATE results SET status='stale', superseded_seq=? WHERE id=?",
                    (seq, r["id"]))
                staled.append(r["id"])
        created = []
        for fp, (subject, src, payload) in new_fps.items():
            existing = self.conn.execute(
                "SELECT id, status FROM results WHERE fingerprint=?", (fp,)).fetchone()
            if existing:
                if existing["status"] != "current":
                    self.conn.execute(
                        "UPDATE results SET status='current', superseded_seq=NULL WHERE id=?",
                        (existing["id"],))
                    created.append(existing["id"])
                continue
            rid = f"rs-{seq:04d}-{_slug(subject)}"
            self.conn.execute(
                "INSERT INTO results VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (rid, iid, subject, wasmcore.ALGO_VERSION, fp, params_json, src,
                 "current", json.dumps(payload, sort_keys=True), seq, None))
            created.append(rid)
        self.conn.commit()
        self._event("validation_completed", {
            "input_id": iid, "created_results": created, "staled_results": staled,
            "judgments": res["judgments"], "ok": res["ok"]})

    def list_inputs(self, at_seq=None):
        rows = self.conn.execute(
            "SELECT * FROM inputs" + (" WHERE seq<=?" if at_seq else "") + " ORDER BY seq",
            (at_seq,) if at_seq else ()).fetchall()
        return [{"id": r["id"], "seq": r["seq"], "parent_id": r["parent_id"],
                 "label": r["label"], "proposals": json.loads(r["proposals"]),
                 "host_imports": json.loads(r["host_imports"]),
                 "created_at": r["created_at"],
                 "wasm_len": len(r["wasm"]),
                 "wasm_sha256": hashlib.sha256(bytes(r["wasm"])).hexdigest()}
                for r in rows]

    def get_input(self, iid):
        r = self.conn.execute("SELECT * FROM inputs WHERE id=?", (iid,)).fetchone()
        if not r:
            raise KeyError(iid)
        return r

    # ---------- results ----------
    def _visible_results(self, at_seq=None, status=None):
        rows = self.conn.execute("SELECT * FROM results ORDER BY created_seq, id").fetchall()
        out = []
        for r in rows:
            if at_seq is not None and r["created_seq"] > at_seq:
                continue
            st = "stale" if (r["superseded_seq"] is not None
                             and (at_seq is None or r["superseded_seq"] <= at_seq)) else "current"
            if status and st != status:
                continue
            out.append(dict(r) | {"status": st, "payload": json.loads(r["payload"])})
        return out

    def get_result(self, rid):
        r = self.conn.execute("SELECT * FROM results WHERE id=?", (rid,)).fetchone()
        if not r:
            raise KeyError(rid)
        return dict(r) | {"payload": json.loads(r["payload"])}

    def input_view(self, iid, at_seq=None):
        row = self.get_input(iid)
        wasm = bytes(row["wasm"])
        proposals = json.loads(row["proposals"])
        host_imports = json.loads(row["host_imports"])
        res = wasmcore.validate_module(wasm, proposals, host_imports)
        params = {"proposals": sorted(proposals), "host_imports": host_imports}
        mod_src = hashlib.sha256(wasm).hexdigest()
        wanted = {fingerprint("module", params, mod_src): "module"}
        for fn in res["functions"]:
            src = hashlib.sha256(
                (fn["body_sha256"] + json.dumps(fn["type"], sort_keys=True)).encode()
            ).hexdigest()
            wanted[fingerprint(f"function/{fn['index']}", params, src)] = f"function/{fn['index']}"
        matched = {}
        for r in self._visible_results(at_seq):
            if r["fingerprint"] in wanted:
                matched[r["fingerprint"]] = r
        results = []
        for fp, subject in wanted.items():
            m = matched.get(fp)
            results.append({"subject": subject, "fingerprint": fp,
                            "result": m, "carried_from": m["input_id"] if m else None})
        return {
            "input": {"id": row["id"], "seq": row["seq"], "parent_id": row["parent_id"],
                      "label": row["label"], "proposals": proposals,
                      "host_imports": host_imports, "wasm_hex": wasm.hex(),
                      "created_at": row["created_at"]},
            "validation": res,
            "results": results,
            "decisions": self._decisions_for([r["result"]["id"] for r in results
                                              if r["result"]], at_seq),
        }

    # ---------- decisions ----------
    def decide(self, result_id, verdict, note, reviewer):
        if verdict not in ("accept", "reject", "adjust"):
            raise ValueError("verdict must be accept|reject|adjust")
        self.get_result(result_id)
        seq, _ = self._event("decision_recorded", {
            "result_id": result_id, "verdict": verdict,
            "reviewer": reviewer, "note": note})
        did = f"dn-{seq:04d}"
        self.conn.execute("INSERT INTO decisions VALUES(?,?,?,?,?,?,?)",
                          (did, result_id, verdict, note, reviewer, seq, None))
        self.conn.commit()
        return did

    def undo_decision(self, did):
        r = self.conn.execute("SELECT * FROM decisions WHERE id=?", (did,)).fetchone()
        if not r:
            raise KeyError(did)
        if r["undone_seq"] is not None:
            raise ValueError("decision already undone")
        seq, _ = self._event("decision_undone", {"decision_id": did,
                                                 "result_id": r["result_id"]})
        self.conn.execute("UPDATE decisions SET undone_seq=? WHERE id=?", (seq, did))
        self.conn.commit()
        return seq

    def _decisions_for(self, result_ids, at_seq=None):
        if not result_ids:
            return {}
        marks = ",".join("?" * len(result_ids))
        rows = self.conn.execute(
            f"SELECT * FROM decisions WHERE result_id IN ({marks}) ORDER BY created_seq",
            tuple(result_ids)).fetchall()
        out = {}
        for r in rows:
            if at_seq is not None and r["created_seq"] > at_seq:
                continue
            active = r["undone_seq"] is None or (at_seq is not None and r["undone_seq"] > at_seq)
            out.setdefault(r["result_id"], []).append(dict(r) | {"active": active})
        return out

    def conflicts(self, at_seq=None):
        rows = self.conn.execute("SELECT * FROM decisions ORDER BY created_seq").fetchall()
        by_result = {}
        for r in rows:
            if at_seq is not None and r["created_seq"] > at_seq:
                continue
            if r["undone_seq"] is not None and (at_seq is None or r["undone_seq"] <= at_seq):
                continue
            by_result.setdefault(r["result_id"], set()).add(r["verdict"])
        return sorted(rid for rid, verdicts in by_result.items() if len(verdicts) > 1)

    # ---------- state / archive ----------
    def state(self, at_seq=None):
        return {"inputs": self.list_inputs(at_seq),
                "results": self._visible_results(at_seq),
                "events": self.events(at_seq),
                "conflicts": self.conflicts(at_seq),
                "view_seq": at_seq,
                "algo_version": wasmcore.ALGO_VERSION}

    def export_archive(self):
        dump = {}
        for table in ("inputs", "results", "decisions", "events"):
            rows = []
            for r in self.conn.execute(f"SELECT * FROM {table} ORDER BY rowid"):
                d = dict(r)
                if table == "inputs":
                    d["wasm"] = bytes(d["wasm"]).hex()
                rows.append(d)
            dump[table] = rows
        return {"format": "wasmv-archive/1", "tables": dump}

    def import_archive(self, archive):
        if archive.get("format") != "wasmv-archive/1":
            raise ValueError("unsupported archive format")
        tables = archive["tables"]
        with self.conn:
            for table in ("decisions", "results", "inputs", "events"):
                self.conn.execute(f"DELETE FROM {table}")
            self.conn.execute("DELETE FROM sqlite_sequence WHERE name='events'")
            for r in tables["events"]:
                self.conn.execute("INSERT INTO events VALUES(?,?,?,?,?)",
                                  (r["seq"], r["id"], r["ts"], r["kind"], r["payload"]))
            for r in tables["inputs"]:
                self.conn.execute("INSERT INTO inputs VALUES(?,?,?,?,?,?,?,?)",
                                  (r["id"], r["seq"], r["parent_id"], r["label"],
                                   bytes.fromhex(r["wasm"]), r["proposals"],
                                   r["host_imports"], r["created_at"]))
            for r in tables["results"]:
                self.conn.execute("INSERT INTO results VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                                  (r["id"], r["input_id"], r["subject"], r["algo"],
                                   r["fingerprint"], r["params"], r["source_hash"],
                                   r["status"], r["payload"], r["created_seq"],
                                   r["superseded_seq"]))
            for r in tables["decisions"]:
                self.conn.execute("INSERT INTO decisions VALUES(?,?,?,?,?,?,?)",
                                  (r["id"], r["result_id"], r["verdict"], r["note"],
                                   r["reviewer"], r["created_seq"], r["undone_seq"]))
        self._event("archive_imported", {
            "inputs": len(tables["inputs"]), "results": len(tables["results"]),
            "decisions": len(tables["decisions"]), "events": len(tables["events"])})
