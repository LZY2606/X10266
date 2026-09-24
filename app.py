"""FastAPI entry: 模块边界庭 — WebAssembly 段索引、类型栈与提案能力验证."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

import casepack
from store import Store

STATIC = Path(__file__).parent / "web" / "static" / "index.html"


class InputBody(BaseModel):
    label: str
    wasm_hex: str
    proposals: list[str]
    host_imports: list[dict] = []
    parent_id: str | None = None


class DecisionBody(BaseModel):
    verdict: str
    note: str = ""
    reviewer: str = "reviewer"


def create_app(db_path=None, clock=None):
    store = Store(db_path or os.environ.get("WASMV_DB", "wasmv.db"), clock=clock)
    app = FastAPI(title="模块边界庭")
    app.state.store = store

    @app.get("/", response_class=HTMLResponse)
    def index():
        return HTMLResponse(STATIC.read_text(encoding="utf-8"))

    @app.get("/api/state")
    def state(at_seq: int | None = None):
        return store.state(at_seq)

    @app.post("/api/inputs", status_code=201)
    def commit_input(body: InputBody):
        try:
            wasm = bytes.fromhex(body.wasm_hex.replace(" ", "").replace("\n", ""))
        except ValueError:
            raise HTTPException(400, "wasm_hex is not valid hex")
        try:
            iid = store.commit_input(body.label, wasm, body.proposals,
                                     body.host_imports, body.parent_id)
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, str(exc))
        return {"input_id": iid}

    @app.get("/api/inputs/{iid}")
    def input_view(iid: str, at_seq: int | None = None):
        try:
            return store.input_view(iid, at_seq)
        except KeyError:
            raise HTTPException(404, f"unknown input {iid}")

    @app.post("/api/results/{rid}/decisions", status_code=201)
    def decide(rid: str, body: DecisionBody):
        try:
            did = store.decide(rid, body.verdict, body.note, body.reviewer)
        except KeyError:
            raise HTTPException(404, f"unknown result {rid}")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"decision_id": did}

    @app.post("/api/decisions/{did}/undo")
    def undo(did: str):
        try:
            store.undo_decision(did)
        except KeyError:
            raise HTTPException(404, f"unknown decision {did}")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"undone": did}

    @app.get("/api/export")
    def export():
        return store.export_archive()

    @app.post("/api/import")
    def import_(archive: dict):
        try:
            store.import_archive(archive)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"imported": True}

    @app.post("/api/casepack/load")
    def load_casepack():
        return casepack.load_case(store)

    return app


app = create_app()
