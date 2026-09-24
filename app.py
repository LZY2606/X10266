from __future__ import annotations

import base64
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from wasmverify.engine import Engine
from wasmverify.store import Store


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "court.sqlite3"
store = Store(str(DB_PATH))
engine = Engine(store)
app = FastAPI(title="Module Boundary Court", version="1.0")


class ProjectIn(BaseModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9._-]{3,64}$")
    title: str
    timestamp: str | None = None


class ModuleIn(BaseModel):
    base64: str
    label: str
    timestamp: str | None = None


class ConfigIn(BaseModel):
    features: dict[str, bool] = {}
    host_imports: list[dict] = []
    label: str
    timestamp: str | None = None


class DecisionIn(BaseModel):
    target_stable_id: str
    accepted: bool
    rationale: str
    timestamp: str | None = None


def get_project(project_id: str):
    project = store.project(project_id)
    if not project:
        raise HTTPException(404, "project not found")
    return project


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/api/health")
def health():
    return {"ok": True, "database": str(DB_PATH), "network": "offline"}


@app.post("/api/projects")
def create_project(body: ProjectIn):
    if store.project(body.id):
        raise HTTPException(409, "project already exists")
    return store.add_project(body.id, body.title, body.timestamp)


@app.get("/api/projects")
def list_projects():
    return store.list_projects()


@app.get("/api/projects/{project_id}")
def get_state(project_id: str, at_seq: int | None = None):
    get_project(project_id)
    latest_seq = store.events(project_id)[-1]["seq"] if store.events(project_id) else 0
    state = engine.state(project_id, at_seq)
    state["view_state"] = "historical" if at_seq and at_seq < latest_seq else "current"
    if state["view_state"] == "current" and state.get("ready"):
        store.mark_current_analysis(project_id, state["stable_id"])
    return state


@app.post("/api/projects/{project_id}/modules")
def submit_module(project_id: str, body: ModuleIn):
    get_project(project_id)
    try:
        raw = base64.b64decode(body.base64, validate=True)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "base64 input is malformed"})
    event = store.add_module(project_id, raw, body.label, body.timestamp)
    engine.parse_event(event)
    state = engine.state(project_id)
    store.mark_current_analysis(project_id, state["stable_id"])
    return event


@app.post("/api/projects/{project_id}/configs")
def submit_config(project_id: str, body: ConfigIn):
    get_project(project_id)
    event = store.add_config(project_id, body.model_dump(), body.label, body.timestamp)
    state = engine.state(project_id)
    store.mark_current_analysis(project_id, state["stable_id"])
    return event


@app.post("/api/projects/{project_id}/decisions")
def make_decision(project_id: str, body: DecisionIn):
    get_project(project_id)
    event = store.add_decision(project_id, body.target_stable_id, body.accepted, body.rationale, body.timestamp)
    state = engine.state(project_id)
    store.mark_current_analysis(project_id, state["stable_id"])
    return event


@app.get("/api/projects/{project_id}/events")
def events(project_id: str, at_seq: int | None = None):
    get_project(project_id)
    return store.events(project_id, at_seq)


@app.get("/api/projects/{project_id}/export")
def export_project(project_id: str):
    get_project(project_id)
    return store.export_project(project_id)


@app.post("/api/archive/import")
def import_archive(archive: dict):
    if archive.get("archive_format") != "module-boundary-court/event-log/v1":
        raise HTTPException(400, "unsupported archive format")
    project = store.import_archive(archive, replace=True)
    engine.state(project["id"])
    store.mark_current_analysis(project["id"], None)
    return {"ok": True, "project": project}


@app.post("/api/database/clear")
def clear_database():
    store.conn.executescript("DELETE FROM derived; DELETE FROM events; DELETE FROM projects; DELETE FROM blobs;")
    store.conn.commit()
    return {"ok": True}


@app.get("/api/casepack")
def get_casepack():
    path = ROOT / "casepack" / "module-boundary-court.json"
    if not path.exists():
        raise HTTPException(404, "casepack has not been generated")
    return JSONResponse(json.loads(path.read_text(encoding="utf-8")))


@app.post("/api/casepack/load")
def load_casepack():
    archive = get_casepack().body
    project = store.import_archive(json.loads(archive.decode("utf-8")), replace=True)
    state = engine.state(project["id"])
    store.mark_current_analysis(project["id"], state["stable_id"])
    return {"ok": True, "project_id": project["id"], "at_seq": state["at_seq"]}


@app.get("/api/derived/{project_id}")
def derived(project_id: str, include_stale: bool = True):
    get_project(project_id)
    return store.derived_list(project_id, include_stale=include_stale)
