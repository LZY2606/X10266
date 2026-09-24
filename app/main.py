from __future__ import annotations
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from .storage import ProjectStore, VirtualClock, canonical_json, now_iso

DB_PATH = os.environ.get("MODULE_COURT_DB", str(Path.cwd() / "data" / "module_court.sqlite3"))
CASE_PATH = Path(__file__).resolve().parents[1] / "cases" / "module-boundary-court" / "case.json"
app = FastAPI(title="Module Boundary Court", version="1.0.0")
_clock = VirtualClock()


def store() -> ProjectStore:
    return ProjectStore(DB_PATH, _clock)


class BinarySubmit(BaseModel):
    title: str | None = None
    binary_hex: str
    proposals: dict = Field(default_factory=dict)
    host_imports: dict = Field(default_factory=lambda: {"imports": []})
    label: str = "initial import"
    actor: str = "runtime-team"


class ParamSubmit(BaseModel):
    proposals: dict = Field(default_factory=dict)
    host_imports: dict = Field(default_factory=lambda: {"imports": []})
    label: str = "parameter revision"
    actor: str = "runtime-team"
    finding_id: str | None = None
    rationale: str = ""


class DecisionSubmit(BaseModel):
    finding_id: str
    decision: str
    rationale: str = ""
    actor: str = "reviewer"
    conflict_with: str | None = None
    undo_of: str | None = None


class CaseInstall(BaseModel):
    project_id: str | None = "case-module-boundary-court"
    include_conflict: bool = True


@app.get("/", response_class=HTMLResponse)
def index():
    return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {"ok": True, "db": DB_PATH, "time": _clock()}


@app.get("/api/projects")
def projects():
    db = store()
    try:
        return db.list_projects()
    finally:
        db.close()


@app.post("/api/projects/empty")
def empty_project(title: str = "未命名模块边界项目"):
    db = store()
    try:
        p = db.create_project(title)
        return db.current_review(p["project_id"])
    finally:
        db.close()


@app.post("/api/import-binary")
def import_binary(payload: BinarySubmit):
    db = store()
    try:
        try:
            binary = bytes.fromhex(payload.binary_hex)
        except ValueError:
            raise HTTPException(400, "binary_hex must be hexadecimal")
        title = payload.title or "导入的 Wasm 模块"
        project = db.create_project(title)
        params = {"proposals": payload.proposals, "host_imports": payload.host_imports}
        db.submit_input(project["project_id"], binary, params, payload.label, payload.actor, kind="import")
        return db.current_review(project["project_id"])
    finally:
        db.close()


@app.get("/api/projects/{project_id}/review")
def review(project_id: str, revision_id: str | None = None):
    db = store()
    try:
        p = db.get_project(project_id)
        if not p: raise HTTPException(404, "project not found")
        rid = revision_id or p["head_revision_id"]
        if not db.get_revision(rid): raise HTTPException(404, "revision not found")
        return db.review(rid)
    finally:
        db.close()


@app.get("/api/projects/{project_id}/events")
def events(project_id: str):
    db = store()
    try:
        return db.list_events(project_id)
    finally:
        db.close()


@app.post("/api/projects/{project_id}/revisions/params")
def revise_params(project_id: str, payload: ParamSubmit):
    db = store()
    try:
        if not db.get_project(project_id): raise HTTPException(404, "project not found")
        params = {"proposals": payload.proposals, "host_imports": payload.host_imports}
        db.revise_params(project_id, params, payload.label, payload.actor, payload.finding_id, rationale=payload.rationale)
        return db.current_review(project_id)
    finally:
        db.close()


@app.post("/api/projects/{project_id}/decisions")
def decide(project_id: str, payload: DecisionSubmit):
    db = store()
    try:
        if payload.decision not in ("accepted", "rejected", "adjust_params"):
            raise HTTPException(400, "decision must be accepted, rejected or adjust_params")
        db.record_decision(project_id, payload.finding_id, payload.decision, payload.rationale, payload.actor, payload.conflict_with, payload.undo_of)
        return db.current_review(project_id)
    finally:
        db.close()


@app.post("/api/cases/install")
def install_case(payload: CaseInstall):
    db = store()
    try:
        data = json.loads(CASE_PATH.read_text(encoding="utf-8"))
        pid = payload.project_id
        if db.get_project(pid):
            raise HTTPException(409, "case project already exists; choose another project_id")
        first = data["steps"][0]
        db.create_project(data["title"], pid, first["label"])
        # Remove the empty seed revision by starting an explicit head; it remains in history as immutable seed.
        first_params = first["params"]
        db.submit_input(pid, bytes.fromhex(first["binary_hex"]), first_params, first["label"], first.get("actor", "runtime-team"))
        candidate_id = None
        for step in data["steps"][1:]:
            if step["kind"] == "parameter_adjustment":
                db.revise_params(pid, step["params"], step["label"], step.get("actor", "runtime-team"), rationale="scripted case parameter revision")
            else:
                db.submit_input(pid, bytes.fromhex(step["binary_hex"]), step.get("params", first_params), step["label"], step.get("actor", "runtime-team"), kind=step["kind"])
        if payload.include_conflict:
            review = db.current_review(pid)
            target = next((x for x in review["findings"] if x["data"].get("code") == "unreachable_stack"), None)
            if target:
                candidate_id = target["artifact_id"]
                first_event = db.record_decision(pid, candidate_id, "accepted", data["conflict"]["rationale_a"], "reviewer-a")
                event_id = db.list_events(pid)[-1]["event_id"]
                db.record_decision(pid, candidate_id, "rejected", data["conflict"]["rationale_b"], "reviewer-b", conflict_with=event_id)
        return db.current_review(pid)
    finally:
        db.close()


@app.get("/api/projects/{project_id}/export")
def export_project(project_id: str):
    db = store()
    try:
        data = db.export_project(project_id)
        return JSONResponse(data, headers={"content-disposition": f'attachment; filename="{project_id}.json"'})
    finally:
        db.close()


@app.post("/api/projects/import")
async def import_project(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(400, "request body must be an exported JSON archive")
    db = store()
    try:
        project = db.import_project(data)
        return db.current_review(project["project_id"])
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    finally:
        db.close()


@app.get("/api/revisions/{revision_id}/section-map.svg")
def section_map_svg(revision_id: str):
    db = store()
    try:
        review = db.review(revision_id)
        svg = render_section_map(review)
        return Response(svg, media_type="image/svg+xml")
    finally:
        db.close()

def render_section_map(review: dict) -> str:
    sections = review["sections"]
    total = max(1, review["input"]["byte_length"])
    width, row_h, left, top = 1120, 42, 120, 24
    colors = {0: "#8b5cf6", 1: "#60a5fa", 2: "#34d399", 3: "#f59e0b", 10: "#fb7185"}
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{top + row_h * max(1, len(sections)) + 40}" viewBox="0 0 {width} {top + row_h * max(1, len(sections)) + 40}">',
             '<rect width="100%" height="100%" fill="#0f172a"/>',
             '<text x="16" y="18" fill="#e2e8f0" font-family="monospace">Section Map — stable section identity and zero-based byte spans</text>']
    for i, sec in enumerate(sections):
        data = sec["data"]
        y = top + i * row_h
        x0 = left + int(data["start"] / total * (width - left - 20))
        x1 = max(x0 + 3, left + int(data["end"] / total * (width - left - 20)))
        color = colors.get(data["section_id"], "#94a3b8")
        parts.append(f'<text x="12" y="{y+25}" fill="#cbd5e1" font-family="monospace" font-size="12">{sec["artifact_id"][:18]}… {data["name"]} #{data["order"]}</text>')
        parts.append(f'<line x1="{left}" y1="{y+30}" x2="{width-20}" y2="{y+30}" stroke="#1e293b"/>')
        parts.append(f'<rect data-stable-id="{sec["artifact_id"]}" x="{x0}" y="{y+13}" width="{max(2,x1-x0)}" height="18" rx="4" fill="{color}"/>')
        parts.append(f'<text x="{x1+6}" y="{y+27}" fill="#e2e8f0" font-family="monospace" font-size="11">[{data["start"]},{data["end"]}) size={data["size_value"]}</text>')
    parts.append('</svg>')
    return ''.join(parts)
