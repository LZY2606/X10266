import importlib
import os
from pathlib import Path

import pytest

import app.main as main_mod
from app.storage import ProjectStore, VirtualClock

SEED = 20260925
FIXED_TIME = "2026-09-25T00:00:00Z"
CASE_PATH = Path(__file__).resolve().parents[1] / "cases" / "module-boundary-court" / "case.json"


@pytest.fixture
def clock():
    return VirtualClock(FIXED_TIME)


@pytest.fixture
def store(tmp_path, clock):
    db = ProjectStore(str(tmp_path / "court.sqlite3"), clock)
    yield db
    db.close()


@pytest.fixture
def client(tmp_path, monkeypatch, clock):
    from fastapi.testclient import TestClient
    db_path = str(tmp_path / "api.sqlite3")
    monkeypatch.setenv("MODULE_COURT_DB", db_path)
    importlib.reload(main_mod)
    main_mod._clock = clock
    with TestClient(main_mod.app) as c:
        yield c


@pytest.fixture
def case_data():
    import json
    import random
    random.seed(SEED)
    return json.loads(CASE_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def replay(store, case_data):
    first = case_data["steps"][0]
    project = store.create_project(case_data["title"], "case-fixed", first["label"])
    store.submit_input(project["project_id"], bytes.fromhex(first["binary_hex"]), first["params"], first["label"], first["actor"])
    binary = bytes.fromhex(first["binary_hex"])
    for step in case_data["steps"][1:]:
        if step["kind"] == "parameter_adjustment":
            store.revise_params(project["project_id"], step["params"], step["label"], step["actor"], rationale="case")
        else:
            binary = bytes.fromhex(step["binary_hex"])
            store.submit_input(project["project_id"], binary, step["params"], step["label"], step["actor"], kind=step["kind"])
    return store, project["project_id"], case_data
