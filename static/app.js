let state = null;
let viewSeq = null;

const featureNames = ["multi_value", "reference_types", "tail_call", "simd"];
const $ = (id) => document.getElementById(id);

function api(path, options = {}) {
  return fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  }).then(async (response) => {
    const value = await response.json();
    if (!response.ok) throw new Error(value.detail || value.error || response.statusText);
    return value;
  });
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

function sid(value) {
  return `<span class="mono" title="${esc(value)}">${esc(value)}</span>`;
}

function range(r) {
  return Array.isArray(r) ? `[${r[0]}, ${r[1]}) byte` : "";
}

function initFeatures() {
  $("feature-grid").innerHTML = featureNames.map((name) =>
    `<label class="feature"><input type="checkbox" data-feature="${name}"> ${name}</label>`
  ).join("");
}

function currentConfig() {
  const features = {};
  document.querySelectorAll("[data-feature]").forEach((box) => { features[box.dataset.feature] = box.checked; });
  return {
    features,
    host_imports: JSON.parse($("host-imports").value),
    label: "reviewer parameter revision",
  };
}

async function refresh(seq = viewSeq) {
  const project = $("project-id").value.trim();
  const endpoint = `/api/projects/${encodeURIComponent(project)}${seq ? `?at_seq=${seq}` : ""}`;
  try {
    state = await api(endpoint);
    viewSeq = seq || state.at_seq;
    render();
  } catch (error) {
    $("project-title").textContent = error.message;
  }
}

function render() {
  if (!state) return;
  $("project-title").textContent = state.module_version?.label || "模块边界庭";
  renderEvents();
  renderSections();
  renderIndexes();
  renderFeaturesAndBasis();
  renderControl();
  renderFindings();
  renderCustomAndCells();
  const banner = $("view-banner");
  if (state.view_state === "historical") {
    banner.classList.remove("hidden");
    banner.textContent = `历史视图 @e${state.at_seq}：显示当时依赖版本与可见结论；接受/否定会在当前项目中生成新事件。`;
  } else {
    banner.classList.add("hidden");
  }
}

function renderEvents() {
  $("events").innerHTML = state.events.map((event) => {
    const payload = event.payload || {};
    const label = payload.label || payload.title || payload.rationale || payload.module_id || payload.config_id || "";
    return `<article class="event ${event.seq === state.at_seq ? "current" : ""}" data-seq="${event.seq}">
      <time>${esc(event.timestamp)}</time><div class="type">#${event.seq} ${esc(event.type)}</div>
      <div class="label">${esc(label)}</div><div class="sid">${sid(event.id)}</div>
    </article>`;
  }).join("");
  document.querySelectorAll(".event").forEach((node) => node.addEventListener("click", () => refresh(Number(node.dataset.seq))));
}

function renderSections() {
  const bars = state.section_map?.bars || [];
  $("section-map").innerHTML = bars.map((bar) => {
    const section = state.sections.find((s) => s.stable_id === bar.section_id);
    const bad = state.findings.some((f) => f.sources.includes(section.stable_id));
    return `<div class="bar-row">${sid(bar.stable_id)}
      <div class="bar-track"><div class="bar ${section.id === 0 ? "custom" : ""} ${bad ? "bad" : ""}" style="left:${bar.x}px;width:${bar.width}px"></div></div>
      <span>${esc(section.name)} ${range(section.raw_range)}</span></div>`;
  }).join("") || `<p class="muted">尚未导入模块。</p>`;
  $("section-table").innerHTML = table(
    ["stable_id", "ordinal", "id", "name", "id_range", "payload_range", "size LEB", "raw"],
    (state.sections || []).map((s) => ({
      stable_id: s.stable_id, ordinal: s.ordinal, id: s.id, name: s.name,
      id_range: range(s.id_range), payload_range: range(s.payload_range),
      "size LEB": `${s.size_leb.value} / canonical=${s.size_leb.canonical} / ${range([s.size_leb.start,s.size_leb.end])}`,
      raw: s.raw_hex,
    }))
  );
}

function renderIndexes() {
  $("index-table").innerHTML = table(
    ["stable_id", "index_space", "index", "origin", "type_index", "source_id"],
    state.index_table || []
  );
  $("import-table").innerHTML = table(
    ["stable_id", "module", "field", "kind", "type_index", "range"],
    (state.imports || []).map((x) => ({
      stable_id: x.stable_id, module: x.module.value, field: x.field.value, kind: x.kind,
      type_index: x.type_index, range: range(x.byte_range),
    }))
  );
}

function renderFeaturesAndBasis() {
  $("features").innerHTML = (state.feature_gates || []).map((f) =>
    `<span class="tag ${f.enabled ? "" : "off"}" data-stable-id="feature:${state.current_config_event_id || "none"}:${f.proposal}">
      ${f.proposal}=${f.enabled ? "enabled" : "disabled"}</span>`).join("");
  $("basis").innerHTML = (state.judgment_basis_events || []).map((b) =>
    `<div class="basis" data-stable-id="${esc(b.stable_id)}">
      <strong>${esc(b.rule_id)}</strong> ${sid(b.stable_id)}<br>
      <span class="muted">${esc(b.predicate)}</span><br>
      minimal: ${range(b.minimal_failure_byte_range)}<br>
      evidence: ${(b.evidence_source_ids || []).map(sid).join(" ")}
      <pre>${esc(JSON.stringify(b.classification, null, 2))}</pre>
    </div>`).join("");
}

function renderControl() {
  const rows = state.type_transitions || [];
  $("control-stack").innerHTML = table(
    ["stable_id", "fn", "opcode", "range", "before", "after", "control", "note"],
    rows.map((t) => ({
      stable_id: t.stable_id, fn: t.function_index, opcode: t.opcode, range: range(t.byte_range),
      before: t.before.join(","), after: t.after.join(","),
      control: (t.control_stack || []).map((f) => `${f.label}${f.unreachable ? "*" : ""}`).join(" > "),
      note: t.note,
    }))
  );
}

function findingClass(f) {
  if (f.accepted === true) return "accepted";
  if (f.accepted === false) return "rejected";
  return f.severity;
}

function renderFindings() {
  const findings = state.findings || [];
  $("findings").innerHTML = findings.map((f) => `<article class="finding ${findingClass(f)}" data-stable-id="${esc(f.stable_id)}">
    <h3><span class="tag ${f.severity}">${esc(f.code)}</span> ${esc(f.title)}</h3>
    ${sid(f.stable_id)}<p>${esc(f.rationale)}</p>
    <p><strong>最小失败范围：</strong>${range(f.minimal_failure_byte_range)}</p>
    <p><strong>来源：</strong>${(f.sources || []).map(sid).join(" ")}</p>
    ${f.unknown ? `<span class="tag unknown">unknown / needs decision</span>` : ""}
    ${f.accepted === true ? `<span class="tag accept">人工接受 @${esc(f.decision_event_id)}</span>` : ""}
    ${f.accepted === false ? `<span class="tag reject">人工否定 @${esc(f.decision_event_id)}</span>` : ""}
    ${f.conflicting_decisions ? `<p class="muted">冲突历史：${f.conflicting_decisions.map(sid).join(" ")}</p>` : ""}
    ${f.candidates?.length ? `<h4>全部合法候选</h4>${table(["stable_id","module","name","params","results"], f.candidates)}` : ""}
    ${f.rejected_reasons?.length ? `<h4>拒绝原因</h4>${table(["stable_id","reason"], f.rejected_reasons)}` : ""}
    <div class="actions"><button data-target="${esc(f.stable_id)}" data-accept="true">接受</button><button data-target="${esc(f.stable_id)}" data-accept="false">否定</button></div>
  </article>`).join("") || `<p class="muted">无候选或失败。</p>`;
  document.querySelectorAll("[data-target]").forEach((button) => button.addEventListener("click", async () => {
    const rationale = prompt("请输入裁定理由（会生成新的 decision 事件）", button.dataset.accept === "true" ? "accept via UI" : "reject via UI");
    if (rationale == null) return;
    await api(`/api/projects/${encodeURIComponent(state.project_id)}/decisions`, {
      method: "POST",
      body: { target_stable_id: button.dataset.target, accepted: button.dataset.accept === "true", rationale },
    });
    viewSeq = null;
    await refresh();
  }));
}

function renderCustomAndCells() {
  const custom = state.custom_sections?.sections || [];
  $("custom-sections").innerHTML = table(
    ["stable_id", "name", "raw_range", "payload_range", "raw_hex", "payload_hex"],
    custom.map((s) => ({
      stable_id: s.stable_id, name: s.custom?.name?.value, raw_range: range(s.raw_range),
      payload_range: range(s.custom?.payload_range), raw_hex: s.raw_hex, payload_hex: s.custom?.payload_hex,
    }))
  );
  $("cells").innerHTML = table(
    ["stable_id", "kind", "value", "range", "raw", "sources"],
    (state.cells || []).map((c) => ({
      stable_id: c.stable_id, kind: c.kind, value: typeof c.value === "object" ? JSON.stringify(c.value) : c.value,
      range: range(c.byte_range), raw: c.raw_representation, sources: (c.sources || []).join(" "),
    }))
  );
}

function table(columns, rows) {
  if (!rows?.length) return `<p class="muted">无记录</p>`;
  return `<table><thead><tr>${columns.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>
    ${rows.map((row) => `<tr>${columns.map((c) => {
      const value = row[c];
      if (c === "stable_id" || c === "source_id" || c === "sources") return `<td>${sid(value)}</td>`;
      if (Array.isArray(value) || (typeof value === "object" && value !== null)) return `<td class="mono">${esc(JSON.stringify(value))}</td>`;
      return `<td class="mono">${esc(value)}</td>`;
    }).join("")}</tr>`).join("")}</tbody></table>`;
}

$("create-project").addEventListener("click", async () => {
  await api("/api/projects", { method: "POST", body: { id: $("project-id").value, title: $("project-title-input").value } });
  await refresh();
});
$("submit-module").addEventListener("click", async () => {
  await api(`/api/projects/${encodeURIComponent($("project-id").value)}/modules`, {
    method: "POST",
    body: { base64: $("wasm-base64").value.trim(), label: $("module-label").value, timestamp: $("module-time").value || undefined },
  });
  await refresh();
});
$("submit-config").addEventListener("click", async () => {
  await api(`/api/projects/${encodeURIComponent($("project-id").value)}/configs`, {
    method: "POST", body: currentConfig(),
  });
  await refresh();
});
$("submit-decision").addEventListener("click", async () => {
  await api(`/api/projects/${encodeURIComponent($("project-id").value)}/decisions`, {
    method: "POST",
    body: {
      target_stable_id: $("decision-target").value,
      accepted: $("decision-choice").value === "true",
      rationale: $("decision-rationale").value,
    },
  });
  await refresh();
});
$("load-case").addEventListener("click", async () => {
  const result = await api("/api/casepack/load", { method: "POST" });
  $("project-id").value = result.project_id;
  viewSeq = null;
  await refresh();
});
$("export").addEventListener("click", async () => {
  const archive = await api(`/api/projects/${encodeURIComponent($("project-id").value)}/export`);
  $("archive-text").value = JSON.stringify(archive, null, 2);
  $("import-dialog").showModal();
});
$("wipe-import").addEventListener("click", () => $("import-dialog").showModal());
$("close-dialog").addEventListener("click", () => $("import-dialog").close());
$("copy-archive").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("archive-text").value);
});
$("dialog-import").addEventListener("click", async () => {
  const archive = JSON.parse($("archive-text").value);
  await api("/api/database/clear", { method: "POST" });
  const result = await api("/api/archive/import", { method: "POST", body: archive });
  $("project-id").value = result.project.id;
  viewSeq = null;
  $("import-dialog").close();
  await refresh();
});

initFeatures();
refresh();
