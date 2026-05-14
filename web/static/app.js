// 未知流量识别 — 前端单页逻辑
"use strict";

const $ = (id) => document.getElementById(id);

const PALETTE = [
  "#3b6cf2", "#1ca777", "#d97706", "#d33d4a", "#8e63f0",
  "#0ea5e9", "#84cc16", "#ec4899", "#facc15", "#64748b",
  "#06b6d4", "#f97316",
];

const PROGRESS_PCT = {
  "排队中": 5,
  "预处理中": 25,
  "Agent 推理中": 60,
  "合并中": 85,
  "生成可视化产物中": 92,
  "完成": 100,
};

const state = {
  taskId: null,
  pollTimer: null,
  dashboard: null,
};

document.addEventListener("DOMContentLoaded", () => {
  $("upload-form").addEventListener("submit", onSubmit);
  $("modal-close").addEventListener("click", closeModal);
  $("flow-modal").addEventListener("click", (e) => {
    if (e.target.id === "flow-modal") closeModal();
  });
  document.querySelectorAll(".tab-btn").forEach((btn) =>
    btn.addEventListener("click", () => switchTab(btn.dataset.tab))
  );
});

async function onSubmit(ev) {
  ev.preventDefault();
  const fileInput = $("pcap-file");
  if (!fileInput.files.length) return;

  resetForNewTask();

  const fd = new FormData();
  fd.append("file", fileInput.files[0]);
  fd.append("skip_agent", $("skip-agent").checked);
  fd.append("enable_viz", $("enable-viz").checked);

  $("upload-btn").disabled = true;
  $("progress-section").hidden = false;
  setProgress("上传中", 2);

  let resp;
  try {
    resp = await fetch("/api/upload", { method: "POST", body: fd });
  } catch (err) {
    showError(`上传失败：${err}`);
    return;
  }
  if (!resp.ok) {
    let msg = `上传失败 (HTTP ${resp.status})`;
    try {
      const body = await resp.json();
      if (body && body.detail) msg = body.detail;
    } catch (_) {}
    showError(msg);
    return;
  }
  const data = await resp.json();
  state.taskId = data.task_id;
  $("progress-meta").textContent = `任务 ID: ${data.task_id} · 文件: ${data.display_name} · ${formatBytes(data.size_bytes)}`;
  setProgress("排队中", PROGRESS_PCT["排队中"]);
  state.pollTimer = setInterval(poll, 1500);
}

function resetForNewTask() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = null;
  state.taskId = null;
  state.dashboard = null;
  $("dashboard").hidden = true;
}

async function poll() {
  if (!state.taskId) return;
  let resp;
  try {
    resp = await fetch(`/api/tasks/${state.taskId}`);
  } catch (err) {
    return;
  }
  if (!resp.ok) return;
  const data = await resp.json();
  const status = data.status;
  const msg = data.progress_msg || status;
  setProgress(msg, PROGRESS_PCT[msg] || 50);

  if (status === "success" && data.dashboard) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
    state.dashboard = data.dashboard;
    renderDashboard(data.dashboard);
    $("upload-btn").disabled = false;
  } else if (status === "failed") {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
    showError(data.error || "任务失败");
  }
}

function setProgress(text, pct) {
  $("progress-status").textContent = text;
  $("progress-bar-fill").style.width = `${pct}%`;
}

function showError(msg) {
  $("progress-status").textContent = "失败";
  $("progress-status").style.color = "var(--danger)";
  $("progress-meta").textContent = msg;
  $("progress-bar-fill").style.background = "var(--danger)";
  $("upload-btn").disabled = false;
}

function renderDashboard(d) {
  const headerName = d.pcap_name || "PCAP";
  $("page-title").textContent = `${headerName} 流量识别结果可视化`;
  const ts = formatTimestamp(d.timestamp);
  $("page-subtitle").textContent = `PCAP: ${headerName}${ts ? "  ·  处理时间: " + ts : ""}`;

  $("dashboard").hidden = false;
  renderAlerts(d);
  renderStats(d.stats);
  renderAppPie(d.by_app);
  renderUnknownTable(d.unknown_results, d.stats.unknown_count);
}

function renderAlerts(d) {
  const banner = $("alert-banner");
  const errors = d.errors || [];
  const s = d.stats || {};
  const items = [];

  if (s.unknown_count > 0 && s.agent_labeled_count !== undefined) {
    const cov = s.agent_coverage_pct ?? 0;
    if (s.agent_labeled_count === 0) {
      items.push(`Agent 未对任何未知流量给出有效决策 (0 / ${s.unknown_count})。可能原因：LLM 输出 JSON 不合法、flow_key 编造，或 Agent 未启用。`);
    } else if (cov < 100) {
      items.push(`Agent 仅覆盖 ${s.agent_labeled_count} / ${s.unknown_count} (${cov}%) 条未知流量；其余仍按 unknown_app:unknown 聚合。`);
    }
  }
  for (const e of errors) items.push(escapeHtml(e));

  if (!items.length) {
    banner.hidden = true;
    banner.innerHTML = "";
    return;
  }
  banner.hidden = false;
  banner.innerHTML = `<h3>处理过程中产生了警告</h3><ul>${items.map((t) => `<li>${t}</li>`).join("")}</ul>`;
}

function renderStats(s) {
  const row1 = [
    { label: "总流量", value: fmtNum(s.total_flows) },
    { label: "已知流量", value: fmtNum(s.known_count), sub: `${s.known_pct}%`, subClass: "green" },
    { label: "未知流量", value: fmtNum(s.unknown_count), sub: `${s.unknown_pct}%` },
    { label: "总字节数", value: fmtNum(s.total_bytes) },
    { label: "平均时长", value: s.avg_duration_sec.toFixed(2) },
    { label: "最大时长", value: s.max_duration_sec.toFixed(3) },
  ];
  const row2 = [
    { label: "唯一 APP", value: fmtNum(s.unique_apps) },
    { label: "唯一服务", value: fmtNum(s.unique_services) },
    { label: "nDPI 识别率", value: `${s.ndpi_recognition_rate}%` },
  ];
  $("stats-row-1").innerHTML = row1.map(statCard).join("");
  $("stats-row-2").innerHTML = row2.map(statCard).join("");
}

function statCard(c) {
  const sub = c.sub ? `<div class="stat-sub ${c.subClass || ""}">${c.sub}</div>` : "";
  return `<div class="stat-card"><div class="stat-label">${c.label}</div><div class="stat-value">${c.value}</div>${sub}</div>`;
}

function renderAppPie(byApp) {
  const labels = byApp.map((x) => x.app);
  const values = byApp.map((x) => x.count);
  const colors = labels.map((_, i) => PALETTE[i % PALETTE.length]);
  const data = [
    {
      type: "pie",
      labels,
      values,
      hole: 0.45,
      marker: { colors },
      textinfo: "none",
      hovertemplate: "<b>%{label}</b><br>数量: %{value}<br>占比: %{percent}<extra></extra>",
    },
  ];
  const layout = {
    showlegend: false,
    margin: { l: 8, r: 8, t: 8, b: 8 },
    height: 280,
  };
  Plotly.newPlot("app-pie-chart", data, layout, { displayModeBar: false, responsive: true });

  const legend = byApp
    .map(
      (x, i) => `<tr>
        <td><span class="swatch" style="background:${colors[i]}"></span>${escapeHtml(x.app)}</td>
        <td style="text-align:right">${fmtNum(x.count)}</td>
        <td style="text-align:right;color:var(--muted)">${x.pct}%</td>
      </tr>`
    )
    .join("");
  $("app-legend").innerHTML = legend;
}

function renderUnknownTable(rows, totalUnknown) {
  const tbody = $("unknown-table").querySelector("tbody");
  if (!rows || !rows.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty">无未知流量（或 Agent 未运行）</td></tr>`;
    return;
  }
  tbody.innerHTML = rows
    .map((r) => {
      const flowKeys = (r.flow_keys || []).join(",");
      const widthPx = Math.max(2, Math.round(r.pct));
      return `<tr data-flow-keys="${escapeHtml(flowKeys)}" data-label="${escapeHtml(r.label)}">
        <td class="label-cell">${escapeHtml(r.label)}</td>
        <td>${escapeHtml(r.app)}</td>
        <td>${escapeHtml(r.service_type)}</td>
        <td>${fmtNum(r.count)}</td>
        <td><span class="pct-bar" style="width:${widthPx * 1.6}px"></span>${r.pct}%</td>
      </tr>`;
    })
    .join("");
  tbody.querySelectorAll("tr").forEach((tr) => {
    tr.addEventListener("click", () => {
      const keys = (tr.dataset.flowKeys || "").split(",").filter(Boolean);
      if (!keys.length) return;
      // 多个 flow 共享同一 label 时，提供选择菜单（简单做法：弹一个二级列表）
      if (keys.length === 1) {
        openFlowDetail(keys[0]);
      } else {
        openFlowChooser(tr.dataset.label, keys);
      }
    });
  });
}

function openFlowChooser(label, keys) {
  // 简单实现：在 modal 概要 tab 里列出所有 flow_key 让用户点
  $("modal-flow-key").textContent = label;
  $("modal-summary").textContent = `该标签下共 ${keys.length} 条流，请选择一条查看详情`;
  $("pane-overview").innerHTML = `<div class="section-title">选择一条 flow</div>` +
    keys.map((k) => `<div><a href="#" data-flow-key="${escapeHtml(k)}">${escapeHtml(k)}</a></div>`).join("");
  $("pane-overview").querySelectorAll("a").forEach((a) =>
    a.addEventListener("click", (e) => {
      e.preventDefault();
      openFlowDetail(a.dataset.flowKey);
    })
  );
  $("pane-features").innerHTML = "";
  $("pane-trace").innerHTML = "";
  switchTab("overview");
  $("flow-modal").hidden = false;
}

async function openFlowDetail(flowKey) {
  $("flow-modal").hidden = false;
  $("modal-flow-key").textContent = flowKey;
  $("modal-summary").textContent = "加载中…";
  $("pane-overview").innerHTML = '<div class="empty">加载中…</div>';
  $("pane-features").innerHTML = "";
  $("pane-trace").innerHTML = "";
  switchTab("overview");

  let resp;
  try {
    resp = await fetch(`/api/tasks/${state.taskId}/flows/${encodeURIComponent(flowKey)}`);
  } catch (err) {
    $("pane-overview").innerHTML = `<div class="empty">请求失败：${escapeHtml(String(err))}</div>`;
    return;
  }
  if (!resp.ok) {
    $("pane-overview").innerHTML = `<div class="empty">请求失败：HTTP ${resp.status}</div>`;
    return;
  }
  const detail = await resp.json();
  renderModalHeader(detail);
  renderOverviewPane(detail);
  renderFeaturesPane(detail);
  renderTracePane(detail);
}

function renderModalHeader(d) {
  $("modal-flow-key").textContent = d.flow_key;
  const a = d.agent || {};
  const conf = (a.confidence ?? null) === null ? "—" : Number(a.confidence).toFixed(2);
  $("modal-summary").textContent =
    `final_label = ${a.final_label || "—"}   ·   confidence = ${conf}   ·   chunk 内序号 = ${d.flow_in_chunk_index ?? "—"}`;
}

function renderOverviewPane(d) {
  const a = d.agent || {};
  const evidence = a.evidence || [];
  const tt = a.tool_trace || {};
  const html = [];

  html.push(`<div class="section-title">判定理由</div>`);
  html.push(`<div style="font-size:13px;line-height:1.6;">${escapeHtml(a.reason || "—")}</div>`);

  html.push(`<div class="section-title">复合标签</div>`);
  html.push(`<table class="kv-table">
    <tr><td class="k">final_label</td><td class="v">${escapeHtml(a.final_label || "—")}</td></tr>
    <tr><td class="k">app</td><td class="v">${escapeHtml(a.app || "—")}</td></tr>
    <tr><td class="k">service_type</td><td class="v">${escapeHtml(a.service_type || "—")}</td></tr>
    <tr><td class="k">confidence</td><td class="v">${a.confidence ?? "—"}</td></tr>
  </table>`);

  if (evidence.length) {
    html.push(`<div class="section-title">证据</div>`);
    html.push(`<table class="kv-table"><thead><tr><td class="k">source</td><td class="k">value</td><td class="k">weight</td></tr></thead><tbody>`);
    for (const ev of evidence) {
      html.push(`<tr><td class="v">${escapeHtml(ev.source || "")}</td><td class="v">${escapeHtml(stringify(ev.value))}</td><td class="v">${ev.weight ?? ""}</td></tr>`);
    }
    html.push(`</tbody></table>`);
  }

  html.push(`<div class="section-title">工具调用快照 (tool_trace)</div>`);
  if (tt && Object.keys(tt).length) {
    html.push(`<pre class="code-block">${escapeHtml(JSON.stringify(tt, null, 2))}</pre>`);
  } else {
    html.push(`<div class="empty" style="text-align:left;padding:0;">— 无</div>`);
  }

  $("pane-overview").innerHTML = html.join("");
}

function renderFeaturesPane(d) {
  const f = d.flow || {};
  const s = f.stats || {};
  const html = [];

  html.push(`<div class="section-title">五元组 / 协议</div>`);
  html.push(`<table class="kv-table">
    <tr><td class="k">flow_key</td><td class="v">${escapeHtml(f.flow_key || "")}</td></tr>
    <tr><td class="k">transport</td><td class="v">${escapeHtml(f.transport || "")}</td></tr>
    <tr><td class="k">src</td><td class="v">${escapeHtml(f.src_ip || "")}:${f.src_port ?? ""}</td></tr>
    <tr><td class="k">dst</td><td class="v">${escapeHtml(f.dst_ip || "")}:${f.dst_port ?? ""}</td></tr>
    <tr><td class="k">proto_stack</td><td class="v">${escapeHtml(f.proto_stack || "")}</td></tr>
    <tr><td class="k">ndpi_app</td><td class="v">${escapeHtml(f.ndpi_app || "")}</td></tr>
    <tr><td class="k">is_encrypted</td><td class="v">${f.is_encrypted ? "yes" : "no"}</td></tr>
    <tr><td class="k">sni</td><td class="v">${escapeHtml(f.sni || "")}</td></tr>
  </table>`);

  html.push(`<div class="section-title">流统计 (stats)</div>`);
  html.push(`<table class="kv-table">
    <tr><td class="k">duration</td><td class="v">${fmtMaybe(s.duration)} s</td></tr>
    <tr><td class="k">total_bytes</td><td class="v">${fmtMaybe(s.total_bytes)}</td></tr>
    <tr><td class="k">c_to_s_bytes / packets</td><td class="v">${fmtMaybe(s.c_to_s_bytes)} / ${fmtMaybe(s.c_to_s_packets)}</td></tr>
    <tr><td class="k">s_to_c_bytes / packets</td><td class="v">${fmtMaybe(s.s_to_c_bytes)} / ${fmtMaybe(s.s_to_c_packets)}</td></tr>
    <tr><td class="k">data_ratio</td><td class="v">${fmtMaybe(s.data_ratio)}</td></tr>
    <tr><td class="k">start_ts → end_ts</td><td class="v">${fmtMaybe(s.start_ts)} → ${fmtMaybe(s.end_ts)}</td></tr>
    <tr><td class="k">flow_risk</td><td class="v">${escapeHtml(stringify(s.flow_risk))}</td></tr>
  </table>`);

  for (const subKey of ["tls", "dns", "http"]) {
    const sub = f[subKey];
    if (sub && Object.values(sub).some((v) => v && (Array.isArray(v) ? v.length : true))) {
      html.push(`<div class="section-title">${subKey.toUpperCase()}</div>`);
      html.push(`<pre class="code-block">${escapeHtml(JSON.stringify(sub, null, 2))}</pre>`);
    }
  }

  if (f.model_label || f.model_probability != null) {
    html.push(`<div class="section-title">分类模型预判 (ET-BERT)</div>`);
    html.push(`<table class="kv-table">
      <tr><td class="k">model_label</td><td class="v">${escapeHtml(f.model_label || "—")}</td></tr>
      <tr><td class="k">model_probability</td><td class="v">${fmtMaybe(f.model_probability)}</td></tr>
    </table>`);
  }

  html.push(`<div class="section-title">完整 flow JSON</div>`);
  html.push(`<pre class="code-block">${escapeHtml(JSON.stringify(f, null, 2))}</pre>`);

  $("pane-features").innerHTML = html.join("");
}

function renderTracePane(d) {
  const trace = d.agent_trace || {};
  const meta = trace.meta || {};
  const messages = trace.messages || [];
  const html = [];

  html.push(`<div class="section-title">Session</div>`);
  html.push(`<table class="kv-table">
    <tr><td class="k">session_key</td><td class="v">${escapeHtml(trace.session_key || "—")}</td></tr>
    <tr><td class="k">created_at</td><td class="v">${escapeHtml(meta.created_at || "—")}</td></tr>
    <tr><td class="k">updated_at</td><td class="v">${escapeHtml(meta.updated_at || "—")}</td></tr>
    <tr><td class="k">source_file</td><td class="v">${escapeHtml(meta.source_file || "—")}</td></tr>
    <tr><td class="k">truncated</td><td class="v">${trace.truncated ? "yes (超出 5MB 已截断)" : "no"}</td></tr>
  </table>`);

  html.push(`<div class="section-title">推理时间轴 (${messages.length} 条)</div>`);
  if (!messages.length) {
    html.push(`<div class="empty" style="text-align:left;padding:0;">— 无 (Agent 可能未运行或 session 文件缺失)</div>`);
  } else {
    html.push(`<div class="trace-list">`);
    for (let i = 0; i < messages.length; i++) {
      const m = messages[i];
      const role = m.role || "?";
      const cls = ["role-user", "role-assistant", "role-tool"].includes(`role-${role}`)
        ? `role-${role}`
        : "";
      html.push(`<div class="trace-item ${cls}">`);
      html.push(`<div class="trace-meta">
        <span class="trace-role">${escapeHtml(role)}</span>
        <span>#${i + 1}</span>
        ${m.timestamp ? `<span>${escapeHtml(m.timestamp)}</span>` : ""}
        ${m.tool_call_id ? `<span>tool_call_id=${escapeHtml(m.tool_call_id)}</span>` : ""}
      </div>`);
      html.push(`<div class="trace-content">${escapeHtml(m.content || "")}</div>`);
      if (m.reasoning_content) {
        html.push(`<button class="trace-toggle" data-target="reasoning-${i}">展开思考链</button>`);
        html.push(`<div class="trace-foldable" id="reasoning-${i}"><pre class="code-block">${escapeHtml(m.reasoning_content)}</pre></div>`);
      }
      if (m.tool_calls && m.tool_calls.length) {
        html.push(`<button class="trace-toggle" data-target="tools-${i}">展开工具调用 (${m.tool_calls.length})</button>`);
        html.push(`<div class="trace-foldable" id="tools-${i}"><pre class="code-block">${escapeHtml(JSON.stringify(m.tool_calls, null, 2))}</pre></div>`);
      }
      html.push(`</div>`);
    }
    html.push(`</div>`);
  }

  $("pane-trace").innerHTML = html.join("");
  $("pane-trace").querySelectorAll(".trace-toggle").forEach((btn) =>
    btn.addEventListener("click", () => {
      const target = $(btn.dataset.target);
      if (target) target.classList.toggle("open");
    })
  );
}

function switchTab(name) {
  document.querySelectorAll(".tab-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.tab === name)
  );
  document.querySelectorAll(".tab-pane").forEach((p) =>
    p.classList.toggle("active", p.dataset.pane === name)
  );
}

function closeModal() {
  $("flow-modal").hidden = true;
}

function fmtNum(n) {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  return Number(n).toLocaleString("en-US");
}
function fmtMaybe(v) {
  if (v === null || v === undefined) return "—";
  return String(v);
}
function stringify(v) {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function formatTimestamp(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function formatBytes(b) {
  if (!b) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(i ? 1 : 0)} ${units[i]}`;
}
