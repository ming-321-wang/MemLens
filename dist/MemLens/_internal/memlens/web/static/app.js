/* ═══════════════════════════════════════════════════════════════
   MemLens · 取证控制台 前端
   纯原生 JS（无构建步骤、无 CDN 依赖 → 完全离线可用）
   ═══════════════════════════════════════════════════════════════ */
'use strict';

const S = {
  caseId: null,
  caseInfo: null,
  profile: null,
  artifacts: [],
  findings: [],
  stats: {},
  cases: [],
  runId: null,
  ws: null,
  logLines: [],
  loaded: { timeline: false, intel: false },
  drawer: { artifactId: null, offset: 0, limit: 200, keyword: '', columns: [] },
};

const $ = (id) => document.getElementById(id);
/* ★ 产物/插件状态中文化 */
const STATUS_ZH = { ok: '成功', partial: '部分', failed: '失败',
  cancelled: '已取消', running: '运行中', pending: '等待',
  skipped: '跳过', error: '错误' };
function stZh(s) { return STATUS_ZH[s] || s || '?'; }

const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
};
const esc = (s) => String(s === null || s === undefined ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/* ───────────── 通用请求 ───────────── */
async function api(path, opts = {}) {
  // ★ 超时 + 一次重试：后端卡住时前端不能无限等（用户感知就是"打不开"）
  const attempts = opts.retries === undefined ? 1 : opts.retries;
  let lastErr = null;
  for (let i = 0; i <= attempts; i++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), opts.timeout || 20000);
    try {
      const r = await fetch(path, {
        headers: { 'Content-Type': 'application/json' },
        signal: ctrl.signal,
        ...opts,
        body: opts.body ? JSON.stringify(opts.body) : undefined,
      });
      clearTimeout(timer);
      if (!r.ok) {
        let detail = r.statusText;
        try { detail = (await r.json()).detail || detail; } catch (e) { }
        throw new Error(detail);
      }
      return await r.json();
    } catch (e) {
      clearTimeout(timer);
      lastErr = e;
      if (i < attempts) await new Promise(r => setTimeout(r, 400));
    }
  }
  throw lastErr;
}

let toastTimer = null;
function toast(msg, kind = '') {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast ' + kind;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 4200);
}

function fmtBytes(n) {
  n = Number(n || 0);
  if (n <= 0) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(2)) + ' ' + u[i];
}
function fmtDur(ms) {
  ms = Number(ms || 0);
  if (!ms) return '—';
  if (ms < 1000) return ms + ' ms';
  if (ms < 60000) return (ms / 1000).toFixed(1) + ' s';
  return Math.floor(ms / 60000) + 'm' + Math.round((ms % 60000) / 1000) + 's';
}
function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  if (isNaN(d.getTime())) return String(ts);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function fmtCell(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

/* ═════════════════════ 启动 ═════════════════════ */
async function boot() {
  bindUI();
  if (typeof initV2 === 'function') initV2();   // ★ UI v2（向导/控制台/状态栏）
  const t0 = performance.now();
  // ★ 并行：health 与 cases 同时发，别串行等
  const [health, cases] = await Promise.allSettled([
    api('/api/health', { retries: 2 }),
    api('/api/cases', { retries: 2 }),
  ]);
  if (health.status === 'fulfilled') {
    const h = health.value;
    $('dbText').textContent = h.database.backend.toUpperCase();
    $('dbBadge').title = `数据库：${h.database.backend}\n${h.database.url}`;
    const dots = $('engineDots');
    dots.innerHTML = '';
    (h.engines || []).forEach(e => {
      const i = el('i', e.available ? 'ok' : 'bad');
      i.title = `${e.display}：${e.detail}`;
      dots.appendChild(i);
    });
  } else {
    toast('后端连接失败：' + health.reason.message, 'err');
    $('dbText').textContent = '离线';
  }
  if (cases.status === 'fulfilled') {
    await refreshCases(cases.value);
  } else {
    toast('案件库读取失败：' + cases.reason.message, 'err');
  }
  connectLog();
  console.log(`[MemLens] 首屏 ${(performance.now() - t0).toFixed(0)}ms`);

  // ★ 启动器会带 `#open=<证据路径>` 打开页面（拖 exe / 命令行传文件）
  const m = location.hash.match(/#open=(.+)$/);
  if (m) {
    const p = decodeURIComponent(m[1]);
    log('启动器请求打开：' + p, 'step');
    setTimeout(() => doOpen(p), 300);
  }
}

/** 页签切换：重数据（时间线/情报）改为**懒加载**，首屏不再等它们。 */
function showTab(name) {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
  const tab = document.querySelector(`.tab[data-tab="${name}"]`);
  if (tab) tab.classList.add('active');
  const panel = $('panel-' + name);
  if (panel) panel.classList.add('active');
  if (name === 'timeline' && !S.loaded.timeline) { S.loaded.timeline = true; loadTimeline(); }
  if (name === 'intel' && !S.loaded.intel) { S.loaded.intel = true; loadIntel(); }
  if (name === 'artifacts') renderArtifacts();
  if (name === 'compliance') { loadRulepack(); loadAudit(); loadGaps(); }
  if (typeof navSyncActive === 'function') navSyncActive(name);   // ★ v3 导航同步
}

function bindUI() {
  document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => showTab(t.dataset.tab));
  });
  $('btnOpen').addEventListener('click', openFsModal);
  $('fsClose').addEventListener('click', () => $('fsModal').classList.add('hidden'));
  $('fsGo').addEventListener('click', () => fsList($('fsPath').value));
  $('fsPath').addEventListener('keydown', e => { if (e.key === 'Enter') fsList($('fsPath').value); });
  $('fsPickBtn').addEventListener('click', () => doOpen($('fsPick').value));

  $('btnAnalyze').addEventListener('click', startAnalysis);
  $('btnCancel').addEventListener('click', cancelAnalysis);
  $('btnReport').addEventListener('click', () => {
    if (!S.caseId) return;
    window.open(`/api/cases/${S.caseId}/report?fmt=html`, '_blank');
  });

  $('artifactFilter').addEventListener('input', renderArtifacts);
  $('artifactStatus').addEventListener('change', renderArtifacts);
  $('btnExportAll').addEventListener('click', () => {
    if (!S.caseId) return;
    window.location = `/api/cases/${S.caseId}/export/all.csv`;
  });

  $('timelineKeyword').addEventListener('input', debounce(loadTimeline, 320));
  $('timelineCategory').addEventListener('change', loadTimeline);
  $('timelineOrder').addEventListener('change', loadTimeline);

  $('findingSeverity').addEventListener('change', renderFindings);
  $('tabIoc').addEventListener('click', () => {
    $('tabIoc').classList.add('active'); $('tabDict').classList.remove('active');
    $('iocTable').classList.remove('hidden'); $('dictTableWrap').classList.add('hidden');
  });
  $('tabDict').addEventListener('click', () => {
    $('tabDict').classList.add('active'); $('tabIoc').classList.remove('active');
    $('dictTableWrap').classList.remove('hidden'); $('iocTable').classList.add('hidden');
  });

  $('btnClearLog').addEventListener('click', () => { S.logLines = []; $('logBox').innerHTML = ''; });
  $('drawerClose').addEventListener('click', closeDrawer);
  $('drawerSearch').addEventListener('input', debounce(() => {
    S.drawer.keyword = $('drawerSearch').value; S.drawer.offset = 0; loadRecords();
  }, 300));
  $('drawerExport').addEventListener('click', () => {
    if (S.drawer.artifactId) window.location = `/api/cases/${S.caseId}/export/${S.drawer.artifactId}.csv`;
  });
  $('pagePrev').addEventListener('click', () => {
    S.drawer.offset = Math.max(0, S.drawer.offset - S.drawer.limit); loadRecords();
  });
  $('pageNext').addEventListener('click', () => {
    S.drawer.offset += S.drawer.limit; loadRecords();
  });

  /* ── 工具箱（按需功能：点按钮才执行） ── */
  bindTools();

  /* ── 文件详情模态（未知/失败产物点得进去） ── */
  $('fmClose').addEventListener('click', closeFileModal);
  $('fmCopyPath').addEventListener('click', () => {
    if (S.fileModal && S.fileModal.path) copy(S.fileModal.path);
  });
  $('fmExportRaw').addEventListener('click', () => {
    if (!S.fileModal || S.fileModal.exported) return;
    const blob = new Blob([S.fileModal.raw_output || '(无原始输出)'], {type: 'text/plain'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `raw_${S.fileModal.plugin || S.fileModal.caseId}.txt`;
    a.click(); URL.revokeObjectURL(a.href);
    S.fileModal.exported = true;
  });
  $('fmRunStatic').addEventListener('click', () => triggerTool('flag'));
  $('fileModal').addEventListener('click', (e) => { if (e.target === $('fileModal')) closeFileModal(); });

  /* ── 合规：规则包 / 审计 / 缺口 ── */
  $('btnRpImport').addEventListener('click', async () => {
    const path = $('rpPath').value.trim();
    if (!path) { toast('请先填写离线规则包 JSON 的绝对路径', 'err'); return; }
    try {
      await api('/api/rulepack/import', { method: 'POST', body: { path, activate: true } });
      toast('规则包已导入并激活', 'ok');
      log('规则包导入并激活：' + path, 'step');
      loadRulepack();
    } catch (e) { toast('导入失败：' + e.message, 'err'); }
  });
  $('btnRpReload').addEventListener('click', loadRulepack);
  $('btnAuditVerify').addEventListener('click', async () => {
    try {
      const d = await api(`/api/cases/${S.caseId}/audit?limit=1`);
      const c = d.chain || {};
      toast(c.ok ? '哈希链完整' : '⚠ 哈希链断裂', c.ok ? 'ok' : 'err');
      log('审计链校验：' + (c.detail || ''), c.ok ? 'ok' : 'err');
    } catch (e) { toast('校验失败：' + e.message, 'err'); }
  });
  $('auditCriticalOnly').addEventListener('change', loadAudit);

  /* ── 五维判定 ── */
  $('btnDimRun').addEventListener('click', runDimensions);
  bindMountUI();
}

/* ═══════════════════════════════════════════════════════════════════════
   镜像挂载页（新增）：打开镜像 → 卷列表 → 文件树 → 读 / 提取 / 雕刻
   ═══════════════════════════════════════════════════════════════════════ */
let S_mount = { mid: null, vols: [] };

function mlog(msg) {
  const box = $('mountLog');
  if (!box) return;
  box.textContent = (box.textContent ? box.textContent + '\n' : '') + msg;
  box.scrollTop = box.scrollHeight;
}

function bindMountUI() {
  const on = (id, fn) => { const n = $(id); if (n) n.addEventListener('click', fn); };
  on('btnMountOpen', mountOpen);
  on('btnMountTree', mountTree);
  on('btnMountCarve', mountCarve);
  on('btnMountHash', mountHash);
  on('btnMountSearch', mountSearch);
  on('btnMountReg', mountRegister);
  const p = $('mountPath');
  if (p) p.addEventListener('keydown', e => { if (e.key === 'Enter') mountOpen(); });
  const s = $('mountSearchKw');
  if (s) s.addEventListener('keydown', e => { if (e.key === 'Enter') mountSearch(); });
}

async function mountRegister() {
  const path = $('mountPath').value.trim();
  if (!path) { toast('先填镜像路径', 'err'); return; }
  const pw = $('mountPw').value;
  $('mountVolMeta').textContent = '登记中…';
  try {
    const r = await api('/api/evidence', { method: 'POST', body: { path, password: pw }, timeout: 300000 });
    mlog(`登记证据 #${r.id} → SHA256 ${(r.hashes && r.hashes.sha256 || '').slice(0, 16)}…`);
    toast('已登记证据 #' + r.id, 'ok');
  } catch (e) { toast('登记失败：' + e.message, 'err'); }
  $('mountVolMeta').textContent = $('mountVolMeta').textContent.replace('登记中…', '');
}

async function mountSearch() {
  if (!S_mount.mid) return;
  const vol = parseInt($('mountVolSel').value || '0', 10);
  const kw = $('mountSearchKw').value.trim();
  if (!kw) { toast('输入关键词', 'err'); return; }
  $('mountSearchMeta').textContent = '搜索中…';
  try {
    const r = await api(`/api/mount/${S_mount.mid}/search?vol=${vol}&keyword=${encodeURIComponent(kw)}&limit=200`, { timeout: 120000 });
    const tb = $('mountSearchTable').querySelector('tbody');
    tb.innerHTML = '';
    (r.hits || []).forEach(h => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${h.offset}</td><td>${h.enc}</td><td style="word-break:break-all">${esc(h.context)}</td>`;
      tb.appendChild(tr);
    });
    $('mountSearchWrap').style.display = '';
    $('mountSearchMeta').textContent = `${r.count} 个命中`;
    mlog(`检索「${kw}」：${r.count} 个命中`);
  } catch (e) { toast('检索失败：' + e.message, 'err'); }
  $('mountSearchMeta').textContent = $('mountSearchMeta').textContent.replace('搜索中…', '');
}

async function mountOpen() {
  const path = $('mountPath').value.trim();
  if (!path) { toast('先填镜像路径', 'err'); return; }
  const pw = $('mountPw').value;
  $('mountMeta').textContent = '打开中…';
  try {
    const r = await api('/api/mount/open', { method: 'POST', body: { path, password: pw }, timeout: 300000 });
    S_mount.mid = r.id; S_mount.vols = r.volumes || [];
    $('mountMeta').textContent = `已挂载：${r.kind} · ${r.volumes.length} 卷 · ${fmtBytes(r.size)}`;
    mlog(`挂载 ${path} → ${r.kind}（${r.volumes.length} 卷）`);
    (r.notes || []).forEach(n => mlog('· ' + n));
    // 卷选择器
    const sel = $('mountVolSel');
    sel.innerHTML = '';
    S_mount.vols.forEach(v => {
      const o = document.createElement('option');
      o.value = v.index;
      o.textContent = `卷${v.index} · ${v.fs} · ${fmtBytes(v.size)}`;
      sel.appendChild(o);
    });
    $('mountToolbar').style.display = '';
    $('mountSearchBar').style.display = '';
    mountTree();
  } catch (e) { toast('打开失败：' + e.message, 'err'); mlog('✗ ' + e.message); }
  $('mountMeta').textContent = $('mountMeta').textContent.replace('打开中…', '');
}

async function mountTree() {
  if (!S_mount.mid) return;
  const vol = parseInt($('mountVolSel').value || '1', 10);
  const filt = ($('mountPathFilter').value || '').toLowerCase();
  $('mountVolMeta').textContent = '列目录…';
  try {
    const r = await api(`/api/mount/${S_mount.mid}/tree?vol=${vol}&limit=3000`, { timeout: 60000 });
    $('mountVolMeta').textContent = `${r.fs} · ${r.tree.length} 项`;
    const tb = $('mountTable').querySelector('tbody');
    tb.innerHTML = '';
    r.tree.forEach(it => {
      if (filt && !it.path.toLowerCase().includes(filt)) return;
      const tr = document.createElement('tr');
      const kind = it.dir ? '目录' : fmtBytes(it.size || 0);
      const del = it.deleted ? '<span style="color:#e67e22">已删除</span>' : '';
      const btn = it.dir ? '' : `<button class="btn sm" data-mpath="${encodeURIComponent(it.path)}">读</button>`;
      tr.innerHTML = `<td>${esc(it.path)}</td><td>${kind}</td><td>${del}</td><td>${btn}</td>`;
      const b = tr.querySelector('[data-mpath]');
      if (b) b.addEventListener('click', () => mountRead(vol, it.path));
      tb.appendChild(tr);
    });
  } catch (e) { toast('列目录失败：' + e.message, 'err'); }
  $('mountVolMeta').textContent = $('mountVolMeta').textContent.replace('列目录…', '');
}

async function mountRead(vol, path) {
  try {
    const r = await fetch(`/api/mount/${S_mount.mid}/read?vol=${vol}&path=${encodeURIComponent(path)}`);
    if (!r.ok) { toast('读取失败：' + r.statusText, 'err'); return; }
    const buf = await r.arrayBuffer();
    const blob = new Blob([buf]);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = path.split('/').pop() || 'file';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    mlog(`读取 ${path}（${fmtBytes(buf.byteLength)}）`);
  } catch (e) { toast('读取失败：' + e.message, 'err'); }
}

async function mountCarve() {
  if (!S_mount.mid) return;
  const vol = parseInt($('mountVolSel').value || '1', 10);
  const rules = $('mountCarveRules').value.trim();
  $('mountVolMeta').textContent = '雕刻中…';
  try {
    const r = await api(`/api/mount/${S_mount.mid}/carve`, { method: 'POST', body: { vol, rules }, timeout: 120000 });
    const tb = $('mountCarveTable').querySelector('tbody');
    tb.innerHTML = '';
    (r.hits || []).forEach(h => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${h.rule}</td><td>${h.start}</td><td>${h.end}</td><td>${h.size}</td><td>${h.note}</td>`;
      tb.appendChild(tr);
    });
    $('mountCarveWrap').style.display = '';
    mlog(`雕刻：${r.count} 个命中`);
  } catch (e) { toast('雕刻失败：' + e.message, 'err'); }
  $('mountVolMeta').textContent = $('mountVolMeta').textContent.replace('雕刻中…', '');
}

async function mountHash() {
  const path = $('mountPath').value.trim();
  if (!path) { toast('先填镜像路径', 'err'); return; }
  $('mountMeta').textContent = '哈希中…';
  try {
    const r = await api('/api/hash', { method: 'POST', body: { path }, timeout: 300000 });
    mlog('哈希 ' + path);
    Object.entries(r).forEach(([a, v]) => mlog(`  ${a.toUpperCase()}  ${v}`));
    toast('哈希完成', 'ok');
  } catch (e) { toast('哈希失败：' + e.message, 'err'); }
  $('mountMeta').textContent = $('mountMeta').textContent.replace('哈希中…', '');
}

function debounce(fn, ms) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

/* ═════════════════════ 案件 ═════════════════════ */
async function refreshCases(prefetched) {
  const d = prefetched || await api('/api/cases');
  S.cases = d.cases || [];        // ★ 供载入向导「最近打开的证据」复用
  const list = $('caseList');
  list.innerHTML = '';
  $('caseCount').textContent = d.cases.length;
  /* 「完整分析信息」展开区（插入到案件列表下方，跟随当前选中案件） */
  let box = $('caseDetail');
  if (!box) {
    box = el('div', 'case-detail hidden');
    box.id = 'caseDetail';
    const side = list.closest('.side-section');
    side ? side.insertBefore(box, side.querySelector('.phase-list')) : list.parentNode.insertBefore(box, list.nextSibling);
  }
  d.cases.forEach(c => {
    const it = el('div', 'case-item' + (c.case_id === S.caseId ? ' active' : ''));
    it.dataset.cid = c.case_id;
    it.appendChild(el('div', 'ci-name', c.name || c.case_id));
    it.appendChild(el('div', 'ci-meta', `${c.os_type || '?'} / ${c.container || '?'} · ${fmtBytes(c.image_size)}`));
    it.addEventListener('click', () => selectCase(c.case_id));
    /* ★ 双击 = 选中 + 展开完整分析信息（用户可自己分辨这个文件是什么） */
    it.addEventListener('dblclick', () => { caseDetailOpen = true; selectCase(c.case_id); });
    const btn = el('button', 'btn sm cd-toggle', '详情');
    btn.title = '查看该案件的完整分析信息';
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      caseDetailOpen = !caseDetailOpen;
      selectCase(c.case_id);
    });
    it.appendChild(btn);
    list.appendChild(it);
  });
  if (!S.caseId && d.cases.length) selectCase(d.cases[0].case_id);
  renderCaseDetail();
}

async function selectCase(id) {
  S.caseId = id;
  // 侧栏列表不必等详情（详情要拉 artifacts/findings，可能上百 KB）
  markActiveCase(id);
  caseDetailOpen = true;        // ★ 点击案件库条目 = 选中 + 输出该案件完整分析信息
  const d = await api('/api/cases/' + id, { timeout: 30000 });
  S.caseInfo = d.case;
  S.profile = d.profile;
  S.artifacts = d.artifacts || [];
  S.findings = d.findings || [];
  S.stats = d.stats || {};
  S.verdict = d.verdict || null;
  $('caseName').textContent = (d.case.name || id) + '  ·  ' + (d.case.os_type || '?');
  $('btnAnalyze').disabled = false;
  $('btnReport').disabled = false;
  setToolButtons(true);          // 案件存在 → 工具按钮可用
  renderSysInfo();
  renderAll();
  loadGaps();                    // ★ 缺口清单（概览卡片 + 合规页）
  loadDimensions();              // ★ 五维判定结果（有缓存则显示）
  connectCaseWS(id);
  renderCaseDetail();            // ★ 侧栏下方输出"案件完整分析信息"
  // ── UI v2：切换案件后刷新分组角标 + 降级提示 ──
  if (typeof renderAnalysisGroups === 'function') renderAnalysisGroups();
  if (typeof renderDegradeNotice === 'function') renderDegradeNotice();
  if (typeof sbPhase === 'function') sbPhase('已载入 ' + (d.case.name || id));
  log(`已载入案件 ${d.case.name || id}：产物 ${S.artifacts.length} 个 · `
    + `发现项 ${S.findings.length} 个 · ${d.case.os_type || '?'}`, 'step');
}

/* 案件库：当前选中案件的完整分析信息（可展开/收起） */
let caseDetailOpen = false;
function renderCaseDetail() {
  let box = $('caseDetail');
  if (!box) {
    box = el('div', 'case-detail hidden');
    box.id = 'caseDetail';
    const list = $('caseList');
    list.parentNode.insertBefore(box, list.nextSibling);
  }
  box.classList.toggle('hidden', !caseDetailOpen);
  if (!caseDetailOpen) return;
  const c = S.caseInfo || {};
  const st = S.stats || {};
  const sev = st.findings_by_severity || {};
  box.innerHTML = '';
  const hd = el('div', 'cd-title');
  hd.appendChild(el('span', '', '📋 案件完整分析信息'));
  const cl = el('button', 'cd-close', '×');
  cl.title = '收起';
  cl.addEventListener('click', () => { caseDetailOpen = false; box.classList.add('hidden'); });
  hd.appendChild(cl);
  box.appendChild(hd);
  const rows = [
    ['案件 ID', c.case_id],
    ['证据文件', c.image_path],
    ['文件大小', fmtBytes(c.image_size)],
    ['SHA-256', c.image_sha256 || '—'],
    ['容器格式', c.container || '—'],
    ['操作系统', (c.os_type || '—') + '（置信度 ' + Math.round((c.os_confidence || 0) * 100) + '%）'],
    ['分析状态', c.state || '—'],
    ['产物 / 记录', `${st.artifacts || 0} / ${st.records || 0}`],
    ['发现项', `${st.findings || 0}（critical/high ${sev.critical || 0}/${sev.high || 0}，medium ${sev.medium || 0}）`],
    ['IOC / 旗标', `${st.iocs || 0} / ${st.flags || 0}`],
    ['创建时间', c.created_at || '—'],
  ];
  const tb = el('table', 'kv'); const tbody = el('tbody');
  rows.forEach(([k, v]) => {
    const tr = el('tr');
    tr.appendChild(el('th', '', k));
    tr.appendChild(el('td', '', (v === null || v === undefined || v === '') ? '—' : v));
    tbody.appendChild(tr);
  });
  tb.appendChild(tbody);
  box.appendChild(tb);
  /* 产物清单（每个产物可点进记录抽屉） */
  const arts = S.artifacts || [];
  if (arts.length) {
    box.appendChild(el('div', 'cd-sub', `产物清单（${arts.length} 个，点击行查看记录）`));
    const at = el('table', 'data');
    at.innerHTML = '<thead><tr><th>引擎</th><th>产物</th><th>状态</th><th class="num">行数</th></tr></thead>';
    const ab = el('tbody');
    arts.forEach(a => {
      const tr = el('tr', 'clickable');
      tr.appendChild(el('td', '', a.engine));
      tr.appendChild(el('td', '', a.plugin));
      tr.appendChild(el('td', '', stZh(a.status)));
      tr.appendChild(el('td', 'num', (a.row_count || 0).toLocaleString()));
      tr.addEventListener('click', () => openDrawer(a));
      ab.appendChild(tr);
    });
    at.appendChild(ab);
    box.appendChild(at);
  }
}

/* 机器信息卡：把当前案件的系统画像渲染到「工具」页 */
function renderSysInfo() {
  const body = $('sysBody');
  const p = S.profile || {};
  const fields = p.profile_json || p.fields || {};
  const entries = Object.entries(fields || {});
  if (!entries.length) {
    body.innerHTML = '<div class="empty">尚未生成系统画像 —— 完成深度分析后这里会显示可重取的机器信息。</div>';
    $('sysMeta').textContent = '—';
    return;
  }
  body.innerHTML = '';
  const grid = el('div', 'pg-grid');
  entries.slice(0, 24).forEach(([k, v]) => {
    const box = el('div', 'pf');
    let val = v.value;
    if (typeof val === 'number' && k.endsWith('_bytes')) val = fmtBytes(val);
    box.appendChild(el('div', 'pf-lab', v.label || k));
    const d = el('div', 'pf-val' + (typeof val === 'string' && val.length > 26 ? ' txt' : ''), String(val));
    if (typeof val === 'string' && val.length > 26) d.title = val;
    box.appendChild(d);
    grid.appendChild(box);
  });
  body.appendChild(grid);
  $('sysMeta').textContent = `${entries.length} 个字段（最近提取：${S.caseInfo && S.caseInfo.state || '—'}）`;
}

function markActiveCase(id) {
  document.querySelectorAll('.case-item').forEach(n => {
    n.classList.toggle('active', n.dataset.cid === id);
  });
}

function renderAll() {
  renderKpi();
  renderVerdict();
  renderProfile();
  renderCaseInfo();
  renderSysInfo();
  renderFindings();
  renderArtifacts();
  renderUsers();
  renderFlags();
  // ★ 时间线 / 情报改为懒加载（切到那个页签才拉）——首屏不再等它们
  S.loaded.timeline = false;
  S.loaded.intel = false;
}

/* ───────────── 结论速览（一页纸） ───────────── */
function renderVerdict() {
  const body = $('verdictBody');
  const v = S.verdict || null;
  if (!v || v.error) {
    body.innerHTML = '<div class="empty">分析完成后，这里会给出「一句话结论 + 旗标候选 + 关键事实 + 下一步建议」。</div>';
    $('verdictMeta').textContent = v && v.error ? ('生成失败：' + v.error) : '—';
    return;
  }
  body.innerHTML = '';
  body.appendChild(el('div', 'verdict-headline', v.headline || ''));

  if ((v.flags || []).length) {
    const box = el('div', 'verdict-flags');
    v.flags.slice(0, 8).forEach(f => {
      const row = el('div', 'verdict-flag');
      row.appendChild(el('code', '', f.value || ''));
      row.appendChild(el('span', 'muted',
        '  ' + (f.kind || '') + (f.offset_hex ? '  @' + f.offset_hex : '') +
        ((f.sources || []).length ? '  ← ' + f.sources.join(',') : '')));
      box.appendChild(row);
    });
    body.appendChild(box);
  }

  if ((v.key_facts || []).length) {
    const tb = el('table', 'kv');
    const tbody = el('tbody');
    v.key_facts.forEach(r => {
      const tr = el('tr');
      tr.appendChild(el('th', '', r.k || ''));
      tr.appendChild(el('td', '', r.v === undefined || r.v === null ? '—' : String(r.v)));
      tbody.appendChild(tr);
    });
    tb.appendChild(tbody);
    body.appendChild(tb);
  }

  if ((v.next_steps || []).length) {
    const wrap = el('div', 'verdict-steps');
    v.next_steps.forEach(s => wrap.appendChild(el('div', 'step', s)));
    body.appendChild(wrap);
  }
  const n = (v.top_findings || []).length;
  $('verdictMeta').textContent = n ? (n + ' 条重点发现') : '无重点发现';
}

function renderKpi() {
  const st = S.stats || {};
  const sev = st.findings_by_severity || {};
  const row = $('kpiRow');
  row.innerHTML = '';
  const items = [
    ['产物', st.artifacts || 0, ''],
    ['记录', st.records || 0, ''],
    ['发现项', st.findings || 0, sev.critical || sev.high ? 'crit' : (sev.medium ? 'med' : 'ok')],
    ['时间线', st.timeline || 0, ''],
    ['IOC', st.iocs || 0, ''],
    ['词典命中', st.dict_hits || 0, ''],
    ['旗标', st.flags || 0, st.flags ? 'high' : ''],
  ];
  items.forEach(([lab, val, cls]) => {
    const k = el('div', 'kpi ' + cls);
    k.appendChild(el('div', 'k-val', val));
    k.appendChild(el('div', 'k-lab', lab));
    row.appendChild(k);
  });
  $('pillFindings').textContent = st.findings || 0;
  $('pillFlags').textContent = st.flags || 0;
  if (typeof syncNavBadges === 'function') syncNavBadges();   // ★ v3 导航角标
  if (typeof syncNavBadges === 'function') syncNavBadges();
}

/* ───────────── 系统画像 ───────────── */
function renderProfile() {
  const body = $('profileBody');
  body.innerHTML = '';
  const p = S.profile || {};
  const fields = p.profile_json || p.fields || {};
  const entries = Object.entries(fields);
  if (!entries.length) {
    body.innerHTML = '<div class="empty">尚未生成系统画像 —— 点击「深度分析」后这里会显示操作系统版本、'
      + '物理内存大小、CPU、开机时间、用户与 SID 等信息。</div>';
    $('profileMeta').textContent = '—';
    return;
  }
  const groups = {};
  entries.forEach(([k, v]) => {
    const g = (v && v.group) || '其它';
    (groups[g] = groups[g] || []).push([k, v]);
  });
  const order = ['系统', '硬件', '标识', '时间', '其它'];
  Object.keys(groups).sort((a, b) => order.indexOf(a) - order.indexOf(b)).forEach(g => {
    const gd = el('div', 'profile-group');
    gd.appendChild(el('div', 'pg-title', g));
    const grid = el('div', 'pg-grid');
    groups[g].forEach(([k, v]) => {
      const box = el('div', 'pf' + (v.alternatives && v.alternatives.length ? ' multi' : ''));
      box.appendChild(el('div', 'pf-lab', v.label || k));
      let val = v.value;
      if (k.endsWith('_bytes') && typeof val === 'number') {
        val = fmtBytes(val) + '（' + val.toLocaleString() + ' B）';
        box.appendChild(el('div', 'pf-val', val));
      } else {
        const isText = typeof val === 'string' && val.length > 26;
        const d = el('div', 'pf-val' + (isText ? ' txt' : ''), val);
        if (isText) d.title = val;
        box.appendChild(d);
      }
      const src = el('div', 'pf-src');
      src.appendChild(el('span', '', '来源：' + (v.source || '—')));
      box.appendChild(src);
      const conf = el('div', 'conf');
      const bar = el('i');
      bar.style.width = Math.round((v.confidence || 0) * 100) + '%';
      conf.appendChild(bar);
      box.appendChild(conf);
      if (v.alternatives && v.alternatives.length) {
        box.title = '其它来源取值：' + v.alternatives.map(a => `${a.value}（${a.source}）`).join('；');
      }
      grid.appendChild(box);
    });
    gd.appendChild(grid);
    body.appendChild(gd);
  });
  $('profileMeta').textContent = `${entries.length} 个字段`;
}

/* ───────────── 案件信息 ───────────── */
function renderCaseInfo() {
  const c = S.caseInfo || {};
  const tb = $('caseInfo').querySelector('tbody');
  tb.innerHTML = '';
  const rows = [
    ['案件 ID', c.case_id],
    ['证据文件', c.image_path],
    ['文件大小', fmtBytes(c.image_size)],
    ['SHA-256', c.image_sha256 || '—'],
    ['容器格式', c.container || '—'],
    ['操作系统', `${c.os_type || '—'}（置信度 ${Math.round((c.os_confidence || 0) * 100)}%）`],
    ['状态', c.state || '—'],
    ['创建时间', c.created_at || '—'],
  ];
  rows.forEach(([k, v]) => {
    const tr = el('tr');
    tr.appendChild(el('th', '', k));
    tr.appendChild(el('td', '', v === null || v === undefined || v === '' ? '—' : v));
    tb.appendChild(tr);
  });
}

/* ───────────── 发现项 ───────────── */
function renderFindings() {
  const sev = $('findingSeverity').value;
  const list = $('findingList');
  list.innerHTML = '';
  const items = S.findings.filter(f => !sev || f.severity === sev);
  $('findingMeta').textContent = `${items.length} 条`;
  if (!items.length) {
    list.innerHTML = '<div class="empty">没有符合条件的发现项</div>';
    $('topFindings').innerHTML = '<div class="empty">暂无</div>';
    return;
  }
  items.forEach(f => {
    const d = el('div', 'finding ' + (f.severity || 'info'));
    const head = el('div', 'f-head');
    head.appendChild(el('span', 'tag ' + (f.severity || 'info'), f.severity || 'info'));
    head.appendChild(el('span', 'f-title', f.title));
    head.appendChild(el('span', 'muted', Math.round((f.confidence || 0) * 100) + '%'));
    d.appendChild(head);
    if (f.description) d.appendChild(el('div', 'f-desc', f.description));
    const meta = [];
    if (f.detector) meta.push('检测器：' + f.detector);
    if (f.sources && f.sources.length) meta.push('来源：' + f.sources.join(', '));
    if (meta.length) d.appendChild(el('div', 'f-meta', meta.join('　|　')));
    list.appendChild(d);
  });
  // 概览页 Top 5
  const top = $('topFindings');
  top.innerHTML = '';
  S.findings.slice(0, 6).forEach(f => {
    const r = el('div', 'finding ' + (f.severity || 'info'));
    const head = el('div', 'f-head');
    head.appendChild(el('span', 'tag ' + (f.severity || 'info'), f.severity || 'info'));
    head.appendChild(el('span', 'f-title', f.title));
    r.appendChild(head);
    if (f.description) r.appendChild(el('div', 'f-desc', f.description));
    top.appendChild(r);
  });
  $('findMeta').textContent = `${S.findings.length} 条`;
}

/* ───────────── 产物 ───────────── */
function renderArtifacts() {
  const kw = $('artifactFilter').value.trim().toLowerCase();
  const stt = $('artifactStatus').value;
  const tb = $('artifactTable').querySelector('tbody');
  tb.innerHTML = '';
  const items = S.artifacts.filter(a => {
    if (stt && a.status !== stt) return false;
    if (!kw) return true;
    return [a.engine, a.plugin, a.category, a.error].join(' ').toLowerCase().includes(kw);
  });
  $('artifactMeta').textContent = `${items.length} / ${S.artifacts.length} 个产物`;
  if (!items.length) {
    const tr = el('tr');
    const td = el('td', 'empty', '没有符合条件的产物');
    td.colSpan = 8;
    tr.appendChild(td); tb.appendChild(tr);
    return;
  }
  items.forEach(a => {
    const tr = el('tr', 'clickable');
    tr.appendChild(el('td', '', a.engine));
    tr.appendChild(el('td', '', a.plugin));
    tr.appendChild(el('td', '', a.category || '—'));
    const st = el('td');
    st.appendChild(el('span', 'tag ' + (a.status || 'info'), stZh(a.status)));
    tr.appendChild(st);
    tr.appendChild(el('td', 'num mono', (a.row_count || 0).toLocaleString()));
    tr.appendChild(el('td', 'num mono', fmtDur(a.duration_ms)));
    const msg = el('td', 'clip', a.error || a.output_path || '—');
    msg.title = a.error || a.output_path || '';
    tr.appendChild(msg);
    const op = el('td');
    const b = el('button', 'btn sm', '查看');
    b.addEventListener('click', (e) => { e.stopPropagation(); openDrawer(a); });
    op.appendChild(b);
    /* ★ 未知/失败产物（？？？）加"详情"按钮：点得进去，看魔数/画像/原始输出，自己分辨是什么文件、有无危险 */
    if (a.status === 'failed' || a.error || !a.row_count || a.status === 'partial') {
      const b2 = el('button', 'btn sm', '详情');
      b2.title = '查看该文件/产物的详细信息（魔数 / static 画像 / 原始输出）';
      b2.addEventListener('click', (e) => { e.stopPropagation(); openFileModal(a); });
      op.appendChild(b2);
    }
    tr.appendChild(op);
    tr.addEventListener('click', () => openDrawer(a));
    tb.appendChild(tr);
  });
}

/* ───────────── 用户 ───────────── */
function renderUsers() {
  const tb = $('usersTable').querySelector('tbody');
  tb.innerHTML = '';
  const p = S.profile || {};
  const users = (p.profile_json && p.profile_json.users) || p.users || [];
  $('userMeta').textContent = users.length ? users.length + ' 个用户' : '—';
  if (!users.length) {
    const tr = el('tr'); const td = el('td', 'empty', '暂无用户信息');
    td.colSpan = 3; tr.appendChild(td); tb.appendChild(tr);
    return;
  }
  users.forEach(u => {
    const tr = el('tr');
    tr.appendChild(el('td', '', u.name || '—'));
    tr.appendChild(el('td', 'mono', u.sid || '—'));
    tr.appendChild(el('td', 'mono', u.home || '—'));
    tb.appendChild(tr);
  });
}

/* ───────────── 旗标 ───────────── */
function renderFlags() {
  const tb = $('flagTable').querySelector('tbody');
  tb.innerHTML = '';
  const flags = S.flags || [];
  if (!flags.length) {
    const tr = el('tr'); const td = el('td', 'empty', '未发现旗标');
    td.colSpan = 5; tr.appendChild(td); tb.appendChild(tr);
    $('flagBanner').innerHTML = '';
    return;
  }
  flags.forEach(f => {
    const tr = el('tr');
    const v = el('td', 'mono', f.value);
    v.style.color = '#b8f0cb'; v.style.cursor = 'pointer';
    v.addEventListener('click', () => copy(f.value));
    tr.appendChild(v);
    tr.appendChild(el('td', '', f.kind || '—'));
    tr.appendChild(el('td', 'num', f.hits || 1));
    tr.appendChild(el('td', 'clip', f.source || '—'));
    tr.appendChild(el('td', 'clip', f.context || '—'));
    tb.appendChild(tr);
  });
  // 概览横幅
  const banner = $('flagBanner');
  banner.innerHTML = '';
  const b = el('div', 'flag-banner');
  b.appendChild(el('h4', '', `发现 ${flags.length} 个旗标候选（点击复制）`));
  flags.slice(0, 8).forEach(f => {
    const s = el('span', 'flag-val', f.value);
    s.addEventListener('click', () => copy(f.value));
    b.appendChild(s);
  });
  banner.appendChild(b);
}

function copy(text) {
  navigator.clipboard?.writeText(text).then(
    () => toast('已复制：' + text, 'ok'),
    () => toast('复制失败', 'err'));
}

/* ───────────── 时间线 ───────────── */
async function loadTimeline() {
  if (!S.caseId) return;
  const kw = $('timelineKeyword').value.trim();
  const cat = $('timelineCategory').value;
  const order = $('timelineOrder').value;
  const q = new URLSearchParams({ limit: 500, order });
  if (kw) q.set('keyword', kw);
  if (cat) q.set('category', cat);
  const d = await api(`/api/cases/${S.caseId}/timeline?` + q.toString());
  const tb = $('timelineTable').querySelector('tbody');
  tb.innerHTML = '';
  const sel = $('timelineCategory');
  const seen = new Set(Array.from(sel.options).map(o => o.value).filter(Boolean));
  d.events.forEach(e => { if (e.category && !seen.has(e.category)) { seen.add(e.category); sel.appendChild(new Option(e.category, e.category)); } });
  $('timelineMeta').textContent = `${d.count} 个事件`;
  if (!d.events.length) {
    const tr = el('tr'); const td = el('td', 'empty', '暂无时间线事件');
    td.colSpan = 5; tr.appendChild(td); tb.appendChild(tr);
    return;
  }
  d.events.forEach(e => {
    const tr = el('tr');
    tr.appendChild(el('td', 'mono', e.ts || '—'));
    tr.appendChild(el('td', '', e.category || '—'));
    tr.appendChild(el('td', 'clip', e.source || '—'));
    tr.appendChild(el('td', 'clip', e.title || '—'));
    tr.appendChild(el('td', 'clip', e.detail || '—'));
    tb.appendChild(tr);
  });
}

/* ───────────── 情报 ───────────── */
async function loadIntel() {
  if (!S.caseId) return;
  const ioc = await api(`/api/cases/${S.caseId}/iocs?limit=1000`);
  const tb = $('iocTable').querySelector('tbody');
  tb.innerHTML = '';
  (ioc.iocs || []).forEach(r => {
    const tr = el('tr');
    tr.appendChild(el('td', '', r.kind || '—'));
    const v = el('td', 'mono', r.value);
    v.title = r.value; v.style.cursor = 'pointer';
    v.addEventListener('click', () => copy(r.value));
    tr.appendChild(v);
    const s = el('td'); s.appendChild(el('span', 'tag plain', r.severity || 'info'));
    tr.appendChild(s);
    tr.appendChild(el('td', 'clip', r.source || '—'));
    tr.appendChild(el('td', 'clip', r.context || '—'));
    tb.appendChild(tr);
  });
  if (!ioc.iocs.length) {
    const tr = el('tr'); const td = el('td', 'empty', '暂无 IOC');
    td.colSpan = 5; tr.appendChild(td); tb.appendChild(tr);
  }
  const dh = await api(`/api/cases/${S.caseId}/dict_hits?limit=500`);
  const db = $('dictTable').querySelector('tbody');
  db.innerHTML = '';
  (dh.hits || []).forEach(r => {
    const tr = el('tr');
    tr.appendChild(el('td', '', r.dictionary || '—'));
    tr.appendChild(el('td', 'clip', r.label || r.entry_id || '—'));
    tr.appendChild(el('td', '', r.category || '—'));
    const s = el('td'); s.appendChild(el('span', 'tag plain', r.severity || 'info'));
    tr.appendChild(s);
    tr.appendChild(el('td', 'clip mono', r.value || '—'));
    db.appendChild(tr);
  });
  $('intelMeta').textContent = `IOC ${(ioc.iocs || []).length} · 词典命中 ${(dh.hits || []).length}`;
}

/* ───────────── 记录抽屉 ───────────── */
function openDrawer(a) {
  S.drawer.artifactId = a.artifact_id;
  S.drawer.offset = 0;
  S.drawer.keyword = '';
  $('drawerSearch').value = '';
  $('drawerTitle').textContent = `${a.engine} · ${a.plugin}`;
  $('drawerMeta').textContent = `${a.category || ''} · ${a.status || ''} · ${(a.row_count || 0).toLocaleString()} 行`;
  $('drawer').classList.remove('hidden');
  loadRecords();
}
function closeDrawer() { $('drawer').classList.add('hidden'); }

async function loadRecords() {
  if (!S.caseId || !S.drawer.artifactId) return;
  const q = new URLSearchParams({
    artifact_id: S.drawer.artifactId,
    limit: S.drawer.limit,
    offset: S.drawer.offset,
  });
  if (S.drawer.keyword) q.set('keyword', S.drawer.keyword);
  const d = await api(`/api/cases/${S.caseId}/records?` + q.toString());
  const table = $('recordTable');
  const thead = table.querySelector('thead');
  const tb = table.querySelector('tbody');
  thead.innerHTML = ''; tb.innerHTML = '';
  let cols = [];
  (d.rows || []).forEach(r => Object.keys(r.parsed || {}).forEach(k => { if (!cols.includes(k)) cols.push(k); }));
  if (!cols.length) cols = ['(无字段)'];
  S.drawer.columns = cols;
  const htr = el('tr');
  cols.slice(0, 14).forEach(c => htr.appendChild(el('th', '', c)));
  thead.appendChild(htr);
  (d.rows || []).forEach(r => {
    const tr = el('tr');
    cols.slice(0, 14).forEach(c => {
      const td = el('td', 'clip mono', fmtCell((r.parsed || {})[c]));
      td.title = fmtCell((r.parsed || {})[c]);
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
  if (!d.rows.length) {
    const tr = el('tr'); const td = el('td', 'empty', '该产物没有记录');
    td.colSpan = Math.min(cols.length, 14); tr.appendChild(td); tb.appendChild(tr);
  }
  $('pageInfo').textContent = `${d.count} 行（${S.drawer.offset}–${S.drawer.offset + d.count}）`;
}

/* ═════════════════════ 分析 ═════════════════════ */
async function startAnalysis() {
  if (!S.caseId) return;
  $('btnAnalyze').disabled = true;
  $('btnCancel').disabled = false;
  resetPhases();
  try {
    const r = await api(`/api/cases/${S.caseId}/analyze`, { method: 'POST', body: {} });
    S.runId = r.run_id;
    log('深度分析已启动（run ' + r.run_id + '）', 'step');
  } catch (e) {
    toast('启动失败：' + e.message, 'err');
    $('btnAnalyze').disabled = false;
    $('btnCancel').disabled = true;
  }
}

async function cancelAnalysis() {
  if (!S.runId) return;
  try {
    await api(`/api/runs/${S.runId}/cancel`, { method: 'POST' });
    log('已请求停止分析', 'warn');
  } catch (e) { toast('停止失败：' + e.message, 'err'); }
}

function resetPhases() {
  document.querySelectorAll('.phase-item').forEach(p => {
    p.className = 'phase-item'; p.querySelector('em').textContent = '';
  });
  $('progressFill').style.width = '0%';
  $('progressText').textContent = '启动中…';
}

function markPhase(name, state, msg) {
  const p = document.querySelector(`.phase-item[data-phase="${name}"]`);
  if (!p) return;
  p.className = 'phase-item ' + state;
  if (msg) p.querySelector('em').textContent = msg;
}

const PHASE_ORDER = ['probe', 'plan', 'engine', 'detect', 'intel', 'timeline', 'flags', 'profile', 'report'];

function connectCaseWS(caseId) {
  if (S.ws) { try { S.ws.close(); } catch (e) { } S.ws = null; }
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/case/${caseId}`);
  S.ws = ws;
  ws.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
    handleEvent(m.type, m.payload);
  };
  ws.onclose = () => { if (S.ws === ws) S.ws = null; };
  ws.onerror = () => { /* 断线由重连逻辑处理 */ };
  setTimeout(() => { if (S.ws && S.ws.readyState !== 1) connectCaseWS(caseId); }, 3000);
}

function connectLog() {
  // 日志页没有案件时也要能显示引擎自检
  log('MemLens 控制台已就绪', 'ok');
}

/* ═════════════════════ 事件处理 ═════════════════════ */
function handleEvent(type, p) {
  if (type === 'tool_done' || type === 'tool_error') { handleToolEvent(type, p); return; }
  switch (type) {
    case 'probe':
      log(`探测：容器=${p.container} (${Math.round(p.container_confidence * 100)}%)  系统=${p.os_type} (${Math.round(p.os_confidence * 100)}%)`, 'step');
      if (typeof wzSetProgress === 'function') {
        wzSetProgress(8, `已识别容器：${p.container} / ${p.os_type}`);
      }
      break;
    case 'plan': {
      log(`分析计划：${p.total} 个执行项 —— ` + Object.entries(p.by_engine || {}).map(([k, v]) => `${k}:${v}`).join('  '), 'step');
      (p.notes || []).forEach(n => log('计划说明：' + n, 'info'));
      (p.skipped || []).forEach(s => log(`跳过 ${s.plugin || s.engine}：${s.reason}`, 'warn'));
      if (typeof wzSetProgress === 'function') wzSetProgress(15, `分析计划：${p.total} 个执行项`);
      if (typeof sbPhase === 'function') sbPhase('计划完成');
      break;
    }
    case 'log':
      log(p.text);
      break;
    case 'progress': {
      $('progressFill').style.width = (p.percent || 0) + '%';
      $('progressText').textContent = `${p.percent || 0}% · ${p.phase || ''} ${p.phase_message || ''}`;
      // 向导进度条映射：真实进度只占 15%~92%（留给最后的报告阶段）
      if (typeof wzSetProgress === 'function') {
        wzSetProgress(15 + (p.percent || 0) * 0.77,
          (p.phase_message ? String(p.phase_message) : (p.phase || '')) );
      }
      if (typeof sbPhase === 'function') sbPhase(p.phase || '');
      if (p.phase) {
        const idx = PHASE_ORDER.indexOf(p.phase);
        PHASE_ORDER.forEach((n, i) => {
          if (i < idx) markPhase(n, 'done');
          else if (i === idx) markPhase(n, 'run', p.phase_message ? String(p.phase_message).slice(0, 26) : '');
        });
      }
      break;
    }
    case 'plugin_start':
      log(`▶ ${p.display || p.plugin}（${p.index}/${p.total}）`, 'step');
      break;
    case 'plugin_done': {
      const mark = p.status === 'ok' ? 'ok' : (p.status === 'failed' ? 'err' : 'warn');
      log(`  ${p.status} · ${p.plugin} · ${p.rows || 0} 行 · ${fmtDur(p.duration_ms)}${p.error ? ' · ' + p.error : ''}`, mark);
      break;
    }
    case 'done': {
      PHASE_ORDER.forEach(n => markPhase(n, 'done'));
      $('progressFill').style.width = '100%';
      $('progressText').textContent = `完成（${fmtDur(p.duration_ms)}）`;
      $('btnAnalyze').disabled = false;
      $('btnCancel').disabled = true;
      log('★ 深度分析完成：' + JSON.stringify(p.stats || {}), 'ok');
      if (p.profile) { S.profile = { profile_json: p.profile }; }
      refreshCases();
      selectCase(S.caseId);
      toast('深度分析完成', 'ok');
      if (typeof wzDone === 'function') wzDone();
      if (typeof renderDegradeNotice === 'function') renderDegradeNotice();
      break;
    }
    case 'error':
      log('分析异常：' + (p.message || ''), 'err');
      $('btnAnalyze').disabled = false;
      $('btnCancel').disabled = true;
      if (typeof wzFail === 'function') wzFail('分析失败', String(p.message || ''));
      break;
  }
}

function log(text, cls = 'info') {
  if (!text) return;
  S.logLines.push({ t: Date.now(), text, cls });
  if (S.logLines.length > 4000) S.logLines.shift();
  const box = $('logBox');
  const d = el('div', 'l-' + cls);
  const tm = el('span', 'l-time', new Date().toLocaleTimeString('zh-CN', { hour12: false }));
  d.appendChild(tm);
  d.appendChild(document.createTextNode(text));
  box.appendChild(d);
  if ($('logAutoScroll').checked) box.scrollTop = box.scrollHeight;
  consolePush(text, cls);          // ★ 镜像到内联控制台（v2）
}

/* ═════════════════════ 工具箱（按需功能） ═════════════════════ */
/* 原则：所有"细粒度功能"都以按钮形式显式触发 —— 不随启动自动跑。
   浏览器记录走 /api/browser-history*（本机，只读副本）；
   镜像内操作走 /api/tools/{tool}（登记入证据模型，「产物」页可见）。 */

function bindTools() {
  $('btnBhCollect').addEventListener('click', collectBrowserHistory);
  $('btnBhCsv').addEventListener('click', exportBrowserHistory);
  $('btnSysRefresh').addEventListener('click', refreshMachineInfo);
  $('btnVmscan').addEventListener('click', runVmscan);
  document.querySelectorAll('.tool-btn').forEach(b => {
    b.addEventListener('click', () => runTool(b.dataset.tool, b));
  });
}

function setToolButtons(enabled) {
  document.querySelectorAll('.tool-btn').forEach(b => { b.disabled = !enabled; });
  $('btnSysRefresh').disabled = !enabled;
  $('btnVmscan').disabled = !enabled;
}

/* ── ① 浏览器浏览记录（本机） ── */
async function collectBrowserHistory() {
  const q = new URLSearchParams();
  q.set('browser', $('bhBrowser').value || 'all');
  if ($('bhSince').value) q.set('since', $('bhSince').value.trim());
  if ($('bhUntil').value) q.set('until', $('bhUntil').value.trim());
  if ($('bhKeyword').value) q.set('keyword', $('bhKeyword').value.trim());
  if ($('bhAllDrives').checked) q.set('all_drives', 'true');
  q.set('show', '500');
  $('btnBhCollect').disabled = true;
  log('采集浏览器记录' + ($('bhAllDrives').checked ? '（全盘扫描）' : '') + '…', 'step');
  try {
    const d = await api('/api/browser-history?' + q.toString(), { timeout: 300000 });
    renderBrowserHistory(d);
  } catch (e) {
    toast('采集失败：' + e.message, 'err');
  } finally {
    $('btnBhCollect').disabled = false;
  }
}

function renderBrowserHistory(d) {
  S.bhData = d;
  const tb = $('bhTable').querySelector('tbody');
  tb.innerHTML = '';

  /* 来源库列表 */
  const srcs = $('bhSources');
  srcs.innerHTML = '';
  (d.sources || []).forEach(s => {
    const row = el('div', 'bh-src');
    row.appendChild(el('span', 'src-browser', s.browser + '/' + s.profile));
    row.appendChild(el('span', 'src-drive', s.drive || (s.kind === 'firefox' ? 'Roaming' : 'Local')));
    const p = el('span', 'src-path', s.path);
    p.title = s.path;
    row.appendChild(p);
    row.appendChild(el('span', 'src-size', s.size_mb + ' MB'));
    srcs.appendChild(row);
  });

  /* 摘要 + 分析（Top 域名 / 按日分布） */
  const sum = $('bhSummary');
  sum.innerHTML = '';
  const s = d.summary;
  if (s) {
    sum.appendChild(el('span', '', `共 <b>${s.total}</b> 条访问`));
    if (s.first || s.last) sum.appendChild(el('span', '', `时间范围：${s.first || '?'} ~ ${s.last || '?'}`));
    Object.entries(s.by_browser || {}).forEach(([k, v]) =>
      sum.appendChild(el('span', '', `${k}：<b>${v}</b>`)));
    /* Top 域名 chips */
    const doms = el('div', 'bh-domains');
    (s.top_domains || []).slice(0, 12).forEach(t => {
      const c = el('span', 'bh-domain', t['域名'] + ' <b>×' + t['次数'] + '</b>');
      c.innerHTML = `${esc(t['域名'])} <b>×${t['次数']}</b>`;
      doms.appendChild(c);
    });
    if (doms.children.length) sum.appendChild(doms);
    /* 按日分布（最近 14 天的迷你柱状图） */
    const days = s.by_day || {};
    const keys = Object.keys(days).filter(k => k).sort().slice(-14);
    if (keys.length) {
      const maxV = Math.max(...keys.map(k => days[k]));
      const wrap = el('div');
      const lbl = el('div', 'bh-days-label');
      lbl.appendChild(el('span', '', keys[0]));
      lbl.appendChild(el('span', '', keys[keys.length - 1]));
      const bars = el('div', 'bh-days');
      keys.forEach(k => {
        const b = el('i');
        b.style.height = Math.max(4, Math.round(days[k] / maxV * 40)) + 'px';
        b.title = `${k}：${days[k]} 条`;
        bars.appendChild(b);
      });
      wrap.appendChild(lbl);
      wrap.appendChild(bars);
      sum.appendChild(wrap);
    }
  }
  $('btnBhCsv').disabled = !d.total;
  $('bhMeta').textContent = `${d.total} 条${(d.sources || []).length ? ' · ' + d.sources.length + ' 个来源库' : ''}` +
    (d.all_drives ? '（全盘扫描）' : '');

  /* 明细表 */
  if (!d.visits.length) {
    const tr = el('tr'); const td = el('td', 'empty',
      d.total ? '（摘要已生成，明细超出显示上限，请用 CSV 导出全量）' : '未发现浏览记录');
    td.colSpan = 8; tr.appendChild(td); tb.appendChild(tr);
    return;
  }
  d.visits.forEach(v => {
    const tr = el('tr');
    tr.appendChild(el('td', 'mono', v.visited_at || '—'));
    tr.appendChild(el('td', '', v.browser || '—'));
    tr.appendChild(el('td', '', v.profile || '—'));
    tr.appendChild(el('td', 'clip', v.title || '—'));
    const u = el('td', 'clip mono', v.url || '');
    u.title = v.url; u.style.cursor = 'pointer';
    u.addEventListener('click', () => copy(v.url));
    tr.appendChild(u);
    tr.appendChild(el('td', '', v.transition || '—'));
    tr.appendChild(el('td', 'num', v.visit_count || ''));
    tr.appendChild(el('td', 'mono', d.all_drives ? (v.source || prof) : ''));
    tb.appendChild(tr);
  });
}

function exportBrowserHistory() {
  const q = new URLSearchParams();
  q.set('browser', $('bhBrowser').value || 'all');
  if ($('bhSince').value) q.set('since', $('bhSince').value.trim());
  if ($('bhUntil').value) q.set('until', $('bhUntil').value.trim());
  if ($('bhKeyword').value) q.set('keyword', $('bhKeyword').value.trim());
  if ($('bhAllDrives').checked) q.set('all_drives', 'true');
  window.location = '/api/browser-history.csv?' + q.toString();
}

/* ── ② 机器信息（按需重取） ── */
async function refreshMachineInfo() {
  if (!S.caseId) { toast('请先打开一个证据文件', 'err'); return; }
  $('btnSysRefresh').disabled = true;
  $('sysMeta').textContent = '提取中…';
  const ok = await triggerTool('sysinfo');
  if (!ok) $('btnSysRefresh').disabled = false;
}

async function runVmscan() {
  const paths = prompt('虚拟机目录（分号分隔，留空=扫描用户主目录）：', '');
  if (paths === null) return;
  const q = new URLSearchParams({ depth: '3' });
  if (paths.trim()) q.set('paths', paths.trim());
  log('虚拟机扫描：' + (paths.trim() || '主目录'), 'step');
  try {
    const d = await api('/api/vmscan?' + q.toString(), { timeout: 300000 });
    const sm = d.summary || {};
    log(`VM 发现 ${sm.vm_count ?? 0} 台，磁盘命中 ${sm['磁盘命中'] ? sm['磁盘命中'].length : 0} 处 flag/密钥`, 'ok');
    (sm.vms || []).forEach(v => log(`· VM ${v['目录']}（${v['家族']}）配置线索 ${(v['配置线索'] || []).length} 条`, 'info'));
    (d.next_steps || []).forEach(s => log('· ' + s, 'info'));
    toast('虚拟机扫描完成', 'ok');
  } catch (e) {
    toast('虚拟机扫描失败：' + e.message, 'err');
  }
}

/* ── ③ 镜像内单项操作 ── */
const TOOL_NAMES = { sysinfo: '机器信息', users: '用户与SID', envs: '环境变量', files: '未释放文件',
                     flag: '字节快扫', process_dump: '进程内存导出' };
async function triggerTool(tool) {
  if (!S.caseId) { toast('请先打开一个证据文件', 'err'); return false; }
  $('toolBusy').textContent = `正在执行「${TOOL_NAMES[tool] || tool}」…`;
  const btn = document.querySelector(`.tool-btn[data-tool="${tool}"]`);
  if (btn) btn.disabled = true;
  try {
    const r = await api('/api/tools/' + tool, {
      method: 'POST', body: { case_id: S.caseId }, timeout: 30000,
    });
    if (r.state === 'unavailable') {
      toast(`引擎不可用：${r.note}`, 'err');
      log(`工具 ${tool} 未启动：${r.note}`, 'warn');
      $('toolBusy').textContent = '';
      if (btn) btn.disabled = false;
      return false;
    }
    log(`工具 ${tool} 已启动（run ${r.run_id}），完成后自动刷新` + '「产物」页', 'step');
    return true;
  } catch (e) {
    toast(`工具启动失败：${e.message}`, 'err');
    $('toolBusy').textContent = '';
    if (btn) btn.disabled = false;
    return false;
  }
}

async function runTool(tool, btn) {
  const ok = await triggerTool(tool);
  if (ok && btn) setTimeout(() => { btn.disabled = false; }, 60000);
}

/* ── 事件处理里的工具完成通知 ── */
function handleToolEvent(type, p) {
  if (type === 'tool_done') {
    $('toolBusy').textContent = '';
    log(`工具 ${p.tool} 完成：${p.status} · ${p.rows || 0} 行${p.error ? ' · ' + p.error : ''}`,
        p.status === 'ok' ? 'ok' : 'warn');
    document.querySelectorAll('.tool-btn').forEach(b => { b.disabled = !S.caseId; });
    S.loaded.timeline = false; S.loaded.intel = false;
    if (S.caseId && p.case_id === S.caseId) selectCase(S.caseId);  // 刷新产物/概览
  } else if (type === 'tool_error') {
    $('toolBusy').textContent = '';
    log(`工具 ${p.tool} 失败：${p.message}`, 'err');
    document.querySelectorAll('.tool-btn').forEach(b => { b.disabled = !S.caseId; });
  }
}

/* ═════════════════════ 五维判定（FR-01~FR-07） ═════════════════════ */
async function loadDimensions() {
  if (!S.caseId) return;
  try {
    const d = await api(`/api/cases/${S.caseId}/dimensions`);
    if (!d.dimensions || !d.dimensions.length) return;
    renderDimensions(d);
  } catch (e) { /* 无缓存结果时静默 */ }
}

async function runDimensions() {
  if (!S.caseId) { toast('请先打开一个证据文件', 'err'); return; }
  const btn = $('btnDimRun');
  btn.disabled = true;
  $('dimMeta').textContent = '判定中…';
  $('dimBody').innerHTML = '<div class="empty">正在跑五维判定…</div>';
  try {
    const usage = $('dimUsage').value || 'check';
    const allowDir = $('dimAllowDirection').checked;
    const d = await api(`/api/cases/${S.caseId}/dimensions`, {
      method: 'POST', body: { usage, allow_direction: allowDir }, timeout: 120000,
    });
    renderDimensions(d);
    log(`五维判定完成：总分 ${(d.total || 0).toFixed(3)} · `
      + (usage === 'check' ? (d.tier_label || d.tier) : (d.level_label || d.level)), 'ok');
  } catch (e) {
    $('dimMeta').textContent = '判定失败';
    $('dimBody').innerHTML = '<div class="empty">判定失败：' + e.message + '</div>';
    toast('五维判定失败：' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

function renderDimensions(d) {
  // 结果写到 #dimResult；**不碰** #dimControls（持久控件，见 index.html 注释）
  const body = $('dimResult') || $('dimBody');
  body.innerHTML = '';
  const isCheck = (d.usage || 'check') === 'check';
  const concl = isCheck ? (d.tier_label || d.tier) : (d.level_label || d.level);
  $('dimMeta').textContent = `总分 ${(d.total || 0).toFixed(3)} · ${concl}`
    + (d.level_cap ? ` · 等级上限 ${d.level_cap}` : '')
    + (d.rulepack_version ? ` · 规则包 ${d.rulepack_version}` : '');
  // 同步持久控件的取值（不重建，避免 id 丢失）
  const u = $('dimUsage');
  if (u) u.value = d.usage || 'check';

  (d.dimensions || []).forEach(dim => {
    const box = el('div', 'dim-row');
    const head = el('div', 'dim-head');
    head.appendChild(el('span', 'dim-name', (dim.label || dim.dimension) + (dim.fr ? '（' + dim.fr + '）' : '')));
    const st = el('span', 'tag ' + (dim.state === 'established' ? 'high'
      : dim.state === 'disabled' ? 'info'
      : dim.state === 'degraded' ? 'partial' : 'info'),
      dim.state === 'established' ? '已成立'
      : dim.state === 'disabled' ? '未启用'
      : dim.state === 'degraded' ? '已降级' : '未发现');
    head.appendChild(st);
    head.appendChild(el('span', 'dim-score', (dim.score || 0).toFixed(2)));
    head.appendChild(el('span', 'dim-cap', '上限 ' + (dim.level_cap || '—')));
    box.appendChild(head);
    const bar = el('div', 'dim-bar');
    const fill = el('i');
    fill.style.width = Math.round((dim.score || 0) * 100) + '%';
    bar.appendChild(fill);
    box.appendChild(bar);
    (dim.findings || []).slice(0, 6).forEach(f => box.appendChild(el('div', 'dim-find', f)));
    (dim.gaps || []).forEach(g => {
      const gp = el('div', 'dim-gap');
      gp.appendChild(el('b', '', (g.impact === 'none' ? '未启用' : '降级') + '：'));
      gp.appendChild(document.createTextNode((g.reason || '') + '　→ ' + (g.suggestion || '')));
      box.appendChild(gp);
    });
    body.appendChild(box);
  });
  (d.notes || []).forEach(n => body.appendChild(el('div', 'dim-gap', '· ' + n)));
}

/* ═════════════════════ 合规：规则包 / 审计链 / 缺口清单 ═════════════════════ */
async function loadRulepack() {
  try {
    const d = await api('/api/rulepack');
    const cur = d.current || {};
    $('rpMeta').textContent = cur.version ? `${cur.version}（发布 ${cur.published_at || '—'}）` : '—';
    const body = $('rpBody');
    body.innerHTML = '';
    const curBox = el('div', 'rp-current');
    curBox.appendChild(el('div', 'rp-line', `生效版本：<b>${cur.version || '—'}</b>　发布日期：${cur.published_at || '—'}`));
    curBox.appendChild(el('div', 'rp-line', `SHA-256：<code>${cur.sha256 || '—'}</code>`));
    curBox.appendChild(el('div', 'rp-line',
      `阈值 ${cur.threshold_count ?? 0} 条　维度权重 ${Object.keys(cur.dimension_weights || {}).length} 项　`
      + `工具指纹 ${cur.proxy_tool_count ?? 0} 个`));
    if (cur.change_log) curBox.appendChild(el('div', 'rp-line', `变更记录：${cur.change_log}`));
    body.appendChild(curBox);
    const packs = d.packs || [];
    if (packs.length) {
      const tb = el('table', 'data');
      tb.innerHTML = '<thead><tr><th>版本</th><th>发布日期</th><th>状态</th><th>SHA-256</th><th>变更记录</th><th></th></tr></thead>';
      const tbody = el('tbody');
      packs.forEach(pk => {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono', pk.version || '—'));
        tr.appendChild(el('td', '', pk.published_at || '—'));
        const st = el('td');
        st.appendChild(el('span', 'tag ' + (pk.active ? 'ok' : 'info'), pk.active ? '生效' : '历史'));
        tr.appendChild(st);
        tr.appendChild(el('td', 'mono clip', (pk.sha256 || '').slice(0, 16)));
        tr.appendChild(el('td', 'clip', pk.change_log || pk.error || '—'));
        const op = el('td');
        if (!pk.active) {
          const b = el('button', 'btn sm', '切换到此版本');
          b.addEventListener('click', async () => {
            try {
              await api('/api/rulepack/activate', { method: 'POST', body: { pack_id: pk.pack_id } });
              toast('已切换规则包：' + pk.version, 'ok');
              log('规则包切换为 ' + pk.version + '（已留痕）', 'step');
              loadRulepack();
            } catch (e) { toast('切换失败：' + e.message, 'err'); }
          });
          op.appendChild(b);
        }
        tr.appendChild(op);
        tbody.appendChild(tr);
      });
      tb.appendChild(tbody);
      body.appendChild(tb);
    }
  } catch (e) {
    $('rpBody').innerHTML = '<div class="empty">规则包读取失败：' + e.message + '</div>';
  }
}

async function loadAudit() {
  if (!S.caseId) return;
  const q = new URLSearchParams({ limit: '300' });
  if ($('auditCriticalOnly').checked) q.set('critical_only', 'true');
  try {
    const d = await api(`/api/cases/${S.caseId}/audit?` + q.toString());
    const chain = d.chain || {};
    $('auditMeta').textContent = chain.ok ? `哈希链完整（${chain.total || 0} 条）`
      : `⚠ 链已断裂（断点 audit_id=${chain.broken_at}）`;
    const tb = $('auditTable').querySelector('tbody');
    tb.innerHTML = '';
    (d.entries || []).forEach(r => {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', r.ts_utc || '—'));
      tr.appendChild(el('td', '', r.actor || '—'));
      const ac = el('td');
      ac.appendChild(el('span', 'tag ' + (r.critical ? 'high' : 'info'), r.action || '—'));
      tr.appendChild(ac);
      tr.appendChild(el('td', 'clip', r.target || '—'));
      tr.appendChild(el('td', 'clip', r.detail || '—'));
      tr.appendChild(el('td', 'mono clip', (r.entry_hash || '').slice(0, 16)));
      tb.appendChild(tr);
    });
    if (!(d.entries || []).length) {
      const tr = el('tr'); const td = el('td', 'empty', '暂无审计记录');
      td.colSpan = 6; tr.appendChild(td); tb.appendChild(tr);
    }
  } catch (e) {
    $('auditMeta').textContent = '读取失败：' + e.message;
  }
}

async function loadGaps() {
  if (!S.caseId) { $('gapMeta').textContent = '—'; return; }
  try {
    const d = await api(`/api/cases/${S.caseId}/gaps`);
    const gaps = d.gaps || [];
    $('gapMeta').textContent = `${gaps.length} 项`;
    if ($('gapMeta2')) $('gapMeta2').textContent = `${gaps.length} 项`;
    if ($('pillGaps')) $('pillGaps').textContent = gaps.length;
    if (typeof syncNavBadges === 'function') syncNavBadges();
    const body = $('gapBody');
    body.innerHTML = '';
    if (!gaps.length) {
      body.appendChild(el('div', 'empty', '本次分析未记录数据源缺口。'));
    } else {
      const tb = el('table', 'data');
      tb.innerHTML = '<thead><tr><th>维度/数据源</th><th>缺失原因</th><th>影响</th><th>建议补证</th></tr></thead>';
      const tbody = el('tbody');
      gaps.slice(0, 12).forEach(g => {
        const tr = el('tr');
        tr.appendChild(el('td', 'mono clip', g.dimension || g.source || '—'));
        tr.appendChild(el('td', 'clip', g.reason || '—'));
        tr.appendChild(el('td', '', g.impact || '—'));
        tr.appendChild(el('td', 'clip', g.suggestion || '—'));
        tbody.appendChild(tr);
      });
      tb.appendChild(tbody);
      body.appendChild(tb);
      if (gaps.length > 12) {
        body.appendChild(el('div', 'muted', `另有 ${gaps.length - 12} 项，见「合规」页签`));
      }
    }
    const tb2 = $('gapTable') && $('gapTable').querySelector('tbody');
    if (tb2) {
      tb2.innerHTML = '';
      gaps.forEach(g => {
        const tr = el('tr');
        tr.appendChild(el('td', '', g.scope || '—'));
        tr.appendChild(el('td', 'mono clip', g.dimension || g.source || '—'));
        tr.appendChild(el('td', 'clip', g.reason || '—'));
        tr.appendChild(el('td', '', g.impact || '—'));
        tr.appendChild(el('td', '', g.level_cap || '—'));
        tr.appendChild(el('td', 'clip', g.suggestion || '—'));
        tb2.appendChild(tr);
      });
      if (!gaps.length) {
        const tr = el('tr'); const td = el('td', 'empty', '无缺口记录');
        td.colSpan = 6; tr.appendChild(td); tb2.appendChild(tr);
      }
    }
  } catch (e) {
    $('gapMeta').textContent = '读取失败：' + e.message;
  }
}

/* ═════════════════════ 文件详情（未知/失败产物点得进来） ═════════════════════ */
function openFileModal(a) {
  /* a: artifact 记录；未知/失败时 a.error 与 a.output_path 是关键 */
  if (!S.caseId || !a) return;
  S.fileModal = { caseId: S.caseId, plugin: a.plugin, raw_output: '', path: '', exported: false };
  $('fmTitle').textContent = `${a.engine} · ${a.plugin}（${stZh(a.status)}）`;
  const body = $('fmBody');
  body.innerHTML = '<div class="empty">加载中…</div>';
  $('fileModal').classList.remove('hidden');
  api(`/api/cases/${S.caseId}/file-info?plugin=${encodeURIComponent(a.plugin || '')}`)
    .then(d => {
      S.fileModal.raw_output = d.raw_output || '';
      S.fileModal.path = d.path || '';
      body.innerHTML = '';
      /* ① 状态与错误 */
      const st = el('div', 'fm-status');
      st.appendChild(el('span', 'tag ' + (a.status || 'info'), stZh(a.status)));
      if (a.error) st.appendChild(el('span', 'muted', '　' + a.error));
      body.appendChild(st);
      /* ② 基本信息 */
      const info = el('div', 'fm-sec');
      info.appendChild(el('div', 'fm-sec-h', '基本信息'));
      const ib = el('div', 'fm-sec-body');
      ib.appendChild(el('div', '', `文件：${d.name}（${fmtBytes(d.size)}）`));
      if (d.sha256) ib.appendChild(el('div', 'fm-hex', 'SHA-256：' + d.sha256));
      info.appendChild(ib);
      body.appendChild(info);
      /* ③ 探测结论（容器 / 系统 / 证据 / 警告） */
      if (d.probe && d.probe.container) {
        const s2 = el('div', 'fm-sec');
        s2.appendChild(el('div', 'fm-sec-h', '探测结论'));
        const b2 = el('div', 'fm-sec-body');
        b2.appendChild(el('div', '',
          `容器：<b>${d.probe.container}</b>（${Math.round((d.probe.confidence || 0) * 100)}%）　系统：${d.probe.os_type || '—'}`));
        (d.probe.evidence || []).forEach(e => b2.appendChild(el('div', 'fm-hex', '· ' + e)));
        (d.probe.warnings || []).forEach(w => b2.appendChild(el('div', 'fm-note', '⚠ ' + w)));
        s2.appendChild(b2);
        body.appendChild(s2);
      }
      /* ④ 文件头 hex（魔数判断） */
      if (d.head_hex) {
        const s3 = el('div', 'fm-sec');
        s3.appendChild(el('div', 'fm-sec-h', '文件头前 64 字节'));
        const b3 = el('div', 'fm-sec-body');
        const pre = el('pre', 'fm-hex');
        pre.textContent = d.head_hex.match(/.{1,32}/g).join('\n');
        b3.appendChild(pre);
        if (d.head_text) b3.appendChild(el('div', 'fm-hex', '可打印：' + d.head_text.slice(0, 48)));
        s3.appendChild(b3);
        body.appendChild(s3);
      }
      /* ⑤ static 画像（类型/哈希/熵/加壳/危险 API） */
      const prof = Array.isArray(d.profile) ? d.profile : [];
      if (prof.length) {
        const s4 = el('div', 'fm-sec');
        s4.appendChild(el('div', 'fm-sec-h', 'static 画像'));
        const b4 = el('div', 'fm-sec-body');
        const tb = el('table', 'kv'); const tbod = el('tbody');
        prof.slice(0, 40).forEach(r => {
          const k = r['字段'] || r['项目'] || Object.keys(r)[0];
          const v = r['值'] !== undefined ? r['值'] : (r['数据'] !== undefined ? r['数据'] : Object.values(r).slice(1).join(' '));
          const tr = el('tr');
          tr.appendChild(el('th', '', String(k)));
          tr.appendChild(el('td', '', String(v || '—')));
          tbod.appendChild(tr);
        });
        tb.appendChild(tbod);
        b4.appendChild(tb);
        s4.appendChild(b4);
        body.appendChild(s4);
      }
      /* ⑥ 产物执行信息 + 原始输出 */
      if (d.artifact || d.raw_output || d.error) {
        const s5 = el('div', 'fm-sec');
        s5.appendChild(el('div', 'fm-sec-h', '产物执行信息'));
        const b5 = el('div', 'fm-sec-body');
        if (d.artifact) {
          b5.appendChild(el('div', '',
            `状态：${d.artifact.status}　行数：${d.artifact.rows ?? '—'}　耗时：${fmtDur(d.artifact.duration_ms)}`));
          if (d.artifact.error) b5.appendChild(el('div', 'fm-note', '错误：' + d.artifact.error));
        } else if (d.error) {
          b5.appendChild(el('div', 'fm-note', '案件状态：' + d.error));
        }
        if (d.raw_output) {
          const pre = el('pre', 'fm-raw');
          pre.textContent = d.raw_output.slice(0, 8000);
          b5.appendChild(pre);
        }
        s5.appendChild(b5);
        body.appendChild(s5);
      }
    })
    .catch(e => { body.innerHTML = ''; body.appendChild(el('div', 'empty', '加载失败：' + e.message)); });
}
function closeFileModal() { $('fileModal').classList.add('hidden'); S.fileModal = null; }
async function openFsModal() {
  $('fsModal').classList.remove('hidden');
  await fsList($('fsPath').value || 'C:\\');
}
async function fsList(path) {
  try {
    const d = await api('/api/fs/list?path=' + encodeURIComponent(path || ''));
    $('fsPath').value = d.path;
    const dr = $('fsDrives');
    dr.innerHTML = '';
    (d.drives || []).forEach(x => {
      const b = el('button', '', x);
      b.addEventListener('click', () => fsList(x));
      dr.appendChild(b);
    });
    const list = $('fsList');
    list.innerHTML = '';
    if (d.parent) {
      const up = el('div', 'fs-item');
      up.appendChild(el('span', '', '.. 上级目录'));
      up.addEventListener('click', () => fsList(d.parent));
      list.appendChild(up);
    }
    (d.entries || []).forEach(e => {
      const it = el('div', 'fs-item');
      const nm = el('span', '', (e.is_dir ? '📁 ' : '📄 ') + e.name);
      it.appendChild(nm);
      it.appendChild(el('span', 'fs-size', e.is_dir ? '' : fmtBytes(e.size)));
      it.addEventListener('click', () => {
        if (e.is_dir) fsList(e.path);
        else { $('fsPick').value = e.path; }
      });
      it.addEventListener('dblclick', () => { if (!e.is_dir) doOpen(e.path); });
      list.appendChild(it);
    });
  } catch (e) { toast('读取目录失败：' + e.message, 'err'); }
}
async function doOpen(path) {
  path = (path || '').trim();
  if (!path) { toast('请先选择文件', 'err'); return; }
  try {
    const r = await api('/api/cases', { method: 'POST', body: { path } });
    $('fsModal').classList.add('hidden');
    toast('已打开：' + path, 'ok');
    log('打开证据：' + path, 'step');
    log('探测结果：' + r.probe.summary, 'info');
    (r.probe.evidence || []).forEach(e => log('  · ' + e.source + '：' + e.detail, 'info'));
    if (r.note) log(r.note, 'info');
    await refreshCases();
    await selectCase(r.case_id);
    // ★ 打开即深度分析（用户要求：不要"快速/深度"选项）
    startAnalysis();
  } catch (e) {
    toast('打开失败：' + e.message, 'err');
  }
}

document.addEventListener('DOMContentLoaded', boot);
