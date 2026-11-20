/* ═══════════════════════════════════════════════════════════════════════
   MemLens · UI v2 交互层
     ① 内联控制台面板（时间戳 + 级别着色，可折叠）
     ② 底部状态栏（CPU / 内存 / 阶段 / 引擎，2 秒轮询）
     ③ 三步载入向导（选择镜像 → 选择兼容引擎 → 生成基础证据）
     ④ 兼容性 / 降级分析（引擎失败时给可执行的下一步，而不是甩报错）
     ⑤ 分析分组导航（多类分析一眼可见）
   ═══════════════════════════════════════════════════════════════════════ */

/* ───────────────── ① 控制台面板 ───────────────── */

const CONSOLE = { lines: [], max: 1500, collapsed: true };

/** 往控制台面板追加一行（带时间戳）。log() 会自动镜像到这里。 */
function consolePush(text, cls) {
  const body = $('consoleBody');
  if (!body) return;
  cls = cls || 'info';
  CONSOLE.lines.push({ t: Date.now(), text, cls });
  if (CONSOLE.lines.length > CONSOLE.max) CONSOLE.lines.shift();

  const d = el('div', 'c-line l-' + cls);
  d.appendChild(el('span', 'c-time',
    new Date().toLocaleTimeString('zh-CN', { hour12: false })));
  d.appendChild(document.createTextNode(String(text == null ? '' : text)));
  body.appendChild(d);
  while (body.childElementCount > CONSOLE.max) body.removeChild(body.firstChild);
  if (!CONSOLE.collapsed) body.scrollTop = body.scrollHeight;
}

function consoleSetCollapsed(v) {
  CONSOLE.collapsed = !!v;
  const dock = $('consoleDock');
  if (!dock) return;
  dock.classList.toggle('collapsed', CONSOLE.collapsed);
  if (!CONSOLE.collapsed) {
    const b = $('consoleBody');
    b.scrollTop = b.scrollHeight;
  }
}

function consoleMark(mode) {
  const b = $('consoleBadge');
  if (!b) return;
  b.classList.toggle('live', mode === 'live');
  b.textContent = mode === 'live' ? '运行中' : mode === 'err' ? '异常' : 'MemLens';
}

/* ───────────────── ② 底部状态栏 ───────────────── */

let _sbTimer = null;
let _sbErrors = 0;

function sbState(text, kind) {
  const t = $('sbState'), d = $('sbStateDot');
  if (!t) return;
  t.textContent = text;
  d.className = 'sb-dot' + (kind === 'busy' ? '' : kind === 'err' ? ' bad' : ' idle');
}

function sbPhase(text) { const e = $('sbPhase'); if (e) e.textContent = '阶段 ' + (text || '—'); }
function sbEngine(text) { const e = $('sbEngine'); if (e) e.textContent = '引擎 ' + (text || '—'); }

async function sbTick() {
  try {
    const s = await api('/api/sysstat');
    _sbErrors = 0;
    const cpu = s.cpu_percent;
    const cText = $('sbCpuText'), cBar = $('sbCpu');
    if (cpu === null || cpu === undefined) { cText.textContent = '—'; cBar.style.width = '0%'; }
    else {
      cText.textContent = cpu.toFixed(1) + '%';
      cBar.style.width = Math.min(100, cpu) + '%';
      cBar.className = cpu > 85 ? 'err' : cpu > 60 ? 'warn' : '';
    }
    const m = s.mem;
    if (m) {
      $('sbMemText').textContent =
        (m.used_mb / 1024).toFixed(2) + ' / ' + (m.total_mb / 1024).toFixed(1) + ' GB';
      const mBar = $('sbMem');
      mBar.style.width = Math.min(100, m.percent) + '%';
      mBar.className = m.percent > 90 ? 'err' : m.percent > 75 ? 'warn' : '';
      $('sbMemText').title = `系统内存占用 ${m.percent}%` +
        (s.self_mb ? `　MemLens 进程 ${s.self_mb} MB` : '');
    }
  } catch (e) {
    // 状态栏永远不该拖垮界面：连续失败就标红，不弹提示
    if (++_sbErrors === 3) {
      sbState('后端失联', 'err');
      const t = $('sbCpuText'); if (t) t.textContent = '—';
    }
  }
}

/* ───────────────── ⑤ 分析分组导航（多类分析） ───────────────── */

const ANALYSIS_GROUPS = [
  { id: 'proc',   icon: '🧠', name: '进程与内存', desc: '进程枚举 / 隐藏进程 / 代码注入',
    actions: [{ label: '进程列表', run: () => openArtifact('mprocfs.process') },
              { label: '注入检测', run: () => showTab('findings') }] },
  { id: 'net',    icon: '🌐', name: '网络与域名', desc: '连接表 / DNS 缓存 / 浏览器记录',
    actions: [{ label: '连接表', run: () => openArtifact('mprocfs.net') },
              { label: '浏览器记录', run: () => showTab('tools') }] },
  { id: 'persist', icon: '🔒', name: '持久化与注册表', desc: '自启动项 / 代理配置 / 服务',
    actions: [{ label: '自启动项', run: () => openArtifact('mprocfs.registry_run') },
              { label: '代理配置', run: () => openArtifact('mprocfs.registry_proxy') }] },
  { id: 'cred',   icon: '🔑', name: '凭据与用户', desc: '账户 / SID / 环境变量',
    actions: [{ label: '用户账户', run: () => showTab('users') },
              { label: '环境变量', run: () => showTab('tools') }] },
  { id: 'file',   icon: '🗂️', name: '文件与产物', desc: '未释放文件 / 内存字符串 / 静态解析',
    actions: [{ label: '全部产物', run: () => showTab('artifacts') },
              { label: '未释放文件', run: () => openArtifact('mprocfs.memory_files') }] },
  { id: 'host',   icon: '🖥️', name: '主机信息', desc: '系统画像 / 版本 / 虚拟化',
    actions: [{ label: '系统画像', run: () => showTab('overview') },
              { label: '机器信息', run: () => showTab('tools') }] },
  { id: 'timeline', icon: '⏱️', name: '时间线', desc: 'UTC 归一后的统一时序',
    actions: [{ label: '打开时间线', run: () => showTab('timeline') }] },
  { id: 'compliance', icon: '🧭', name: '合规判定', desc: '五维判定 / 规则包 / 审计链',
    actions: [{ label: '五维判定', run: () => showTab('compliance') },
              { label: '概览结论', run: () => showTab('overview') }] },
];

function renderAnalysisGroups() {
  const box = $('analysisNav');
  if (!box) return;
  box.innerHTML = '';
  ANALYSIS_GROUPS.forEach(g => {
    const card = el('div', 'agroup');
    card.dataset.group = g.id;
    card.appendChild(el('div', 'ag-icon', g.icon));
    card.appendChild(el('div', 'ag-name', g.name));
    card.appendChild(el('div', 'ag-desc', g.desc));
    const foot = el('div', 'ag-foot');
    const cnt = el('span', 'ag-count', groupCount(g.id));
    foot.appendChild(cnt);
    const st = groupCount(g.id);
    const kind = st.includes('无命中') || st.includes('无缺口') ? 'warn'
               : (st.includes('产物') || st.includes('缺口')) ? 'ok' : '';
    foot.appendChild(el('span', 'ag-state ' + kind,
      st.includes('无命中') ? '未命中'
      : st.includes('产物') ? '有数据'
      : st.includes('缺口') ? '有缺口'
      : st.includes('按需') || st.includes('待') ? '待分析' : '就绪'));
    card.appendChild(foot);
    card.addEventListener('click', () => {
      box.querySelectorAll('.agroup').forEach(x => x.classList.remove('active'));
      card.classList.add('active');
      const a = g.actions[0];
      if (a) a.run();
      log('分析分组：' + g.name + ' → ' + (a ? a.label : ''), 'step');
    });
    box.appendChild(card);
  });
}

/** 分组角标：按产物插件名前缀统计真实数量（取不到就显示占位，不编数）。 */
const GROUP_MATCH = {
  proc:       ['process', 'findevil', 'injection', 'hidden'],
  net:        ['net', 'netdns', 'browser'],
  persist:    ['registry_run', 'registry_proxy', 'services', 'registry_hives'],
  cred:       ['users', 'envs', 'sam', 'credential'],
  file:       ['memory_files', 'memstrings', 'static', 'findevil'],
  host:       ['sysinfo', 'harvest', 'modules', 'drivers'],
  timeline:   ['timeline'],
  compliance: ['dimension', 'gap', 'audit', 'rulepack'],
};

function groupCount(id) {
  // 时间线 / 合规判定不来自「产物」，各有自己的计数来源
  if (id === 'timeline') return '按需加载';
  if (id === 'compliance') {
    const p = $('pillGaps');
    const n = p ? String(p.textContent).trim() : '';
    if (!S.caseId) return '待判定';
    return (n && n !== '0') ? n + ' 项缺口' : '无缺口';
  }
  const pats = GROUP_MATCH[id] || [];
  if (!pats.length) return '按需加载';
  const arts = S.artifacts || [];
  if (!arts.length) return '待分析';
  const n = arts.filter(a => {
    const pl = (a.plugin || '').toLowerCase();
    return pats.some(k => pl.includes(k)) && a.status !== 'failed';
  }).length;
  return n ? n + ' 个产物' : '无命中';
}

/** 直接跳到「产物」页并打开指定产物的记录抽屉。 */
function openArtifact(pluginLike) {
  showTab('artifacts');
  const a = (S.artifacts || []).find(x => (x.plugin || '').includes(pluginLike));
  if (a) { openDrawer(a); return; }
  const hasPcap = (S.artifacts || []).some(x => (x.plugin || '').includes('static.pcap'));
  if (hasPcap) {
    toast('本次分析没有「' + pluginLike + '」产物——该检材是流量包，请到「流量」分组查看 static.pcap 分析，或用 static 引擎分析', 'err');
  } else {
    toast('本次分析没有「' + pluginLike + '」产物', 'err');
  }
}

/* ───────────────── ③ 三步载入向导 ───────────────── */

const WZ = {
  step: 1,
  file: null,
  engine: 'memprocfs',
  t0: 0,
  timer: null,
  running: false,
};

const WZ_ENGINES = [
  { id: 'memprocfs', name: 'MemProcFS 虚拟盘', tag: '首选', tagCls: 'ok',
    desc: '内存域首选：无需内核符号表，可直读进程 / 网络 / 注册表 / 文件系统' },
  { id: 'vol3', name: 'Volatility 3', tag: '需符号', tagCls: 'warn',
    desc: '插件最全（180 个）；依赖内核符号表，镜像缺 RSDS 符号记录时会失败' },
  { id: 'memstrings', name: 'memstrings 字符串', tag: '兜底', tagCls: 'ok',
    desc: '纯字符串提取，无符号依赖；适合符号不可用时的基础分析' },
  { id: 'static', name: 'static 静态解析', tag: '单文件', tagCls: '',
    desc: '对产物文件做 PE / ELF / 内容识别解析' },
];

function wzOpen(file) {
  if (file) WZ.file = file;
  const w = $('wizard');
  if (!w) return;
  w.classList.remove('hidden');
  $('wzKicker').textContent = WZ.file ? basename(WZ.file) : 'MemLens';
  wzGoto(WZ.file ? 2 : 1);
}

function wzClose() {
  $('wizard').classList.add('hidden');
  if (WZ.timer) { clearInterval(WZ.timer); WZ.timer = null; }
  WZ.running = false;
}

function wzGoto(n) {
  WZ.step = n;
  document.querySelectorAll('#wzStepper .step').forEach(s => {
    const k = +s.dataset.step;
    s.classList.toggle('done', k < n);
    s.classList.toggle('active', k === n);
  });
  document.querySelectorAll('#wzStepper .step-line').forEach(l => {
    l.classList.toggle('done', +l.dataset.line < n);
  });
  if (n === 1) wzRenderPick();
  else if (n === 2) wzRenderEngine();
  else wzRenderProgress();
}

function _wzHead(title, sub) {
  $('wzTitle').textContent = title;
  $('wzSub').textContent = sub;
}

function _wzFoot(buttons) {
  const f = $('wzFoot');
  f.innerHTML = '';
  buttons.forEach(b => {
    const btn = el('button', 'btn btn-lg ' + (b.cls || ''), b.label);
    btn.disabled = !!b.disabled;
    btn.addEventListener('click', b.run);
    f.appendChild(btn);
  });
}

function _fileBadge(path) {
  const ext = (path.split('.').pop() || '').toLowerCase();
  // ⚠ 数字开头的键必须加引号（`7z:` 是语法错误，实测被 node --check 拦下）
  const map = { raw: ['RAW', 'raw'], mem: ['RAW', 'raw'], dmp: ['DMP', 'raw'],
                vmem: ['VMEM', 'raw'], img: ['IMG', 'raw'], '7z': ['7Z', 'enc'],
                zip: ['ZIP', 'enc'], rar: ['RAR', 'enc'], gz: ['GZ', 'enc'],
                vhd: ['VHD', 'raw'], vhdx: ['VHDX', 'raw'], qcow2: ['QCOW', 'raw'],
                iso: ['ISO', 'raw'], e01: ['E01', 'raw'], pcap: ['PCAP', 'raw'] };
  const [txt, cls] = map[ext] || [(ext || 'BIN').slice(0, 3).toUpperCase(), 'raw'];
  return { txt, cls };
}

function _fileCard(path, meta) {
  const b = _fileBadge(path);
  const box = el('div', 'wz-file');
  box.appendChild(el('div', 'wz-badge ' + b.cls, b.txt));
  const main = el('div', 'wz-file-main');
  main.appendChild(el('div', 'wz-file-name', basename(path)));
  main.appendChild(el('div', 'wz-file-path', path));
  if (meta) main.appendChild(el('div', 'wz-file-meta', meta));
  box.appendChild(main);
  return box;
}

/** 步骤 1：选择镜像。 */
function wzRenderPick() {
  _wzHead('选择证据文件', '指定要分析的内存镜像或磁盘镜像。可拖拽文件到此处，或从案件库中挑一个已打开过的。');
  const body = $('wzBody');
  body.innerHTML = '';

  const drop = el('div', 'wz-file');
  drop.id = 'wzDrop';
  drop.style.borderStyle = 'dashed';
  drop.style.justifyContent = 'center';
  drop.style.textAlign = 'center';
  drop.style.display = 'block';
  drop.style.padding = '30px 18px';
  drop.innerHTML = '<div style="font-size:26px;margin-bottom:8px">📂</div>'
    + '<div style="font-size:13px;font-weight:600;margin-bottom:5px">拖拽镜像到此处</div>'
    + '<div class="muted">或点击下方「浏览文件…」选择</div>';
  body.appendChild(drop);

  // 拖放
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.style.borderColor = 'var(--accent)';
  }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.style.borderColor = '';
  }));
  drop.addEventListener('drop', e => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (!f) return;
    // 浏览器拿不到真实路径（安全限制），只能取文件名做提示
    toast('浏览器无法读取本地文件路径，请用「浏览文件…」选择：' + f.name, 'err');
  });

  // 案件库
  const recent = (S.cases || []).slice(0, 6);
  if (recent.length) {
    const t = el('div', 'muted', '最近打开的证据');
    t.style.margin = '14px 0 7px';
    body.appendChild(t);
    recent.forEach(c => {
      const row = el('div', 'eng');
      row.appendChild(el('div', 'eng-radio'));
      const m = el('div', 'eng-main');
      m.appendChild(el('div', 'eng-name', c.name || basename(c.image_path)));
      m.appendChild(el('div', 'eng-desc clip', c.image_path));
      row.appendChild(m);
      row.appendChild(el('span', 'eng-tag', `${(c.size_bytes / 1024 / 1024 / 1024).toFixed(2)} GB`));
      row.addEventListener('click', () => {
        WZ.file = c.image_path;
        $('wzKicker').textContent = basename(c.image_path);
        wzGoto(2);
      });
      body.appendChild(row);
    });
  }

  _wzFoot([
    { label: '浏览文件…', cls: 'btn-primary', run: () => {
        $('fsModal').classList.remove('hidden');
        $('fsModal').dataset.wz = '1';
        fsList('');
      } },
    { label: '取消', cls: 'btn-ghost', run: wzClose },
  ]);
}

/** 步骤 2：选择兼容引擎。 */
async function wzRenderEngine() {
  _wzHead('选择兼容引擎', '不同引擎依赖不同的镜像条件。首选 MemProcFS（无需内核符号表）；'
    + '若符号表不可用，可退回字符串兜底分析。');
  const body = $('wzBody');
  body.innerHTML = '';
  body.appendChild(_fileCard(WZ.file || '(未选择)'));

  // 取引擎可用性
  let engines = [];
  try {
    const h = await api('/api/health');
    engines = h.engines || [];
    WZ.health = h;
  } catch (e) { /* 拿不到就按静态清单渲染 */ }
  const avail = {};
  engines.forEach(e => { avail[e.name] = e; });

  const list = el('div', 'wz-engines');
  WZ_ENGINES.forEach(E => {
    // health 里的引擎名可能是 'memprocfs'/'vol3'/'memstrings'/'static'
    const h = avail[E.id] || avail[E.name] || null;
    const ok = h ? !!h.available : null;
    const row = el('div', 'eng' + (WZ.engine === E.id ? ' sel' : ''));
    row.dataset.engine = E.id;
    row.appendChild(el('div', 'eng-radio'));
    const m = el('div', 'eng-main');
    m.appendChild(el('div', 'eng-name', E.name));
    m.appendChild(el('div', 'eng-desc', E.desc));
    if (h && h.detail) m.appendChild(el('div', 'eng-desc', '· ' + h.detail));
    row.appendChild(m);
    const tg = el('span', 'eng-tag ' + (ok === false ? 'bad' : E.tagCls),
      ok === false ? '不可用' : E.tag);
    row.appendChild(tg);
    row.addEventListener('click', () => {
      WZ.engine = E.id;
      list.querySelectorAll('.eng').forEach(x => x.classList.remove('sel'));
      row.classList.add('sel');
    });
    list.appendChild(row);
  });
  body.appendChild(list);

  _wzFoot([
    { label: '上一步', cls: 'btn-ghost', run: () => wzGoto(1) },
    { label: '生成基础证据', cls: 'btn-primary', run: wzStart },
  ]);
}

/** 步骤 3：生成基础证据（进度 + 计时 + 取消）。 */
function wzRenderProgress() {
  _wzHead('正在生成基础证据', '无需挂载盘，正在生成进程、网络等基础证据；'
    + '完成后将直接进入分析工作台。');
  const body = $('wzBody');
  body.innerHTML = '';
  body.appendChild(_fileCard(WZ.file || '(未选择)',
    `引擎：${(WZ_ENGINES.find(e => e.id === WZ.engine) || {}).name || WZ.engine}`));

  const bar = el('div', 'wz-bar');
  const fill = el('i');
  fill.id = 'wzBarFill';
  bar.appendChild(fill);
  body.appendChild(bar);

  const stage = el('div', 'wz-stage');
  stage.innerHTML = '<span id="wzStageText">准备中…</span><em id="wzStagePct">0%</em>';
  body.appendChild(stage);

  const el2 = el('div', 'wz-elapsed');
  el2.id = 'wzElapsed';
  el2.textContent = '已用时间 0 秒';
  body.appendChild(el2);

  const note = el('div', 'wz-note');
  note.id = 'wzNote';
  note.textContent = '小提示：大镜像的第一步较慢，属正常现象。';
  body.appendChild(note);

  const consoleBox = el('div');
  consoleBox.id = 'wzInlineLog';
  body.appendChild(consoleBox);

  _wzFoot([
    { label: '取消加载', cls: 'btn-danger', run: wzCancel },
  ]);
}

function wzSetProgress(pct, text) {
  const f = $('wzBarFill');
  if (f) f.style.width = Math.max(0, Math.min(100, pct)) + '%';
  const p = $('wzStagePct');
  if (p) p.textContent = Math.round(pct) + '%';
  const s = $('wzStageText');
  if (s && text) s.textContent = text;
}

function wzStartTimer() {
  WZ.t0 = Date.now();
  if (WZ.timer) clearInterval(WZ.timer);
  WZ.timer = setInterval(() => {
    const e = $('wzElapsed');
    if (!e) return;
    const s = Math.floor((Date.now() - WZ.t0) / 1000);
    e.textContent = `已用时间 ${Math.floor(s / 60)} 分 ${s % 60} 秒`;
  }, 1000);
}

async function wzStart() {
  wzGoto(3);
  wzStartTimer();
  wzSetProgress(3, '正在探测镜像…');
  WZ.running = true;
  consoleSetCollapsed(false);
  consoleMark('live');
  sbState('生成基础证据…', 'busy');

  if (!WZ.file) {
    wzFail('未选择证据文件', '请回到第 1 步选择镜像。');
    return;
  }
  // 已经打开过同一文件 → 直接分析
  const same = (S.cases || []).find(c => c.image_path === WZ.file);
  try {
    if (same) {
      wzSetProgress(20, '复用已打开的镜像…');
      await selectCase(same.case_id);
      await startAnalysis();
    } else {
      wzSetProgress(10, '正在登记证据并计算哈希…');
      await doOpen(WZ.file);
    }
  } catch (e) {
    wzFail('载入失败', String(e.message || e));
  }
}

function wzCancel() {
  WZ.running = false;
  if (WZ.timer) { clearInterval(WZ.timer); WZ.timer = null; }
  cancelAnalysis();
  consoleMark('err');
  sbState('已取消', 'err');
  wzGoto(2);
  toast('已取消加载', 'err');
}

function wzDone() {
  WZ.running = false;
  if (WZ.timer) { clearInterval(WZ.timer); WZ.timer = null; }
  wzSetProgress(100, '完成');
  consoleMark('ok');
  sbState('空闲');
  setTimeout(wzClose, 700);
}

function wzFail(title, detail) {
  WZ.running = false;
  if (WZ.timer) { clearInterval(WZ.timer); WZ.timer = null; }
  consoleMark('err');
  sbState('失败', 'err');
  _wzHead(title, '可以用下面的兼容方案继续，不必从头再来。');
  const body = $('wzBody');
  body.innerHTML = '';
  body.appendChild(_fileCard(WZ.file || '(未选择)'));
  body.appendChild(degradeCard({
    level: 'err',
    title: '载入失败',
    lines: [detail],
    raw: (S.logLines || []).slice(-14).map(l => l.text).join('\n'),
    actions: [
      { label: '⚡ 启动兼容分析', cls: 'btn-primary',
        run: () => { WZ.engine = 'memstrings'; wzStart(); } },
      { label: '无符号基础分析', cls: '',
        run: () => { WZ.engine = 'memprocfs'; wzStart(); } },
      { label: '重试加载', cls: '', run: () => wzGoto(2) },
      { label: '返回', cls: 'btn-ghost', run: wzClose },
    ],
  }));
  _wzFoot([{ label: '返回', cls: 'btn-ghost', run: wzClose }]);
}

/* ───────────────── ④ 兼容性 / 降级分析卡片 ───────────────── */

/**
 * 统一的降级说明卡：把「哪里失败了 + 为什么 + 能怎么办」摆在一起。
 * 参考同类工作台的做法——失败不是终点，要给出可执行的下一步。
 */
function degradeCard(o) {
  const cls = o.level === 'ok' ? 'ok' : o.level === 'warn' ? 'warn' : '';
  const box = el('div', 'degrade ' + cls);
  const h = el('h4');
  h.appendChild(document.createTextNode(o.level === 'ok' ? '✅ ' : o.level === 'warn' ? '⚠️ ' : '⛔ '));
  h.appendChild(document.createTextNode(o.title || '分析降级'));
  box.appendChild(h);
  (o.lines || []).forEach(t => { if (t) box.appendChild(el('p', '', t)); });
  if (o.raw) box.appendChild(el('pre', '', o.raw));
  if (o.actions && o.actions.length) {
    const acts = el('div', 'degrade-actions');
    o.actions.forEach(a => {
      const b = el('button', 'btn ' + (a.cls || ''), a.label);
      b.addEventListener('click', a.run);
      acts.appendChild(b);
    });
    box.appendChild(acts);
  }
  return box;
}

/** 分析结束后的降级提示：数据源缺口 → 可执行的兼容动作。 */
async function renderDegradeNotice() {
  const host = $('degradeHost');
  if (!host || !S.caseId) return;
  host.innerHTML = '';
  let gaps = [];
  try { gaps = (await api(`/api/cases/${S.caseId}/gaps`)).gaps || []; }
  catch (e) { return; }
  if (!gaps.length) return;

  const blocked = gaps.filter(g => g.impact === 'blocked');
  const downg = gaps.filter(g => g.impact !== 'blocked' && g.impact !== 'none');
  const syn = gaps.find(g => g.source === 'synthetic');
  const level = syn ? 'warn' : (blocked.length ? 'err' : downg.length ? 'warn' : 'ok');
  const title = syn
    ? `⚠ ${syn.reason || '该检材疑似合成/占位样本'}`
    : (blocked.length
        ? `有 ${blocked.length} 项数据源不可用，结论已自动降级`
        : `有 ${downg.length} 项数据源缺失，结论已受限`);

  host.appendChild(degradeCard({
    level,
    title,
    lines: syn ? [
      '⛔ ' + (syn.suggestion || syn.reason),
      'MemProcFS/vol3 需要真实内核镜像；memstrings/static 无符号依赖，合成样本也能出字符串/进程名。',
    ] : [
      blocked.length ? '⛔ ' + blocked[0].reason : '',
      downg.length ? '⚠️ ' + downg[0].reason : '',
      '降级不等于失败：缺失项已写进报告「缺口清单」，结论强度按上限标注。',
    ],
    raw: gaps.slice(0, 6)
      .map(g => `· [${g.dimension || g.source || '—'}] ${g.reason}\n  → ${g.suggestion || ''}`)
      .join('\n'),
    actions: [
      { label: '查看完整缺口清单', cls: 'btn-primary', run: () => showTab('compliance') },
      { label: '⚡ 无符号兜底分析', cls: '', run: async () => {
          toast('已切换 memstrings 兜底引擎并重跑', 'ok');
          log('兼容分析：切换 memstrings 兜底引擎重跑', 'step');
          await startAnalysis();
        } },
      { label: '重试本次分析', cls: '', run: () => startAnalysis() },
    ],
  }));
}

/* ───────────────── 初始化 ───────────────── */

/* ───────────────── 跨产物检索 ───────────────── */
async function runSearch() {
  const q = $('srQuery').value.trim();
  if (!q) { toast('请输入检索式', 'err'); return; }
  const btn = $('srRun');
  btn.disabled = true;
  $('srResult').innerHTML = '<div class="empty">检索中…</div>';
  try {
    const d = await api('/api/search', {
      method: 'POST', timeout: 120000,
      body: {
        case_id: $('srAll').checked ? '' : (S.caseId || ''),
        query: q,
        scopes: $('srScope').value,
        regex: $('srRegex').checked,
        limit: 300,
      },
    });
    renderSearch(d);
    log(`检索「${d.parsed}」命中 ${d.count} 条（${d.elapsed}s）`, 'step');
  } catch (e) {
    $('srResult').innerHTML = '<div class="empty">检索失败：' + e.message + '</div>';
    toast('检索失败：' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

function renderSearch(d) {
  const box = $('srResult');
  box.innerHTML = '';
  $('srMeta').textContent = `${d.parsed} · 命中 ${d.count} 条 · ${d.elapsed}s`;
  if (!d.hits.length) {
    box.appendChild(el('div', 'empty', '没有命中。试试更短的词，或换字段过滤（如 name: / pid:）。'));
    return;
  }
  const cols = ['scope', 'source', 'row_no', 'ts', 'context'];
  const LABEL = { scope: '范围', source: '来源', row_no: '行', ts: '时间(UTC)', context: '命中上下文' };
  const wrap = el('div', 'table-wrap');
  const tbl = el('table', 'data');
  const th = el('thead');
  const htr = el('tr');
  cols.forEach(c => htr.appendChild(el('th', '', LABEL[c] || c)));
  th.appendChild(htr);
  tbl.appendChild(th);
  const tb = el('tbody');
  d.hits.forEach(h => {
    const tr = el('tr');
    cols.forEach(c => {
      let v = h[c];
      if (v === null || v === undefined) v = '';
      v = String(v);
      const td = el('td', c === 'context' ? 'clip' : (c === 'ts' ? 'mono' : ''), v);
      td.title = v;
      tr.appendChild(td);
    });
    tr.addEventListener('click', () => {
      if (h.source && S.artifacts) {
        const a = S.artifacts.find(x => x.plugin === h.source);
        if (a) { showTab('artifacts'); openDrawer(a); }
      }
    });
    tb.appendChild(tr);
  });
  tbl.appendChild(tb);
  wrap.appendChild(tbl);
  box.appendChild(wrap);
  box.appendChild(el('div', 'muted', `共 ${d.hits.length} 条（点击行可跳到对应产物）`));
}

async function runContainerSearch() {
  const path = $('srCtPath').value.trim();
  if (!path) { toast('请先填写容器文件路径', 'err'); return; }
  const btn = $('srCtRun');
  btn.disabled = true;
  $('srResult').innerHTML = '<div class="empty">容器内检索中…（大容器可能较慢）</div>';
  try {
    const d = await api('/api/search', {
      method: 'POST', timeout: 900000,
      body: {
        container: path,
        password: $('srCtPw').value || '',
        query: $('srQuery').value.trim(),
        regex: $('srRegex').checked,
        limit: 200,
      },
    });
    renderSearch(d);
    log(`容器检索「${d.parsed}」命中 ${d.count} 条`, 'step');
  } catch (e) {
    $('srResult').innerHTML = '<div class="empty">容器检索失败：' + e.message + '</div>';
    toast('容器检索失败：' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

function bindSearchUI() {
  const run = $('srRun');
  if (run) run.addEventListener('click', runSearch);
  const q = $('srQuery');
  if (q) q.addEventListener('keydown', e => { if (e.key === 'Enter') runSearch(); });
  const cr = $('srCtRun');
  if (cr) cr.addEventListener('click', runContainerSearch);
}

/* ───────────────── 取证容器通道 ───────────────── */
async function ctAnalyze(kind) {
  const path = $('ctPath').value.trim();
  if (!path) { toast('请先填写目标文件路径', 'err'); return; }
  const btn = $('ctRun');
  btn.disabled = true;
  $('ctResult').innerHTML = '<div class="empty">分析中…</div>';
  try {
    const body = {
      target: path, kind: kind,
      password: $('ctPw').value || '',
      path: $('ctInner').value || '',
      traffic: $('ctTraffic').value || 'interfaces',
      lv: $('ctLv').value || 'root',
      scan: $('ctScan').value || '1',
      ino: $('ctIno').value || '',
      mode: $('ctMode').value || '',
      list: $('ctMode').value || '',
      limit: $('ctLimit').value || '',
    };
    const d = await api('/api/container/analyze', { method: 'POST', body, timeout: 600000 });
    renderContainer(d);
    log(`容器分析：${kind} → ${(d.rows || []).length} 行`, 'step');
  } catch (e) {
    $('ctResult').innerHTML = '<div class="empty">分析失败：' + e.message + '</div>';
    toast('分析失败：' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

function renderContainer(d) {
  const box = $('ctResult');
  box.innerHTML = '';
  if (d.info) {
    const tbl = el('table', 'data');
    const tb = el('tbody');
    Object.entries(d.info).forEach(([k, v]) => {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', k));
      tr.appendChild(el('td', '', String(v)));
      tb.appendChild(tr);
    });
    tbl.appendChild(tb);
    box.appendChild(tbl);
    $('ctMeta').textContent = `类型：${d.info['类型'] || '—'}`;
    return;
  }
  const rows = d.rows || [];
  if (!rows.length) { box.appendChild(el('div', 'empty', '(无记录)')); return; }
  const cols = Object.keys(rows[0]);
  const wrap = el('div', 'table-wrap');
  const tbl = el('table', 'data');
  const th = el('thead');
  const htr = el('tr');
  cols.forEach(c => htr.appendChild(el('th', '', c)));
  th.appendChild(htr);
  tbl.appendChild(th);
  const tb = el('tbody');
  rows.forEach(r => {
    const tr = el('tr');
    cols.forEach(c => {
      const v = String(r[c] === undefined || r[c] === null ? '' : r[c]);
      const td = el('td', v.length > 120 ? 'clip' : 'mono', v.replace(/\n/g, ' '));
      td.title = v;
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
  tbl.appendChild(tb);
  wrap.appendChild(tbl);
  box.appendChild(wrap);
  box.appendChild(el('div', 'muted', `共 ${rows.length} 行`));
}

function bindContainerUI() {
  const kind = $('ctKind');
  const sync = () => {
    const k = kind.value;
    $('ctTraffic').style.display = k === 'traffic' ? '' : 'none';
    $('ctInner').style.display = k === 'extract' ? '' : 'none';
    const xfs = (k === 'xfs' || k === 'xfs_read');
    $('ctLv').style.display = xfs ? '' : 'none';
    $('ctScan').style.display = (k === 'xfs') ? '' : 'none';
    $('ctIno').style.display = (k === 'xfs' || k === 'xfs_read') ? '' : 'none';
    $('ctMode').style.display = xfs ? '' : 'none';
    $('ctLimit').style.display = xfs ? '' : 'none';
    $('ctMode').placeholder = (k === 'xfs_read') ? 'mode: save/text/hex' : 'list: top/空';
    $('ctLimit').placeholder = (k === 'xfs') ? 'limit 200' : 'limit(字节) 0';
  };
  kind.addEventListener('change', sync);
  sync();
  $('ctIdentify').addEventListener('click', () => ctAnalyze('identify'));
  $('ctRun').addEventListener('click', () => ctAnalyze(kind.value));
}

function initV2() {
  // 控制台
  const head = $('consoleHead');
  if (head) head.addEventListener('click', async (e) => {
    if (e.target.id === 'btnConsoleClear') return;
    consoleSetCollapsed(!CONSOLE.collapsed);
  });
  const clr = $('btnConsoleClear');
  if (clr) clr.addEventListener('click', (e) => {
    e.stopPropagation();
    CONSOLE.lines = [];
    $('consoleBody').innerHTML = '';
  });
  consoleSetCollapsed(true);

  // 状态栏
  sbTick();
  if (_sbTimer) clearInterval(_sbTimer);
  _sbTimer = setInterval(sbTick, 2000);
  api('/api/health').then(h => {
    const e = (h.engines || []).filter(x => x.available).map(x => x.name);
    sbEngine(e.join(' / ') || '—');
    const v = $('sbVer');
    if (v && h.version) v.textContent = 'v' + h.version;
  }).catch(() => {});

  // 向导
  const wc = $('wzClose');
  if (wc) wc.addEventListener('click', wzClose);
  const wz = $('wizard');
  if (wz) wz.addEventListener('click', e => { if (e.target === wz) wzClose(); });

  // 分析分组导航
  renderAnalysisGroups();

  // 「打开证据」走向导而不是直接进文件浏览器
  const bo = $('btnOpen');
  if (bo) {
    const clone = bo.cloneNode(true);
    bo.parentNode.replaceChild(clone, bo);
    clone.addEventListener('click', () => wzOpen(null));
  }

  // 文件浏览器选中文件后 → 进向导第 2 步
  const pick = $('fsPickBtn');
  if (pick) {
    const c2 = pick.cloneNode(true);
    pick.parentNode.replaceChild(c2, pick);
    c2.addEventListener('click', () => {
      const p = ($('fsPick').value || '').trim();
      if (!p) { toast('请先选择文件', 'err'); return; }
      $('fsModal').classList.add('hidden');
      wzOpen(p);
    });
  }

  // 分组导航（v3，对标 LovelyMem V3 的左栏分组）
  if (typeof bindNav === 'function') bindNav();
  // 取证容器通道
  if (typeof bindContainerUI === 'function') bindContainerUI();
  // 跨产物检索
  if (typeof bindSearchUI === 'function') bindSearchUI();
  // 浏览器历史 / 境外 IP 风险报告
  if (typeof bindBrowserUI === 'function') bindBrowserUI();
  if (typeof bindWebLog === 'function') bindWebLog();
  if (typeof bindServer === 'function') bindServer();

  consolePush('MemLens 控制台就绪', 'ok');
  log('界面 v3 已加载：分组导航 / 向导 / 控制台 / 状态栏', 'step');
  sbPhase('等待');
}

/** 取路径最后一段（跨平台）。 */
function basename(p) {
  return String(p || '').replace(/[\\/]+$/, '').split(/[\\/]/).pop() || String(p || '');
}

/** 浏览器历史 / 境外 IP 风险报告：绑定 UI（可视化入口）。 */
function bindBrowserUI() {
  const btn = $('brScan');
  if (!btn) return;
  const c = btn.cloneNode(true);
  btn.parentNode.replaceChild(c, btn);
  c.addEventListener('click', () => scanBrowser());
}

/** 网站日志分析 / 扫描器解析（WP 0x05 服务器取证，可视化入口）。 */
function bindWebLog() {
  const l = $('wlLogBtn'), s = $('wlScanBtn');
  if (!l || !s) return;
  const cl = l.cloneNode(true); l.parentNode.replaceChild(cl, l);
  const cs = s.cloneNode(true); s.parentNode.replaceChild(cs, s);
  cl.addEventListener('click', () => runWebLog('log'));
  cs.addEventListener('click', () => runWebLog('scan'));
}

/** 调 /api/web-log/analyze 或 /api/scanner/parse。 */
async function runWebLog(kind) {
  const host = $('wlResult');
  if (!host) return;
  const path = ($('wlPath') && $('wlPath').value.trim()) || '';
  const text = ($('wlText') && $('wlText').value) || '';
  if (!path && !text) { host.innerHTML = '<div class="empty">请填日志路径或粘贴内容</div>'; return; }
  host.innerHTML = '<div class="empty">分析中…</div>';
  try {
    const body = JSON.stringify({ text, path });
    if (kind === 'log') {
      const r = await api('/api/web-log/analyze', { method: 'POST', body });
      renderWebLog(r, host);
    } else {
      const r = await api('/api/scanner/parse', { method: 'POST', body });
      renderScanner(r, host);
    }
  } catch (e) { host.innerHTML = `<div class="empty">失败：${esc(e.message)}</div>`; }
}

function renderWebLog(r, host) {
  const s = r.summary || {};
  let h = `<b>日志分析</b>：共 <b>${s.total_lines || 0}</b> 行 · 可疑 <b>${s.suspicious_count || 0}</b>`
    + ` · 攻击者 <b>${s.attacker_count || 0}</b> · 木马 <b>${s.webshell_count || 0}</b>`;
  const at = r.attackers || [];
  if (at.length) {
    h += '<table class="kv" style="margin:8px 0"><thead><tr><th>攻击者IP</th><th>请求</th>'
      + '<th>可疑</th><th>上传</th></tr></thead><tbody>';
    for (const a of at.slice(0, 20)) {
      h += `<tr><td><b>${esc(a.ip)}</b></td><td>${a.requests}</td><td>${a.suspicious}</td><td>${a.uploads}</td></tr>`;
    }
    h += '</tbody></table>';
  }
  const ws = r.webshell || [];
  if (ws.length) {
    h += '<b>一句话木马</b><ul>';
    for (const w of ws) h += `<li><code>${esc(w.sha256)}</code><br><span class="muted">${esc(w.snippet)}</span></li>`;
    h += '</ul>';
  }
  host.innerHTML = h;
}

function renderScanner(r, host) {
  const items = r.items || [];
  let h = `<b>扫描器解析</b>：${items.length} 个 URL · ${(r.icmp_hosts || []).length} 个 ICMP 存活主机`;
  if (items.length) {
    h += '<table class="kv" style="margin:8px 0"><thead><tr><th>风险</th><th>归属</th>'
      + '<th>URL</th><th>端口</th><th>title/指纹</th></tr></thead><tbody>';
    for (const it of items) {
      const flag = it.country === '境外（疑似）' ? '境外'
        : it.country === '内网' ? '内网' : it.ip ? '境内' : '待解析';
      h += `<tr><td>${esc(it.risk)}</td><td>${flag}</td><td>${esc(it.url)}</td>`
        + `<td>${it.port || '-'}</td><td class="muted">${esc(it.title || it.fingerprint || '')}</td></tr>`;
    }
    h += '</tbody></table>';
  }
  host.innerHTML = h;
}

/** 服务器文件级取证（WP 0x05：wtmp/passwd/trojan/php/sql，可视化入口）。 */
function bindServer() {
  const b = $('svRun');
  if (!b) return;
  const c = b.cloneNode(true); b.parentNode.replaceChild(c, b);
  c.addEventListener('click', () => runServer());
}

async function runServer() {
  const host = $('svResult');
  if (!host) return;
  const kind = $('svKind') ? $('svKind').value : 'wtmp';
  const path = ($('svPath') && $('svPath').value.trim()) || '';
  const password = ($('svPassword') && $('svPassword').value) || '';
  if (!path) { host.innerHTML = '<div class="empty">请填文件路径</div>'; return; }
  host.innerHTML = '<div class="empty">分析中…</div>';
  try {
    const r = await api('/api/server/analyze', {
      method: 'POST', body: JSON.stringify({ kind, path, password }),
    });
    renderServer(kind, r, host);
  } catch (e) { host.innerHTML = `<div class="empty">失败：${esc(e.message)}</div>`; }
}

function renderServer(kind, r, host) {
  let h = '';
  if (kind === 'wtmp') {
    h = `<b>开机时间</b>：${r.boot_count} 次，最早 <b>${esc(r.earliest)}</b>，最新 ${esc(r.latest)}`;
  } else if (kind === 'passwd') {
    h = `<b>用户数</b>：${r.count}（uid==0 或 uid>=1000）<br>`
      + (r.users || []).map(u => `${esc(u.name)} (uid=${u.uid}, ${esc(u.shell)})`).join('<br>');
  } else if (kind === 'trojan') {
    h = `<b>Trojan</b>：run_type=<code>${esc(r.run_type || '-')}</code>  `
      + `local=${esc(r.local_addr)}:${r.local_port}  remote=<b>${esc(r.remote_addr)}</b>:${r.remote_port}`
      + `<br>域名：<b>${esc(r.remote_domain || '-')}</b>`;
  } else if (kind === 'php') {
    h = `<b>AUTH_CODE</b>=<code>${esc(r.auth_code || '-')}</code> 算法=${esc(r.algorithm)}`;
    for (const [pw, hh] of Object.entries(r.hashes || {})) {
      h += `<br>md5('${esc(r.auth_code)}'+'${esc(pw)}') = <code>${hh}</code>`;
    }
  } else if (kind === 'sql') {
    h = `<b>订单数</b>（2016-04-01~2025-04-01）：<b>${r.orders}</b>`;
    if (r.gap && r.gap.best) {
      h += `<br>注册→首单最短用户：<b>${esc(r.gap.best.user_id)}</b> 间隔 ${r.gap.best.gap}s`;
    }
  }
  host.innerHTML = h || '<div class="empty">无结果</div>';
}

/** 扫描浏览器历史 + 境外 IP 风险（调 /api/browser/scan）。 */
async function scanBrowser() {
  const host = $('brResult');
  if (!host) return;
  const appdata = ($('brAppdata') && $('brAppdata').value.trim()) || '';
  const allDrives = $('brAllDrives') ? $('brAllDrives').checked : false;
  const resolve = $('brResolve') ? $('brResolve').checked : false;
  host.innerHTML = '<div class="empty">扫描中…（只读副本，不上传）</div>';
  try {
    const r = await api('/api/browser/scan', {
      method: 'POST',
      body: JSON.stringify({ appdata, all_drives: allDrives, resolve }),
    });
    const src = r.sources || [];
    const rep = r.report || {};
    const sum = rep.summary || {};
    let h = `<b>发现 ${src.length} 个浏览器历史库</b>`
      + (appdata ? `（AppData: ${esc(appdata)}）` : '')
      + (allDrives ? '（全盘）' : '');
    if (!src.length) h += ' <span class="muted">—— 未发现，可能没装浏览器或历史被清理。</span>';
    if (src.length) {
      h += '<table class="kv" style="margin:8px 0"><tbody>';
      for (const s of src.slice(0, 40)) {
        h += `<tr><td><b>${esc(s.browser)}</b></td>`
          + `<td class="muted">${esc(s.profile)} · ${s.size_mb} MB · ${esc(s.path)}</td></tr>`;
      }
      if (src.length > 40) h += `<tr><td class="muted" colspan="2">… 还有 ${src.length - 40} 个</td></tr>`;
      h += '</tbody></table>';
    }
    h += '<div class="card" style="margin-top:10px"><div class="card-head">'
      + '<h3>境外 IP / 风险摘要</h3></div><div class="card-body">';
    const br = (sum.by_risk || {});
    h += `<p>访问 <b>${sum.total || 0}</b> 条 · 境外（疑似）<b style="color:#c0392b">${sum.overseas_count || 0}</b> 条`
      + ` · 风险 高<b style="color:#c0392b">${br['高'] || 0}</b> / 中<b style="color:#e67e22">${br['中'] || 0}</b> / 低<b>${br['低'] || 0}</b></p>`;
    const ov = rep.overseas_access || [];
    if (ov.length) {
      h += '<table class="kv"><thead><tr><th>时间</th><th>浏览器</th><th>域名</th><th>IP</th>'
        + '<th>归属</th><th>风险</th><th>原因</th></tr></thead><tbody>';
      for (const o of ov.slice(0, 120)) {
        const rc = o.risk === '高' ? 'color:#c0392b;font-weight:600'
          : (o.risk === '中' ? 'color:#e67e22' : '');
        h += `<tr><td>${esc(o.visited_at || '')}</td><td>${esc(o.browser || '')}</td>`
          + `<td>${esc(o.host || '')}</td><td>${esc(o.ip || '-')}</td><td>${esc(o.country || '')}</td>`
          + `<td style="${rc}">${esc(o.risk || '')}</td>`
          + `<td>${esc((o.reasons || []).slice(0, 3).join('；'))}</td></tr>`;
      }
      h += '</tbody></table>';
    } else {
      h += '<div class="muted">未发现境外（疑似）地址访问。</div>';
    }
    h += '</div></div>';
    host.innerHTML = h;
    if (typeof toast === 'function') {
      toast(`浏览器扫描完成：${src.length} 库 / ${sum.total || 0} 访问 / ${sum.overseas_count || 0} 境外`, 'ok');
    }
  } catch (e) {
    host.innerHTML = `<div class="empty">扫描失败：${esc(e && (e.message || e) || e)}</div>`;
  }
}
