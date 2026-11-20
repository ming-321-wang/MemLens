
/* ═══════════════════════════════════════════════════════════════════════
   v3 导航栏（对标 LovelyMem V3 的分组导航）
     · 搜索过滤（`/` 聚焦，Esc 清空）
     · 分组折叠展开，组内子项直达「切页签 / 开产物 / 触发工具」
     · 角标实时反映 发现项 / 旗标 / 缺口
   叶子动作三种类型：
     { tab: 'findings' }        → 切换页签
     { artifact: 'mprocfs.net' } → 切到产物页并打开该产物的记录抽屉
     { tool: 'sysinfo' }         → 触发按需取证工具（登记进证据模型）
   ═══════════════════════════════════════════════════════════════════════ */

const NAV_TREE = [
  { id: 'search', icon: '🔍', name: '检索', children: [
    { label: '跨产物检索', tab: 'search' },
    { label: '证据表', tab: 'artifacts' },
    { label: '结论与时间线', tab: 'findings' },
  ]},
  { id: 'sysinfo', icon: 'ⓘ', name: '系统信息', children: [
    { label: '结论速览', tab: 'overview' , k: ['summary', 'verdict', 'conclusion']},
    { label: '系统画像', tab: 'overview' , k: ['profile', 'sysinfo', 'system']},
    { label: '机器信息重取', tool: 'sysinfo' , k: ['sysinfo', 'machine']},
    { label: '虚拟化检测', tool: 'vmscan' , k: ['vmscan', 'vm', 'virtualbox', 'vmware']},
  ]},
  { id: 'process', icon: '▤', name: '进程分析', children: [
    { label: '进程列表', artifact: 'mprocfs.process' , k: ['process', 'pslist', 'tasklist', 'mprocfs.process']},
    { label: '命令行', artifact: 'mprocfs.cmdlines' , k: ['cmdline', 'commandline', 'mprocfs.cmdlines']},
    { label: '隐藏进程 / 注入', tab: 'findings' , k: ['hidden', 'injection', 'findevil', 'malware']},
    { label: '异常内存命中', artifact: 'mprocfs.findevil' , k: ['findevil', 'entropy', 'rwx', 'mprocfs.findevil']},
  ]},
  { id: 'network', icon: '⊕', name: '网络分析', children: [
    { label: '连接表', artifact: 'mprocfs.net' , k: ['net', 'netscan', 'connection', 'socket', 'mprocfs.net']},
    { label: 'DNS 缓存', artifact: 'mprocfs.netdns' , k: ['netdns', 'dns', 'domain', 'mprocfs.netdns']},
    { label: '浏览器记录（本机）', tab: 'tools' , k: ['browser', 'history', 'chrome', 'edge', 'firefox']},
  ]},
  { id: 'file', icon: '▢', name: '文件分析', children: [
    { label: '全部产物', tab: 'artifacts' , k: ['artifact', 'plugin', 'output']},
    { label: '未释放文件', tool: 'files' , k: ['files', 'memory_files', 'mft', 'deleted', 'unlinked']},
    { label: '导出可疑进程内存', tool: 'process_dump' , k: ['process_dump', 'dump', 'vad']},
  ]},
  { id: 'mount', icon: '💿', name: '镜像挂载', children: [
    { label: '镜像挂载', tab: 'mount' , k: ['mount', 'image', 'partition', 'filesystem', 'veracrypt', 'carve', 'hash']},
  ]},
  { id: 'registry', icon: '⌸', name: '注册表', children: [
    { label: '自启动项', artifact: 'mprocfs.registry_run' , k: ['run', 'runonce', 'autorun', 'startup', 'persistence', 'registry_run']},
    { label: '代理配置', artifact: 'mprocfs.registry_proxy' , k: ['proxy', 'internet settings', 'autoconfigurl', 'registry_proxy']},
    { label: '注册表配置单元', artifact: 'mprocfs.registry_hives' , k: ['hive', 'reghive', 'sam', 'system', 'software', 'registry_hives']},
  ]},
  { id: 'malware', icon: '⛨', name: '恶意分析', children: [
    { label: '发现项', tab: 'findings', badge: 'findings' , k: ['finding', 'detection', 'alert']},
    { label: 'IOC 情报', tab: 'intel' , k: ['ioc', 'intel', 'threat']},
    { label: '旗标候选', tab: 'flags', badge: 'flags' , k: ['flag', 'ctf', 'keyword']},
  ]},
  { id: 'credential', icon: '⌘', name: '凭据与加密', children: [
    { label: '用户与 SID', tab: 'users' , k: ['user', 'sid', 'account', 'sam']},
    { label: '环境变量', tool: 'envs' , k: ['env', 'envs', 'environment', 'variable']},
    { label: '字节快扫 flag', tool: 'flag' , k: ['flag', 'scan', 'bytes', 'pattern']},
  ]},
  { id: 'activity', icon: '☺', name: '用户活动痕迹', children: [
    { label: '时间线事件', tab: 'timeline' , k: ['timeline', 'event', 'chronology']},
    { label: '字典命中', tab: 'intel' , k: ['dictionary', 'dict', 'wordlist']},
  ]},
  { id: 'timeline', icon: '◷', name: '时间线分析', children: [
    { label: '统一时间线（UTC）', tab: 'timeline' , k: ['timeline', 'utc', 'chrono']},
  ]},
  { id: 'strings', icon: '🔍', name: '字符串搜索', children: [
    { label: '内存字符串产物', artifact: 'memstrings' , k: ['strings', 'memstrings', 'ascii', 'unicode', 'filescan']},
    { label: '产物记录检索', tab: 'artifacts' , k: ['record', 'search', 'query']},
  ]},
  { id: 'manual', icon: '🔧', name: '手动工作台', children: [
    { label: '手动分析工作台', tab: 'tools' , k: ['manual', 'workbench', 'plugin']},
    { label: '无符号分析（memstrings 兜底）', tab: 'tools' , k: ['nosymbol', 'no-symbol', 'memstrings', 'fallback', 'options']},
    { label: '五维判定', tab: 'compliance' , k: ['dimension', 'five', 'cross-border', 'compliance']},
  ]},
  { id: 'compliance', icon: '⚖', name: '合规与出证', children: [
    { label: '五维判定', tab: 'compliance' },
    { label: '缺口清单', tab: 'compliance', badge: 'gaps' , k: ['gap', 'missing', 'degrade']},
    { label: '审计哈希链', tab: 'compliance' , k: ['audit', 'hashchain', 'chain', 'log']},
    { label: '规则包', tab: 'compliance' , k: ['rulepack', 'threshold', 'whitelist', 'rules']},
  ]},
  { id: 'log', icon: '≡', name: '日志', children: [
    { label: '控制台日志', tab: 'log' , k: ['log', 'console', 'output']},
  ]},
];

/** 页签 → 面包屑分组名 */
const NAV_GROUP_OF = {
  overview: '系统信息', tools: '手动工作台', artifacts: '文件分析',
  timeline: '时间线分析', findings: '恶意分析', intel: '恶意分析',
  flags: '恶意分析', compliance: '合规与出证', users: '凭据与加密',
  mount: '镜像挂载', log: '日志',
};

function renderNav() {
  const box = $('navTree');
  if (!box) return;
  box.innerHTML = '';
  NAV_TREE.forEach(g => {
    const gEl = el('div', 'ngroup');
    gEl.dataset.group = g.id;
    if (g.open) gEl.classList.add('open');

    const head = el('div', 'ngroup-head');
    head.appendChild(el('span', 'ng-icon', g.icon));
    head.appendChild(el('span', 'ng-name', g.name));
    head.appendChild(el('span', 'ng-badge hidden'));
    head.appendChild(el('span', 'ng-caret', '▶'));
    head.addEventListener('click', () => {
      gEl.classList.toggle('open');
      g.open = gEl.classList.contains('open');
    });
    gEl.appendChild(head);

    const kids = el('div', 'nav-kids');
    g.children.forEach(c => {
      const lf = el('div', 'nleaf');
      lf.dataset.label = c.label;
      if (c.tab) lf.dataset.tab = c.tab;
      if (c.artifact) lf.dataset.artifact = c.artifact;
      if (c.tool) lf.dataset.tool = c.tool;
      if (c.k) lf.dataset.keys = c.k.join(' ');
      // 「该叶子最终会落到哪个页签」——用于高亮同步
      lf.dataset.effTab = c.tab || (c.artifact ? 'artifacts' : (c.tool ? 'tools' : ''));
      lf.appendChild(el('span', 'nl-dot'));
      lf.appendChild(el('span', 'nleaf-label', c.label));
      if (c.badge) {
        const b = el('span', 'nl-badge hidden');
        b.dataset.badge = c.badge;
        lf.appendChild(b);
      }
      lf.addEventListener('click', () => navGoto(g, c, lf));
      kids.appendChild(lf);
    });
    gEl.appendChild(kids);
    box.appendChild(gEl);
  });
  syncNavBadges();
  updateNavMeta();
}

function navGoto(group, leaf, node) {
  document.querySelectorAll('.nleaf').forEach(x => x.classList.remove('active'));
  if (node) node.classList.add('active');
  _navPinned = {
    effTab: leaf.tab || (leaf.artifact ? 'artifacts' : (leaf.tool ? 'tools' : '')),
    label: leaf.label,
    group: group.name,
  };
  // 面包屑
  const cg = $('crumbGroup'), ci = $('crumbItem');
  if (cg) cg.textContent = group.name;
  if (ci) ci.textContent = leaf.label;
  const gEl = node ? node.closest('.ngroup') : null;
  if (gEl) { gEl.classList.add('open'); }

  if (leaf.artifact) {
    openArtifact(leaf.artifact);
    log(`导航 → ${group.name} / ${leaf.label}（产物 ${leaf.artifact}）`, 'step');
  } else if (leaf.tool) {
    showTab('tools');
    const btn = document.querySelector(`.tool-btn[data-tool="${leaf.tool}"]`);
    if (btn && !btn.disabled) { btn.click(); log(`导航 → 触发工具 ${leaf.tool}`, 'step'); }
    else if (btn) { toast('该工具需要先打开案件', 'err'); }
    else {
      // sysinfo / vmscan 在工具页是独立按钮
      const map = { sysinfo: 'btnSysRefresh', vmscan: 'btnVmscan' };
      const b2 = map[leaf.tool] ? $(map[leaf.tool]) : null;
      if (b2 && !b2.disabled) b2.click();
    }
  } else if (leaf.tab) {
    showTab(leaf.tab);
    log(`导航 → ${group.name} / ${leaf.label}`, 'step');
  }
}

/** 页签切换后同步导航高亮与面包屑（由 showTab 调用）。 */
/** 手动点击导航钉住的叶子 —— 防止被页签级同步覆盖掉。 */
let _navPinned = null;   // { effTab, label, group }

function navSyncActive(tab) {
  // ★ 若当前活跃叶子是**手动点进来的**，且它最终也落在同一个页签上，
  //   就保留它（否则点「进程列表」会被同步逻辑改回「全部产物」——实测踩过）。
  const cur = document.querySelector('.nleaf.active');
  if (_navPinned && cur && cur.dataset.effTab === tab
      && cur.dataset.label === _navPinned.label) {
    const cg = $('crumbGroup'), ci = $('crumbItem');
    if (cg) cg.textContent = _navPinned.group;
    if (ci) ci.textContent = _navPinned.label;
    return;
  }
  _navPinned = null;

  const gname = NAV_GROUP_OF[tab];
  if (gname) {
    const cg = $('crumbGroup');
    if (cg) cg.textContent = gname;
  }
  const cands = [...document.querySelectorAll('.nleaf')].filter(x => x.dataset.effTab === tab);
  if (cur && cur.dataset.effTab === tab) return;
  document.querySelectorAll('.nleaf').forEach(x => x.classList.remove('active'));
  if (cands.length) {
    cands[0].classList.add('active');
    const ci = $('crumbItem');
    if (ci) ci.textContent = cands[0].dataset.label;
    const g = cands[0].closest('.ngroup');
    if (g) g.classList.add('open');
  }
}

/** 角标：从既有 pill 元素同步，不另造数据源。 */
function syncNavBadges() {
  const src = {
    findings: $('pillFindings'),
    flags: $('pillFlags'),
    gaps: $('pillGaps'),
  };
  const want = {};
  Object.entries(src).forEach(([k, node]) => {
    const v = node ? String(node.textContent).trim() : '';
    want[k] = (v && v !== '0') ? v : '';
  });
  document.querySelectorAll('.nl-badge').forEach(b => {
    const key = b.dataset.badge;
    const v = want[key];
    b.textContent = v || '';
    b.classList.toggle('hidden', !v);
    b.classList.toggle('hot', key === 'gaps' && !!v);
  });
  // 组角标：取组内子项角标之和（有就显示）
  NAV_TREE.forEach(g => {
    const gEl = document.querySelector(`.ngroup[data-group="${g.id}"]`);
    if (!gEl) return;
    let n = 0;
    g.children.forEach(c => { if (c.badge && want[c.badge]) n += parseInt(want[c.badge], 10) || 0; });
    const b = gEl.querySelector('.ng-badge');
    if (!b) return;
    if (n > 0) { b.textContent = String(n); b.classList.remove('hidden'); b.classList.toggle('hot', n >= 20); }
    else { b.classList.add('hidden'); }
  });
  updateNavMeta();
}

function updateNavMeta() {
  const m = $('navMeta');
  if (!m) return;
  const total = NAV_TREE.reduce((a, g) => a + g.children.length, 0);
  m.textContent = `${NAV_TREE.length} 组 / ${total} 项`;
}

/* ── 搜索过滤 ── */
function navFilter(q) {
  const box = $('navTree');
  if (!box) return;
  const kw = String(q || '').trim().toLowerCase();
  if (!kw) {
    box.classList.remove('filtered');
    document.querySelectorAll('.ngroup').forEach(g => {
      g.classList.remove('hit');
      const def = NAV_TREE.find(x => x.id === g.dataset.group);
      g.classList.toggle('open', !!(def && def.open));
    });
    return;
  }
  box.classList.add('filtered');
  document.querySelectorAll('.ngroup').forEach(g => {
    const def = NAV_TREE.find(x => x.id === g.dataset.group);
    if (!def) return;
    const gHit = def.name.toLowerCase().includes(kw);
    let any = gHit;
    g.querySelectorAll('.nleaf').forEach(lf => {
      // 检索面：中文名 + 英文/插件别名 + 页签 + 产物名 + 工具名
      const hay = [lf.dataset.label || '', lf.dataset.keys || '',
                   lf.dataset.tab || '', lf.dataset.artifact || '',
                   lf.dataset.tool || ''].join(' ').toLowerCase();
      const hit = gHit || hay.includes(kw);
      lf.classList.toggle('hidden', !hit);
      if (hit) any = true;
    });
    g.classList.toggle('hit', any);
  });
  const hits = document.querySelectorAll('.ngroup.hit').length;
  const m = $('navMeta');
  if (m) m.textContent = hits ? `${hits} 组命中` : '无匹配';
}

function bindNav() {
  renderNav();
  const s = $('navSearch');
  if (s) {
    s.addEventListener('input', () => navFilter(s.value));
    s.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { s.value = ''; navFilter(''); s.blur(); }
    });
  }
  const ca = $('navCollapseAll');
  if (ca) ca.addEventListener('click', () => {
    document.querySelectorAll('.ngroup').forEach(g => {
      g.classList.remove('open');
      const def = NAV_TREE.find(x => x.id === g.dataset.group);
      if (def) def.open = false;
    });
  });
  // `/` 聚焦搜索（输入框内不劫持）
  document.addEventListener('keydown', (e) => {
    if (e.key !== '/' || e.ctrlKey || e.metaKey) return;
    const t = e.target;
    const tag = (t && t.tagName) || '';
    if (tag === 'INPUT' || tag === 'TEXTAREA' || (t && t.isContentEditable)) return;
    const inp = $('navSearch');
    if (inp) { e.preventDefault(); inp.focus(); inp.select(); }
  });
  // 默认展开前两组，给个初始视野
  NAV_TREE[0].open = true;
  NAV_TREE[1].open = true;
  const g0 = document.querySelector(`.ngroup[data-group="${NAV_TREE[0].id}"]`);
  const g1 = document.querySelector(`.ngroup[data-group="${NAV_TREE[1].id}"]`);
  if (g0) g0.classList.add('open');
  if (g1) g1.classList.add('open');
  navSyncActive('overview');
}
