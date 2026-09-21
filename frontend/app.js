/* ============================================================
   Aiholey · 前端主逻辑（零依赖）
   ============================================================ */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/* ---------------- 认证：CSRF 令牌 + access 静默续期 ---------------- */

/**
 * 读 CSRF 令牌。
 *
 * 后端用 double-submit 模式：令牌同时存在于 cookie（非 httponly，所以 JS 读得到）
 * 和 access JWT 的签名声明里，写操作必须把它放进 `X-CSRF-Token` 头，两者比对通过才放行。
 * 攻击者的跨站请求带不上自定义头，也没法伪造被签名的声明。
 */
function csrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)aiholey_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

let refreshPromise = null;

/**
 * 用 refresh cookie 换新的 access token。
 *
 * 两个细节：
 * - **单例 Promise**：页面初始化时会并发发好几个请求，若各自触发续期，
 *   就是若干个同时打的刷新请求。共享同一个 Promise 只会刷新一次。
 * - **Web Locks 跨标签页串行化**：多标签页共享同一份 cookie，同时刷新会撞上
 *   后端的「刷新令牌轮换」——后到的那个拿着已被轮换掉的令牌，会被判成令牌复用。
 *   加锁让它们排队，第二个进去时 cookie 已经更新，就是正常流程。
 */
async function refreshAccessToken() {
  if (refreshPromise) return refreshPromise;
  const doRefresh = async () => {
    const r = await fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRF-Token': csrfToken() },
    });
    if (!r.ok) throw new Error('会话已过期');
    return r.json();
  };
  refreshPromise = (async () => {
    try {
      if (navigator.locks && navigator.locks.request) {
        return await navigator.locks.request('aiholey-token-refresh', doRefresh);
      }
      return await doRefresh();
    } finally {
      refreshPromise = null;
    }
  })();
  return refreshPromise;
}

let keepAliveTimer = 0;
let tokenExpiresAt = 0;

/**
 * 在 access token 到期前主动续期一次。
 *
 * 只靠「收到 401 再续期」也能工作，但那样每个周期都会有**一个真实请求先失败**——
 * 用户可能正好在点删除、提交表单，白挨一次报错。提前续期把这些失败挪到后台。
 * 页面切回前台时也要重新算：浏览器会节流后台标签页的定时器，挂久了计时器就不准了。
 */
function startTokenKeepAlive() {
  const apply = sec => {
    const n = Number(sec || 0);
    tokenExpiresAt = n > 0 ? Date.now() + n * 1000 : 0;
  };
  apply(state.me && state.me.token ? state.me.token.access_expires_in : 0);
  if (!tokenExpiresAt) return;

  const schedule = () => {
    clearTimeout(keepAliveTimer);
    // 提前 2 分钟续期；下限 15 秒防止在临界点上连打
    const delay = Math.max(15000, tokenExpiresAt - Date.now() - 120000);
    keepAliveTimer = setTimeout(tick, delay);
  };
  const tick = async () => {
    try {
      const d = await refreshAccessToken();
      apply(d.access_expires_in);
    } catch {
      tokenExpiresAt = 0;      // 续期失败就停掉轮询，交给下一次请求的 401 去跳登录
      return;
    }
    schedule();
  };
  schedule();
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible' || !tokenExpiresAt) return;
    if (Date.now() > tokenExpiresAt - 15000) tick(); else schedule();
  });
}

/* ---------------- 基础工具 ---------------- */
async function api(path, { method = 'GET', body, raw = false, retried = false } = {}) {
  const opt = { method, credentials: 'same-origin', headers: {} };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  if (!/^(GET|HEAD|OPTIONS)$/i.test(method)) {
    opt.headers['X-CSRF-Token'] = csrfToken();
  }

  const r = await fetch('/api' + path, opt);

  // access token 只有 30 分钟，过期是常态而不是异常——静默续期一次再重试原请求，
  // 用户不该因为令牌到期被弹回登录页。retried 保证只重试一次，不会无限循环。
  if (r.status === 401 && !retried && !path.startsWith('/auth/refresh')
      && !path.startsWith('/auth/login')) {
    try {
      await refreshAccessToken();
      return await api(path, { method, body, raw, retried: true });
    } catch { /* 续期失败 → 落到下面跳登录页 */ }
  }
  // 会话已失效（或续期也失败）：明确提示后再跳，避免用户以为是页面卡住
  if (r.status === 401) {
    if (!/^\/login/.test(location.pathname)) location.replace('/login?expired=1');
    throw new Error('登录已过期，请重新登录');
  }
  if (raw) {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.text();
  }
  let data = null;
  try { data = await r.json(); } catch { /* 空响应 */ }
  if (!r.ok) throw new Error(describeError(data, r.status));
  return data;
}

/** FastAPI 的校验错误 detail 是一个对象数组，直接塞进 Error 会变成 [object Object]。 */
function describeError(data, status) {
  const d = data && data.detail;
  if (typeof d === 'string' && d) return d;
  if (Array.isArray(d)) {
    return d.map(x => {
      const loc = Array.isArray(x.loc) ? x.loc.filter(p => p !== 'body' && p !== 'query').join('.') : '';
      return (loc ? loc + ': ' : '') + (x.msg || JSON.stringify(x));
    }).join('；') || `请求参数有误（HTTP ${status}）`;
  }
  if (d && typeof d === 'object') return JSON.stringify(d);
  return `请求失败（HTTP ${status}）`;
}

/** 组装查询串，自动丢掉空值，避免把 `repo_id=` 传给需要 int 的后端接口。 */
const qs = obj => Object.entries(obj)
  .filter(([, v]) => v !== '' && v !== null && v !== undefined)
  .map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');

function toast(msg, kind = 'ok', ms = 3200) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `<span class="ti">${kind === 'ok' ? '✅' : kind === 'err' ? '⛔' : 'ℹ️'}</span><span>${esc(msg)}</span>`;
  $('#toastWrap').appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 260); }, ms);
}

const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function fmtTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts * 1000);
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function fmtDur(ms) {
  if (!ms) return '-';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}
const SEV = { critical: '严重', high: '高危', medium: '中危', low: '低危' };
const STATUS = { pending: '待执行', queued: '排队中', running: '运行中', success: '完成', failed: '失败', stopped: '已停止' };
const RUN_LABEL = { pending: '待执行', queued: '排队中', running: '运行中', success: '成功', failed: '失败', stopped: '已停止' };
const sbadge = s => `<span class="badge ${s}">${STATUS[s] || s}</span>`;
function vulnStats(c, h, m, l) {
  return `<span class="vuln-stats"><span class="c">${c || 0}</span><span class="h">${h || 0}</span>` +
         `<span class="m">${m || 0}</span><span class="l">${l || 0}</span></span>`;
}

/* ---------------- 图表（手写 canvas） ---------------- */
function setupCanvas(cv) {
  const dpr = window.devicePixelRatio || 1;
  const rect = cv.getBoundingClientRect();
  cv.width = Math.max(1, rect.width * dpr);
  cv.height = Math.max(1, rect.height * dpr);
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w: rect.width, h: rect.height };
}

function drawTrend(cv, data) {
  const { ctx, w, h } = setupCanvas(cv);
  const pad = { t: 16, r: 12, b: 26, l: 32 };
  const iw = w - pad.l - pad.r, ih = h - pad.t - pad.b;
  const max = Math.max(1, ...data.map(d => d.total));
  ctx.clearRect(0, 0, w, h);
  // 网格
  ctx.strokeStyle = 'rgba(120,160,255,.10)'; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + ih * i / 4;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + iw, y); ctx.stroke();
    ctx.fillStyle = '#5d688f'; ctx.font = '10px -apple-system,sans-serif'; ctx.textAlign = 'right';
    ctx.fillText(String(Math.round(max * (4 - i) / 4)), pad.l - 6, y + 3);
  }
  const step = iw / Math.max(1, data.length - 1);
  const px = i => pad.l + step * i;
  const py = v => pad.t + ih - ih * (v / max);

  // 面积渐变
  const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + ih);
  grad.addColorStop(0, 'rgba(34,211,238,.34)');
  grad.addColorStop(1, 'rgba(139,92,246,0)');
  ctx.beginPath(); ctx.moveTo(px(0), py(data[0].total));
  data.forEach((d, i) => ctx.lineTo(px(i), py(d.total)));
  ctx.lineTo(px(data.length - 1), pad.t + ih); ctx.lineTo(px(0), pad.t + ih); ctx.closePath();
  ctx.fillStyle = grad; ctx.fill();

  // 折线
  const lg = ctx.createLinearGradient(pad.l, 0, pad.l + iw, 0);
  lg.addColorStop(0, '#22d3ee'); lg.addColorStop(1, '#8b5cf6');
  ctx.beginPath(); data.forEach((d, i) => i ? ctx.lineTo(px(i), py(d.total)) : ctx.moveTo(px(i), py(d.total)));
  ctx.strokeStyle = lg; ctx.lineWidth = 2.4; ctx.lineJoin = 'round'; ctx.stroke();

  // 数据点
  data.forEach((d, i) => {
    ctx.beginPath(); ctx.arc(px(i), py(d.total), 3.6, 0, 7);
    ctx.fillStyle = '#0b0f21'; ctx.fill();
    ctx.strokeStyle = '#22d3ee'; ctx.lineWidth = 2; ctx.stroke();
    ctx.fillStyle = '#7d89b8'; ctx.font = '10px -apple-system,sans-serif'; ctx.textAlign = 'center';
    ctx.fillText(d.date, px(i), pad.t + ih + 16);
  });
}

function drawDonut(cv, counts) {
  const { ctx, w, h } = setupCanvas(cv);
  ctx.clearRect(0, 0, w, h);
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const cx = w / 2 - 42, cy = h / 2, R = Math.min(h, w) / 2 - 16, r0 = R * 0.62;
  const colors = { critical: '#ff4d6d', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8' };
  const order = ['critical', 'high', 'medium', 'low'];
  if (!total) {
    ctx.beginPath(); ctx.arc(cx, cy, (R + r0) / 2, 0, 7);
    ctx.strokeStyle = 'rgba(120,160,255,.16)'; ctx.lineWidth = R - r0; ctx.stroke();
    ctx.fillStyle = '#7d89b8'; ctx.font = '12px -apple-system,sans-serif'; ctx.textAlign = 'center';
    ctx.fillText('暂无数据', cx, cy + 4);
    return;
  }
  let a0 = -Math.PI / 2;
  order.forEach(k => {
    const v = counts[k] || 0;
    if (!v) return;
    const a1 = a0 + Math.PI * 2 * (v / total);
    ctx.beginPath();
    ctx.arc(cx, cy, (R + r0) / 2, a0, a1);
    ctx.strokeStyle = colors[k]; ctx.lineWidth = R - r0; ctx.lineCap = 'butt'; ctx.stroke();
    a0 = a1;
  });
  ctx.textAlign = 'center';
  ctx.fillStyle = '#e8ecff'; ctx.font = '700 26px -apple-system,sans-serif';
  ctx.fillText(String(total), cx, cy + 2);
  ctx.fillStyle = '#7d89b8'; ctx.font = '11px -apple-system,sans-serif';
  ctx.fillText('漏洞总数', cx, cy + 20);
  // 图例
  let ly = cy - 40;
  order.forEach(k => {
    ctx.fillStyle = colors[k];
    ctx.beginPath(); ctx.roundRect(cx + R + 6, ly - 6, 9, 9, 2); ctx.fill();
    ctx.fillStyle = '#b6c0e6'; ctx.font = '11.5px -apple-system,sans-serif'; ctx.textAlign = 'left';
    ctx.fillText(`${SEV[k]} ${counts[k] || 0}`, cx + R + 21, ly + 2);
    ly += 21;
  });
}

function drawBars(cv, cats) {
  const { ctx, w, h } = setupCanvas(cv);
  ctx.clearRect(0, 0, w, h);
  if (!cats.length) {
    ctx.fillStyle = '#7d89b8'; ctx.font = '12px -apple-system,sans-serif'; ctx.textAlign = 'center';
    ctx.fillText('暂无数据', w / 2, h / 2); return;
  }
  const rows = cats.slice(0, 8);
  const max = Math.max(...rows.map(r => r.value), 1);
  const labelW = 96, pad = 10;
  const barH = Math.min(19, (h - pad * 2) / rows.length - 8);
  const gap = (h - pad * 2 - barH * rows.length) / Math.max(1, rows.length - 1);
  rows.forEach((row, i) => {
    const y = pad + i * (barH + gap);
    ctx.fillStyle = '#8b96c4'; ctx.font = '11.4px -apple-system,sans-serif'; ctx.textAlign = 'right';
    let label = row.name;
    if (label.length > 9) label = label.slice(0, 8) + '…';
    ctx.fillText(label, labelW - 9, y + barH / 2 + 4);

    const bw = Math.max(3, (w - labelW - 42) * (row.value / max));
    const g = ctx.createLinearGradient(labelW, 0, labelW + bw, 0);
    g.addColorStop(0, '#22d3ee'); g.addColorStop(1, '#8b5cf6');
    ctx.fillStyle = g;
    ctx.beginPath(); ctx.roundRect(labelW, y, bw, barH, barH / 2); ctx.fill();

    ctx.fillStyle = '#c9d4f5'; ctx.font = '600 11.6px -apple-system,sans-serif'; ctx.textAlign = 'left';
    ctx.fillText(String(row.value), labelW + bw + 7, y + barH / 2 + 4);
  });
}

/* ---------------- 弹窗 / 抽屉 ---------------- */
/* 待确认弹窗的中止回调。closeModal 是「取消/关闭/按 Esc/点遮罩」的唯一出口，
   所以中止逻辑必须挂在这里——挂在各自按钮上会漏掉后三种关法。 */
let modalAbort = null;

function openModal({ title, body, foot, wide = false, danger = false }) {
  $('#modalTitle').textContent = title;
  $('#modalBody').innerHTML = body;
  $('#modalFoot').innerHTML = foot || '<button class="btn ghost" data-close>关闭</button>';
  $('#modal').classList.toggle('wide', !!wide);
  $('#modal').classList.toggle('danger', !!danger);
  $('#modalMask').hidden = false;
  $$('[data-close]', $('#modal')).forEach(b => b.onclick = closeModal);
  // 返回整个 #modal 而不是 #modalBody：页脚按钮（#saveRepoBtn/#saveTaskBtn/
  // #saveSkillBtn/#okDel）都在 #modalFoot 里，只返回 body 会让调用方
  // `$('#saveXxxBtn', body)` 取到 null 并抛异常，整个表单静默失效。
  return $('#modal');
}
const closeModal = () => {
  $('#modalMask').hidden = true;
  // 有待确认的弹窗时，「关闭」等价于「取消」。少了这一步，await confirmDialog()
  // 会永远挂着，调用方后面的重新渲染、toast 全都不会执行。
  const abort = modalAbort;
  modalAbort = null;
  if (abort) abort();
};

/**
 * 统一的危险操作确认弹窗，替代原生 confirm()。
 *
 * 原生 confirm 有三个硬伤，这是它必须被换掉的原因：
 *  1. 只能显示一行纯文本 —— 批量删除时用户根本看不清自己会删掉哪几条，
 *     而「删错了」是不可逆的；
 *  2. 承载不了附加选项（例如「同时删除本地已拉取的代码目录」）；
 *  3. 样式完全由浏览器决定，和平台其余部分割裂，危险动作没有任何视觉重量。
 *
 * 返回 `Promise<{ ok: boolean, extra: object }>`：
 *  - ok    —— 确认 true；取消 / 点关闭 / 按 Esc / 点遮罩 都是 false；
 *  - extra —— 附加选项的值，由 body 里带 `data-cdlg-opt="键名"` 的元素收集，
 *             勾选框取 checked、其余取 value。这样调用方不必回头去 DOM 里捞。
 */
function confirmDialog(opts = {}) {
  const o = Object.assign({
    title: '确认操作',
    message: '',
    detailLabel: '',
    details: [],          // 纯文本数组，渲染前统一转义
    note: '',             // 补充说明（纯文本），用于讲清「删了什么、没删什么」
    noteKind: 'warn',     // warn | safe
    extraHtml: '',        // 附加内容，由调用方保证安全（只放自己拼的控件）
    requireText: '',      // 非空时，必须原样输入该文本才能点确认
    confirmLabel: '确认删除',
    cancelLabel: '取消',
    danger: true,
  }, opts);

  return new Promise(resolve => {
    const list = (o.details || []).filter(Boolean);
    const listHtml = list.length ? `
      <div class="cdlg-list">
        ${o.detailLabel ? `<div class="cdlg-list-h">${esc(o.detailLabel)}</div>` : ''}
        <ul>${list.map(d => `<li>${esc(d)}</li>`).join('')}</ul>
      </div>` : '';
    const reqHtml = o.requireText ? `
      <div class="cdlg-req">
        <label>为防止误操作，请输入 <code>${esc(o.requireText)}</code> 后再确认</label>
        <input class="inp" id="cdlgText" autocomplete="off" spellcheck="false"
               placeholder="${esc(o.requireText)}" />
      </div>` : '';

    const box = openModal({
      title: o.title,
      danger: o.danger,
      body: `
        <div class="cdlg">
          <div class="cdlg-icon ${o.danger ? 'danger' : 'warn'}">${o.danger ? '⚠' : '?'}</div>
          <div class="cdlg-main">
            <p class="cdlg-msg">${esc(o.message)}</p>
            ${listHtml}
            ${o.note ? `<div class="cdlg-note ${o.noteKind === 'safe' ? 'safe' : ''}">${esc(o.note)}</div>` : ''}
            ${o.extraHtml || ''}
            ${reqHtml}
          </div>
        </div>`,
      foot: `<button class="btn ghost" data-cdlg-cancel>${esc(o.cancelLabel)}</button>
             <button class="btn ${o.danger ? 'danger' : ''}" id="cdlgOk"${o.requireText ? ' disabled' : ''}>${esc(o.confirmLabel)}</button>`,
    });

    const okBtn = $('#cdlgOk', box);
    $('[data-cdlg-cancel]', box).onclick = closeModal;

    const txt = o.requireText ? $('#cdlgText', box) : null;
    if (txt) {
      txt.focus();
      txt.oninput = () => { okBtn.disabled = txt.value.trim() !== o.requireText; };
      txt.onkeydown = e => { if (e.key === 'Enter' && !okBtn.disabled) okBtn.click(); };
    } else {
      okBtn.focus();
    }

    okBtn.onclick = () => {
      const extra = {};
      $$('[data-cdlg-opt]', box).forEach(el => {
        extra[el.dataset.cdlgOpt] = el.type === 'checkbox' ? el.checked : el.value;
      });
      // 必须在 closeModal() 之前摘掉中止回调。closeModal 是「取消」的统一出口，
      // 它会调用 modalAbort() 把 Promise 解析成 {ok:false}；而 Promise 只认第一次
      // 解析——先调 closeModal 再 resolve({ok:true}) 会让「确认」永远被当成「取消」，
      // 表现为按钮点了、弹窗关了、但什么都没发生（且不报错，极难排查）。
      modalAbort = null;
      closeModal();
      resolve({ ok: true, extra });
    };
    modalAbort = () => resolve({ ok: false, extra: {} });
  });
}

function openDrawer({ title, sub, body, tag }) {
  // tag 标识抽屉当前内容的归属（如 log:<runId>）。带轮询的视图每次刷新都带着自己的
  // tag，轮询前检查 tag 与可见性——用户关掉抽屉、或抽屉被别的内容接管后，轮询必须
  // 停止而不是把抽屉重新拉开（2026-09-21 修复：日志抽屉关不掉的 bug）。
  state.drawerTag = tag || null;
  $('#drawerTitle').textContent = title;
  $('#drawerSub').textContent = sub || '';
  $('#drawerBody').innerHTML = body;
  $('#drawerMask').hidden = false;
}
const closeDrawer = () => { state.drawerTag = null; $('#drawerMask').hidden = true; };

window.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeModal(); closeDrawer(); }
});

/* ---------------- 视图路由 ---------------- */
const VIEW_META = {
  dashboard: ['仪表盘', '漏洞总览与仓库风险排行'],
  repos: ['仓库管理', '配置 Git 仓库，拉取代码到本地'],
  tasks: ['审计任务', '绑定仓库、设定调度方式，排队执行扫描'],
  reports: ['审计报告', '漏洞分级结果、按技能统计与导出'],
  monitor: ['执行引擎', '扫描进程实时监控与日志'],
  skills: ['技能库', '定义交给 AI 的审计指令，支持占位符'],
  quick: ['快速扫描', '不建任务，直接扫描目录或已拉取仓库'],
  webscan: ['Web 漏洞扫描', 'AI 自主规划渗透流程，对多个站点做外部暴露面检查'],
  engines: ['模型设置', '配置 AI 引擎与扫描行为'],
  about: ['系统与账户', '账户安全与版本信息'],
};
let currentView = 'dashboard';
let state = { repos: [], tasks: [], skills: [], reports: [], meta: null, engines: [], wsSkills: [], wsMeta: null,
              monitorTimer: null, quickTimer: null, wsTimer: null, wsJob: null, me: null, sessions: [] };

async function switchView(view) {
  currentView = view;
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === view));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + view));
  const [t, s] = VIEW_META[view] || ['', ''];
  $('#pageTitle').textContent = t;
  $('#pageSub').textContent = s;
  location.hash = view;
  clearInterval(state.monitorTimer);
  clearInterval(state.quickTimer);
  clearInterval(state.wsTimer);
  try {
    if (view === 'dashboard') await renderDashboard();
    else if (view === 'repos') await renderRepos();
    else if (view === 'tasks') await renderTasks();
    else if (view === 'reports') await renderReports();
    else if (view === 'monitor') { await renderMonitor(); state.monitorTimer = setInterval(renderMonitor, 3000); }
    else if (view === 'skills') await renderSkills();
    else if (view === 'quick') await renderQuick();
    else if (view === 'webscan') await renderWebScan();
    else if (view === 'engines') await renderEngines();
    else if (view === 'about') await renderAbout();
  } catch (e) { toast(e.message, 'err'); }
}

/* ---------------- 仪表盘 ---------------- */
async function renderDashboard() {
  const d = await api('/dashboard');
  const c = d.counts;
  const tot = Math.max(1, d.total);
  const cards = [
    { k: '严重', v: c.critical, c: 'var(--crit)' },
    { k: '高危', v: c.high, c: 'var(--high)' },
    { k: '中危', v: c.medium, c: 'var(--med)' },
    { k: '低危', v: c.low, c: 'var(--low)' },
    { k: '总计', v: d.total, c: 'var(--cyan)' },
  ];
  $('#statRow').innerHTML = cards.map(x => `
    <div class="stat" style="--accent:${x.c}">
      <div class="k">${x.k}</div>
      <div class="v">${x.v}</div>
      <div class="bar"><i style="width:${Math.round((x.v / tot) * 100)}%"></i></div>
    </div>`).join('');

  const weekTotal = d.trend.reduce((a, b) => a + b.total, 0);
  $('#trendTag').textContent = `近 7 天共 ${weekTotal}`;
  requestAnimationFrame(() => {
    drawTrend($('#chartTrend'), d.trend);
    drawDonut($('#chartDonut'), c);
    drawBars($('#chartBars'), d.categories);
  });

  $('#riskTable tbody').innerHTML = d.repo_risk.length ? d.repo_risk.map((r, i) => {
    const sum = r.critical + r.high + r.medium + r.low;
    const level = r.critical > 0 ? ['高风险', 'critical'] : r.high > 0 ? ['高风险', 'high']
      : r.medium > 0 ? ['中风险', 'medium'] : sum > 0 ? ['低风险', 'low'] : ['安全', 'success'];
    return `<tr><td>${i + 1}</td><td>${esc(r.name)}</td>
      <td><span class="badge ${level[1]}">${level[0]}</span></td>
      <td>${r.critical}</td><td>${r.high}</td><td>${r.medium}</td>
      <td><b>${sum}</b></td></tr>`;
  }).join('') : `<tr><td colspan="7"><div class="empty"><b>还没有仓库</b>先去「仓库管理」添加 Git 仓库</div></td></tr>`;

  $('#recentTable tbody').innerHTML = d.recent.length ? d.recent.map(r => `
    <tr class="row-link" data-run="${esc(r.run_id)}">
      <td class="mono truncate">${esc(r.run_id)}</td>
      <td><div>${esc(r.task_name || '-')}</div><div class="muted">${esc(r.repo_name || '')}</div></td>
      <td>${sbadge(r.status)}</td>
      <td>${vulnStats(r.sev_critical, r.sev_high, r.sev_medium, r.sev_low)}</td>
      <td>${fmtDur(r.elapsed_ms)}</td>
      <td class="muted">${fmtTime(r.finished_at || r.created_at)}</td>
    </tr>`).join('') : `<tr><td colspan="6"><div class="empty"><b>暂无运行记录</b>创建任务后点「运行」即可</div></td></tr>`;

  $$('[data-run]').forEach(el => el.onclick = () => showReport(el.dataset.run));
}

/* ---------------- 仓库管理 ---------------- */
async function renderRepos() {
  const name = $('#repoSearch').value.trim();
  const status = $('#repoStatusFilter').value;
  const d = await api('/repos?' + qs({ name, status }));
  state.repos = d.items;
  $('#repoTable tbody').innerHTML = d.items.length ? d.items.map(r => `
    <tr>
      <td><b>${esc(r.name)}</b></td>
      <td><span class="chip">${esc(r.type)}</span></td>
      <td class="mono truncate" title="${esc(r.url)}">${esc(r.url)}</td>
      <td class="mono">${esc(r.branch)}</td>
      <td><span class="badge ${r.status === 'active' ? 'on' : 'off'}">${esc(r.status)}</span></td>
      <td class="muted">${r.last_pull_at ? fmtTime(r.last_pull_at) : '<span class="muted">未拉取</span>'}
        ${r.last_pull_status === 'failed' ? '<span class="badge failed" style="margin-left:6px">失败</span>' : ''}</td>
      <td><div class="mini-btns">
        <button class="btn ghost tiny" data-pull="${r.id}">拉取</button>
        <button class="btn ghost tiny" data-edit="${r.id}">编辑</button>
        <button class="btn ghost tiny" data-del="${r.id}">删除</button>
      </div></td>
    </tr>`).join('') : `<tr><td colspan="7"><div class="empty"><b>还没有仓库</b>点右上角「新增仓库」添加 Git 仓库地址</div></td></tr>`;

  $$('[data-pull]').forEach(b => b.onclick = () => pullRepo(+b.dataset.pull, b));
  $$('[data-edit]').forEach(b => b.onclick = () => repoDialog(state.repos.find(x => x.id === +b.dataset.edit)));
  $$('[data-del]').forEach(b => b.onclick = () => delRepo(+b.dataset.del));
}

function repoBlock(i, r = {}) {
  return `<div class="repo-block" data-blk="${i}">
    <div class="blk-head"><b>仓库 ${i + 1}</b>
      <button class="btn ghost tiny" data-rmblk="${i}">移除</button></div>
    <div class="grid-2f">
      <div class="fi"><label>仓库名称 *</label><input class="inp" data-f="name" value="${esc(r.name || '')}" placeholder="例如: ServiceCloud" /></div>
      <div class="fi"><label>仓库类型</label>
        <select class="inp sel" data-f="type" style="width:100%">
          ${['gitlab', 'github', 'gitee', '其他'].map(t => `<option value="${t}" ${r.type === t ? 'selected' : ''}>${t}</option>`).join('')}
        </select></div>
    </div>
    <div class="grid-2f" style="margin-top:11px">
      <div class="fi" style="grid-column:1/3"><label>仓库地址 *</label>
        <input class="inp" data-f="url" value="${esc(r.url || '')}" placeholder="https://gitlab.com/user/repo.git" /></div>
    </div>
    <div class="grid-3f" style="margin-top:11px">
      <div class="fi"><label>分支</label><input class="inp" data-f="branch" value="${esc(r.branch || 'main')}" placeholder="main" /></div>
      <div class="fi"><label>用户名</label><input class="inp" data-f="username" value="${esc(r.username || '')}" placeholder="Git 用户名" /></div>
      <div class="fi"><label>密码 / Token</label><input class="inp" type="password" data-f="password" value="${esc(r.password || '')}" placeholder="Git 密码或 Token" /></div>
    </div>
    <div class="fi" style="margin-top:11px"><label>SSH Key 路径（可选）</label>
      <input class="inp" data-f="ssh_key" value="${esc(r.ssh_key || '')}" placeholder="可选: /path/to/id_rsa" /></div>
  </div>`;
}

function readBlocks(container) {
  return $$('[data-blk]', container).map(b => {
    const o = {};
    $$('[data-f]', b).forEach(i => o[i.dataset.f] = i.value.trim());
    return o;
  }).filter(o => o.name && o.url);
}

function repoDialog(repo) {
  const editing = !!repo;
  const body = openModal({
    title: editing ? '编辑仓库' : '新增仓库',
    wide: !editing,
    body: `<div class="hintline" style="margin-bottom:12px">${editing
      ? '修改仓库信息；密码框显示 *** 表示保持原值不变。'
      : '可同时添加多个仓库，按需点击「+ 添加一个」调整数量。凭据支持「用户名+密码/Token」或「SSH Key」。'}</div>
      <div id="repoBlocks">${repoBlock(0, repo || {})}</div>
      ${editing ? '' : '<button class="btn ghost sm" id="addBlkBtn" style="margin-top:4px">+ 添加一个</button>'}
      <div id="repoTestOut" style="margin-top:12px"></div>`,
    foot: `${editing ? '' : '<button class="btn ghost" id="testAllBtn">批量测试连接</button>'}
      <button class="btn ghost" data-close>取消</button>
      <button class="btn" id="saveRepoBtn">确定</button>`,
  });

  if (!editing) {
    let n = 1;
    $('#addBlkBtn', body).onclick = () => {
      const wrap = document.createElement('div');
      wrap.innerHTML = repoBlock(n, {});
      $('#repoBlocks', body).appendChild(wrap.firstElementChild);
      bindRemove(body); n++;
    };
    bindRemove(body);
    $('#testAllBtn', body).onclick = async (e) => {
      const items = readBlocks(body);
      if (!items.length) return toast('请至少填写一个仓库', 'err');
      const btn = e.target; btn.disabled = true; btn.innerHTML = '<span class="spin"></span> 测试中';
      try {
        const r = await api('/repos/test', { method: 'POST', body: items });
        $('#repoTestOut', body).innerHTML = r.items.map(x =>
          `<div class="meta-row"><span>${esc(x.name)}</span>
            <span class="badge ${x.ok ? 'success' : 'failed'}">${x.ok ? '✓ 通' : '✗ 失败'}</span></div>
            ${x.ok ? '' : `<div class="hintline" style="color:#ff9fae">${esc(x.message)}</div>`}`).join('');
      } catch (err) { toast(err.message, 'err'); }
      btn.disabled = false; btn.textContent = '批量测试连接';
    };
  }

  $('#saveRepoBtn', body).onclick = async (e) => {
    const items = readBlocks(body);
    if (!items.length) return toast('请填写仓库名称与地址', 'err');
    const btn = e.target; btn.disabled = true;
    try {
      if (editing) {
        await api('/repos/' + repo.id, { method: 'PUT', body: items[0] });
        toast('仓库已更新');
      } else {
        await api('/repos', { method: 'POST', body: items });
        toast(`已添加 ${items.length} 个仓库`);
      }
      closeModal(); renderRepos();
    } catch (err) { toast(err.message, 'err'); btn.disabled = false; }
  };
}

function bindRemove(body) {
  $$('[data-rmblk]', body).forEach(b => b.onclick = () => {
    if ($$('[data-blk]', body).length <= 1) return toast('至少保留一个仓库', 'err');
    b.closest('.repo-block').remove();
  });
}

async function pullRepo(id, btn) {
  const old = btn.textContent;
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span>';
  try {
    const r = await api(`/repos/${id}/pull`, { method: 'POST' });
    toast('拉取成功：' + String(r.message).split('\n')[0].slice(0, 70));
    renderRepos();
  } catch (e) { toast(e.message, 'err', 5200); btn.disabled = false; btn.textContent = old; }
}

async function delRepo(id) {
  const r = state.repos.find(x => x.id === id);
  if (!r) return;
  const { ok, extra } = await confirmDialog({
    title: '删除仓库',
    message: `确认删除仓库「${r.name}」？`,
    detailLabel: '该仓库信息',
    details: [`地址：${r.url || '-'}`, `分支：${r.branch || '-'}`,
              `本地目录：${r.local_path || '（尚未拉取）'}`],
    note: '仓库记录与已拉取的本地代码会被移除；历史审计报告会保留，仍可在「审计报告」中查看与下载。',
    extraHtml: `<label class="cdlg-opt"><input type="checkbox" data-cdlg-opt="removeFiles" checked />
      同时删除本地已拉取的代码目录</label>`,
    confirmLabel: '删除仓库',
  });
  if (!ok) return;
  try {
    await api(`/repos/${id}?remove_files=${!!extra.removeFiles}`, { method: 'DELETE' });
    toast('已删除仓库');
    renderRepos();
  } catch (e) { toast(e.message, 'err'); }
}

/* ---------------- 审计任务 ---------------- */
async function renderTasks() {
  if (!state.repos.length) { try { state.repos = (await api('/repos')).items; } catch { } }
  // 技能列表也要在这里兜底加载：否则先进「审计任务」再点「新增任务」，
  // 弹窗里的技能多选框是空的（技能只在「技能库」页渲染时才拉取）。
  if (!state.skills.length) { try { state.skills = (await api('/skills')).items; } catch { } }
  const opts = ['<option value="">仓库：全部</option>']
    .concat(state.repos.map(r => `<option value="${r.id}">${esc(r.name)}</option>`)).join('');
  const keep = $('#taskRepoFilter').value;
  $('#taskRepoFilter').innerHTML = opts;
  $('#taskRepoFilter').value = keep;

  const d = await api('/tasks?' + qs({
    name: $('#taskSearch').value.trim(),
    repo_id: $('#taskRepoFilter').value,
    status: $('#taskStatusFilter').value,
  }));
  state.tasks = d.items;

  const SCHED = { manual: '手动', interval: '定时（间隔）', cron: '定时（cron）', once: '单次' };
  $('#taskTable tbody').innerHTML = d.items.length ? d.items.map(t => `
    <tr>
      <td><b>${esc(t.name)}</b>
        ${t.enabled ? '' : '<span class="badge off" style="margin-left:6px">停用</span>'}</td>
      <td>${esc(t.repo_name)}<div class="muted mono">${esc(t.repo_branch || '')}</div></td>
      <td><span class="chip">${esc(t.depth)}</span></td>
      <td>${esc(t.engine)}</td>
      <td>${SCHED[t.schedule_type] || t.schedule_type}
        ${t.schedule_type === 'interval' && t.interval_seconds ? `<div class="muted">每 ${Math.round(t.interval_seconds / 60)} 分钟</div>` : ''}
        ${t.schedule_type === 'cron' ? `<div class="muted mono">${esc(t.cron)}</div>` : ''}</td>
      <td>${sbadge(t.status)}</td>
      <td class="muted">${t.next_run_at && t.enabled ? fmtTime(t.next_run_at) : '-'}</td>
      <td class="muted">${t.last_run_at ? fmtTime(t.last_run_at) : '-'}</td>
      <td><div class="mini-btns">
        <button class="btn tiny" data-run="${t.id}">运行</button>
        <button class="btn ghost tiny" data-stop="${t.id}">停止</button>
        <button class="btn ghost tiny" data-logs="${t.id}">日志</button>
        <button class="btn ghost tiny" data-tedit="${t.id}">编辑</button>
        <button class="btn ghost tiny" data-tdel="${t.id}">删除</button>
      </div></td>
    </tr>`).join('') : `<tr><td colspan="9"><div class="empty"><b>还没有审计任务</b>点右上角「新增任务」，绑定一个仓库</div></td></tr>`;

  $$('[data-run]').forEach(b => b.onclick = async () => {
    b.disabled = true; b.innerHTML = '<span class="spin"></span>';
    try {
      const r = await api(`/tasks/${b.dataset.run}/run`, { method: 'POST' });
      toast(r.message || '已进入执行队列');
      setTimeout(() => switchView('monitor'), 700);
    } catch (e) { toast(e.message, 'err'); b.disabled = false; b.textContent = '运行'; }
  });
  $$('[data-stop]').forEach(b => b.onclick = async () => {
    try { await api(`/tasks/${b.dataset.stop}/stop`, { method: 'POST' }); toast('已发送停止指令'); renderTasks(); }
    catch (e) { toast(e.message, 'err'); }
  });
  $$('[data-logs]').forEach(b => b.onclick = () => showTaskLogs(+b.dataset.logs));
  $$('[data-tedit]').forEach(b => b.onclick = () => taskDialog(state.tasks.find(x => x.id === +b.dataset.tedit)));
  $$('[data-tdel]').forEach(b => b.onclick = async () => {
    const t = state.tasks.find(x => x.id === +b.dataset.tdel);
    const { ok } = await confirmDialog({
      title: '删除审计任务',
      message: `确认删除任务「${t?.name || b.dataset.tdel}」？`,
      detailLabel: '该任务信息',
      details: t ? [`绑定仓库：${t.repo_name || '-'}`,
                    `调度方式：${SCHED[t.schedule_type] || t.schedule_type || '-'}`,
                    `审计深度：${t.depth || '-'} · 引擎：${t.engine || '-'}`] : [],
      note: '该任务将停止调度。已产生的审计报告不会被删除，仍可在「审计报告」中查看与下载。',
      confirmLabel: '删除任务',
    });
    if (!ok) return;
    try {
      await api('/tasks/' + b.dataset.tdel, { method: 'DELETE' });
      toast('已删除任务');
      renderTasks();
    } catch (e) { toast(e.message, 'err'); }
  });
}

function taskDialog(task) {
  const editing = !!task;
  const repoOpts = state.repos.map(r => `<option value="${r.id}" ${task && task.repo_id === r.id ? 'selected' : ''}>${esc(r.name)}</option>`).join('');
  const skillOpts = state.skills.map(s => `<option value="${esc(s.name)}" ${(task?.skill_names || []).includes(s.name) ? 'selected' : ''}>${esc(s.name)} — ${esc(s.description)}</option>`).join('');
  const body = openModal({
    title: editing ? '编辑任务' : '新增任务',
    wide: true,
    body: `<div class="grid-2f">
      <div class="fi"><label>任务名称 *</label><input class="inp" id="tName" value="${esc(task?.name || '')}" placeholder="例如: 网关服务周度审计" /></div>
      <div class="fi"><label>选择仓库 *</label><select class="inp sel" id="tRepo" style="width:100%">${repoOpts}</select></div>
    </div>
    <div class="grid-3f" style="margin-top:12px">
      <div class="fi"><label>审计深度</label><select class="inp sel" id="tDepth" style="width:100%">
        ${(state.meta?.depths || []).map(d => `<option value="${d.value}" ${task?.depth === d.value ? 'selected' : ''}>${d.label}</option>`).join('')}
      </select></div>
      <div class="fi"><label>扫描引擎</label><select class="inp sel" id="tEngine" style="width:100%">
        <option value="codex" ${task?.engine === 'codex' ? 'selected' : ''}>Codex</option>
        <option value="claude" ${task?.engine === 'claude' ? 'selected' : ''}>Claude Code</option>
      </select></div>
      <div class="fi"><label>调度方式</label><select class="inp sel" id="tSched" style="width:100%">
        <option value="manual" ${task?.schedule_type === 'manual' ? 'selected' : ''}>手动触发</option>
        <option value="interval" ${task?.schedule_type === 'interval' ? 'selected' : ''}>定时执行（间隔）</option>
        <option value="cron" ${task?.schedule_type === 'cron' ? 'selected' : ''}>定时执行（cron）</option>
        <option value="once" ${task?.schedule_type === 'once' ? 'selected' : ''}>单次执行</option>
      </select></div>
    </div>
    <div id="schedExtra" style="margin-top:12px"></div>
    <div class="fi" style="margin-top:12px"><label>参与审计的技能（不选则使用全部启用的检测技能）</label>
      <select class="inp sel multi" id="tSkills" multiple size="8">${skillOpts}</select></div>
    <label class="chk" style="margin-top:12px"><input type="checkbox" id="tEnabled" ${task?.enabled !== 0 ? 'checked' : ''} /> 启用该任务</label>`,
    foot: '<button class="btn ghost" data-close>取消</button><button class="btn" id="saveTaskBtn">确定</button>',
  });

  const sched = $('#tSched', body);
  const drawExtra = () => {
    const v = sched.value;
    let html = '';
    if (v === 'interval') html = `<div class="fi"><label>间隔（分钟，最小 1）</label>
      <input class="inp" type="number" id="tInterval" min="1" value="${task?.interval_seconds ? Math.max(1, Math.round(task.interval_seconds / 60)) : 60}" /></div>`;
    else if (v === 'cron') html = `<div class="fi"><label>cron 表达式（分 时 日 月 周）</label>
      <input class="inp" id="tCron" value="${esc(task?.cron || '0 2 * * *')}" placeholder="0 2 * * * 表示每天 02:00" />
      <div class="hintline">支持 <code>*</code>、<code>*/n</code>、具体数字与逗号列表，例如 <code>0 */6 * * *</code>（每 6 小时）</div></div>`;
    else if (v === 'once') {
      const dt = task?.run_at ? new Date(task.run_at * 1000) : new Date(Date.now() + 3600e3);
      const p = n => String(n).padStart(2, '0');
      const local = `${dt.getFullYear()}-${p(dt.getMonth() + 1)}-${p(dt.getDate())}T${p(dt.getHours())}:${p(dt.getMinutes())}`;
      html = `<div class="fi"><label>执行时间</label><input class="inp" type="datetime-local" id="tRunAt" value="${local}" /></div>`;
    }
    $('#schedExtra', body).innerHTML = html;
  };
  sched.onchange = drawExtra;
  drawExtra();

  $('#saveTaskBtn', body).onclick = async (e) => {
    const st = sched.value;
    const payload = {
      name: $('#tName', body).value.trim(),
      repo_id: +(state.repos.find(r => String(r.id) === $('#tRepo', body).value)?.id || 0),
      depth: $('#tDepth', body).value,
      engine: $('#tEngine', body).value,
      skill_names: [...$('#tSkills', body).selectedOptions].map(o => o.value),
      schedule_type: st,
      interval_seconds: st === 'interval' ? Math.max(60, (+($('#tInterval', body)?.value || 60)) * 60) : 0,
      cron: st === 'cron' ? ($('#tCron', body)?.value || '').trim() : '',
      run_at: st === 'once' && $('#tRunAt', body) ? new Date($('#tRunAt', body).value).getTime() / 1000 : null,
      enabled: $('#tEnabled', body).checked ? 1 : 0,
    };
    if (!payload.name) return toast('请填写任务名称', 'err');
    if (!payload.repo_id) return toast('请选择仓库', 'err');
    const btn = e.target; btn.disabled = true;
    try {
      if (editing) await api('/tasks/' + task.id, { method: 'PUT', body: payload });
      else await api('/tasks', { method: 'POST', body: payload });
      toast(editing ? '任务已更新' : '任务已创建');
      closeModal(); renderTasks();
    } catch (err) { toast(err.message, 'err'); btn.disabled = false; }
  };
}

async function showTaskLogs(taskId) {
  const d = await api(`/runs?task_id=${taskId}&limit=1`);
  if (!d.items.length) return toast('该任务还没有运行记录', 'err');
  showRunLogs(d.items[0].run_id);
}

async function showRunLogs(runId) {
  const tag = 'log:' + runId;
  openDrawer({ title: '审计日志', sub: runId, body: '<div class="muted">加载中…</div>', tag });
  const alive = () => state.drawerTag === tag && !$('#drawerMask').hidden;
  const tick = async () => {
    if (!alive()) return 'closed';
    try {
      const [logs, run] = await Promise.all([api(`/runs/${runId}/logs`), api(`/runs/${runId}`)]);
      if (!alive()) return 'closed';  // 请求往返期间用户可能已关闭抽屉
      const items = logs.items || [];
      const html = items.length ? items.map(l => `
        <div class="ln ${l.level === 'error' ? 'error' : l.level === 'warn' ? 'warn' : l.level === 'ok' ? 'ok' : 'info'}">
          <span class="t">${new Date(l.ts * 1000).toLocaleTimeString('zh-CN', { hour12: false })}</span>
          <span class="m">${esc(l.message)}</span></div>`).join('')
        : '<div class="ln system"><span class="m">暂无日志</span></div>';
      openDrawer({
        title: `审计日志 · ${STATUS[run.status] || run.status}`,
        sub: run.run_id,
        tag,
        body: `<div class="progress-wrap"><div class="progress"><i style="width:${run.progress || 0}%"></i></div>
          <span>${run.progress || 0}%</span></div>
          <div class="hintline" style="margin-bottom:11px">当前阶段：${esc(run.stage || '-')}　${esc(run.message || '')}</div>
          <div class="logbox" id="logScroll" style="height:calc(100vh - 260px)">${html}</div>`,
      });
      const box = $('#logScroll');
      if (box) box.scrollTop = box.scrollHeight;
      return run.status;
    } catch (e) { return 'error'; }
  };
  let last = await tick();
  const t = setInterval(async () => {
    if (!alive()) { clearInterval(t); return; }
    last = await tick();
    if (!['queued', 'running'].includes(last)) clearInterval(t);
  }, 2500);
}

/* ---------------- 审计报告 ---------------- */
async function renderReports() {
  const d = await api('/reports?' + qs({
    task_name: $('#reportSearch').value.trim(),
    status: $('#reportStatusFilter').value,
    severity: $('#reportSevFilter').value,
  }));
  const s = d.summary;
  state.reports = d.items;          // 行内删除 / 批量删除要按 run_id 回查明细
  $('#reportStatRow').innerHTML = [
    { k: '报告总数', v: d.items.length, c: 'var(--cyan)' },
    { k: '漏洞合计', v: s.total, c: 'var(--violet)' },
    { k: '严重', v: s.critical, c: 'var(--crit)' },
    { k: '高危', v: s.high, c: 'var(--high)' },
  ].map(x => `<div class="stat" style="--accent:${x.c}"><div class="k">${x.k}</div><div class="v">${x.v}</div>
    <div class="bar"><i style="width:100%"></i></div></div>`).join('');

  $('#reportTable tbody').innerHTML = d.items.length ? d.items.map(r => {
    // 排队/执行中的报告不给勾选也不给删：后端会拒绝，前端提前禁掉能少一次无效请求，
    // 也避免用户以为「删掉了」。
    const busy = ['queued', 'running'].includes(r.status);
    return `
    <tr>
      <td><input type="checkbox" class="rowchk" value="${esc(r.run_id)}" ${busy ? 'disabled' : ''} /></td>
      <td class="mono truncate row-link" data-open="${esc(r.run_id)}" title="${esc(r.run_id)}">${esc(r.run_id)}</td>
      <td><div>${esc(r.task_name || '-')}</div><div class="muted">${esc(r.repo_name || '')}</div></td>
      <td><span class="chip">${esc(r.depth || '-')}</span></td>
      <td>${esc(r.engine || '-')}</td>
      <td>${sbadge(r.status)}</td>
      <td>${vulnStats(r.sev_critical, r.sev_high, r.sev_medium, r.sev_low)}
        <span class="muted" style="margin-left:6px">共 ${r.findings_count}</span></td>
      <td class="muted">${r.elapsed_ms ? fmtDur(r.elapsed_ms) : (r.status === 'running' ? '<span class="spin"></span>' : '-')}</td>
      <td class="muted">${fmtTime(r.created_at)}</td>
      <td><div class="mini-btns">
        ${r.status === 'success' ? `<button class="btn tiny" data-open="${esc(r.run_id)}">查看报告</button>` : ''}
        ${busy ? `<button class="btn ghost tiny" data-sopen="${esc(r.run_id)}">日志</button>` : ''}
        ${r.status === 'success' ? `
          <button class="btn ghost tiny" data-rescan="${esc(r.run_id)}">复扫</button>` : ''}
        ${busy ? `<button class="btn ghost tiny" data-srun="${esc(r.run_id)}">停止</button>` : ''}
        ${busy ? '' : `<button class="btn ghost tiny del-btn" data-rdel="${esc(r.run_id)}"
          title="删除这份报告（含漏洞明细与日志，不可恢复）">删除</button>`}
      </div></td>
    </tr>`;
  }).join('') : `<tr><td colspan="10"><div class="empty"><b>暂无报告</b>运行审计任务后，报告会出现在这里</div></td></tr>`;

  $$('[data-open]', $('#reportTable')).forEach(b => b.onclick = () => showReport(b.dataset.open));
  $$('[data-sopen]', $('#reportTable')).forEach(b => b.onclick = () => showRunLogs(b.dataset.sopen));
  $$('[data-srun]', $('#reportTable')).forEach(b => b.onclick = async () => {
    try { await api(`/runs/${b.dataset.srun}/stop`, { method: 'POST' }); toast('已发送停止指令'); renderReports(); }
    catch (e) { toast(e.message, 'err'); }
  });
  $$('[data-rescan]', $('#reportTable')).forEach(b => b.onclick = async () => {
    try { const r = await api(`/reports/${b.dataset.rescan}/rescan`, { method: 'POST' }); toast('复扫已入队'); setTimeout(() => switchView('monitor'), 600); }
    catch (e) { toast(e.message, 'err'); }
  });
  $$('[data-rdel]', $('#reportTable')).forEach(b => b.onclick = () => deleteReport(b.dataset.rdel));
  bindRowChecks('#reportTable', '#checkAll', '#reportSelCount');
}

/** 删除单份审计报告（走统一样式的确认弹窗）。 */
async function deleteReport(runId) {
  const r = (state.reports || []).find(x => x.run_id === runId);
  const { ok } = await confirmDialog({
    title: '删除审计报告',
    message: `确认删除报告「${runId}」？`,
    detailLabel: '这份报告包含',
    details: [
      `任务：${r?.task_name || '-'}　仓库：${r?.repo_name || '-'}`,
      `漏洞明细：共 ${r?.findings_count ?? 0} 项（严重 ${r?.sev_critical || 0} / 高危 ${r?.sev_high || 0} / 中危 ${r?.sev_medium || 0}）`,
      '运行日志与磁盘上的报告产物',
    ],
    note: '报告正文、漏洞明细、运行日志与报告文件将一并删除，且不可恢复。仓库代码与审计任务不受影响。',
    confirmLabel: '删除报告',
  });
  if (!ok) return;
  try {
    await api('/reports/' + encodeURIComponent(runId), { method: 'DELETE' });
    toast('已删除报告');
    renderReports();
  } catch (e) { toast(e.message, 'err'); }
}

/** 批量删除选中的审计报告。 */
async function deleteReportsBatch() {
  const ids = $$('#reportTable .rowchk:checked').map(c => c.value);
  if (!ids.length) return toast('请先勾选要删除的报告', 'err');
  const byId = new Map((state.reports || []).map(r => [r.run_id, r]));
  const busy = ids.filter(id => ['queued', 'running'].includes(byId.get(id)?.status));
  const { ok } = await confirmDialog({
    title: '批量删除审计报告',
    message: `确认删除选中的 ${ids.length} 份报告？`,
    detailLabel: `以下 ${ids.length} 份报告及其漏洞明细将被删除`,
    details: ids.map(id => {
      const r = byId.get(id);
      return r ? `${id}　${r.task_name || r.repo_name || '-'}　共 ${r.findings_count} 项` : id;
    }),
    note: '删除不可恢复。仓库代码与审计任务不受影响。'
      + (busy.length ? `其中 ${busy.length} 条正在排队或执行中，会被跳过。` : ''),
    // 条数一多，误点「确认」的代价就变大——加一道输入确认，让手停一下。
    requireText: ids.length >= 5 ? 'DELETE' : '',
    confirmLabel: `删除 ${ids.length} 份报告`,
  });
  if (!ok) return;
  try {
    const r = await api('/reports/delete', { method: 'POST', body: { run_ids: ids } });
    if (r.skipped?.length) {
      toast(`已删除 ${r.deleted} 份，跳过 ${r.skipped.length} 份（执行中或不存在）`, 'err', 5600);
    } else {
      toast(`已删除 ${r.deleted} 份报告`);
    }
    renderReports();
  } catch (e) { toast(e.message, 'err'); }
}

/**
 * 绑定表格多选：表头全选 + 「已选 N 项」与半选态。
 *
 * 计数与全选都要跳过 disabled 的复选框，否则会把不允许删除的行也算进去，
 * 用户点了「批量删除」才发现数量对不上。
 */
function bindRowChecks(tableSel, allSel, countSel) {
  const table = $(tableSel);
  if (!table) return;
  const all = $(allSel);
  const count = $(countSel);
  const usable = () => $$('.rowchk', table).filter(c => !c.disabled);
  const sync = () => {
    const list = usable();
    const picked = list.filter(c => c.checked).length;
    if (count) count.textContent = picked ? `已选 ${picked} 项` : '';
    if (all) {
      all.checked = list.length > 0 && picked === list.length;
      all.indeterminate = picked > 0 && picked < list.length;
    }
  };
  if (all) all.onclick = e => { usable().forEach(c => { c.checked = e.target.checked; }); sync(); };
  $$('.rowchk', table).forEach(c => c.onchange = sync);
  sync();
}

/**
 * 报告抽屉顶部的导出操作条（审计报告与 Web 扫描报告共用同一套）。
 *
 * 两处必须长得一样：用户在哪个页面点「下载」都该是同一个东西。各写一份迟早漂移
 * ——之前 Web 那边就漏了主按钮样式、文案也不一致，看起来像两套不同的功能。
 * 属性名做成参数，因为两处数据键（run_id / job_id）与下载函数不同。
 */
function reportActionsHtml(openAttr, openId, dlAttr) {
  return `<div class="rep-actions">
        <button class="btn primary tiny" ${openAttr}="${esc(openId)}"
          title="在新标签页打开完整 HTML 报告，可 Ctrl/Cmd+P 另存为 PDF">浏览器打开 · 可打印 PDF</button>
        <button class="btn ghost tiny" ${dlAttr}="html">下载 HTML</button>
        <button class="btn ghost tiny" ${dlAttr}="md">下载 Markdown</button>
        <button class="btn ghost tiny" ${dlAttr}="json">下载 JSON</button>
      </div>`;
}

/** 下载报告。fmt: html（默认，自带样式可直接双击打开/打印 PDF）| md | json */
async function downloadReport(runId, fmt = 'html') {
  const map = {
    html: { q: '/html?download=1', type: 'text/html;charset=utf-8', ext: 'html' },
    md: { q: '/markdown', type: 'text/markdown;charset=utf-8', ext: 'md' },
    json: { q: '/json', type: 'application/json;charset=utf-8', ext: 'json' },
  };
  const m = map[fmt] || map.html;
  try {
    const text = await api(`/reports/${runId}${m.q}`, { raw: true });
    const blob = new Blob([text], { type: m.type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `aiholey-${runId}.${m.ext}`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast(fmt === 'html' ? 'HTML 报告已下载，双击用浏览器打开，可另存为 PDF' : '报告已下载');
  } catch (e) { toast(e.message, 'err'); }
}

/** 在浏览器里打开 HTML 报告（可直接 Ctrl/Cmd+P 存成 PDF）。 */
function previewReport(runId) {
  window.open(`/api/reports/${runId}/html`, '_blank');
}

async function showReport(runId) {
  openDrawer({ title: '报告详情', sub: runId, body: '<div class="muted">加载中…</div>' });
  const d = await api('/reports/' + runId);
  const stats = [
    { k: '严重', v: d.sev_critical, c: 'critical' },
    { k: '高危', v: d.sev_high, c: 'high' },
    { k: '中危', v: d.sev_medium, c: 'medium' },
    { k: '低危', v: d.sev_low, c: 'low' },
  ];
  const findHtml = d.findings.length ? d.findings.map((f, i) => `
    <div class="finding ${f.severity}">
      <div class="f-head">
        <span class="badge ${f.severity}">${SEV[f.severity] || f.severity}</span>
        <b>${esc(f.title)}</b>
        <span class="chip">${esc(f.skill)}</span>
        <span class="muted">${f.source === 'ai' ? 'AI 分析' : '内置规则'}</span>
      </div>
      <div class="loc">${esc(f.file)}:${f.line}</div>
      ${f.snippet ? `<pre>${esc(f.snippet)}</pre>` : ''}
      ${f.detail ? `<div class="f-detail">${esc(f.detail)}</div>` : ''}
      ${f.advice ? `<div class="f-advice">修复建议：${esc(f.advice)}</div>` : ''}
    </div>`).join('') : '<div class="empty"><b>未发现可确认的漏洞</b>本次扫描没有命中风险项</div>';

  const skillHtml = d.by_skill.length ? `<div class="table-wrap"><table><thead><tr>
      <th>技能</th><th>严重</th><th>高危</th><th>中危</th><th>低危</th><th>合计</th></tr></thead><tbody>
      ${d.by_skill.map(b => `<tr><td class="mono">${esc(b.skill)}</td><td>${b.critical}</td><td>${b.high}</td>
        <td>${b.medium}</td><td>${b.low}</td><td><b>${b.total}</b></td></tr>`).join('')}
    </tbody></table></div>` : '';

  const prof = d.profile;
  const profHtml = prof ? `
    <div class="rep-sect"><h4>项目适配画像</h4>
      <div class="kv">
        <dt>语言 / 框架</dt><dd>${esc(prof.tech_stack?.language || '?')} / ${esc(prof.tech_stack?.framework || '?')} ${esc(prof.tech_stack?.framework_version || '')}</dd>
        <dt>构建工具</dt><dd>${esc(prof.tech_stack?.build_tool || '?')}</dd>
        <dt>安全机制</dt><dd>${esc(prof.tech_stack?.security_mechanism || '?')}</dd>
        <dt>适配规则</dt><dd>${(prof.adaptations || []).length} 条</dd>
        <dt>项目模式</dt><dd>${(prof.project_patterns || []).length} 条</dd>
      </div>
      ${(prof.adaptations || []).length ? `<div style="margin-top:11px">${prof.adaptations.map(a =>
        `<div class="hintline">· <b>${esc(a.name)}</b>：${esc(a.description)}</div>`).join('')}</div>` : ''}
    </div>` : '';

  openDrawer({
    title: d.task_name || d.repo_name || '审计报告',
    sub: d.run_id,
    body: `
      ${reportActionsHtml('data-rprev', d.run_id, 'data-rdl')}
      <div class="stat-row compact" style="margin-bottom:18px">
        ${stats.map(x => `<div class="stat" style="--accent:var(--${x.c === 'critical' ? 'crit' : x.c === 'high' ? 'high' : x.c === 'medium' ? 'med' : 'low'})">
          <div class="k">${x.k}</div><div class="v">${x.v}</div><div class="bar"><i style="width:100%"></i></div></div>`).join('')}
      </div>
      <div class="rep-sect"><h4>基本信息</h4>
        <div class="kv">
          <dt>仓库</dt><dd>${esc(d.repo_name || '-')} ${d.repo ? `<span class="muted mono">${esc(d.repo.branch || '')}</span>` : ''}</dd>
          <dt>深度 / 引擎</dt><dd>${esc(d.depth || '-')} · ${esc(d.engine || '-')} ${d.ai_used ? '<span class="badge running">AI 已启用</span>' : '<span class="badge off">仅规则</span>'}</dd>
          <dt>扫描范围</dt><dd>${d.files_scanned || 0} 个文件 · ${d.loc || 0} 行代码</dd>
          <dt>耗时</dt><dd>${fmtDur(d.duration_ms)}</dd>
          <dt>工作目录</dt><dd class="mono">${esc(d.workdir || '-')}</dd>
          <dt>完成时间</dt><dd>${fmtTime(d.finished_at)}</dd>
        </div></div>
      ${profHtml}
      ${skillHtml ? `<div class="rep-sect"><h4>按技能统计</h4>${skillHtml}</div>` : ''}
      <div class="rep-sect"><h4>确认漏洞清单（${d.findings.length}）</h4>${findHtml}</div>
      <div class="rep-sect"><h4>Markdown 原文</h4>
        <div class="mdbox">${esc(d.report_md || '（无）')}</div></div>`,
  });
  $$('#drawerBody [data-rprev]').forEach(b => b.onclick = () => previewReport(b.dataset.rprev));
  $$('#drawerBody [data-rdl]').forEach(b => b.onclick = () => downloadReport(d.run_id, b.dataset.rdl));
}

/* ---------------- 执行引擎 ---------------- */
async function renderMonitor() {
  const d = await api('/monitor');
  const running = d.items.filter(x => x.status === 'running').length;
  const queued = d.queued;
  const done = d.items.filter(x => x.status === 'success').length;
  const failed = d.items.filter(x => x.status === 'failed').length;
  $('#monitorStatRow').innerHTML = [
    { k: '运行中', v: running, c: 'var(--cyan)' },
    { k: '排队中', v: queued, c: 'var(--violet)' },
    { k: '已完成', v: done, c: 'var(--lime)' },
    { k: '失败', v: failed, c: 'var(--red)' },
  ].map(x => `<div class="stat" style="--accent:${x.c}"><div class="k">${x.k}</div><div class="v">${x.v}</div>
    <div class="bar"><i style="width:100%"></i></div></div>`).join('');
  $('#monitorHint').textContent = `并发上限 ${state.meta?.max_concurrent ?? '-'}　当前进程 ${d.running}`;

  $('#monitorTable tbody').innerHTML = d.items.length ? d.items.map(x => `
    <tr>
      <td>${esc(x.engine)}</td>
      <td class="mono">${esc(x.entry)}</td>
      <td class="mono">${x.pid || '-'}</td>
      <td>${sbadge(x.status)}${x.status === 'running' ? `<div class="progress" style="margin-top:5px;height:4px"><i style="width:${x.progress || 0}%"></i></div>` : ''}</td>
      <td>${x.status === 'running' ? `<span class="mono">${fmtDur(x.duration_ms)}</span>` : fmtDur(x.duration_ms)}</td>
      <td>${esc(x.task_name || '-')}<div class="muted">${esc(x.repo_name || '')}</div></td>
      <td class="mono truncate" title="${esc(x.run_id)}">${esc(x.run_id)}</td>
      <td><span class="chip">${esc(x.depth || '-')}</span></td>
      <td class="mono truncate" title="${esc(x.workdir)}">${esc(x.workdir || '-')}</td>
      <td class="muted truncate" title="${esc(x.error)}">${x.error ? `<span style="color:#ff9fae">${esc(x.error)}</span>` : '-'}</td>
      <td><div class="mini-btns">
        <button class="btn ghost tiny" data-mlog="${esc(x.run_id)}">日志</button>
        ${['queued', 'running'].includes(x.status) ? `<button class="btn ghost tiny" data-mstop="${esc(x.run_id)}">终止</button>` : ''}
      </div></td>
    </tr>`).join('') : `<tr><td colspan="11"><div class="empty"><b>暂无执行记录</b>运行任务后这里会显示扫描进程</div></td></tr>`;

  $$('[data-mlog]').forEach(b => b.onclick = () => showRunLogs(b.dataset.mlog));
  $$('[data-mstop]').forEach(b => b.onclick = async () => {
    try { await api(`/runs/${b.dataset.mstop}/stop`, { method: 'POST' }); toast('已发送终止指令'); renderMonitor(); }
    catch (e) { toast(e.message, 'err'); }
  });
}

/* ---------------- 技能库 ---------------- */
async function renderSkills() {
  const d = await api('/skills?' + qs({
    name: $('#skillSearch').value.trim(),
    category: $('#skillCatFilter').value,
  }));
  state.skills = d.items;
  const keep = $('#skillCatFilter').value;
  $('#skillCatFilter').innerHTML = '<option value="">分类：全部</option>' +
    d.categories.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
  $('#skillCatFilter').value = keep;

  $('#skillGrid').innerHTML = d.items.length ? d.items.map(s => `
    <div class="skill-card">
      <h4>${esc(s.name)}</h4>
      <div class="desc">${esc(s.description || '（无说明）')}</div>
      <div class="prompt">${esc(s.prompt || '（无提示词）')}</div>
      <div class="foot">
        <div style="display:flex;gap:6px;align-items:center">
          <span class="chip">${esc(s.category)}</span>
          <span class="badge ${s.enabled ? 'on' : 'off'}">${s.enabled ? '启用' : '停用'}</span>
          ${s.builtin ? '<span class="badge off">内置</span>' : ''}
        </div>
        <div class="mini-btns">
          <button class="btn ghost tiny" data-sedit="${s.id}">编辑</button>
          ${s.builtin ? '' : `<button class="btn ghost tiny" data-sdel="${s.id}">删除</button>`}
        </div>
      </div>
    </div>`).join('') : `<div class="empty" style="grid-column:1/-1"><b>没有匹配的技能</b>换个关键词，或点「恢复内置提示词」重建内置技能库</div>`;

  $$('[data-sedit]').forEach(b => b.onclick = () => skillDialog(state.skills.find(x => x.id === +b.dataset.sedit)));
  $$('[data-sdel]').forEach(b => b.onclick = async () => {
    const s = state.skills.find(x => x.id === +b.dataset.sdel);
    const { ok } = await confirmDialog({
      title: '删除 Skill',
      message: `确认删除技能「${s?.name || b.dataset.sdel}」？`,
      detailLabel: '该技能',
      details: s ? [`分类：${s.category || '-'}`, `说明：${s.description || '（无）'}`] : [],
      note: '自定义提示词会一并删除且不可恢复。内置技能不可删除，如需还原可点右上角「恢复内置提示词」。',
      confirmLabel: '删除技能',
    });
    if (!ok) return;
    try { await api('/skills/' + b.dataset.sdel, { method: 'DELETE' }); toast('已删除技能'); renderSkills(); }
    catch (e) { toast(e.message, 'err'); }
  });
}

function skillDialog(skill) {
  const editing = !!skill;
  const body = openModal({
    title: editing ? '编辑 Skill' : '新增 Skill',
    wide: true,
    body: `<div class="grid-2f">
      <div class="fi"><label>Skill 名称 *</label><input class="inp" id="sName" value="${esc(skill?.name || '')}" placeholder="例如: sql-injection-scanner" /></div>
      <div class="fi"><label>分类</label><input class="inp" id="sCat" value="${esc(skill?.category || '通用')}" /></div>
    </div>
    <div class="fi" style="margin-top:12px"><label>Skill 说明</label>
      <input class="inp" id="sDesc" value="${esc(skill?.description || '')}" placeholder="一句话说明这个技能查什么" /></div>
    <div class="fi" style="margin-top:12px"><label>Skill 提示词</label>
      <textarea class="inp" id="sPrompt" rows="11" style="height:auto;padding:10px 12px;line-height:1.7;resize:vertical">${esc(skill?.prompt || '')}</textarea>
      <div class="hintline">可用占位符：<code>\${scanPath}</code> 代码目录、<code>\${reportPath}</code> 报告目录、<code>\${skillName}</code> 当前技能名、<code>\${scanReportPath}</code> 复扫时的上一份报告</div></div>
    <label class="chk" style="margin-top:12px"><input type="checkbox" id="sEnabled" ${skill?.enabled !== 0 ? 'checked' : ''} /> 启用该技能</label>`,
    foot: '<button class="btn ghost" data-close>取消</button><button class="btn" id="saveSkillBtn">确定</button>',
  });
  $('#saveSkillBtn', body).onclick = async (e) => {
    const payload = {
      name: $('#sName', body).value.trim(),
      description: $('#sDesc', body).value.trim(),
      prompt: $('#sPrompt', body).value,
      category: $('#sCat', body).value.trim() || '通用',
      enabled: $('#sEnabled', body).checked ? 1 : 0,
    };
    if (!payload.name) return toast('请填写 Skill 名称', 'err');
    const btn = e.target; btn.disabled = true;
    try {
      if (editing) await api('/skills/' + skill.id, { method: 'PUT', body: payload });
      else await api('/skills', { method: 'POST', body: payload });
      toast('已保存'); closeModal(); renderSkills();
    } catch (err) { toast(err.message, 'err'); btn.disabled = false; }
  };
}

/* ---------------- 快速扫描 ---------------- */
async function renderQuick() {
  if (!state.repos.length) { try { state.repos = (await api('/repos')).items; } catch { } }
  if (!state.skills.length) { try { state.skills = (await api('/skills')).items; } catch { } }
  $('#quickRepo').innerHTML = state.repos.filter(r => r.local_exists)
    .map(r => `<option value="${r.id}">${esc(r.name)}（${esc(r.branch)}）</option>`).join('')
    || '<option value="">（还没有已拉取的仓库）</option>';
  $('#quickDepth').innerHTML = (state.meta?.depths || []).map(d => `<option value="${d.value}">${d.label}</option>`).join('');
  $('#quickSkills').innerHTML = state.skills
    .filter(s => !['project-adapt', 'security-scan-base', 'summarize_report'].includes(s.name))
    .map(s => `<option value="${esc(s.name)}">${esc(s.name)} — ${esc(s.description)}</option>`).join('');
}

async function browseDir(path) {
  try {
    const d = await api('/fs/list?path=' + encodeURIComponent(path || ''));
    $('#quickPath').value = d.path;
    const rows = [];
    if (d.parent && d.path !== '/') rows.push(`<div class="dirrow" data-dir="${esc(d.parent)}"><span class="up">↰</span> 返回上级</div>`);
    d.dirs.forEach(x => rows.push(`<div class="dirrow" data-dir="${esc(x.path)}">📁 ${esc(x.name)}</div>`));
    $('#dirBox').innerHTML = rows.join('') || '<div class="dirrow">（空目录）</div>';
    $('#dirBox').hidden = false;
    $$('[data-dir]', $('#dirBox')).forEach(el => el.onclick = () => browseDir(el.dataset.dir));
  } catch (e) { toast(e.message, 'err'); }
}

async function runQuickScan() {
  const src = $('#quickSource').value;
  const skills = [...$('#quickSkills').selectedOptions].map(o => o.value);
  const payload = {
    path: src === 'dir' ? $('#quickPath').value.trim() : '',
    repo_id: src === 'repo' ? +($('#quickRepo').value || 0) : 0,
    depth: $('#quickDepth').value,
    engine: $('#quickEngine').value,
    skill_names: skills,
  };
  if (src === 'dir' && !payload.path) return toast('请填写或选择目录', 'err');
  const btn = $('#quickRunBtn'); btn.disabled = true; btn.innerHTML = '<span class="spin"></span> 提交中';
  try {
    const r = await api('/quick-scan', { method: 'POST', body: payload });
    toast('已提交，开始扫描');
    $('#quickLog').innerHTML = '';
    pollQuick(r.run_id);
  } catch (e) { toast(e.message, 'err'); btn.disabled = false; btn.textContent = '开始扫描'; }
}

function pollQuick(runId) {
  clearInterval(state.quickTimer);
  const btn = $('#quickRunBtn');
  state.quickTimer = setInterval(async () => {
    try {
      const d = await api('/runs/' + runId);
      $('#quickBar').style.width = (d.progress || 0) + '%';
      $('#quickPct').textContent = (d.progress || 0) + '%';
      $('#quickStage').textContent = d.stage || STATUS[d.status] || d.status;
      $('#quickLog').innerHTML = (d.logs || []).map(l => `
        <div class="ln ${l.level}"><span class="t">${new Date(l.ts * 1000).toLocaleTimeString('zh-CN', { hour12: false })}</span>
        <span class="m">${esc(l.message)}</span></div>`).join('');
      const box = $('#quickLog'); box.scrollTop = box.scrollHeight;
      if (!['queued', 'running'].includes(d.status)) {
        clearInterval(state.quickTimer);
        btn.disabled = false; btn.textContent = '开始扫描';
        if (d.status === 'success') toast(`扫描完成：${d.sev_critical + d.sev_high + d.sev_medium + d.sev_low} 个漏洞`);
        else toast(d.error || '扫描失败', 'err');
      }
    } catch (e) { clearInterval(state.quickTimer); btn.disabled = false; btn.textContent = '开始扫描'; }
  }, 1800);
}

/* ---------------- Web 漏洞扫描 ---------------- */
const WS_SEV_LABEL = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' };
const WS_SEV_COLOR = { critical: '#b91c1c', high: '#dc2626', medium: '#ea580c', low: '#2563eb', info: '#6b7280' };
const WS_FLOW_SKILLS = ['web-recon-base', 'web-target-scope', 'web-vuln-verify', 'web-report-writer'];

function wsSevHtml(j) {
  const total = (j.sev_critical || 0) + (j.sev_high || 0) + (j.sev_medium || 0)
    + (j.sev_low || 0) + (j.sev_info || 0);
  if (!total) return '<span class="muted">—</span>';
  const one = (n, k) => n ? `<span style="color:${WS_SEV_COLOR[k]};margin-right:8px">${WS_SEV_LABEL[k]} ${n}</span>` : '';
  return one(j.sev_critical, 'critical') + one(j.sev_high, 'high') + one(j.sev_medium, 'medium')
    + one(j.sev_low, 'low') + one(j.sev_info, 'info');
}

function wsTime(ts) {
  return ts ? new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }) : '—';
}

async function renderWebScan() {
  if (!state.wsMeta) { try { state.wsMeta = await api('/webscan/meta'); } catch { } }
  if (!state.wsSkills.length) { try { state.wsSkills = (await api('/webscan/skills')).items; } catch { } }
  const depths = state.wsMeta?.depths || [];
  if (!$('#wsDepth').options.length) {
    $('#wsDepth').innerHTML = depths.map(d => `<option value="${d.value}">${esc(d.label)}</option>`).join('');
    const std = depths.find(d => d.value === 'standard');
    $('#wsDepth').value = std ? 'standard' : (depths[0]?.value || 'standard');
  }
  if (!$('#wsEngine').options.length) {
    $('#wsEngine').innerHTML = (state.wsMeta?.engines || [])
      .map(e => `<option value="${esc(e.value)}">${esc(e.label)}</option>`).join('');
  }
  if (!$('#wsSkills').options.length) {
    $('#wsSkills').innerHTML = state.wsSkills.filter(s => !WS_FLOW_SKILLS.includes(s.name))
      .map(s => `<option value="${esc(s.name)}">${esc(s.name)} — ${esc(s.description)}</option>`).join('');
  }
  await renderWebJobs();
  // 切走再切回来时，如果还有作业在跑，恢复轮询
  const live = (state.wsJobsCache || []).find(j => j.status === 'running' || j.status === 'queued');
  if (live && !state.wsTimer) pollWebScan(live.job_id);
}

async function renderWebJobs() {
  let items = [];
  try { items = (await api('/webscan/jobs?limit=50')).items; } catch (e) { toast(e.message, 'err'); }
  state.wsJobsCache = items;

  $('#wsTable tbody').innerHTML = items.length ? items.map(j => `
    <tr>
      <td><input type="checkbox" class="rowchk" value="${esc(j.job_id)}"
            ${['running', 'queued'].includes(j.status) ? 'disabled' : ''} /></td>
      <td>${esc(j.name || '未命名')}<div class="muted mono" style="font-size:11px">${esc(j.job_id)}</div></td>
      <td>${(j.targets || []).length} 个<div class="muted" style="font-size:11px">${esc((j.targets || [])[0] || '')}</div></td>
      <td>${esc(j.depth)}</td>
      <td><span class="dot-st ${esc(j.status)}"></span>${esc(STATUS[j.status] || j.status)}</td>
      <td>${wsSevHtml(j)}</td>
      <td>${j.duration_ms ? (j.duration_ms / 1000).toFixed(1) + 's' : '—'}</td>
      <td>${wsTime(j.created_at)}</td>
      <td class="nowrap">
        <button class="btn ghost tiny" data-wsv="${esc(j.job_id)}">查看报告</button>
        ${['running', 'queued'].includes(j.status)
          ? `<button class="btn ghost tiny" data-wsstop="${esc(j.job_id)}">终止</button>`
          : `<button class="btn ghost tiny del-btn" data-wsdel="${esc(j.job_id)}"
               title="删除这条扫描记录（含发现与报告文件，不可恢复）">删除</button>`}
      </td>
    </tr>`).join('') : '<tr><td colspan="9" class="muted" style="text-align:center;padding:26px">还没有扫描记录，填写上方目标后点「开始扫描」</td></tr>';

  $$('[data-wsv]', $('#wsTable')).forEach(b => b.onclick = () => openWebReport(b.dataset.wsv));
  $$('[data-wsstop]', $('#wsTable')).forEach(b => b.onclick = async () => {
    try { await api('/webscan/jobs/' + b.dataset.wsstop + '/stop', { method: 'POST' }); toast('已终止'); renderWebJobs(); }
    catch (e) { toast(e.message, 'err'); }
  });
  $$('[data-wsdel]', $('#wsTable')).forEach(b => b.onclick = () => deleteWebJob(b.dataset.wsdel));
  bindRowChecks('#wsTable', '#wsCheckAll', '#wsSelCount');
}

/** 一条 Web 扫描记录里的问题总数（含提示级）。 */
const wsJobTotal = j => j ? ['critical', 'high', 'medium', 'low', 'info']
  .reduce((a, k) => a + (j['sev_' + k] || 0), 0) : 0;

/** 删除单条扫描记录（走统一样式的确认弹窗）。 */
async function deleteWebJob(jobId) {
  const j = (state.wsJobsCache || []).find(x => x.job_id === jobId);
  const { ok } = await confirmDialog({
    title: '删除扫描记录',
    message: `确认删除扫描记录「${j?.name || '未命名'}」？`,
    detailLabel: '这条记录',
    details: [
      `记录 ID：${jobId}`,
      `扫描目标：${(j?.targets || []).join('、') || '-'}`,
      `问题清单：共 ${wsJobTotal(j)} 个`,
    ],
    note: '记录、问题清单与磁盘上的报告文件将一并删除，且不可恢复。目标站点本身不受任何影响。',
    confirmLabel: '删除记录',
  });
  if (!ok) return;
  try {
    await api('/webscan/jobs/' + encodeURIComponent(jobId), { method: 'DELETE' });
    toast('已删除扫描记录');
    renderWebJobs();
  } catch (e) { toast(e.message, 'err'); }
}

/** 批量删除选中的扫描记录。 */
async function deleteWebJobsBatch() {
  const ids = $$('#wsTable .rowchk:checked').map(c => c.value);
  if (!ids.length) return toast('请先勾选要删除的扫描记录', 'err');
  const byId = new Map((state.wsJobsCache || []).map(j => [j.job_id, j]));
  const busy = ids.filter(id => ['running', 'queued'].includes(byId.get(id)?.status));
  const { ok } = await confirmDialog({
    title: '批量删除扫描记录',
    message: `确认删除选中的 ${ids.length} 条扫描记录？`,
    detailLabel: `以下 ${ids.length} 条记录及其问题清单将被删除`,
    details: ids.map(id => {
      const j = byId.get(id);
      if (!j) return id;
      return `${j.name || '未命名'}　${(j.targets || []).length} 个目标　`
        + `${wsJobTotal(j)} 个问题　${wsTime(j.created_at)}`;
    }),
    note: '记录、问题清单与磁盘上的报告文件将一并删除，且不可恢复。'
      + (busy.length ? `其中 ${busy.length} 条正在扫描或排队，会被跳过。` : ''),
    // 条数一多，误点「确认」的代价就变大——加一道输入确认，让手停一下。
    requireText: ids.length >= 5 ? 'DELETE' : '',
    confirmLabel: `删除 ${ids.length} 条记录`,
  });
  if (!ok) return;
  try {
    const r = await api('/webscan/jobs/delete', { method: 'POST', body: { job_ids: ids } });
    if (r.skipped?.length) {
      toast(`已删除 ${r.deleted} 条，跳过 ${r.skipped.length} 条（扫描中或不存在）`, 'err', 5600);
    } else {
      toast(`已删除 ${r.deleted} 条扫描记录`);
    }
    renderWebJobs();
  } catch (e) { toast(e.message, 'err'); }
}

async function runWebScan() {
  const raw = $('#wsTargets').value.split('\n').map(s => s.trim()).filter(Boolean);
  if (!raw.length) return toast('请填写至少一个目标站点', 'err');
  if (!raw.some(Boolean)) return toast('目标格式不正确', 'err');
  if (!$('#wsAuthorized').checked) return toast('请先勾选确认已获得测试授权', 'err');

  const payload = {
    name: $('#wsName').value.trim(),
    targets: raw,
    depth: $('#wsDepth').value,
    engine: $('#wsEngine').value,
    skill_names: [...$('#wsSkills').selectedOptions].map(o => o.value),
    authorized: true,
  };
  const btn = $('#wsRunBtn');
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> 启动中';
  try {
    const r = await api('/webscan/jobs', { method: 'POST', body: payload });
    toast(`已启动，共 ${raw.length} 个目标`);
    $('#wsLog').innerHTML = '';
    pollWebScan(r.job_id);
    renderWebJobs();
  } catch (e) {
    toast(e.message, 'err');
    btn.disabled = false; btn.textContent = '开始扫描';
  }
}

function pollWebScan(jobId) {
  clearInterval(state.wsTimer);
  state.wsJob = jobId;
  const btn = $('#wsRunBtn');
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> 扫描中';

  const tick = async () => {
    try {
      const d = await api('/webscan/jobs/' + jobId);
      $('#wsBar').style.width = (d.progress || 0) + '%';
      $('#wsPct').textContent = (d.progress || 0) + '%';
      $('#wsStage').textContent = d.stage || STATUS[d.status] || d.status;
      $('#wsTargetsDone').textContent = d.targets_total
        ? `目标 ${d.targets_done || 0}/${d.targets_total} · 已发起 ${d.requests_made || 0} 次请求 · ${((d.elapsed_ms || 0) / 1000).toFixed(0)}s`
        : '';
      $('#wsLog').innerHTML = (d.logs || []).map(l => `
        <div class="ln ${l.level}"><span class="t">${new Date(l.ts * 1000).toLocaleTimeString('zh-CN', { hour12: false })}</span>
        <span class="m">${esc(l.message)}</span></div>`).join('');
      const box = $('#wsLog'); box.scrollTop = box.scrollHeight;

      if (!['queued', 'running'].includes(d.status)) {
        clearInterval(state.wsTimer);
        state.wsTimer = null;
        btn.disabled = false; btn.textContent = '开始扫描';
        const total = (d.sev_critical || 0) + (d.sev_high || 0) + (d.sev_medium || 0)
          + (d.sev_low || 0) + (d.sev_info || 0);
        if (d.status === 'success') {
          toast(`扫描完成：${total} 个问题`);
          renderWebJobs();
          openWebReport(jobId);
        } else {
          toast(d.error || '扫描失败', 'err');
          renderWebJobs();
        }
      }
    } catch (e) {
      clearInterval(state.wsTimer);
      state.wsTimer = null;
      btn.disabled = false; btn.textContent = '开始扫描';
    }
  };
  tick();
  state.wsTimer = setInterval(tick, 1800);
}

async function openWebReport(jobId) {
  let d;
  try { d = await api('/webscan/jobs/' + jobId); } catch (e) { return toast(e.message, 'err'); }
  const fs = d.findings || [];
  const cards = fs.length ? fs.map(f => `
    <div class="ws-finding ${esc(f.severity)}">
      <div class="ws-fhead">
        <span class="badge" style="background:${WS_SEV_COLOR[f.severity] || '#6b7280'}">${WS_SEV_LABEL[f.severity] || f.severity}</span>
        <b>${esc(f.title)}</b>
        ${f.cwe ? `<span class="tag">${esc(f.cwe)}</span>` : ''}
        <span class="tag">${f.source === 'ai' ? 'AI 研判' : '工具判定'}</span>
      </div>
      <div class="kv">
        <div class="k">地址</div><div><code>${esc(f.url || f.target)}</code></div>
        <div class="k">检测项</div><div>${esc(f.skill)}</div>
        ${f.param ? `<div class="k">参数</div><div><code>${esc(f.param)}</code></div>` : ''}
        ${f.payload ? `<div class="k">载荷</div><div><code>${esc(f.payload)}</code></div>` : ''}
      </div>
      ${f.detail ? `<div class="sect"><div class="lb">问题说明</div>${esc(f.detail)}</div>` : ''}
      ${f.evidence ? `<div class="sect"><div class="lb">复现证据</div><div class="codebox">${esc(f.evidence)}</div></div>` : ''}
      ${f.advice ? `<div class="sect"><div class="lb">修复建议</div><div class="fixbox">${esc(f.advice)}</div></div>` : ''}
    </div>`).join('') : '<p class="muted">本次扫描未发现可确认的问题。</p>';

  const tgt = (d.targets || []).map(t => `<li><code>${esc(t)}</code></li>`).join('');
  openDrawer({
    title: d.name || 'Web 扫描报告',
    sub: `${d.job_id} · ${(d.targets || []).length} 个目标 · ${((d.duration_ms || 0) / 1000).toFixed(1)}s · ${d.requests_made || 0} 次请求`,
    body: `
      ${reportActionsHtml('data-ws-prev', jobId, 'data-ws-dl')}
      <div class="stat-row compact">
        ${['critical', 'high', 'medium', 'low'].map(k => `
          <div class="stat-card" style="border-left-color:${WS_SEV_COLOR[k]}">
            <div class="k">${WS_SEV_LABEL[k]}</div>
            <div class="v" style="color:${WS_SEV_COLOR[k]}">${d['sev_' + k] || 0}</div></div>`).join('')}
        <div class="stat-card"><div class="k">合计</div>
          <div class="v">${fs.length}</div></div>
      </div>
      <div class="rep-sect"><h4>扫描目标</h4><ul class="plain">${tgt}</ul>
        <p class="muted">探测强度 ${esc(d.depth)} · ${d.ai_used ? 'AI 自主规划' : '确定性检查'}${d.error ? ' · ' + esc(d.error) : ''}</p>
      </div>
      <div class="rep-sect"><h4>问题清单（${fs.length}）</h4>${cards}</div>`,
  });

  $('#drawerBody [data-ws-prev]').onclick = () =>
    window.open(`/api/webscan/jobs/${jobId}/html`, '_blank');
  // 逐个绑定并读各自的 data-ws-dl（html/md/json）。之前只绑了第一个、
  // 又去选一个不存在的 [data-ws-md]，结果是 Markdown/JSON 点了没反应。
  $$('#drawerBody [data-ws-dl]').forEach(b => b.onclick = () => downloadWebReport(jobId, b.dataset.wsDl));
}

/** 下载 Web 扫描报告。fmt: html | md | json（后端路径是 /markdown，不能直接拿 fmt 拼）。 */
async function downloadWebReport(jobId, fmt = 'html') {
  const map = {
    html: { q: '/html', type: 'text/html;charset=utf-8', ext: 'html',
            tip: 'HTML 报告已下载，双击用浏览器打开，可另存为 PDF' },
    md: { q: '/markdown', type: 'text/markdown;charset=utf-8', ext: 'md', tip: 'Markdown 报告已下载' },
    json: { q: '/json', type: 'application/json;charset=utf-8', ext: 'json', tip: 'JSON 数据已下载' },
  };
  const m = map[fmt] || map.html;
  try {
    const txt = await api(`/webscan/jobs/${encodeURIComponent(jobId)}${m.q}`, { raw: true });
    const blob = new Blob([txt], { type: m.type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `aiholey-webscan-${jobId}.${m.ext}`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast(m.tip);
  } catch (e) { toast(e.message, 'err'); }
}

/* ---------------- 模型设置 ---------------- */
async function renderEngines() {
  const d = await api('/engines');
  state.engines = d.items;
  $('#engineCards').innerHTML = d.items.map(e => `
    <div class="card engine-card ${e.is_default ? 'default' : ''}">
      <div class="st">
        <b>${esc(e.label)}</b>
        ${e.is_default ? '<span class="badge success">默认引擎</span>' : ''}
        ${e.installed ? `<span class="badge on">CLI 已安装</span>` : '<span class="badge off">未检测到 CLI</span>'}
        ${e.configured ? '<span class="badge running">API Key 已配置</span>' : '<span class="badge queued">未配置 Key</span>'}
      </div>
      ${e.installed ? '' : `<div class="hintline" style="margin:-4px 0 10px">未检测到 <code>${e.name}</code> 命令行工具。<b>不影响使用</b>——本平台通过 OpenAI 兼容 API 直连模型，CLI 仅作能力探测。</div>`}
      <div class="meta-row"><span>CLI 路径</span><span class="mono">${esc(e.cli_path || '—')}</span></div>
      <div class="meta-row"><span>CLI 版本</span><span class="mono">${esc(e.cli_version || '—')}</span></div>
      <div class="meta-row"><span>当前 API Key</span><span class="mono">${esc(e.api_key_masked || '—')}</span></div>
      <div class="form" style="margin-top:13px">
        <div class="fi"><label>OPENAI_API_KEY</label><input class="inp" type="password" data-k="${e.name}" value="${e.configured ? '***' : ''}" placeholder="sk-..." /></div>
        <div class="grid-2f">
          <div class="fi"><label>模型</label><input class="inp" data-m="${e.name}" value="${esc(e.model || '')}" /></div>
          <div class="fi"><label>Base URL</label><input class="inp" data-b="${e.name}" value="${esc(e.base_url || '')}" /></div>
        </div>
      </div>
      <div class="mini-btns" style="margin-top:13px">
        <button class="btn" data-save="${e.name}">保存配置</button>
        <button class="btn ghost" data-test="${e.name}">测试连接</button>
        ${e.is_default ? '' : `<button class="btn ghost" data-default="${e.name}">设为默认</button>`}
      </div>
      <div class="hintline" id="etest-${e.name}" style="margin-top:9px"></div>
    </div>`).join('');

  $$('[data-save]').forEach(b => b.onclick = async () => {
    const n = b.dataset.save;
    try {
      await api('/engines/' + n, { method: 'PUT', body: {
        api_key: $(`[data-k="${n}"]`).value, model: $(`[data-m="${n}"]`).value, base_url: $(`[data-b="${n}"]`).value } });
      toast('配置已保存'); renderEngines(); loadEnginePill();
    } catch (e) { toast(e.message, 'err'); }
  });
  $$('[data-test]').forEach(b => b.onclick = async () => {
    const n = b.dataset.test; const out = $('#etest-' + n);
    out.innerHTML = '<span class="spin"></span> 正在测试…';
    try {
      const r = await api(`/engines/${n}/test`, { method: 'POST', body: {
        api_key: $(`[data-k="${n}"]`).value, model: $(`[data-m="${n}"]`).value, base_url: $(`[data-b="${n}"]`).value } });
      out.innerHTML = r.ok ? `<span style="color:#c6f57e">✓ ${esc(r.message)}</span>` : `<span style="color:#ff9fae">✗ ${esc(r.message)}</span>`;
    } catch (e) { out.innerHTML = `<span style="color:#ff9fae">✗ ${esc(e.message)}</span>`; }
  });
  $$('[data-default]').forEach(b => b.onclick = async () => {
    try { await api('/engines/default/' + b.dataset.default, { method: 'POST' }); toast('已切换默认引擎'); renderEngines(); loadEnginePill(); }
    catch (e) { toast(e.message, 'err'); }
  });

  const m = state.meta;
  $('#metaBox').innerHTML = `
    <div class="meta-row"><span>审计深度档位</span><span>${(m?.depths || []).map(d => d.label).join(' / ') || '-'}</span></div>
    <div class="meta-row"><span>同时执行上限</span><span>${m?.max_concurrent ?? '-'} 个扫描进程</span></div>
    <div class="meta-row"><span>调度方式</span><span>${(m?.schedule_types || []).map(x => x.label).join(' / ')}</span></div>
    <div class="meta-row"><span>AI 未配置时</span><span>自动降级为内置规则扫描（22 条规则）</span></div>`;
}

/* ---------------- 系统与账户 ---------------- */
async function renderAbout() {
  const h = await api('/health');
  const m = state.meta;
  $('#aboutBox').innerHTML = `
    <div class="meta-row"><span>服务</span><span>${esc(h.service)} · v2.0</span></div>
    <div class="meta-row"><span>运行时间</span><span>${esc(h.time)}</span></div>
    <div class="meta-row"><span>当前执行中</span><span>${h.running} 个扫描进程</span></div>
    <div class="meta-row"><span>并发上限</span><span>${m?.max_concurrent ?? '-'}</span></div>
    <div class="meta-row"><span>内置规则</span><span>22 条 · 16 个分类</span></div>
    <div class="meta-row"><span>技术栈</span><span>FastAPI + SQLite + 原生前端</span></div>`;
  await renderSecurity();
}

/** 把 UA 压成可辨识的一小段，别把一长串原始 UA 直接铺在界面上。 */
function shortUA(ua) {
  const s = ua || '';
  const os = /Mac OS X|Macintosh/.test(s) ? 'macOS'
    : /Windows/.test(s) ? 'Windows'
    : /Android/.test(s) ? 'Android'
    : /iPhone|iPad/.test(s) ? 'iOS'
    : /Linux/.test(s) ? 'Linux' : '';
  const br = /Edg\//.test(s) ? 'Edge'
    : /Chrome\//.test(s) ? 'Chrome'
    : /Safari\//.test(s) ? 'Safari'
    : /Firefox\//.test(s) ? 'Firefox' : '';
  const label = [br, os].filter(Boolean).join(' · ');
  return label || (s ? s.slice(0, 26) : '未知设备');
}

/**
 * 「登录安全」卡片：当前令牌状态 + 活跃会话列表（可逐个踢出）。
 *
 * 把安全能力摊开给用户看——否则它只是"看不见的机制"，
 * 用户既无法确认它生效，也无法在怀疑账号被盗时做点什么。
 */
async function renderSecurity() {
  let d;
  try {
    d = await api('/auth/sessions');
  } catch (e) {
    const box = $('#secBox');
    if (box) box.innerHTML = `<div class="meta-row"><span>状态</span><span>${esc(e.message)}</span></div>`;
    return;
  }
  state.sessions = d.items || [];
  const t = d.token || {};
  const mins = Math.floor((t.access_expires_in || 0) / 60);
  $('#secBox').innerHTML = `
    <div class="meta-row"><span>认证方式</span><span>JWT · ${esc(t.alg || 'HS256')} 签名</span></div>
    <div class="meta-row"><span>访问令牌</span><span>${mins} 分钟后到期（后台自动续期）</span></div>
    <div class="meta-row"><span>活跃会话</span><span>${state.sessions.length} 个设备</span></div>
    <div class="meta-row"><span>会话保护</span><span>HttpOnly Cookie · SameSite=Lax · CSRF 校验</span></div>`;

  $('#secSessions').innerHTML = state.sessions.map(s => `
    <div class="sess-row">
      <div class="sess-meta">
        <b>${esc(shortUA(s.user_agent))}</b>
        <span>${esc(s.ip || '未知地址')} · 登录 ${esc(fmtTime(s.first_seen))} · 最近活动 ${esc(fmtTime(s.last_seen))}</span>
      </div>
      ${s.current
        ? '<span class="sess-cur">当前设备</span>'
        : `<button class="btn ghost tiny del-btn" data-kick="${esc(s.id)}"
             title="让这个设备立即下线（撤销其刷新令牌，不影响当前设备）">踢出</button>`}
    </div>`).join('')
    || '<div class="sess-empty">除当前设备外没有其它活跃会话</div>';

  $$('#secSessions [data-kick]').forEach(b => b.onclick = async () => {
    const r = await confirmDialog({
      title: '踢出该会话',
      message: '该设备会立即下线，需要重新输入账号密码才能访问。当前设备不受影响。',
      danger: true,
    });
    if (!r.ok) return;
    try {
      await api('/auth/sessions/revoke', { method: 'POST', body: { id: b.dataset.kick } });
      toast('该会话已下线');
      renderSecurity();
    } catch (e) { toast(e.message, 'err'); }
  });
}

/* ---------------- 初始化 ---------------- */
async function loadEnginePill() {
  try {
    const d = await api('/engines');
    const def = d.items.find(x => x.is_default) || d.items[0];
    $('#enginePillText').textContent = `默认引擎：${def.label}${def.configured ? '' : '（未配 Key）'}`;
  } catch { }
}

async function boot() {
  let me;
  try { me = await api('/auth/me'); } catch { return; }
  state.me = me;
  $('#userName').textContent = me.display_name || me.username;
  $('#avatar').textContent = (me.display_name || me.username || 'A').slice(0, 1).toUpperCase();
  if (me.must_change_password) {
    setTimeout(() => toast('当前使用的是默认密码，建议到「系统与账户」修改', 'info', 6000), 900);
  }
  // 令牌到期时间点前主动续期一次，避免用户在操作过程中恰好撞上 401
  startTokenKeepAlive();
  try { state.meta = await api('/meta'); } catch { }
  loadEnginePill();

  $$('.nav-item').forEach(n => n.onclick = () => switchView(n.dataset.view));
  $$('[data-goto]').forEach(el => el.onclick = () => switchView(el.dataset.goto));

  $('#logoutBtn').onclick = async () => {
    try { await api('/auth/logout', { method: 'POST' }); } catch { }
    // 停掉续期计时器：否则登出瞬间若正好触发续期，会白跑一次请求
    clearTimeout(keepAliveTimer);
    tokenExpiresAt = 0;
    location.replace('/login');
  };

  // 一键退出其它设备：怀疑账号在别处被登录时最直接的动作
  const kickOthers = $('#kickOthersBtn');
  if (kickOthers) kickOthers.onclick = async () => {
    const r = await confirmDialog({
      title: '退出其它所有设备',
      message: '除当前设备外，其它已登录设备都会被注销，需要重新输入账号密码登录。',
      danger: true,
    });
    if (!r.ok) return;
    try {
      const res = await api('/auth/sessions/revoke', { method: 'POST', body: { id: '*' } });
      toast(res.revoked ? `已注销 ${res.revoked} 个会话` : '没有其它活跃会话');
      renderSecurity();
    } catch (e) { toast(e.message, 'err'); }
  };

  // 仓库
  $('#repoAddBtn').onclick = () => repoDialog(null);
  $('#repoSearchBtn').onclick = renderRepos;
  $('#repoResetBtn').onclick = () => { $('#repoSearch').value = ''; $('#repoStatusFilter').value = ''; renderRepos(); };

  // 任务
  $('#taskAddBtn').onclick = () => taskDialog(null);
  $('#taskSearchBtn').onclick = renderTasks;
  $('#taskResetBtn').onclick = () => {
    $('#taskSearch').value = ''; $('#taskRepoFilter').value = ''; $('#taskStatusFilter').value = ''; renderTasks();
  };

  // 报告
  $('#reportSearchBtn').onclick = renderReports;
  $('#reportResetBtn').onclick = () => {
    $('#reportSearch').value = ''; $('#reportStatusFilter').value = ''; $('#reportSevFilter').value = ''; renderReports();
  };
  // 表头全选与「已选 N 项」由 renderReports → bindRowChecks 接管。必须在表格
  // 渲染之后、且只作用于本表绑定；留在这里用全局选择器绑会在初始化时把
  // Web 扫描记录的复选框也一起勾上。
  $('#reportBatchDelBtn').onclick = deleteReportsBatch;
  $('#exportSelectedBtn').onclick = async () => {
    const ids = $$('#reportTable .rowchk:checked').map(c => c.value);
    if (!ids.length) return toast('请勾选要导出的报告', 'err');
    try {
      const md = await api('/reports/export', { method: 'POST', body: { run_ids: ids }, raw: true });
      const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = 'aiholey-batch-export.md'; a.click();
      URL.revokeObjectURL(a.href);
      toast(`已导出 ${ids.length} 份报告`);
    } catch (e) { toast(e.message, 'err'); }
  };
  $('#exportAllBtn').onclick = async () => {
    try {
      const d = await api('/reports?status=success&limit=200');
      if (!d.items.length) return toast('没有可导出的报告', 'err');
      const md = await api('/reports/export', { method: 'POST', body: { run_ids: d.items.map(x => x.run_id) }, raw: true });
      const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = 'aiholey-summary-export.md'; a.click();
      URL.revokeObjectURL(a.href);
      toast(`已导出 ${d.items.length} 份报告汇总`);
    } catch (e) { toast(e.message, 'err'); }
  };

  // 执行引擎
  $('#refreshMonitor').onclick = renderMonitor;
  $('#autoRefresh').onchange = e => {
    clearInterval(state.monitorTimer);
    if (e.target.checked) state.monitorTimer = setInterval(renderMonitor, 3000);
  };

  // 技能
  $('#skillAddBtn').onclick = () => skillDialog(null);
  $('#skillSearchBtn').onclick = renderSkills;
  $('#skillResetBtn').onclick = () => { $('#skillSearch').value = ''; $('#skillCatFilter').value = ''; renderSkills(); };
  $('#skillRestoreBtn').onclick = async () => {
    try { const r = await api('/skills/reset', { method: 'POST' }); toast(`已恢复 ${r.count} 项内置技能`); renderSkills(); }
    catch (e) { toast(e.message, 'err'); }
  };

  // 快速扫描
  $('#quickBrowseBtn').onclick = () => browseDir($('#quickPath').value.trim() || '');
  $('#quickRunBtn').onclick = runQuickScan;
  $('#quickSource').onchange = e => {
    const dir = e.target.value === 'dir';
    $('#quickDirRow').hidden = !dir;
    $('#quickRepoRow').hidden = dir;
    $('#dirBox').hidden = true;
  };

  // Web 漏洞扫描
  $('#wsRunBtn').onclick = runWebScan;
  $('#wsRefreshBtn').onclick = renderWebJobs;
  $('#wsBatchDelBtn').onclick = deleteWebJobsBatch;
  $('#wsTargets').oninput = () => {
    const n = $('#wsTargets').value.split('\n').map(s => s.trim()).filter(Boolean).length;
    const max = state.wsMeta?.max_targets || 20;
    $('#wsCount').textContent = n > max ? `${n} 个目标（超出上限 ${max}）` : `${n} 个目标`;
  };

  // 改密
  $('#changePwdBtn').onclick = async () => {
    const o = $('#oldPwd').value, n = $('#newPwd').value, n2 = $('#newPwd2').value;
    if (!o || !n) return toast('请填写原密码与新密码', 'err');
    if (n !== n2) return toast('两次输入的新密码不一致', 'err');
    try {
      const r = await api('/auth/password', { method: 'POST', body: { old_password: o, new_password: n } });
      $('#oldPwd').value = $('#newPwd').value = $('#newPwd2').value = '';
      // 改密的重点就是「让别处拿着旧密码/旧令牌的人立刻失效」，这点要明确讲出来
      toast(r.revoked_sessions
        ? `密码已修改，其它 ${r.revoked_sessions} 个会话已被注销`
        : '密码已修改');
      state.me = await api('/auth/me');     // 服务端已换发新令牌，重新校准续期时间
      startTokenKeepAlive();
      renderSecurity();
    } catch (e) { toast(e.message, 'err'); }
  };

  $('#modalClose').onclick = closeModal;
  $('#drawerClose').onclick = closeDrawer;
  $('#modalMask').onclick = e => { if (e.target.id === 'modalMask') closeModal(); };
  $('#drawerMask').onclick = e => { if (e.target.id === 'drawerMask') closeDrawer(); };

  window.addEventListener('resize', () => {
    if (currentView === 'dashboard') renderDashboard().catch(() => { });
  });

  const hash = location.hash.replace('#', '');
  switchView(VIEW_META[hash] ? hash : 'dashboard');
}

boot();
