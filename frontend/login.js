/* 登录页交互。
 *
 * 单独拆成外部文件而不是内联 <script>：主站 CSP 是 `script-src 'self'`（不给
 * 'unsafe-inline'），内联脚本会被浏览器直接拦掉——登录页就再也点不动了。
 */
const $ = (s) => document.querySelector(s);
const msg = $('#msg');

/** 显示提示。kind: err | ok */
function show(kind, text) {
  msg.className = 'msg ' + kind;
  msg.textContent = text;
}

// 已登录（access 有效）就直接进控制台。refresh 还活着但 access 过期的情况这里
// 判不了——refresh cookie 限定了 path 只发给 /api/auth，这个请求带不上它；
// 那种情况会走到首页，由 index 里的 api() 自动续期。
fetch('/api/auth/me', { credentials: 'same-origin' })
  .then((r) => { if (r.ok) location.replace('/'); })
  .catch(() => {});

$('#togglePwd').addEventListener('click', () => {
  const p = $('#password');
  p.type = p.type === 'password' ? 'text' : 'password';
});

let cooldown = 0;   // 登录失败过多被锁时的倒计时

$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (cooldown > 0) return;
  const btn = $('#submitBtn');
  btn.disabled = true;
  btn.textContent = '登录中…';
  msg.className = 'msg';
  try {
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: $('#username').value.trim(), password: $('#password').value }),
    });
    const data = await r.json().catch(() => ({}));

    // 429 = 失败次数过多被临时锁定。服务端在 Retry-After 里给了剩余秒数，
    // 这里把它变成可见的倒计时——否则用户只会看到"登录不了"，以为是密码错了，
    // 反而越试越锁。
    if (r.status === 429) {
      let wait = parseInt(r.headers.get('Retry-After') || '0', 10);
      if (!wait || Number.isNaN(wait)) wait = 60;
      startCooldown(wait, data.detail || '尝试次数过多，请稍后再试');
      return;
    }
    if (!r.ok) throw new Error(data.detail || `登录失败（HTTP ${r.status}）`);

    show('ok', '登录成功，正在进入控制台…');
    setTimeout(() => location.replace('/'), 420);
  } catch (err) {
    show('err', err.message || '登录失败');
    btn.disabled = false;
    btn.textContent = '登 录';
  }
});

function startCooldown(sec, text) {
  const btn = $('#submitBtn');
  cooldown = sec;
  const tick = () => {
    if (cooldown <= 0) {
      btn.disabled = false;
      btn.textContent = '登 录';
      show('err', '可以重新登录了');
      clearInterval(timer);
      return;
    }
    btn.disabled = true;
    btn.textContent = `请等待 ${cooldown}s`;
    show('err', `${text}（${cooldown} 秒后可重试）`);
    cooldown -= 1;
  };
  const timer = setInterval(tick, 1000);
  tick();
}
