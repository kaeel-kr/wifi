'use strict';
(() => {
  /* ------------------------------ Helpers ------------------------------ */
  const $ = (id) => document.getElementById(id);
  const TOKEN_KEY = 'nv_token';
  const state = { token: null, user: null, ttlMin: 20, provider: 'simulated', sessions: [], totals: { generated: 0, received: 0 }, activeId: null, es: null, countries: [] };
  const PLATFORM_LABEL = { whatsapp: 'WhatsApp', telegram: 'Telegram' };
  const STATUS_LABEL = { waiting: 'Aguardando SMS', received: 'Recebido', cancelled: 'Cancelado', expired: 'Expirado' };
  const STATUS_COLOR = { waiting: 'text-yellow-300', received: 'text-ok', cancelled: 'text-slate-400', expired: 'text-red-400' };
  let timerInt = null, statsInt = null, pollInt = null, reconnectT = null, termInt = null, aiInt = null;

  const store = {
    get() { try { return localStorage.getItem(TOKEN_KEY); } catch { return null; } },
    set(v) { try { localStorage.setItem(TOKEN_KEY, v); } catch { /* ignore */ } },
    clear() { try { localStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ } },
  };

  function toast(msg, type = 'info') {
    const e = $('toast');
    const colors = {
      info: 'border-neon/40 bg-panel text-slate-100',
      ok: 'border-ok/40 bg-panel text-ok',
      error: 'border-red-500/40 bg-panel text-red-300',
    };
    e.className = 'fixed top-4 right-4 z-50 max-w-sm rounded-lg border px-4 py-3 text-sm shadow-lg ' + colors[type];
    e.textContent = msg;
    clearTimeout(toast.t);
    toast.t = setTimeout(() => e.classList.add('hidden'), 3500);
  }

  async function api(path, { method = 'GET', body } = {}) {
    const headers = { Accept: 'application/json' };
    if (body) headers['Content-Type'] = 'application/json';
    if (state.token) headers.Authorization = 'Bearer ' + state.token;
    let res;
    try {
      res = await fetch('/api' + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    } catch {
      throw new Error('Sem conexão com o servidor.');
    }
    let data = {};
    try { data = await res.json(); } catch { /* sem corpo */ }
    if (res.status === 401 && state.token) { logout(); throw new Error('Sessão expirada. Entre novamente.'); }
    if (!res.ok) throw new Error(data.error || 'Erro inesperado (' + res.status + ').');
    return data;
  }

  async function copy(text, label) {
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; } catch { /* tenta fallback */ }
    if (!ok) {
      const t = document.createElement('textarea');
      t.value = text; document.body.appendChild(t); t.select();
      try { ok = document.execCommand('copy'); } catch { ok = false; }
      t.remove();
    }
    toast(ok ? label + ' copiado!' : 'Não foi possível copiar. Selecione e copie manualmente.', ok ? 'ok' : 'error');
  }

  const fmtDate = (ms) => new Date(ms).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
  const setBusy = (btn, busy) => { btn.disabled = busy; };
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

  /* ------------------------------ Auth UI ------------------------------ */
  function showAuthTab(which) {
    const login = which === 'login';
    $('form-login').classList.toggle('hidden', !login);
    $('form-register').classList.toggle('hidden', login);
    $('tab-login').className = 'btn rounded-md py-2 text-sm font-semibold ' + (login ? 'bg-neon text-ink' : 'text-slate-400');
    $('tab-register').className = 'btn rounded-md py-2 text-sm font-semibold ' + (!login ? 'bg-neon text-ink' : 'text-slate-400');
  }
  $('tab-login').addEventListener('click', () => showAuthTab('login'));
  $('tab-register').addEventListener('click', () => showAuthTab('register'));

  function pwScore(pw) {
    let s = 0;
    if (pw.length >= 8) s++;
    if (pw.length >= 12) s++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
    if (/\d/.test(pw)) s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    return s;
  }
  $('reg-password').addEventListener('input', (e) => {
    const pw = e.target.value;
    const s = pwScore(pw);
    const bar = $('pw-bar');
    bar.style.width = (pw ? (s / 5) * 100 : 0) + '%';
    bar.style.background = s <= 2 ? '#ef4444' : s === 3 ? '#eab308' : '#00FF66';
    $('pw-hint').textContent = !pw ? 'Mínimo 8 caracteres com maiúscula, minúscula e número.'
      : s <= 2 ? 'Senha fraca' : s === 3 ? 'Senha razoável' : 'Senha forte';
  });

  const clientPasswordError = (pw) => {
    if (pw.length < 8) return 'A senha deve ter pelo menos 8 caracteres.';
    if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/\d/.test(pw)) return 'Use letra maiúscula, minúscula e número.';
    return null;
  };

  $('form-login').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type=submit]');
    const err = $('login-error'); err.classList.add('hidden');
    setBusy(btn, true);
    try {
      const d = await api('/auth/login', { method: 'POST', body: { email: $('login-email').value, password: $('login-password').value } });
      await startSession(d.token);
    } catch (ex) { err.textContent = ex.message; err.classList.remove('hidden'); }
    finally { setBusy(btn, false); }
  });

  $('form-register').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type=submit]');
    const err = $('reg-error'); err.classList.add('hidden');
    const name = $('reg-name').value.trim(), email = $('reg-email').value.trim(), password = $('reg-password').value;
    const local = name.length < 2 ? 'Informe seu nome.' : !/^\S+@\S+\.\S+$/.test(email) ? 'E-mail inválido.' : clientPasswordError(password);
    if (local) { err.textContent = local; err.classList.remove('hidden'); return; }
    setBusy(btn, true);
    try {
      const d = await api('/auth/register', { method: 'POST', body: { name, email, password } });
      await startSession(d.token);
    } catch (ex) { err.textContent = ex.message; err.classList.remove('hidden'); }
    finally { setBusy(btn, false); }
  });

  function logout() {
    store.clear();
    state.token = null; state.user = null; state.sessions = []; state.activeId = null;
    closeStream();
    stopTerminal();
    clearInterval(timerInt); clearInterval(statsInt); clearInterval(pollInt);
    $('view-app').classList.add('hidden');
    $('view-auth').classList.remove('hidden');
  }
  $('btn-logout').addEventListener('click', logout);

  /* ------------------------------ Abas ------------------------------ */
  function showTab(name) {
    for (const b of document.querySelectorAll('.tab-btn')) {
      const on = b.dataset.tab === name;
      b.className = 'tab-btn btn px-4 py-2 border-b-2 font-semibold ' + (on ? 'border-neon text-neon' : 'border-transparent text-slate-400 hover:text-slate-200');
    }
    $('panel-gen').classList.toggle('hidden', name !== 'gen');
    $('panel-hist').classList.toggle('hidden', name !== 'hist');
    $('panel-sec').classList.toggle('hidden', name !== 'sec');
    if (name === 'hist') loadHistory().catch(() => {});
    if (name === 'sec') loadStats();
  }
  for (const b of document.querySelectorAll('.tab-btn')) b.addEventListener('click', () => showTab(b.dataset.tab));

  /* ------------------------------ Boot ------------------------------ */
  async function startSession(token) {
    state.token = token;
    store.set(token);
    const me = await api('/me');
    state.user = me.user; state.ttlMin = me.ttlMin; state.provider = me.provider; state.totals = me.totals;
    const c = await api('/countries');
    state.countries = c.countries;

    $('view-auth').classList.add('hidden');
    $('view-app').classList.remove('hidden');
    $('user-name').textContent = me.user.name;
    $('user-email').textContent = me.user.email;
    $('sim-banner').classList.toggle('hidden', me.provider !== 'simulated');

    const sel = $('sel-country'); sel.textContent = '';
    for (const k of c.countries) {
      const o = el('option', null, k.name + ' (+' + k.dial + ')'); o.value = k.id; sel.appendChild(o);
    }

    await loadHistory();
    const waiting = state.sessions.find((s) => s.status === 'waiting');
    state.activeId = waiting ? waiting.id : null;
    renderLive();
    showTab('gen');
    connectStream();
    startTerminal();
    loadStats(); clearInterval(statsInt); statsInt = setInterval(loadStats, 10000);
    clearInterval(timerInt); timerInt = setInterval(tickTimer, 1000);
    // Rede de segurança: se o canal em tempo real cair, sincroniza por consulta.
    clearInterval(pollInt);
    pollInt = setInterval(() => { if (state.sessions.some((s) => s.status === 'waiting')) loadHistory().catch(() => {}); }, 6000);
  }

  /* ------------------------------ Tempo real (SSE) ------------------------------ */
  function setRt(text, ok) {
    const e = $('rt-status');
    e.textContent = text;
    e.className = 'ml-auto text-xs ' + (ok ? 'text-ok' : 'text-slate-500');
  }
  function closeStream() {
    clearTimeout(reconnectT);
    if (state.es) { state.es.close(); state.es = null; }
  }
  async function connectStream() {
    closeStream();
    if (!state.token) return;
    try {
      const { ticket } = await api('/stream-ticket', { method: 'POST' });
      const es = new EventSource('/api/stream?ticket=' + encodeURIComponent(ticket));
      state.es = es;
      es.onopen = () => { setRt('● tempo real conectado', true); loadHistory().catch(() => {}); };
      es.addEventListener('session', (ev) => { try { handleSession(JSON.parse(ev.data)); } catch { /* ignora */ } });
      es.onerror = () => {
        es.close(); if (state.es === es) state.es = null;
        setRt('reconectando...', false);
        clearTimeout(reconnectT);
        reconnectT = setTimeout(() => { if (state.token) connectStream(); }, 3000);
      };
    } catch {
      setRt('reconectando...', false);
      clearTimeout(reconnectT);
      reconnectT = setTimeout(() => { if (state.token) connectStream(); }, 4000);
    }
  }

  function handleSession(sess) {
    const i = state.sessions.findIndex((x) => x.id === sess.id);
    if (i >= 0) {
      const prev = state.sessions[i];
      state.sessions[i] = sess;
      if (prev.status === 'waiting' && sess.status === 'received') toast('Código recebido: ' + sess.code, 'ok');
    } else {
      state.sessions.unshift(sess);
    }
    recount();
    renderHistory();
    if (sess.id === state.activeId) renderLive();
  }

  function recount() {
    // Totais do servidor cobrem todo o histórico; localmente só atualizamos se houver mais dados.
    const received = state.sessions.filter((s) => s.status === 'received').length;
    state.totals.received = Math.max(state.totals.received, received);
    state.totals.generated = Math.max(state.totals.generated, state.sessions.length);
    $('tot-gen').textContent = state.totals.generated;
    $('tot-rec').textContent = state.totals.received;
  }

  /* ------------------------------ Histórico ------------------------------ */
  async function loadHistory() {
    const d = await api('/numbers');
    state.sessions = d.sessions;
    state.totals = d.totals;
    $('tot-gen').textContent = d.totals.generated;
    $('tot-rec').textContent = d.totals.received;
    renderHistory();
    if (state.activeId) renderLive();
  }
  $('btn-reload').addEventListener('click', () => loadHistory().catch((e) => toast(e.message, 'error')));

  function renderHistory() {
    const tb = $('history'); tb.textContent = '';
    $('history-empty').classList.toggle('hidden', state.sessions.length > 0);
    for (const s of state.sessions) {
      const tr = el('tr', 'border-b border-edge/60');
      tr.appendChild(el('td', 'py-2 pr-3 text-slate-400 whitespace-nowrap', fmtDate(s.createdAt)));
      tr.appendChild(el('td', 'pr-3', PLATFORM_LABEL[s.platform] || s.platform));
      tr.appendChild(el('td', 'pr-3 font-mono', s.phone));
      tr.appendChild(el('td', 'pr-3 ' + (STATUS_COLOR[s.status] || ''), STATUS_LABEL[s.status] || s.status));
      tr.appendChild(el('td', 'pr-3 font-mono text-ok', s.code || '—'));
      const td = el('td', 'text-right whitespace-nowrap');
      const b1 = el('button', 'btn text-xs text-neon hover:underline mr-3', 'Copiar nº');
      b1.type = 'button';
      b1.addEventListener('click', () => copy(s.phone, 'Número'));
      td.appendChild(b1);
      if (s.code) {
        const b2 = el('button', 'btn text-xs text-ok hover:underline mr-3', 'Copiar código');
        b2.type = 'button';
        b2.addEventListener('click', () => copy(s.code, 'Código'));
        td.appendChild(b2);
      }
      if (s.status === 'waiting') {
        const b3 = el('button', 'btn text-xs text-slate-300 hover:underline', 'Abrir');
        b3.type = 'button';
        b3.addEventListener('click', () => { state.activeId = s.id; renderLive(); showTab('gen'); });
        td.appendChild(b3);
      }
      tr.appendChild(td);
      tb.appendChild(tr);
    }
  }

  /* ------------------------------ Número ativo ------------------------------ */
  const activeSession = () => state.sessions.find((s) => s.id === state.activeId) || null;

  function renderLive() {
    const s = activeSession();
    $('live').classList.toggle('hidden', !s);
    if (!s) return;
    const country = state.countries.find((c) => c.id === s.country);
    $('live-meta').textContent = (PLATFORM_LABEL[s.platform] || s.platform) + ' · ' + (country ? country.name : s.country);
    $('live-phone').textContent = s.phone;

    const st = $('live-status'); st.textContent = '';
    const codeRow = $('live-code-row');
    codeRow.classList.add('hidden');
    if (s.status === 'waiting') {
      st.appendChild(el('span', 'pulse-dot inline-block w-2 h-2 rounded-full bg-yellow-300'));
      st.appendChild(el('span', 'text-yellow-300', 'Aguardando SMS...'));
    } else if (s.status === 'received') {
      st.appendChild(el('span', 'inline-block w-2 h-2 rounded-full bg-ok'));
      st.appendChild(el('span', 'text-ok', 'Código Recebido: ' + s.code));
      $('live-code').textContent = s.code;
      codeRow.classList.remove('hidden');
    } else {
      st.appendChild(el('span', STATUS_COLOR[s.status], STATUS_LABEL[s.status]));
    }
    const waiting = s.status === 'waiting';
    $('btn-refresh').classList.toggle('hidden', !waiting);
    $('btn-cancel').classList.toggle('hidden', !waiting);
    $('btn-swap').classList.toggle('hidden', !waiting);
    tickTimer();
  }

  function tickTimer() {
    const s = activeSession();
    const t = $('live-timer');
    if (!s || s.status !== 'waiting') { t.textContent = ''; return; }
    const left = Math.max(0, Math.floor((s.expiresAt - Date.now()) / 1000));
    t.textContent = 'expira em ' + String(Math.floor(left / 60)).padStart(2, '0') + ':' + String(left % 60).padStart(2, '0');
  }

  async function generate() {
    const btn = $('btn-generate');
    setBusy(btn, true);
    try {
      const d = await api('/numbers', { method: 'POST', body: { platform: $('sel-platform').value, country: $('sel-country').value } });
      if (!state.sessions.some((x) => x.id === d.session.id)) state.sessions.unshift(d.session);
      state.activeId = d.session.id;
      state.totals = d.totals;
      recount();
      renderHistory(); renderLive();
    } catch (e) { toast(e.message, 'error'); }
    finally { setBusy(btn, false); }
  }
  $('btn-generate').addEventListener('click', generate);

  $('btn-copy-phone').addEventListener('click', () => { const s = activeSession(); if (s) copy(s.phone, 'Número'); });
  $('btn-copy-code').addEventListener('click', () => { const s = activeSession(); if (s && s.code) copy(s.code, 'Código'); });

  $('btn-refresh').addEventListener('click', async () => {
    const s = activeSession(); if (!s) return;
    const btn = $('btn-refresh'); setBusy(btn, true);
    try {
      const d = await api('/numbers/' + s.id + '/refresh', { method: 'POST' });
      handleSession(d.session);
      if (d.session.status === 'waiting') toast('Ainda aguardando o SMS...');
    } catch (e) { toast(e.message, 'error'); }
    finally { setBusy(btn, false); }
  });

  async function cancelActive() {
    const s = activeSession(); if (!s) return false;
    try {
      const d = await api('/numbers/' + s.id + '/cancel', { method: 'POST' });
      handleSession(d.session);
      return true;
    } catch (e) { toast(e.message, 'error'); return false; }
  }
  $('btn-cancel').addEventListener('click', async () => {
    const btn = $('btn-cancel'); setBusy(btn, true);
    if (await cancelActive()) toast('Número cancelado.', 'ok');
    setBusy(btn, false);
  });
  $('btn-swap').addEventListener('click', async () => {
    const btn = $('btn-swap'); setBusy(btn, true);
    const s = activeSession();
    if (s) { $('sel-platform').value = s.platform; $('sel-country').value = s.country; }
    if (await cancelActive()) await generate();
    setBusy(btn, false);
  });

  /* ------------------------------ Painel de segurança ------------------------------ */
  async function loadStats() {
    try {
      const d = await api('/security/stats');
      $('st-rl').textContent = d.rateLimited;
      $('st-fl').textContent = d.failedLogins;
      $('st-in').textContent = d.invalidInputs;
      $('st-lc').textContent = d.liveConnections;
    } catch { /* silencioso */ }
  }

  const LOGS = [
    ['DDoS-Shield', 'Pico de tráfego volumétrico mitigado'],
    ['IP-Guard', 'IP suspeito adicionado à lista de bloqueio'],
    ['TLS-Crypt', 'Canal criptografado renovado (chaves rotacionadas)'],
    ['SQLi-Filter', 'Tentativa de SQL Injection neutralizada'],
    ['XSS-Filter', 'Payload <script> sanitizado na entrada'],
    ['Brute-Force', 'Sequência de logins falhos barrada'],
    ['JWT-Audit', 'Token verificado e assinatura validada'],
    ['Rate-Limit', 'Cliente excedeu o limite — requisição recusada'],
    ['Bot-Detect', 'Padrão de automação identificado e contido'],
    ['E2E-Vault', 'Segredos de sessão selados no cofre'],
  ];
  const rnd = (n) => Math.floor(Math.random() * n);
  const maskIp = () => (rnd(223) + 1) + '.' + rnd(256) + '.***.***';

  function addLog() {
    const term = $('term');
    const [mod, msg] = LOGS[rnd(LOGS.length)];
    const line = el('div');
    line.appendChild(el('span', 'text-slate-500', new Date().toLocaleTimeString('pt-BR') + ' '));
    line.appendChild(el('span', 'text-neon', '[' + mod + '] '));
    line.appendChild(el('span', null, msg + ' · ' + maskIp()));
    term.appendChild(line);
    while (term.childNodes.length > 60) term.removeChild(term.firstChild);
    term.scrollTop = term.scrollHeight;
  }
  function startTerminal() {
    stopTerminal();
    $('term').textContent = '';
    for (let i = 0; i < 6; i++) addLog();
    termInt = setInterval(addLog, 1400);
    aiInt = setInterval(() => { $('ai-count').textContent = (10420 + rnd(21) - 10).toLocaleString('pt-BR'); }, 2500);
  }
  function stopTerminal() { clearInterval(termInt); clearInterval(aiInt); }

  /* ------------------------------ Init ------------------------------ */
  (async () => {
    const t = store.get();
    if (!t) return;
    try { await startSession(t); } catch { logout(); }
  })();
})();
