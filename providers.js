'use strict';
/**
 * Provedores de números/SMS.
 * PROVIDER=simulated (padrão) | 5sim | smsactivate
 * PROVIDER_API_KEY=<sua chave>
 *
 * Interface comum:
 *   buy({ country, platform })  -> { providerId, phone, simulateAt? }
 *   check(session)              -> { code: string|null }
 *   cancel(session)             -> void
 */
const crypto = require('crypto');

const COUNTRIES = [
  { id: 'br', name: 'Brasil', dial: '55', fivesim: 'brazil', sa: 73 },
  { id: 'us', name: 'Estados Unidos', dial: '1', fivesim: 'usa', sa: 12 },
  { id: 'in', name: 'Índia', dial: '91', fivesim: 'india', sa: 22 },
  { id: 'id', name: 'Indonésia', dial: '62', fivesim: 'indonesia', sa: 6 },
  { id: 'ru', name: 'Rússia', dial: '7', fivesim: 'russia', sa: 0 },
  { id: 'gb', name: 'Reino Unido', dial: '44', fivesim: 'england', sa: 16 },
];

const PLATFORMS = ['whatsapp', 'telegram'];

const randDigits = (n) =>
  Array.from({ length: n }, () => crypto.randomInt(0, 10)).join('');

/* ---------------------------- Simulado ---------------------------- */
const simulated = {
  name: 'simulated',
  async buy({ country }) {
    const delay = 5000 + crypto.randomInt(0, 10000);
    return {
      providerId: 'sim-' + crypto.randomUUID(),
      phone: '+' + country.dial + randDigits(10),
      simulateAt: Date.now() + delay,
    };
  },
  async check(session) {
    if (session.simulateAt && Date.now() >= session.simulateAt) {
      return { code: randDigits(6) };
    }
    return { code: null };
  },
  async cancel() {},
};

/* ------------------------------ 5sim ------------------------------ */
function make5sim(key) {
  const base = 'https://5sim.net/v1';
  const api = async (p) => {
    const r = await fetch(base + p, {
      headers: { Authorization: 'Bearer ' + key, Accept: 'application/json' },
    });
    const text = await r.text();
    if (!r.ok) throw new Error('5sim: ' + (text || r.status));
    try { return JSON.parse(text); } catch { return text; }
  };
  return {
    name: '5sim',
    async buy({ country, platform }) {
      const d = await api(`/user/buy/activation/${country.fivesim}/any/${platform}`);
      if (!d || !d.id || !d.phone) throw new Error('5sim: resposta inválida');
      const phone = String(d.phone).startsWith('+') ? String(d.phone) : '+' + d.phone;
      return { providerId: String(d.id), phone };
    },
    async check(session) {
      const d = await api(`/user/check/${session.providerId}`);
      const sms = d && Array.isArray(d.sms) ? d.sms : [];
      if (sms.length && sms[0].code) return { code: String(sms[0].code) };
      const m = sms.length && sms[0].text ? String(sms[0].text).match(/\b(\d{4,8})\b/) : null;
      return { code: m ? m[1] : null };
    },
    async cancel(session) {
      await api(`/user/cancel/${session.providerId}`);
    },
  };
}

/* -------------------------- SMS-Activate -------------------------- */
function makeSmsActivate(key) {
  const base = 'https://api.sms-activate.org/stubs/handler_api.php';
  const call = async (params) => {
    const r = await fetch(base + '?' + new URLSearchParams({ api_key: key, ...params }));
    return (await r.text()).trim();
  };
  return {
    name: 'smsactivate',
    async buy({ country, platform }) {
      const text = await call({
        action: 'getNumber',
        service: platform === 'whatsapp' ? 'wa' : 'tg',
        country: String(country.sa),
      });
      if (!text.startsWith('ACCESS_NUMBER')) throw new Error('SMS-Activate: ' + text);
      const [, id, number] = text.split(':');
      return { providerId: id, phone: '+' + number };
    },
    async check(session) {
      const text = await call({ action: 'getStatus', id: session.providerId });
      if (text.startsWith('STATUS_OK')) return { code: text.split(':')[1] || null };
      return { code: null };
    },
    async cancel(session) {
      await call({ action: 'setStatus', status: '8', id: session.providerId });
    },
  };
}

function getProvider() {
  const name = (process.env.PROVIDER || 'simulated').toLowerCase();
  const key = process.env.PROVIDER_API_KEY || '';
  if (name !== 'simulated' && !key) {
    console.warn(`[provider] PROVIDER=${name} sem PROVIDER_API_KEY — usando modo simulado.`);
    return simulated;
  }
  if (name === '5sim') return make5sim(key);
  if (name === 'smsactivate') return makeSmsActivate(key);
  return simulated;
}

module.exports = { COUNTRIES, PLATFORMS, getProvider };
