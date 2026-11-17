// Runs all attacks against Version 1 (port 3000) and Version 2 (port 3001) and prints a before/after table.
const Database = require('better-sqlite3');
const send = async (base, path, method = 'GET', data, token) => {
  const r = await fetch(base + path, { method, headers: { 'Content-Type': 'application/json', ...(token && { Authorization: 'Bearer ' + token }) }, body: data && JSON.stringify(data) });
  let b = null; try { b = await r.json(); } catch {}
  return { s: r.status, b, h: r.headers };
};
const login = (base, u, p) => send(base, '/api/login', 'POST', { username: u, password: p });
const verdict = (ok, good, bad) => ok ? 'PASSED: ' + good : 'FAILED: ' + bad;

async function run(base, dbFile) {
  const out = {};
  const pat = (await login(base, 'pat1', 'Pat1#2026')).b?.token;      // log in first, before the brute-force test
  const adm = (await login(base, 'admin', 'Admin#2026')).b?.token;
  let r = await login(base, "admin' --", 'x');
  out['SQL injection on login'] = verdict(r.s !== 200, 'blocked (' + r.s + ')', 'logged in as admin without a password');
  r = await send(base, '/api/records/2', 'GET', null, pat);
  out['Patient reads another patient record'] = verdict(r.s === 403, '403 Forbidden', r.s + ' leaked: ' + JSON.stringify(r.b?.note));
  r = await send(base, '/api/admin/users', 'GET', null, pat);
  out['Patient opens admin user list'] = verdict(r.s === 403, '403 Forbidden', r.s + ' user list leaked');
  r = await send(base, '/api/admin/audit', 'GET', null, adm);
  out['Audit log records activity'] = verdict(Array.isArray(r.b) && r.b.length > 0, r.b?.length + ' entries logged', 'nothing logged');
  r = await send(base, '/api/appointments', 'GET', null, adm);
  out['Security headers present'] = verdict(!!r.h.get('x-content-type-options'), 'Helmet headers found', 'headers missing');
  try {
    const note = new Database(dbFile, { readonly: true }).prepare('SELECT note FROM records WHERE id = 2').get().note;
    out['Medical data encrypted at rest'] = verdict(/^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/.test(note), 'stored encrypted', 'stored as plain text: ' + note);
  } catch (e) { out['Medical data encrypted at rest'] = 'could not open ' + dbFile; }
  let blocked = 0;
  for (let i = 0; i < 10; i++) if ((await login(base, 'pat1', 'wrong' + i)).s === 429) blocked++;
  out['Brute-force login (10 tries)'] = verdict(blocked > 0, 'blocked after too many tries (429)', 'all 10 tries allowed');
  return out;
}
(async () => {
  try {
    const before = await run('http://localhost:3000', 'vulnerable.db');
    const after = await run('http://localhost:3001', 'secure.db');
    console.table(Object.keys(before).map(k => ({ Attack: k, 'BEFORE (Version 1)': before[k], 'AFTER (Version 2)': after[k] })));
  } catch (e) { console.log('Could not reach the servers. Are BOTH terminals running? ->', e.message); }
})();
