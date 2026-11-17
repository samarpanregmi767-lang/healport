Demo: https://claude.ai/artifact/J2XUbU7nFzMRVWWg3nWh9V
Slides: https://claude.ai/artifact/N4LFvXaL69SPzgiaHCxbeE

# HealPort backend (Week 4 testing)

## Run
    npm install
    cp .env.example .env      # then change both secrets
    npm run vuln              # Version 1, port 3000 (before)
    npm run secure            # Version 2, port 3001 (after)   (use a second terminal)
Windows and Mac both work with these npm scripts (cross-env is included).

Test users: admin/Admin#2026, dr.kim/Doc#2026, pat1/Pat1#2026, pat2/Pat2#2026

## Attacks (run against port 3000, then 3001, and screenshot both)
1. SQL injection (Postman: POST /api/login, body `{"username":"admin' --","password":"x"}`)
   Expect: v1 returns a token, v2 returns 401.
2. IDOR: log in as pat1, then `GET /api/records/2` with `Authorization: Bearer <token>`.
   Expect: v1 returns Patient Two's note, v2 returns 403.
3. Privilege escalation: as pat1, `GET /api/admin/users`. Expect: v1 200, v2 403.
4. Brute force: `for i in {1..10}; do curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:3000/api/login -H "Content-Type: application/json" -d '{"username":"pat1","password":"bad"}'; done`
   Expect: v1 ten 401s, v2 five 401s then 429.
5. Headers: `curl -I localhost:3000/api/appointments` vs port 3001 (Helmet headers appear).
6. Data at rest: open `vulnerable.db` and `secure.db` in DB Browser for SQLite and compare the `records.note` and `users.password` columns.
7. Audit: as admin on v2, `GET /api/admin/audit` shows logins, denied attempts and record reads.

## STRIDE mapping
S: bcrypt + JWT 1h + login limit | T: parameterized queries + validation | R: audit table
I: AES-256-GCM + Helmet + ownership check | D: express-rate-limit | E: role middleware
Production note: use HTTPS (Render/Vercel provide it) and move SQLite to Supabase/PostgreSQL.

## One-command test
With both servers running, open a third terminal and run `npm run attack`.
It prints the before/after table. Restart `npm run secure` before re-running (the rate limiter remembers).
