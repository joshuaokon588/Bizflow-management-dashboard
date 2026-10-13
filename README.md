# BizFlow Production Security Plan — Full-stack application

A local full-stack business management application built with Node.js, Express, MySQL 8+, and a responsive browser interface. It includes customer/product management, sales recording with transaction-safe inventory deduction, expenses, login, role-based authorization, audit events, request limits, security headers, health checks, and a Windows backup script.

> **Production note:** This is a security-conscious application foundation, not a guarantee of production certification. Before handling real customer/business data, complete the deployment checklist below, run tests and security review, use HTTPS, configure backups off-host, and test restoration. Do not publish `.env` or real data to GitHub.

## Requirements
- Node.js 22+ (your Node 24 installation is compatible)
- MySQL Server 8.0+ (MySQL Workbench is only a database client; it is not the server)
- PowerShell / VS Code on Windows

## 1. Create database and restricted DB user
1. Start MySQL Server.
2. Open MySQL Workbench and connect to your local server.
3. Open `database/schema.sql`, then execute it.
4. Create an application account. Replace the password with a unique strong value:

```sql
CREATE USER 'bizflow_app'@'localhost' IDENTIFIED BY 'REPLACE_WITH_A_LONG_UNIQUE_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON bizflow.* TO 'bizflow_app'@'localhost';
FLUSH PRIVILEGES;
```

Do not use the MySQL `root` account in the application configuration. For a remote database, use a specific host/allowlist and TLS rather than `%` if possible.

## 2. Configure secrets
From this project folder in the VS Code terminal:

```powershell
Copy-Item .env.example .env
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Edit `.env` and set `JWT_SECRET` to the generated output, plus your database credentials. Keep `APP_ORIGIN=http://localhost:4000` for local use. Set `NODE_ENV=production` only when deploying with production settings. Never commit `.env`.

## 3. Install and start

```powershell
npm.cmd install
npm.cmd run create-admin
npm.cmd run dev
```

The administrator-creation script prompts for name, email, and a password of at least 12 characters. Keep the credentials private. Open `http://localhost:4000` and sign in. Check `http://localhost:4000/api/health` for database connectivity.

For normal start use `npm.cmd start`. `npm.cmd` works around PowerShell configurations that block the `npm.ps1` wrapper.

## Roles
- **admin:** all permitted operations plus audit trail; can archive products.
- **manager:** manage customers/products/expenses and record sales; no audit trail.
- **staff:** view records and record sales; cannot create products or expenses.

Create new users through a separately reviewed admin-management feature or an approved administrative process. Do not make a public self-registration endpoint for an internal business app.

## Security included
- Password hashes via bcrypt (12 rounds for seeded admin)
- Signed JWT access tokens with issuer, audience, algorithm restriction, and expiry
- Role checks on sensitive operations
- Helmet security headers and a restrictive same-origin content security policy
- CORS allowlist from `APP_ORIGIN`
- API-wide rate limiting and stricter login rate limiting
- JSON/body size limits, basic validation, parameterized SQL
- MySQL transaction around sale creation and stock deduction
- Audit events for login and core record creation/update/archive
- Generic server errors in production and request IDs
- Health endpoint and structured request/error logs
- Restricted DB user instructions and `.env` secret exclusion
- Windows `mysqldump` backup script

## Backups (Windows PowerShell)
Set `DB_HOST`, `DB_PORT`, `DB_USER`, and `DB_PASSWORD` in the shell or load them from a trusted secret manager, then run:

```powershell
.\scripts\backup.ps1
```

The script creates a timestamped SQL dump in `backups/`. Keep backups encrypted and off the application host, restrict access, define retention, and periodically test restoring to a separate database. A backup that has never been restored is not a verified recovery plan.

## Production deployment checklist
- [ ] Deploy API behind HTTPS and a maintained reverse proxy/platform.
- [ ] Set `NODE_ENV=production`, strong secret values, `APP_ORIGIN` to the exact deployed origin, and `TRUST_PROXY=true` only when behind a correctly configured trusted proxy.
- [ ] Use a managed/private MySQL service with TLS, least-privilege account, network allowlist, automated snapshots, and tested restore.
- [ ] Store secrets in deployment secret management; never commit `.env` or put server secrets in browser JavaScript.
- [ ] Configure centralized logs, alerts for 5xx spikes, login abuse, database failures, and disk/backup failures.
- [ ] Set up uptime monitoring for `/api/health` and a separate external alert path.
- [ ] Establish a patch schedule for Node.js and npm dependencies; run `npm audit` and resolve issues deliberately.
- [ ] Add integration tests for login, roles, CRUD, concurrent sales, stock boundaries, and database outage behavior.
- [ ] Verify backup restore, RPO/RTO, log retention, incident response, and account offboarding.
- [ ] Review privacy obligations and retention for customer information.

## Known scope limitations
- JWT is stored in `sessionStorage` in this starter, so an XSS vulnerability could expose a session token. The included restrictive CSP reduces some exposure but does not eliminate all XSS risk. For a public production deployment, consider migrating to secure, HttpOnly, SameSite cookies with CSRF protections.
- There is no self-service user administration UI, password reset, MFA, sales void/refund workflow, export/reporting module, or automated test suite yet.
- The backup script is a starting point and does not encrypt backups or automatically copy them offsite.
- Deployment, HTTPS, provider monitoring, firewall rules, and live database configuration must be set up in the chosen hosting environment.

## Main routes
- `POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/logout`
- `GET /api/dashboard`
- `GET/POST/PATCH/DELETE /api/customers` (delete requires manager/admin)
- `GET/POST/PATCH/DELETE /api/products` (product creation/edit requires manager/admin; archive requires admin)
- `GET/POST /api/sales`, `GET /api/sales/:id/items`
- `GET/POST /api/expenses` (create requires manager/admin)
- `GET /api/audit-logs` (admin only)
- `GET /api/health`
