# SAST Workshop – Node.js Vulnerable App

A small Node.js (Express) application **intentionally built with security vulnerabilities** for testing **Static Application Security Testing (SAST)** and dependency scanning. Designed to be connected to **GitHub** and scanned by **Datadog** (and optionally other tools).

⚠️ **Do not use this code or patterns in production.**

---

## What’s in this repo

- **Vulnerable application code** – patterns that SAST tools (e.g. Datadog) can detect.
- **Vulnerable dependency** – `lodash@4.17.20` (prior to 4.17.21, affected by [CVE-2021-23337](https://nvd.nist.gov/vuln/detail/CVE-2021-23337) – command injection via `_.template()`).
- **GitHub Actions workflow** – runs Datadog Static Analyzer on **push** to `main`/`master`.
- **`docker-compose.yml`** – optional stack: **Datadog Agent** (Workload Protection / runtime security) + this **Node** app with **IAST** and **App and API Protection** (`DD_IAST_ENABLED`, `DD_APPSEC_ENABLED`, `dd-trace`). Requires `DD_API_KEY` in the environment. In the lab, the track script may start it automatically; locally run `npm run docker:up`.
- **`env.agent.lab`** – injected into **`datadog-agent`**; sets **`DD_TAGS`** (including `repository:secure-software-delivery-app-<sandbox>`) so **Workload Protection / CWS** signals tied to the Agent can surface that tag.
- **`env.lab`** – injected into **`workshop-app`**; **`DD_TAGS`** for the Node tracer so **App and API Protection** / APM spans include the same `repository` tag. Instruqt overwrites both files at track start; after changing them locally, run `docker compose up -d --force-recreate`.
- **`docker-compose.cws-proc-demo.yml`** – separate **one-shot** **CWS process-execution** demo container (see **`cws-proc-demo/`**). Run **`npm run lab:trigger-cws`** after Docker is available (Lab 05).
- **App & API Protection traffic** – the **`appsec-traffic`** service starts with **`npm run docker:up`** and keeps sending varied **`/api/vuln`** GET/POST traffic until you stop Compose (see **`script/README.md`**). Tune with **`APPSEC_TRAFFIC_INTERVAL`** (seconds between sweeps, default **90**), **`APPSEC_TRAFFIC_PAUSE`** (delay between requests in a sweep), or **`APPSEC_TRAFFIC_LOOP=0`** for a single sweep then exit.

---

## Vulnerable HTTP API (SAST + API Protection demos)

All intentional issues live under **`/api/vuln`**. A machine-readable index is at **`GET /api/vuln`**.

| # | Type | Route | Example |
|---|------|-------|---------|
| 1 | Command injection | `GET /api/vuln/command/ping?host=` | `127.0.0.1; id` |
| 2 | Command injection | `GET /api/vuln/command/nslookup?domain=` | shell metacharacters in `domain` |
| 3 | SQL injection | `GET /api/vuln/sql?id=` | `1 OR 1=1` |
| 4 | SQL injection | `POST /api/vuln/sql` | `{"username":"admin' OR '1'='1"}` |
| 5 | SQL injection (multi-field) | `POST /api/vuln/sql-search` | `{"table":"users","column":"x","value":"y"}` |
| 6 | Reflected XSS | `GET /api/vuln/xss?q=` | `<script>…</script>` |
| 7 | Path traversal | `GET /api/vuln/path?name=` | `../../../etc/passwd` |
| 8 | Path traversal (CWE-22) | `GET /api/vuln/documents?file=` | `../` sequences |
| 9 | Arbitrary file read | `POST /api/vuln/validate-json` | `{"files":["/etc/passwd"]}` |
| 10 | `eval()` | `POST /api/vuln/eval/calc` | `{"expression":"1+1"}` |
| 11 | `Function()` | `POST /api/vuln/eval/transform` | `{"code":"return x"}` |
| 12 | Lodash `_.template` (CVE pattern) | `GET /api/vuln/eval/greet?name=` | toxic `name` |
| 13 | Implied eval | `GET /api/vuln/eval/schedule?code=` | string passed to `setTimeout` |
| 14 | Dynamic `require()` | `GET /api/vuln/eval/require?module=` | user-controlled module |
| 15 | SSRF | `GET /api/vuln/ssrf?url=` | user-controlled URL fetch |
| 16 | Plain HTTP client | `GET /api/vuln/http-legacy` | `axios` to `http://` |
| 17 | Misconfiguration / info | `GET /api/vuln/misconfig` | verbose flags (no real credentials) |
| 18 | ReDoS / glob (CVE dep) | `GET /api/vuln/glob` | `micromatch` (see `package.json`) |
| 19 | JWT (vulnerable dep) | `GET /api/vuln/jwt/sign?sub=` | signs with workshop-only secret |

There are **no hardcoded cloud/API keys** in the source; signing uses `WORKSHOP_JWT_SECRET` or a labeled demo default in `src/config.js`.

---

## Run the app locally

```bash
npm install
npm start
```

If your environment blocks installation of known-vulnerable packages (e.g. SCFW or similar), you may need to use a dedicated workspace or temporarily allow this repo so that `lodash@4.17.20` installs for the workshop.

- App: `http://localhost:3000`
- Health: `http://localhost:3000/health`
- Vulnerable route index: `http://localhost:3000/api/vuln`

---

## Hardened application (workshop cleanup)

The repo includes a **safer** implementation of the same **`/api/vuln`** surface in **`workshop/secure-app/`** (routes + `lib/mockDb.js`). To copy that into the running app’s **`src/`** tree:

```bash
npm run workshop:apply-secure
```

Equivalent:

```bash
bash script/apply-secure-app.sh
```

That overwrites **`src/routes/vuln.js`** and **`src/lib/mockDb.js`**. After applying, the table above no longer describes working exploit payloads—endpoints stay at the same paths but use validation, allowlists, and safer APIs (`execFileSync`, path checks, etc.).

To restore the **original teaching (vulnerable) versions**: if you only changed those files locally, reset them from your branch tip with:

```bash
git checkout -- src/routes/vuln.js src/lib/mockDb.js
```

If you already **committed** the hardened copies, restore the paths from an **older commit** that still had the vulnerable sources (e.g. `git checkout <commit> -- src/routes/vuln.js src/lib/mockDb.js`).

---

## Connect GitHub and scan with Datadog SAST

### 1. Push this repo to GitHub

Create a new repository on GitHub and push this project (or use an existing repo and add these files).

### 2. Datadog API and Application keys

1. In [Datadog](https://app.datadoghq.com): **Organization Settings → API Keys** – create or copy an **API key**.
2. **Organization Settings → Application Keys** – create an **Application key** with at least the **`code_analysis_read`** scope.
3. In your GitHub repo: **Settings → Secrets and variables → Actions** – add:
   - `DD_API_KEY` = your Datadog API key  
   - `DD_APP_KEY` = your Datadog Application key  

### 3. Run the workflow

- The workflow is in `.github/workflows/datadog-sast.yml`.
- It runs on **push** to `main` or `master`.
- Push a commit; the "Datadog Static Analysis (SAST)" job will run and send results to Datadog.

### 4. View results in Datadog

- Go to **Security → Code Security → Static Analysis** (or equivalent in your Datadog site).
- Select your repository and the run to see findings.

### 5. Rulesets and defaults

- **`code-security.datadog.yaml`** at the repo root sets `use-default-rulesets: true` so Datadog applies its **default JavaScript rulesets** (including security), as described under [Default rulesets](https://docs.datadoghq.com/security/code_security/static_analysis/configuration/#default-rulesets).
- To customize, use `use-rulesets`, `ignore-rulesets`, or `ruleset-configs` under the `sast` key—see [Static Code Analysis (SAST) Configuration](https://docs.datadoghq.com/security/code_security/static_analysis/configuration/).

### 6. Other Datadog sites

If you use a site other than `datadoghq.com` (e.g. EU), set the `dd_site` input in `.github/workflows/datadog-sast.yml` accordingly (e.g. `datadoghq.eu`).

---

## References

- [Datadog – Static Code Analysis and GitHub Actions](https://docs.datadoghq.com/security/code_security/static_analysis/github_actions)
- [Datadog Static Analyzer (GitHub)](https://github.com/DataDog/datadog-static-analyzer)
- [CVE-2021-23337 (lodash)](https://nvd.nist.gov/vuln/detail/CVE-2021-23337) – command injection in `_.template()`
