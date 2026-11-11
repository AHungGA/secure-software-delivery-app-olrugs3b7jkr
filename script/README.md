# IAST API test scripts

Scripts to generate API calls that exercise the vulnerable endpoints so **IAST** (Interactive Application Security Testing) can detect issues in the running app.

## Cloud Workload Security (CWS) — two triggers

### 1) Process execution demo (Lab 05 — **`npm run lab:trigger-cws`**)

**`docker-compose.cws-proc-demo.yml`** builds and runs a **one-shot** **`cws-proc-demo`** image. The entrypoint **`cws-proc-demo/trigger-process-execution-patterns.sh`** runs **benign** patterns aligned with common [Workload Protection — process execution](https://docs.datadoghq.com/security/default_rules/?category=cat-workload-protection#all) themes (for example **executable bit added to newly created file**, **interactive shell spawned in container** via **`script` + `bash -i`**, **DNS** lookups to IP/paste-style hostnames, **sqlite3 .shell**, **curl** piped to **`sh`** using a **`file://`** script only).

```bash
npm run lab:trigger-cws
```

This stack is **separate** from **`docker-compose.yml`** (no dependency on **`workshop-app`**).

### 2) Node app spawning shells + FIM (**`npm run lab:trigger-cws-app`**)

**`script/trigger-cws-workload-protection-demo.sh`** drives the **live** **`workshop-app`** over HTTP: **`child_process`** / **`sh -c`** (ping, nslookup, exec, **`bash -c id`**), **`GET /api/vuln/workload/bash-spawn?confirm=1`**, optional **`docker exec`** noise, and optional **FIM** (cron drop-in + **`chmod`** on **`/bin/cat`**) when the app container is running. Uses a **throwaway `curl` container** with **`--network host`** (default **`BASE_URL=http://127.0.0.1:80`**).

```bash
npm run lab:trigger-cws-app
```

```bash
BASE_URL=http://127.0.0.1:3000 npm run lab:trigger-cws-app
```

```bash
CWS_DEMO_MODE=http-and-container npm run lab:trigger-cws-app
```

**FIM** — default **`CWS_TRIGGER_FIM=1`**: [Cron job modified](https://docs.datadoghq.com/security/default_rules/a78-b2n-xmd/) style **`/etc/cron.d/`** write/delete; [Verify Essential Linux Binary Modified in Container](https://docs.datadoghq.com/security/default_rules/def-000-mpk/) style **`chmod`** on **`/bin/cat`**. Skip: **`CWS_TRIGGER_FIM=0`**. FIM-only: **`CWS_DEMO_MODE=fim-container npm run lab:trigger-cws-app`**.

The legacy path **`script/trigger-workload-protection-demo.sh`** delegates to **`trigger-cws-workload-protection-demo.sh`** (same as **`lab:trigger-cws-app`**).

## App and API Protection — traffic from Docker Compose

The **`appsec-traffic`** service runs **`script/trigger-api-protection-traffic.sh`** inside a **`curlimages/curl`** container on the **same Docker network** as **`workshop-app`**. By default it **loops for the whole workshop**: each cycle is a **full sweep** of many **`/api/vuln`** routes (SQLi, command injection, XSS, SSRF, path traversal, `eval`/`Function`/`setTimeout` paths, JWT, misconfig, crypto, file read/write, ReDoS-style regexp, health check, and the vuln index), with a short pause between requests, then a longer pause before the next sweep. Compose uses **`restart: on-failure`** so a **clean exit** (for example **`APPSEC_TRAFFIC_LOOP=0`**) does not respawn the sidecar; a **crashed** script can still be restarted by Docker.

- **Default (continuous traffic)**:

  ```bash
  npm run docker:up
  ```

- **Tune timing** (host env vars read by Compose):

  | Variable | Default | Meaning |
  |----------|---------|---------|
  | `APPSEC_TRAFFIC_INTERVAL` | `90` | Seconds between full sweeps |
  | `APPSEC_TRAFFIC_PAUSE` | `1` | Seconds between requests inside a sweep |
  | `APPSEC_TRAFFIC_LOOP` | `1` | Set to **`0`** for **one sweep** then the container exits |

- **From the host** (same script; **`LOOP` defaults to `0`** — one full sweep unless you set **`LOOP=1`**):

  ```bash
  BASE_URL=http://127.0.0.1:80 npm run lab:trigger-appsec
  ```

Requires **`DD_APPSEC_ENABLED=true`** on the app (already set in **`docker-compose.yml`** for **`workshop-app`**). See [App and API Protection](https://docs.datadoghq.com/security/application_security/).

## Prerequisites

1. Start the app (with IAST instrumentation if your tool requires it):
   ```bash
   npm start
   ```
2. Point your IAST agent at this app (Datadog or other) so traffic is instrumented.

## Usage

From the project root:

```bash
node script/iast-api-calls.js
```

Optional base URL (default `http://localhost:3000`):

```bash
node script/iast-api-calls.js http://localhost:8080
```

## Endpoints exercised

See `script/iast-api-calls.js` for the exact list. Routes are under **`/api/vuln/...`** (plus `/health`).

| # | Vulnerability      | Endpoint    | Method | Payload / note                          |
|---|--------------------|------------|--------|-----------------------------------------|
| 1 | Command injection  | `/api/vuln/command/ping` | GET    | `?host=127.0.0.1` |
| 2 | SQL injection      | `/api/vuln/sql`    | GET / POST | `?id=1` or body `username` |
| 3 | Reflected XSS      | `/api/vuln/xss`    | GET    | toxic `?q=` |
| 4 | Path traversal     | `/api/vuln/path`   | GET    | `?name=package.json` |
| 5 | SSRF               | `/api/vuln/ssrf`   | GET    | `?url=` |
| 6 | eval()             | `/api/vuln/eval/calc` | POST | `{"expression":"1+1"}` |
| 7 | Lodash template    | `/api/vuln/eval/greet` | GET | `?name=World` |
| 8 | Function()         | `/api/vuln/eval/transform` | POST | `{"code":"return x * 2"}` |
| 9 | Misconfig          | `/api/vuln/misconfig` | GET | - |
| 10 | Health            | `/health`  | GET    | - |

After running the script, check your IAST product (e.g. Datadog) for findings triggered by these requests.
