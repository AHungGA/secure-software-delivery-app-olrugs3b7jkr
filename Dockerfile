# Node workshop app with Datadog tracing + IAST (load dd-trace before application code).
FROM node:22-bookworm-slim

# ping / nslookup for CWS lab routes (/api/vuln/command/ping, nslookup) — not in slim by default
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    dnsutils \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 3000

# dd-trace must load first; dotenv-load picks up optional /app/.env in container
CMD ["node", "-r", "dd-trace/init", "-r", "./dotenv-load.js", "src/index.js"]
