# Ephemeral container for Cloud Workload Security / process execution lab demos.
# Built by docker-compose.cws-proc-demo.yml (separate from workshop-app stack).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    sqlite3 \
    procps \
    util-linux \
  && rm -rf /var/lib/apt/lists/*

COPY trigger-process-execution-patterns.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/trigger-process-execution-patterns.sh

ENTRYPOINT ["/usr/local/bin/trigger-process-execution-patterns.sh"]
