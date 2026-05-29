# ORTHRUS application/worker image (PRD §15.2).
# Uses Python 3.12 (broad wheel availability) — the code targets 3.11+.
FROM python:3.12-slim

WORKDIR /app

# nmap for port scanning; the rest comes from pip extras.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY orthrus ./orthrus

RUN pip install --no-cache-dir -e ".[scanners,reporting,browser,distributed,postgres,api,mcp,perf]" \
    && python -m playwright install --with-deps chromium

# Expose the REST API / dashboard port (used when run as: docker run ... serve --host 0.0.0.0)
EXPOSE 8000

ENTRYPOINT ["orthrus"]
CMD ["--help"]
