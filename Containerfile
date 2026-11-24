# Build only from the allowlisted context in .containerignore.
FROM ghcr.io/astral-sh/uv:0.9.13 AS uv
FROM docker.io/library/python:3.13-slim-trixie

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        ca-certificates git libstdc++6 openssh-client openssl systemd \
    && rm -rf /var/lib/apt/lists/*
COPY --from=uv /uv /uvx /usr/local/bin/

WORKDIR /opt/switchyard
COPY pyproject.toml uv.lock LICENSE ./
COPY switchyard/ ./switchyard/
COPY --chmod=0644 catalogs/example.json ./catalogs/example.json
RUN uv sync --locked --no-dev --no-editable --no-cache \
    && mkdir -p /tmp/switchyard-home \
    && chmod 1777 /tmp/switchyard-home

ENV PATH="/opt/switchyard/.venv/bin:/usr/local/bin:/usr/bin:/bin" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_CACHE_DIR=/tmp/switchyard-uv \
    HOME=/tmp/switchyard-home
LABEL org.opencontainers.image.title="Switchyard" \
      org.opencontainers.image.description="Rootless control-plane packaging, not an isolation boundary" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"
ENTRYPOINT ["switchyard"]
CMD ["--catalog", "/opt/switchyard/catalogs/example.json", "--state-dir", "/tmp/switchyard-state", "web"]
