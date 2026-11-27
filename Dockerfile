# Backend for the "C / Memory" visualizer. Run it with docker compose, which
# adds the runtime limits (see docker-compose.yml). The image alone has none.

FROM ubuntu:24.04 AS app

# libc6-dev: headers needed to compile submissions.
# libc6-dbg: without it gdb cannot read malloc's return value, and heap
#            tracking silently disappears.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc libc6-dev libc6-dbg gdb python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

# The name must match SANDBOX_USER in sandboxed_worker.py, otherwise the
# resource limits are not applied.
RUN useradd --system --no-create-home --uid 10001 \
        --shell /usr/sbin/nologin sandboxrunner

COPY pages/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pages/app.py pages/sandbox_run.py pages/sandboxed_worker.py pages/trace_extractor.py ./


# pytest suite:  docker compose run --rm --build tests
FROM app AS test
RUN pip install --no-cache-dir "pytest>=8,<10"
COPY tests/test_tracer.py ./tests/
USER sandboxrunner
CMD ["python3", "-m", "pytest", "-v", "-p", "no:cacheprovider", "tests/test_tracer.py"]


# Last stage, so a plain "docker build ." produces the server image.
FROM app AS runtime
USER sandboxrunner
EXPOSE 5001
CMD ["python3", "app.py"]
