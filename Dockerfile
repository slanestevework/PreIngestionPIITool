FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    GUNICORN_CMD_ARGS=--worker-tmp-dir=/tmp \
    PORT=8000

WORKDIR /app

# Minimal system deps for pandas/openpyxl/pyarrow and common wheels.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install gunicorn en-core-web-sm

COPY . .

EXPOSE 8000

# OpenShift sends SIGTERM during rollout; use Gunicorn for graceful worker restarts.
CMD ["gunicorn", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "api:app", "--bind", "0.0.0.0:8000", "--timeout", "120"]