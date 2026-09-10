FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    GUNICORN_CMD_ARGS=--worker-tmp-dir=/tmp \
    PORT=8000

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install gunicorn && \
    python -m spacy download en_core_web_sm

COPY . .

EXPOSE 8000

# OpenShift sends SIGTERM during rollout; use Gunicorn for graceful worker restarts.
CMD ["gunicorn", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "api:app", "--bind", "0.0.0.0:8000", "--timeout", "900"]