# Build context: repository root (see docker-compose.yml)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    REPO_DIR=/srv

# libgomp1: OpenMP runtime required by XGBoost; curl: container health check
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/backend
COPY backend/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

# Embedding model baked into the image: the knowledge base works offline once it has been downloaded
ENV KB_MODEL_CACHE=/srv/ml/fastembed
RUN python -c "from fastembed import TextEmbedding; TextEmbedding('BAAI/bge-small-en-v1.5', cache_dir='/srv/ml/fastembed')"

COPY backend/ /srv/backend/
COPY examples/ /srv/examples/
COPY playbooks/ /srv/playbooks/
COPY config/ /srv/config/
COPY ml/ /srv/ml/

RUN useradd --create-home --uid 10001 sfumato \
    && rm -f /srv/backend/.env /srv/backend/*.db* \
    && chown -R sfumato:sfumato /srv
USER sfumato

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=12 \
    CMD curl -fsS http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
