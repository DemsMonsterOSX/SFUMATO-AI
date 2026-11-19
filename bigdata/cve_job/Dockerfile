FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY cve_ingest.py .
# Cloud Run jobs set CLOUD_RUN_JOB themselves; BUCKET is set at deploy time. Incremental mode: only what changed since the last run.
ENV PYTHONUNBUFFERED=1
CMD ["python", "cve_ingest.py", "--incremental", "--days", "30"]
