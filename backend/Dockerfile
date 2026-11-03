# Build context: repository root (see docker-compose.yml)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DATA_DIR=/srv/data ES_ASSETS_DIR=/srv/elasticsearch KEYCLOAK_LOG_DIR=/runtime-logs
WORKDIR /srv

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/app backend/app
COPY elasticsearch elasticsearch
COPY tests tests
COPY scripts scripts
COPY pytest.ini pytest.ini
COPY data data

WORKDIR /srv/backend
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=5s --retries=12 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/api/health').status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
