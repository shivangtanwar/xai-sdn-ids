# Live dashboard: FastAPI backend + static single-page frontend.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# Plain uvicorn, not uvicorn[standard]: the `standard` extra pulls websockets/uvloop,
# and this app streams over Server-Sent Events (StreamingResponse), never WebSockets.
RUN pip install "fastapi==0.115.6" "uvicorn==0.34.0" "httpx==0.28.1"

WORKDIR /srv
COPY dashboard/ /srv/dashboard/
EXPOSE 8200
CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8200", "--proxy-headers", "--forwarded-allow-ips", "*"]
