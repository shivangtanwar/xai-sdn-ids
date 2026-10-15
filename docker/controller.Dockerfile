# Control/application plane: Ryu controller + XAI-IDS (scikit-learn, SHAP).
# Ryu 4.34 is unmaintained and breaks on Python >= 3.10/newer setuptools,
# so the controller is pinned to Python 3.9 with known-good build deps.
FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install "setuptools==58.2.0" wheel \
    && pip install --no-build-isolation "ryu==4.34" \
    && pip install "eventlet==0.30.2" "dnspython<2.3"

COPY requirements-ml.txt /tmp/requirements-ml.txt
RUN pip install -r /tmp/requirements-ml.txt

WORKDIR /app
ENV PYTHONPATH=/app
EXPOSE 6653 8080
CMD ["ryu-manager", "--ofp-tcp-listen-port", "6653", "--wsapi-port", "8080", "controller/xai_ids_app.py"]
