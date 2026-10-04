# syntax=docker/dockerfile:1
FROM python:3.12-slim

LABEL maintainer="CloudGate Team"
LABEL description="CloudGate 2.0 — Real-Time AWS Security Gatekeeper & Compliance Engine"

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install CloudGate and dependencies
COPY requirements.txt pyproject.toml /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . /app/
RUN pip install --no-cache-dir -e .

# Create volume mounts for AWS credentials and generated reports
VOLUME ["/root/.aws", "/app/reports"]

ENTRYPOINT ["cloudgate"]
CMD ["--level", "1"]
