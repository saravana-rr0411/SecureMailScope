# Dedicated Dockerfile for SecureMailScope Capture Agent
# Requires Linux container with CAP_NET_RAW / CAP_NET_ADMIN capabilities
FROM python:3.12-slim-bookworm

# Install tcpdump and libcap utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash captureagent

# Grant packet capture capabilities to tcpdump binary
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump

WORKDIR /app

# Install Python dependencies
COPY capture_agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Capture Agent codebase
COPY capture_agent /app/capture_agent

# Create storage directory with appropriate ownership
RUN mkdir -p /app/capture_agent/storage && chown -R captureagent:captureagent /app

USER captureagent

EXPOSE 9000

ENV AGENT_HOST=0.0.0.0
ENV AGENT_PORT=9000
ENV PYTHONPATH=/app

CMD ["python", "-m", "uvicorn", "capture_agent.main:app", "--host", "0.0.0.0", "--port", "9000"]
