# AegisRAG Docker Image
# Multi-stage build for optimized production image

# Stage 1: Builder - Install dependencies
FROM python:3.10-slim as builder

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only requirements files
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt && \
    pip install -r requirements-dev.txt

# Stage 2: Runtime - Create slim production image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    AEGIS_ENV=production

# Install only runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 aegis && \
    mkdir -p /app/logs /app/output /app/data && \
    chown -R aegis:aegis /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=aegis:aegis . .

# Switch to non-root user
USER aegis

# Create necessary directories
RUN mkdir -p logs output data/patterns

# Expose port (if needed for future API)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import src; print('OK')" || exit 1

# Default command: Run tests
CMD ["pytest", "tests/", "-v", "--cov=src", "--cov-report=term-missing"]

# Alternative commands (override with docker run):
# Development: docker run aegisrag python examples/basic_usage.py
# Tests: docker run aegisrag pytest tests/
# Shell: docker run -it aegisrag /bin/bash
