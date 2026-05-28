FROM python:3.11-slim

WORKDIR /app

# System deps for androguard
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Python deps
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY .env .env

# Create data directories
RUN mkdir -p data/uploads data/sample_apks

# Expose port
EXPOSE 8001

# Run with production settings
CMD ["python", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8001", \
     "--workers", "2", \
     "--log-level", "info"]

WORKDIR /app/backend
