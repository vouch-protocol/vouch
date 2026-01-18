FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[server]"

# Copy source
COPY vouch/ vouch/

# Expose webhook port
EXPOSE 3000

# Run webhook server
CMD ["python", "-m", "vouch.integrations.hasura.webhook", "--host", "0.0.0.0", "--port", "3000"]
