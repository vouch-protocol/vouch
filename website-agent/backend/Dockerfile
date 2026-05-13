FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e .

COPY vouch_agent ./vouch_agent
COPY knowledge ./knowledge

EXPOSE 8000
CMD ["uvicorn", "vouch_agent.main:app", "--host", "0.0.0.0", "--port", "8000"]
