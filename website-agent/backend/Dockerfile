FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml ./
# Include the gemini extra so the default hosted provider (google-genai) is in
# the image; the assistant runs on Gemini via VOUCH_LLM_PROVIDER.
RUN pip install --no-cache-dir -e ".[gemini]"

COPY vouch_agent ./vouch_agent
COPY knowledge ./knowledge

EXPOSE 8000
CMD ["uvicorn", "vouch_agent.main:app", "--host", "0.0.0.0", "--port", "8000"]
