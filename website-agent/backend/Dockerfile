FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml ./
# Include the gemini extra so the default hosted provider (google-genai) is in
# the image; the assistant runs on Gemini via VOUCH_LLM_PROVIDER.
RUN pip install --no-cache-dir -e ".[gemini]"

COPY vouch_agent ./vouch_agent
COPY knowledge ./knowledge
COPY start.sh ./start.sh
RUN chmod +x ./start.sh

# start.sh runs the signing sidecar on localhost and the chat server on 8000.
# It needs VOUCH_AGENT_SIGNING_KEY (a private Ed25519 JWK) to be set.
EXPOSE 8000
CMD ["./start.sh"]
