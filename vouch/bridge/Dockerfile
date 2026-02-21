FROM python:3.12-slim

WORKDIR /app

# Install system deps for Pillow and c2pa
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev \
    libjpeg-dev \
    libpng-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN pip install --no-cache-dir -e ".[server,media]"

EXPOSE 21000

CMD ["uvicorn", "vouch.bridge.server:app", "--host", "0.0.0.0", "--port", "21000"]
