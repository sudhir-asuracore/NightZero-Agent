FROM python:3.12-slim

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -U pip setuptools wheel
RUN pip install --no-cache-dir "google-api-core>=2.24.0,<2.35.0" "google-cloud-firestore>=2.20.0" .
EXPOSE 8080
CMD ["python", "-m", "nightzero"]