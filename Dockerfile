FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .
EXPOSE 8080
CMD ["python", "-m", "nightzero"]