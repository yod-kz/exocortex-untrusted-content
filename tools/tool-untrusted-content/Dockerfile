FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip install --no-cache-dir .

RUN mkdir -p /var/lib/untrusted-content/raw \
    /var/lib/untrusted-content/clean \
    /var/lib/untrusted-content/incidents

EXPOSE 8787

CMD ["untrusted-content", "server", "--host", "0.0.0.0", "--port", "8787"]
