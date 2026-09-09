FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml uv.lock README.md .

CMD ["python", "-m", "verifierci"]
