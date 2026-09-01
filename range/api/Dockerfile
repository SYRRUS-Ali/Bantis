# ---- Build stage: install dependencies ----
FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ---- Final stage: minimal runtime image ----
FROM python:3.12-slim

# Create a dedicated non-root user to run the application
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

WORKDIR /app

# Bring in only the installed dependencies, not the build toolchain
COPY --from=builder /root/.local /home/appuser/.local
COPY ./app ./app

ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
