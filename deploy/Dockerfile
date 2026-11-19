FROM python:3.12-slim AS detection
WORKDIR /app
COPY detection-engine/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY detection-engine/app ./app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 1000:1000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM python:3.12-slim AS copilot
WORKDIR /app
COPY ai-copilot/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY ai-copilot/*.py ./
COPY ai-copilot/providers ./providers
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 1000:1000
CMD ["python", "api.py", "--host", "0.0.0.0", "--port", "8100"]