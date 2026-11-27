FROM python:3.12-slim

ARG APP_UID=1001
ARG APP_GID=1004

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --gid "${APP_GID}" driveradar \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home driveradar

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py api.py advisor.py monitor.py service.py sources.py force_sync.py ./
COPY radar_core ./radar_core
COPY static ./static
RUN mkdir -p /app/cache && chown -R driveradar:driveradar /app/cache

USER driveradar
EXPOSE 8512

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8512/driveradar/health', timeout=3)" || exit 1

CMD ["python", "app.py"]
