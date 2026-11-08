# Prepared configuration. Image build/integration NOT TESTED in this environment.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 securitylab && useradd -u 10001 -g 10001 -m securitylab \
    && mkdir /data && chown 10001:10001 /data
WORKDIR /app
COPY securitylab /app/securitylab
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "securitylab"]
CMD ["--state", "/data", "doctor"]
