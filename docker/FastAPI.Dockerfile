# Build separately and explicitly, never from an untrusted repository manifest.
# Base image must already be the locally accepted SecurityLab demo image.
FROM securitylab-demo:local
USER root
# Direct versions are pinned; transitive wheel hashes are NOT yet locked.
# This setup stage may reach package indexes; runtime always has no egress.
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
    fastapi==0.115.12 uvicorn==0.34.2
LABEL org.securitylab.profile="fastapi-s63c-v1"
USER 10001:10001
