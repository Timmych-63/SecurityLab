FROM python:3.14-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates build-essential && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/hermes
RUN git init . && git remote add origin https://github.com/NousResearch/hermes-agent.git && git fetch --depth 1 origin e075441241b8d626789b4aae0e376f86eabf824d && git checkout --detach FETCH_HEAD && test "$(git rev-parse HEAD)" = e075441241b8d626789b4aae0e376f86eabf824d
RUN python -m pm.build_env --source /opt/hermes --out /opt/hermes/.venv --python /usr/local/bin/python --no-install-project --sealed
ENV PATH="/opt/hermes/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HERMES_HOME=/tmp/hermes
WORKDIR /app
COPY securitylab /app/securitylab
RUN python -c "import sys; sys.path.insert(0, '/opt/hermes'); from run_agent import AIAgent"
USER 10001:10001
ENTRYPOINT ["python", "-m", "securitylab.hermes_worker"]
