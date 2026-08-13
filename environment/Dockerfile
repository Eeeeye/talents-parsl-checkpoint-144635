FROM python:3.13-slim-bookworm@sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1

COPY wheels /opt/parsl-wheels
COPY requirements.lock /opt/parsl-requirements.lock
RUN python3 -m pip install \
        --no-index \
        --no-cache-dir \
        --find-links /opt/parsl-wheels \
        --requirement /opt/parsl-requirements.lock && \
    rm -rf /opt/parsl-wheels /root/.cache && \
    groupadd --gid 1000 candidate && \
    useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash candidate

COPY --chown=root:candidate parsl /workspace/parsl-checkpoint/parsl
COPY --chown=candidate:candidate incident /workspace/parsl-checkpoint/incident
COPY --chown=candidate:candidate scripts /workspace/parsl-checkpoint/scripts
COPY --chown=candidate:candidate README.md UPSTREAM.md LICENSE /workspace/parsl-checkpoint/
COPY entrypoint.sh /usr/local/bin/parsl-task-entrypoint

RUN chmod 0755 /usr/local/bin/parsl-task-entrypoint \
        /workspace/parsl-checkpoint/scripts/reproduce.sh \
        /workspace/parsl-checkpoint/incident/reproduce.py && \
    python3 -B -m compileall -q -f /workspace/parsl-checkpoint/parsl && \
    find /workspace/parsl-checkpoint -type f -name '*.pyc' -delete && \
    find /workspace/parsl-checkpoint -depth -type d -name '__pycache__' -empty -delete && \
    find /workspace/parsl-checkpoint/parsl -type d -exec chmod 0775 {} + && \
    find /workspace/parsl-checkpoint/parsl -type f -exec chmod 0664 {} + && \
    mkdir -p /tests /solution && \
    chmod 0700 /tests && \
    chmod 0755 /solution

WORKDIR /workspace/parsl-checkpoint
ENV PYTHONPATH=/workspace/parsl-checkpoint \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PARSL_WORKSPACE=/workspace/parsl-checkpoint
ENTRYPOINT ["/usr/local/bin/parsl-task-entrypoint"]
