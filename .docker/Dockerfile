FROM debian:stable-slim as builder

COPY . /source

WORKDIR /source

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    gosu \
    python3 \
    python-is-python3 \
    pipx && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install poetry

RUN rm -rf dist && /root/.local/bin/poetry build -f wheel

FROM debian:stable-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PIP_NO_CACHE_DIR off

WORKDIR /gvm-tools

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    gosu \
    python3 \
    python3-pip && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN addgroup --gid 1001 --system gvm && \
    adduser --no-create-home --shell /bin/false --disabled-password --uid 1001 --system --group gvm

COPY --from=builder /source/dist/* /gvm-tools/
COPY .docker/entrypoint.sh /usr/local/bin/entrypoint

RUN python3 -m pip install --break-system-packages /gvm-tools/*

RUN chown -R gvm:gvm /gvm-tools && \
    chmod 755 /usr/local/bin/entrypoint

ENTRYPOINT [ "/usr/local/bin/entrypoint" ]

CMD ["/bin/bash"]
