FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN uv build

FROM python:3.13-slim
RUN useradd --create-home --uid 10001 drl
COPY --from=builder /build/dist/*.whl /tmp/drl.whl
RUN python -m pip install --no-cache-dir /tmp/drl.whl && rm /tmp/drl.whl
USER drl
WORKDIR /lab
ENTRYPOINT ["drl"]
CMD ["--help"]

