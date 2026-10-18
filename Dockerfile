# Run SecPosture audits from a container (local audit of a mounted root, or
# remote audits over SSH). Builds a wheel, installs it into a clean runtime
# image and runs as an unprivileged user.
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --wheel-dir /wheels ".[dashboard]"

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 HOME=/home/secposture
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin secposture
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links=/wheels "secposture[dashboard]" && rm -rf /wheels
WORKDIR /work
RUN chown secposture:secposture /work
USER secposture
ENTRYPOINT ["secposture"]
CMD ["--help"]
