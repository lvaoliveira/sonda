# syntax=docker/dockerfile:1
# The sonda server image (ADR-0005): the server binary plus the built web
# app, on a distroless runtime with no shell, running as a non-root user.
# Base images are pinned by digest; Dependabot proposes updates.

# Node 22 LTS, as in CI's web job. Node 25+ no longer ships corepack, which
# installs the exact pnpm in package.json's packageManager field.
FROM node:22-trixie-slim@sha256:2117f713a417f3aff682ac8f5bc2ebbdf1beed51f36e67ab1e0fd3866b6d2d8f AS web
WORKDIR /web
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
# Honors pnpm-workspace.yaml's 14-day minimumReleaseAge, as in CI.
RUN --mount=type=cache,target=/root/.local/share/pnpm/store pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM rust:1.99-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p sonda-server \
    && cp target/release/sonda-server /sonda-server

# The CLI as one static (musl) binary, for hosts without Rust:
# scripts/install-cli.sh builds this target. Not part of the server image.
FROM rust:1.99-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS cli-build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=sonda-cli-target \
    cargo build --release --locked -p sonda \
    && cp target/release/sonda /sonda

FROM scratch AS cli
COPY --from=cli-build /sonda /sonda

# The server image: the default target, so it stays last.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:08476c244888bfb425bae1ae4dd7c17f093e972aab8426883d97f3c6f280f7c1
COPY --from=build /sonda-server /usr/local/bin/sonda-server
COPY --from=web /web/dist /usr/share/sonda/web
USER nonroot
# Inside the container the server must listen on all interfaces; compose.yaml
# publishes the port on the host's localhost only.
ENV SONDA_LISTEN=0.0.0.0:9000 \
    SONDA_WEB_DIR=/usr/share/sonda/web
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/sonda-server"]
