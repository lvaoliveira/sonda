FROM rust:1.99-slim-trixie
RUN rustup component add clippy \
 && apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev pkg-config cmake make python3 \
 && rm -rf /var/lib/apt/lists/*
# An unprivileged user with its own home: cargo's caches live there, in the container only.
RUN useradd -m -u 1000 oracle
USER oracle
ENV CARGO_HOME=/home/oracle/.cargo RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:$PATH
WORKDIR /home/oracle
