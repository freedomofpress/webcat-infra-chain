# Adapted from: https://github.com/penumbra-zone/penumbra/blob/main/deployments/containerfiles/Dockerfile

# We use the latest stable version of the official Rust container.
# The rust:1-slim-bookworm image comes with Rust and Cargo pre-installed.
FROM docker.io/rust:1-slim-bookworm AS build-env

# Install build dependencies.
RUN apt-get update && apt-get install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        clang \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/felidae

# Add rust dependency lockfiles first, to cache downloads.
COPY Cargo.lock Cargo.toml ./

# Copy all Cargo.toml files to cache dependencies
COPY crates ./crates

# Download all workspace dependencies specified in Cargo.toml
# This will cache dependencies even if source code changes
RUN cargo fetch --locked

# Build Felidae binaries
# Use `--bins` flag to force dependency resolution per-binary, rather than once for the workspace.
RUN cargo build --release --bins

# Runtime image.
FROM docker.io/debian:bookworm-slim

ARG USERNAME=felidae
ARG UID=1000
ARG GID=1000

# We add curl & jq so we can munge JSON during init steps for deployment.
RUN apt-get update && apt-get install -y \
        curl \
        jq \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Add normal user account
RUN groupadd --gid ${GID} ${USERNAME} \
    && useradd -m -d /home/${USERNAME} -g ${GID} -u ${UID} ${USERNAME}

# Install chain binaries
COPY --from=build-env \
    /usr/src/felidae/target/release/felidae \
    /usr/src/felidae/target/release/felidae-publish \
    /usr/bin/

WORKDIR /home/${USERNAME}
USER ${USERNAME}

# Default to running felidae start, but can be overridden to run felidae-publish
# or the felidae oracle or admin commands
CMD [ "/usr/bin/felidae", "start" ]
