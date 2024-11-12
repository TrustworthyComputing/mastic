FROM rust:latest AS build

ENV BASE /usr/local
ADD . /opt/mastic
WORKDIR /opt/mastic
RUN cargo build --release --workspace --target-dir /opt/mastic/bin

# cleanup everything except binaries
RUN mkdir -p /opt/mastic/exec && \
cp bin/release/server exec && \
cp bin/release/driver exec

# Thin container with binaries base image is taken from
# https://hub.docker.com/_/debian/
FROM debian:stable-slim AS mastic
COPY --from=build /opt/mastic/exec /opt/mastic/bin
COPY --from=build /opt/mastic/src/configs/*.toml /opt/mastic/bin/
WORKDIR /opt/mastic
