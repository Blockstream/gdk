# Manylinux (main build) image. Build with:
# DOCKER_BUILDKIT=1 docker build . -t greenaddress/gdk-python-builder -f docker/python/Dockerfile
#
FROM quay.io/pypa/manylinux_2_28_x86_64@sha256:a0bac0e8aa5a77d4746ff0dc80cd3ea5208c0297f56201641dd139d93291759d AS base
#FROM quay.io/pypa/manylinux_2_34_x86_64@sha256:fa538e6c36fe23e8334813c7586dfca3657907312784d2adbf420ec6367d27b7 AS base
WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles ./cmake/profiles
# Optionally copy dependency sources from the build directory if present
COPY ./downloads ./downloads
COPY ./docker/python/install_deps.sh ./docker/python/install_deps.sh
RUN ./docker/python/install_deps.sh

ENV GDK_KEEP_DOWNLOADS=1

FROM base AS builderlinux
#wally absolutely wants a running python -- it doesn't really matter the version here
RUN source /opt/python/default/bin/activate && ./tools/builddeps.sh --clang --prefix /prebuild/clang

FROM rust:1.81-bullseye AS builderrust

FROM base AS final
# Remove copied/downloaded dependency sources
RUN rm -rf ./tools ./downloads ./cmake ./docker

COPY --from=builderlinux /prebuild/clang /prebuild/clang

COPY --from=builderrust /usr/local/cargo /usr/local/cargo
COPY --from=builderrust /usr/local/rustup /usr/local/rustup

ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV RUST_VERSION=1.81.0
ENV PATH="/usr/local/cargo/bin:${PATH}"

# predownloading rust dependencies
COPY ./subprojects/gdk_rust/Cargo.* ./subprojects/gdk_rust/
COPY ./subprojects/gdk_rust/gdk_common/Cargo.* ./subprojects/gdk_rust/gdk_common
COPY ./subprojects/gdk_rust/gdk_electrum/Cargo.* ./subprojects/gdk_rust/gdk_electrum
COPY ./subprojects/gdk_rust/gdk_pin_client/Cargo.* ./subprojects/gdk_rust/gdk_pin_client
COPY ./subprojects/gdk_rust/gdk_registry/Cargo.* ./subprojects/gdk_rust/gdk_registry
COPY ./subprojects/gdk_rust/gdk_rust/Cargo.* ./subprojects/gdk_rust/gdk_rust
RUN cargo fetch --manifest-path ./subprojects/gdk_rust/Cargo.toml
RUN rm -rf ./subprojects

RUN chmod +xr /root
WORKDIR /root/gdk
VOLUME /root/gdk
