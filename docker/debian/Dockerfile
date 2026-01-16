# Debian (main build) image. Build with:
# DOCKER_BUILDKIT=1 docker build . -t blockstream/gdk-debian-ci -f docker/debian/Dockerfile
#
FROM debian:bullseye@sha256:25c0cab214b810db1b3c8adef5a12a92596979abddf86bb364e8d9c9d111df9f AS base
WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles ./cmake/profiles
# Optionally copy dependency sources from the build directory if present
COPY ./downloads ./downloads
COPY ./docker/debian/install_deps.sh ./docker/debian/install_deps.sh
RUN ./docker/debian/install_deps.sh

ENV JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
ENV GDK_KEEP_DOWNLOADS=1


FROM base AS builderlinux
RUN mkdir -p /prebuild/gcc /prebuild/clang
RUN ./tools/builddeps.sh --gcc --prefix /prebuild/gcc && \
    ./tools/builddeps.sh --clang --prefix /prebuild/clang

FROM base AS buildermingw
RUN mkdir -p /prebuild/mingw-w64
RUN ./tools/builddeps.sh --mingw-w64 --prefix /prebuild/mingw-w64

FROM rust:1.85-bullseye AS builderrust
WORKDIR /root
COPY ./docker/debian/install_rust_tools.sh ./docker/debian/install_rust_tools.sh
RUN ./docker/debian/install_rust_tools.sh

FROM blockstream/esplora@sha256:dabc2501137dea9db6107e6c5c4d6d575616b2274dc278647f91ab9a4f75a848 AS esplora-base-image


FROM base AS final
# Remove copied/downloaded dependency sources
RUN rm -rf ./tools ./downloads ./cmake ./docker

COPY --from=esplora-base-image /srv/explorer/electrs_bitcoin/bin/electrs /root/bin/electrs_bitcoin
COPY --from=esplora-base-image /srv/explorer/bitcoin/bin/bitcoind /root/bin/bitcoind

COPY --from=builderlinux /prebuild/gcc /prebuild/gcc
COPY --from=builderlinux /prebuild/clang /prebuild/clang

COPY --from=buildermingw /prebuild/mingw-w64 /prebuild/mingw-w64

COPY --from=builderrust /usr/local/cargo /usr/local/cargo
COPY --from=builderrust /usr/local/rustup /usr/local/rustup

ENV OPENSSL_DIR=/prebuild/clang
ENV OPENSSL_STATIC=True
ENV ELECTRS_EXEC=/root/bin/electrs_bitcoin
ENV BITCOIND_EXEC=/root/bin/bitcoind

ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV RUST_VERSION=1.85.0
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
