# Debian (main build) image. Build with:
# DOCKER_BUILDKIT=1 docker build . -t greenaddress/ci -f tools/Dockerfile
#
FROM debian:bullseye@sha256:d0bf7d85ad1e61ab3520b1d22d1e2a136799defd4e0d1e3f998d3b9045f38551 as base
WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles/ ./cmake/profiles/
# Optionally copy dependency sources from the build directory if present
COPY ./tools/requirements.txt ./*.tar.gz /root/
COPY ./docker/debian/install_deps.sh ./docker/debian/install_deps.sh
RUN ./docker/debian/install_deps.sh

ENV GDK_KEEP_DOWNLOADS=1


FROM base AS builderlinux
RUN mkdir -p /prebuild/gcc /prebuild/clang
RUN ./tools/builddeps.sh --gcc --prefix /prebuild/gcc && \
    ./tools/builddeps.sh --clang --prefix /prebuild/clang

FROM base AS buildermingw
RUN mkdir -p /prebuild/mingw-w64
RUN ./tools/builddeps.sh --mingw-w64 --prefix /prebuild/mingw-w64

FROM rust:1.68-bullseye as builderrust
RUN rustup component add rustfmt clippy llvm-tools-preview
RUN rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android x86_64-pc-windows-gnu
RUN cargo install cargo-audit grcov cargo-nextest

FROM blockstream/esplora@sha256:dabc2501137dea9db6107e6c5c4d6d575616b2274dc278647f91ab9a4f75a848 AS esplora-base-image


FROM base as final

COPY --from=esplora-base-image /srv/explorer/electrs_bitcoin/bin/electrs /root/bin/electrs_bitcoin
COPY --from=esplora-base-image /srv/explorer/electrs_liquid/bin/electrs /root/bin/electrs_liquid
COPY --from=esplora-base-image /srv/explorer/bitcoin/bin/bitcoind /root/bin/bitcoind
COPY --from=esplora-base-image /srv/explorer/liquid/bin/liquidd /root/bin/elementsd

COPY --from=builderlinux /prebuild/gcc /prebuild/gcc
COPY --from=builderlinux /prebuild/clang /prebuild/clang

COPY --from=buildermingw /prebuild/mingw-w64 /prebuild/mingw-w64

COPY --from=builderrust /usr/local/cargo /usr/local/cargo
COPY --from=builderrust /usr/local/rustup /usr/local/rustup

# Remove copied/downloaded dependency sources
RUN rm -f /root/requirements.txt /root/*.tar.gz

ENV OPENSSL_DIR=/prebuild/gcc/openssl/build
ENV OPENSSL_STATIC=True
ENV ELECTRS_EXEC=/root/bin/electrs_bitcoin
ENV ELECTRS_LIQUID_EXEC=/root/bin/electrs_liquid
ENV BITCOIND_EXEC=/root/bin/bitcoind
ENV ELEMENTSD_EXEC=/root/bin/elementsd

ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV RUST_VERSION=1.68.0
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
