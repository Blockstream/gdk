# Manylinux (main build) image. Build with:
# DOCKER_BUILDKIT=1 docker build . -t greenaddress/gdk-manylinux-builder -f docker/manylinux/Dockerfile
#
FROM quay.io/pypa/manylinux_2_28_x86_64@sha256:9b66019db1656866ed7353b4f6ade7260bb4e74e8205bce63dac3d6fc076c7e6 as base
WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles/ ./cmake/profiles/
# Optionally copy dependency sources from the build directory if present
COPY ./tools/requirements.txt ./*.tar.gz /root/
COPY ./docker/python/install_deps.sh ./docker/python/install_deps.sh
RUN ./docker/python/install_deps.sh

ENV GDK_KEEP_DOWNLOADS=1

FROM base AS builderlinux
#wally absolutely wants a running python -- it doesn't really matter the version here
RUN source /opt/python/default/bin/activate && ./tools/builddeps.sh --gcc --prefix /prebuild/gcc

FROM rust:1.68-bullseye as builderrust

FROM base as final

COPY --from=builderlinux /prebuild/gcc /prebuild/gcc

COPY --from=builderrust /usr/local/cargo /usr/local/cargo
COPY --from=builderrust /usr/local/rustup /usr/local/rustup

RUN rm -f /root/requirements.txt /root/*.tar.gz

ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV RUST_VERSION=1.64.0
ENV PATH="/usr/local/cargo/bin:${PATH}"

RUN chmod +xr /root
WORKDIR /root/gdk
VOLUME /root/gdk
