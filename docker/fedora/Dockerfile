# Fedora image. Build with:
# DOCKER_BUILDKIT=1 docker build . -t blockstream/gdk-fedora-builder -f docker/fedora/Dockerfile
#
FROM fedora:32@sha256:7afb459893c1c5defb714d7e0a2aae4a5c2a12f24aa5b26ff5f8f8e7dd8b2317 AS base
WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles ./cmake/profiles
# Optionally copy dependency sources from the build directory if present
COPY ./downloads ./downloads
COPY ./docker/fedora/install_deps.sh ./docker/fedora/install_deps.sh
RUN ./docker/fedora/install_deps.sh

FROM base AS buildergcc
ENV GDK_KEEP_DOWNLOADS=1
RUN mkdir -p /prebuild/gcc
RUN ./tools/builddeps.sh --gcc --prefix /prebuild/gcc

FROM base AS builderclang
ENV GDK_KEEP_DOWNLOADS=1
RUN mkdir -p /prebuild/clang
RUN ./tools/builddeps.sh --clang --prefix /prebuild/clang

FROM base AS final
# Remove copied/downloaded dependency sources
RUN rm -rf ./tools ./downloads ./cmake ./docker

COPY --from=buildergcc /prebuild/gcc /prebuild/gcc
COPY --from=builderclang /prebuild/clang /prebuild/clang

RUN chmod +xr /root
WORKDIR /root/gdk
VOLUME /root/gdk
