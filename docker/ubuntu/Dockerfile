# Ubuntu image. Build with:
# DOCKER_BUILDKIT=1 docker build . -t blockstream/gdk-ubuntu-builder -f docker/ubuntu-arm64/Dockerfile
#
FROM ubuntu:20.04@sha256:3626dff0d616e8ee7065a9ac8c7117e904a4178725385910eeecd7f1872fc12d AS base
WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles ./cmake/profiles
# Optionally copy dependency sources from the build directory if present
COPY ./downloads ./downloads
COPY ./docker/ubuntu/install_deps.sh ./docker/ubuntu/install_deps.sh
RUN ./docker/ubuntu/install_deps.sh

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
