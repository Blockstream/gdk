FROM ubuntu:20.04@sha256:71201a4c55f72ec33671cfcbf007689df61a13a35f028f94f8c510967dfb52e1 as base
WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles ./cmake/profiles
# Optionally copy dependency sources from the build directory if present
COPY ./downloads ./downloads
COPY ./docker/ubuntu-arm64/install_deps.sh ./docker/ubuntu-arm64/install_deps.sh
RUN ./docker/ubuntu-arm64/install_deps.sh
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-arm64

FROM base AS buildergcc
ENV GDK_KEEP_DOWNLOADS=1
RUN mkdir -p /prebuild/gcc
RUN ./tools/builddeps.sh --gcc --prefix /prebuild/gcc

FROM base
COPY --from=buildergcc /prebuild/gcc /prebuild/gcc
# Remove copied/downloaded dependency sources
RUN rm -rf ./tools ./downloads ./cmake ./docker

RUN chmod +xr /root
WORKDIR /root/gdk
VOLUME /root/gdk
