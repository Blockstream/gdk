# Debian (main build) image. Build with:
# DOCKER_BUILDKIT=1 docker build . -t greenaddress/ci -f tools/Dockerfile
#
FROM debian:bullseye@sha256:45ee40a844048c2f6d0105899c1a17733530b56d481612608aab5e2e4048570b as base
WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles/ ./cmake/profiles/
# Optionally copy dependency sources from the build directory if present
COPY ./tools/requirements.txt ./*.tar.gz /root/
RUN ./tools/bullseye_deps.sh

ENV ANDROID_NDK=/root/android-ndk-r23b
ENV JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
ENV GDK_KEEP_DOWNLOADS=1


FROM base AS builderandroid
RUN ./tools/builddeps.sh --ndk armeabi-v7a --prefix /prebuild/android-armeabi-v7a && \
    ./tools/builddeps.sh --ndk arm64-v8a --prefix /prebuild/android-arm64-v8a && \
    ./tools/builddeps.sh --ndk x86 --prefix /prebuild/android-x86 && \
    ./tools/builddeps.sh --ndk x86_64 --prefix /prebuild/android-x86_64

FROM base AS builderlinux
RUN mkdir -p /prebuild/gcc /prebuild/clang
RUN ./tools/builddeps.sh --gcc --prefix /prebuild/gcc && \
    ./tools/builddeps.sh --clang --prefix /prebuild/clang

FROM base AS buildermingw
RUN mkdir -p /prebuild/mingw-w64
RUN ./tools/builddeps.sh --mingw-w64 --prefix /prebuild/mingw-w64

FROM blockstream/esplora@sha256:dabc2501137dea9db6107e6c5c4d6d575616b2274dc278647f91ab9a4f75a848 AS esplora-base-image
FROM base as final

COPY --from=esplora-base-image /srv/explorer/electrs_bitcoin/bin/electrs /root/bin/electrs_bitcoin
COPY --from=esplora-base-image /srv/explorer/electrs_liquid/bin/electrs /root/bin/electrs_liquid
COPY --from=esplora-base-image /srv/explorer/bitcoin/bin/bitcoind /root/bin/bitcoind
COPY --from=esplora-base-image /srv/explorer/liquid/bin/liquidd /root/bin/elementsd

COPY --from=builderandroid /prebuild/android-armeabi-v7a /prebuild/android-armeabi-v7a
COPY --from=builderandroid /prebuild/android-arm64-v8a /prebuild/android-arm64-v8a
COPY --from=builderandroid /prebuild/android-x86 /prebuild/android-x86
COPY --from=builderandroid /prebuild/android-x86_64 /prebuild/android-x86_64


COPY --from=builderlinux /prebuild/gcc /prebuild/gcc
COPY --from=builderlinux /prebuild/clang /prebuild/clang

COPY --from=buildermingw /prebuild/mingw-w64 /prebuild/mingw-w64
# Remove copied/downloaded dependency sources
RUN rm -f /root/requirements.txt /root/*.tar.gz

ENV OPENSSL_DIR=/prebuild/gcc/openssl/build
ENV OPENSSL_STATIC=True
ENV ELECTRS_EXEC=/root/bin/electrs_bitcoin
ENV ELECTRS_LIQUID_EXEC=/root/bin/electrs_liquid
ENV BITCOIND_EXEC=/root/bin/bitcoind
ENV ELEMENTSD_EXEC=/root/bin/elementsd

RUN chmod +xr /root
WORKDIR /root/gdk
VOLUME /root/gdk
