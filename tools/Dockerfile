FROM debian:bullseye@sha256:45ee40a844048c2f6d0105899c1a17733530b56d481612608aab5e2e4048570b as base
WORKDIR /root
COPY ./tools/bullseye_deps.sh ./tools/deps.sh
COPY ./tools/requirements.txt /requirements.txt
COPY ./cmake/profiles/ ./cmake/profiles/
RUN ./tools/deps.sh

ENV ANDROID_NDK=/root/android-ndk-r23b
ENV JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64


FROM base AS builderandroid
COPY ./tools ./tools
RUN mkdir -p /prebuild/armv7a /prebuild/armv8a /prebuild/x86 /prebuild/x86_64
ENV GDK_KEEP_DOWNLOADS=1
RUN ./tools/builddeps.sh --ndk armeabi-v7a --prefix /prebuild/armv7a && \
    ./tools/builddeps.sh --ndk arm64-v8a --prefix /prebuild/armv8a && \
    ./tools/builddeps.sh --ndk x86 --prefix /prebuild/x86 && \
    ./tools/builddeps.sh --ndk x86_64 --prefix /prebuild/x86_64 && \
    rm -f /prebuild/*/*gz

FROM base AS builderlinux
COPY ./tools ./tools
RUN mkdir -p /prebuild/gcc /prebuild/clang
ENV GDK_KEEP_DOWNLOADS=1
RUN ./tools/builddeps.sh --gcc --prefix /prebuild/gcc && \
    ./tools/builddeps.sh --clang --prefix /prebuild/clang && \
    rm -f /prebuild/*/*gz

FROM base AS buildermingw
COPY ./tools ./tools
RUN mkdir -p /prebuild/mingw-w64
RUN ./tools/builddeps.sh --mingw-w64 --prefix /prebuild/mingw-w64


FROM blockstream/esplora@sha256:dabc2501137dea9db6107e6c5c4d6d575616b2274dc278647f91ab9a4f75a848 AS esplora-base-image
FROM base as final

COPY --from=esplora-base-image /srv/explorer/electrs_bitcoin/bin/electrs /root/bin/electrs_bitcoin
COPY --from=esplora-base-image /srv/explorer/electrs_liquid/bin/electrs /root/bin/electrs_liquid
COPY --from=esplora-base-image /srv/explorer/bitcoin/bin/bitcoind /root/bin/bitcoind
COPY --from=esplora-base-image /srv/explorer/liquid/bin/liquidd /root/bin/elementsd

COPY --from=builderandroid /prebuild/armv7a /prebuild/armv7a
COPY --from=builderandroid /prebuild/armv8a /prebuild/armv8a
COPY --from=builderandroid /prebuild/x86 /prebuild/x86
COPY --from=builderandroid /prebuild/x86_64 /prebuild/x86_64

COPY --from=builderlinux /prebuild/gcc /prebuild/gcc
COPY --from=builderlinux /prebuild/clang /prebuild/clang

COPY --from=buildermingw /prebuild/mingw-w64 /prebuild/mingw-w64

ENV OPENSSL_DIR=/prebuild/gcc/openssl/build
ENV OPENSSL_STATIC=True
ENV ELECTRS_EXEC=/root/bin/electrs_bitcoin
ENV ELECTRS_LIQUID_EXEC=/root/bin/electrs_liquid
ENV BITCOIND_EXEC=/root/bin/bitcoind
ENV ELEMENTSD_EXEC=/root/bin/elementsd

RUN chmod +xr /root
WORKDIR /root/gdk
VOLUME /root/gdk
