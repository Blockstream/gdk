FROM debian:bullseye@sha256:45ee40a844048c2f6d0105899c1a17733530b56d481612608aab5e2e4048570b as base
WORKDIR /root
COPY ./tools/bullseye_deps.sh ./tools/bullseye_deps.sh
COPY ./tools/requirements.txt /requirements.txt
RUN ./tools/bullseye_deps.sh

ENV ANDROID_NDK=/root/android-ndk-r23b
ENV JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64


FROM curlimages/curl as downloader
WORKDIR /home/curl_user
RUN curl -L https://github.com/RCasatta/electrsd/releases/download/electrs_releases/electrs_linux_esplora_703c6a20d52b61a234a18812503bd754d448992a.gz | tar -xz
RUN echo "6c62b280db4455a0bee1c60dcb7bb18f741313deb8aafdb7bad1bc2a3f4ff0b8  electrs" | sha256sum -c
RUN chmod 755 electrs && mv electrs electrs_bitcoin
RUN curl -L https://github.com/RCasatta/electrsd/releases/download/electrs_releases/electrs_linux_esplora_703c6a20d52b61a234a18812503bd754d448992a_liquid.gz | tar -xz
RUN echo "47571e09fbc5bc25504e3b66ee47295cea9912182d42721c11d895183e5b6c6e  electrs" | sha256sum -c
RUN chmod 755 electrs && mv electrs electrs_liquid
RUN curl https://bitcoincore.org/bin/bitcoin-core-0.20.1/bitcoin-0.20.1-x86_64-linux-gnu.tar.gz | tar -xz bitcoin-0.20.1/bin/bitcoind && mv bitcoin-0.20.1/bin/bitcoind bitcoind
RUN curl -L https://github.com/ElementsProject/elements/releases/download/elements-0.21.0/elements-elements-0.21.0-x86_64-linux-gnu.tar.gz | tar -xz elements-elements-0.21.0/bin/elementsd && mv elements-elements-0.21.0/bin/elementsd elementsd


FROM base AS builderarmv7a
COPY ./tools ./tools
RUN mkdir -p /prebuild/armv7a
RUN ./tools/builddeps.sh --ndk armeabi-v7a --prefix /prebuild/armv7a

FROM base AS builderarmv8a
COPY ./tools ./tools
RUN mkdir -p /prebuild/armv8a
RUN ./tools/builddeps.sh --ndk arm64-v8a --prefix /prebuild/armv8a

FROM base AS builderx86
COPY ./tools ./tools
RUN mkdir -p /prebuild/x86
RUN ./tools/builddeps.sh --ndk x86 --prefix /prebuild/x86

FROM base AS builderx86_64
COPY ./tools ./tools
RUN mkdir -p /prebuild/x86_64
RUN ./tools/builddeps.sh --ndk x86_64 --prefix /prebuild/x86_64

FROM base AS buildergcc
COPY ./tools ./tools
RUN mkdir -p /prebuild/gcc
RUN ./tools/builddeps.sh --gcc --prefix /prebuild/gcc

FROM base AS builderclang
COPY ./tools ./tools
RUN mkdir -p /prebuild/clang
RUN ./tools/builddeps.sh --clang --prefix /prebuild/clang

FROM base AS buildermingw
COPY ./tools ./tools
RUN mkdir -p /prebuild/mingw-w64
RUN ./tools/builddeps.sh --mingw-w64 --prefix /prebuild/mingw-w64


FROM base as final

COPY --from=downloader /home/curl_user/electrs_bitcoin /root/bin/electrs_bitcoin
COPY --from=downloader /home/curl_user/electrs_liquid /root/bin/electrs_liquid
COPY --from=downloader /home/curl_user/bitcoind /root/bin/bitcoind
COPY --from=downloader /home/curl_user/elementsd /root/bin/elementsd

COPY --from=builderarmv7a /prebuild/armv7a /prebld/armv7a
COPY --from=builderarmv8a /prebuild/armv8a /prebld/armv8a
COPY --from=builderx86 /prebuild/x86 /prebld/x86
COPY --from=builderx86_64 /prebuild/x86_64 /prebld/x86_64

COPY --from=buildergcc /prebuild/gcc /prebld/gcc
COPY --from=builderclang /prebuild/clang /prebld/clang

COPY --from=buildermingw /prebuild/mingw-w64 /prebld/mingw-w64

ENV OPENSSL_DIR=/prebld/gcc/openssl/build
ENV OPENSSL_STATIC=True
ENV ELECTRS_EXEC=/root/bin/electrs_bitcoin
ENV ELECTRS_LIQUID_EXEC=/root/bin/electrs_liquid
ENV BITCOIND_EXEC=/root/bin/bitcoind
ENV ELEMENTSD_EXEC=/root/bin/elementsd

RUN chmod +xr /root
WORKDIR /root/gdk
VOLUME /root/gdk
