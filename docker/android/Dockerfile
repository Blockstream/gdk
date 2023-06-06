# Android (main build) image. Build with:
# DOCKER_BUILDKIT=1 docker build . -t blockstream/gdk-android-build -f docker/android/Dockerfile
#
FROM debian:bullseye@sha256:d0bf7d85ad1e61ab3520b1d22d1e2a136799defd4e0d1e3f998d3b9045f38551 as base
WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles/ ./cmake/profiles/
# Optionally copy dependency sources from the build directory if present
COPY ./*.tar.gz /root/
COPY ./docker/android/install_deps.sh ./docker/android/install_deps.sh
RUN ./docker/android/install_deps.sh

ENV ANDROID_NDK=/root/android-ndk-r23b
ENV JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
ENV GDK_KEEP_DOWNLOADS=1


FROM base AS builderandroid
RUN ./tools/builddeps.sh --ndk armeabi-v7a --prefix /prebuild/android-armeabi-v7a && \
    ./tools/builddeps.sh --ndk arm64-v8a --prefix /prebuild/android-arm64-v8a && \
    ./tools/builddeps.sh --ndk x86 --prefix /prebuild/android-x86 && \
    ./tools/builddeps.sh --ndk x86_64 --prefix /prebuild/android-x86_64


FROM rust:1.68-bullseye as builderrust
RUN rustup component add rustfmt clippy llvm-tools-preview
RUN rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android


FROM base as final


COPY --from=builderandroid /prebuild/android-armeabi-v7a /prebuild/android-armeabi-v7a
COPY --from=builderandroid /prebuild/android-arm64-v8a /prebuild/android-arm64-v8a
COPY --from=builderandroid /prebuild/android-x86 /prebuild/android-x86
COPY --from=builderandroid /prebuild/android-x86_64 /prebuild/android-x86_64


COPY --from=builderrust /usr/local/cargo /usr/local/cargo
COPY --from=builderrust /usr/local/rustup /usr/local/rustup

# Remove copied/downloaded dependency sources
RUN rm -f /root/*.tar.gz

ENV OPENSSL_DIR=/prebuild/gcc/openssl/build
ENV OPENSSL_STATIC=True

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
