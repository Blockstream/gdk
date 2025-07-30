# Android (main build) image. Build with:
# DOCKER_BUILDKIT=1 docker build . -t blockstream/gdk-android-build -f docker/android/Dockerfile
#
FROM debian:bookworm@sha256:b6507e340c43553136f5078284c8c68d86ec8262b1724dde73c325e8d3dcdeba AS base
WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles ./cmake/profiles
# Optionally copy dependency sources from the build directory if present
COPY ./downloads ./downloads
COPY ./docker/android-bookworm/install_deps.sh ./docker/android/install_deps.sh
RUN ./docker/android/install_deps.sh

ENV ANDROID_NDK=/root/android-ndk-r26b
ENV JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-amd64
ENV GDK_KEEP_DOWNLOADS=1


FROM base AS builderandroid
RUN ./tools/builddeps.sh --ndk armeabi-v7a --prefix /prebuild/android-armeabi-v7a && \
    ./tools/builddeps.sh --ndk arm64-v8a --prefix /prebuild/android-arm64-v8a && \
    ./tools/builddeps.sh --ndk x86 --prefix /prebuild/android-x86 && \
    ./tools/builddeps.sh --ndk x86_64 --prefix /prebuild/android-x86_64


FROM rust:1.81-bullseye AS builderrust
RUN rustup component add rustfmt clippy llvm-tools-preview
RUN rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android


FROM base AS final
# Remove copied/downloaded dependency sources
RUN rm -rf ./tools ./downloads ./cmake ./docker


COPY --from=builderandroid /prebuild/android-armeabi-v7a /prebuild/android-armeabi-v7a
COPY --from=builderandroid /prebuild/android-arm64-v8a /prebuild/android-arm64-v8a
COPY --from=builderandroid /prebuild/android-x86 /prebuild/android-x86
COPY --from=builderandroid /prebuild/android-x86_64 /prebuild/android-x86_64


COPY --from=builderrust /usr/local/cargo /usr/local/cargo
COPY --from=builderrust /usr/local/rustup /usr/local/rustup

ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV RUST_VERSION=1.81.0
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
