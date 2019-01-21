FROM debian:stretch@sha256:21ac5961a3038a839f6fa92ec4583c90f9eb6ca8f580598cde19d35d0f4d8fa6
COPY stretch_deps.sh /deps.sh
COPY requirements.txt /requirements.txt
RUN /deps.sh && rm /deps.sh
ENV ANDROID_NDK=/android-ndk-r19
ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64
CMD cd /sdk && ./tools/build.sh --clang
