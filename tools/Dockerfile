FROM debian:stretch@sha256:066051f6674f6a3293bbd5a190081b1ae7fcae655a3884db59ebb3a2831da623
COPY stretch_deps.sh /deps.sh
COPY requirements.txt /requirements.txt
RUN /deps.sh && rm /deps.sh
ENV ANDROID_NDK=/android-ndk-r19b
ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64
CMD cd /sdk && ./tools/build.sh --clang
