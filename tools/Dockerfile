FROM debian:stretch@sha256:802706fa62e75c96fff96ada0e8ca11f570895ae2e9ba4a9d409981750ca544c
COPY stretch_deps.sh /deps.sh
COPY requirements.txt /requirements.txt
RUN /deps.sh && rm /deps.sh
ENV ANDROID_NDK=/android-ndk-r18b
ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64
CMD cd /sdk && ./tools/build.sh --clang
