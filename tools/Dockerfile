FROM debian:buster@sha256:2f04d3d33b6027bb74ecc81397abe780649ec89f1a2af18d7022737d0482cefe
COPY buster_deps.sh /deps.sh
COPY requirements.txt /requirements.txt
RUN /deps.sh && rm /deps.sh
ENV ANDROID_NDK=/android-ndk-r20
ENV JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
CMD cd /sdk && ./tools/build.sh --clang
