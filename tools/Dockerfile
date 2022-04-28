FROM debian:bullseye@sha256:45ee40a844048c2f6d0105899c1a17733530b56d481612608aab5e2e4048570b
COPY bullseye_deps.sh /deps.sh
COPY requirements.txt /requirements.txt
RUN /deps.sh && rm /deps.sh
ENV ANDROID_NDK=/android-ndk-r23b
ENV JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
CMD cd /sdk && ./tools/build.sh --clang
