FROM debian:buster@sha256:41f76363fd83982e14f7644486e1fb04812b3894aa4e396137c3435eaf05de88
COPY buster_deps.sh /deps.sh
COPY requirements.txt /requirements.txt
RUN /deps.sh && rm /deps.sh
ENV ANDROID_NDK=/android-ndk-r20b
ENV JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
CMD cd /sdk && ./tools/build.sh --clang
