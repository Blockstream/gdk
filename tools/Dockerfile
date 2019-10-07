FROM debian:buster@sha256:e25b64a9cf82c72080074d6b1bba7329cdd752d51574971fd37731ed164f3345
COPY buster_deps.sh /deps.sh
COPY requirements.txt /requirements.txt
RUN /deps.sh && rm /deps.sh
ENV ANDROID_NDK=/android-ndk-r20
ENV JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
CMD cd /sdk && ./tools/build.sh --clang
