FROM debian:buster@sha256:903779f30a7ee46937bfb21406f125d5fdace4178074e1cc71c49039ebf7f48f
COPY buster_deps.sh /deps.sh
COPY requirements.txt /requirements.txt
RUN /deps.sh && rm /deps.sh
ENV ANDROID_NDK=/android-ndk-r20
ENV JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
CMD cd /sdk && ./tools/build.sh --clang
