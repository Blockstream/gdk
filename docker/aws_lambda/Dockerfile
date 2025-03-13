# AWS lambda deployments.
# These use a custom Amazon Linux distro based on Fedora.
# This example is for the Python 3.10 image, adjust as needed.
# Build with:
# DOCKER_BUILDKIT=1 docker build . -t blockstream/gdk-aws-lambda-builder -f docker/aws_lambda/Dockerfile
#
# Once the image is built, you can build gdk inside of it with:
# $ git clone git clone https://github.com/Blockstream/gdk.git
# $ cd gdk
# $ ./tools/build.sh --gcc --python-version=3.10 --external-deps-dir=/prebuild/gcc --no-deps-rebuild
# $ The resulting wheel file will be in build-gcc/src/swig_python/green_gdk/dist/
#
FROM public.ecr.aws/lambda/python:3.10@sha256:c13bdddd001502be3ac79c3a80937332c998c96cb1894fe936f311b443eb6443 AS base

WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles ./cmake/profiles
# Optionally copy dependency sources from the build directory if present
COPY ./downloads ./downloads
COPY ./docker/aws_lambda/install_deps.sh ./docker/aws_lambda/install_deps.sh
RUN ./docker/aws_lambda/install_deps.sh

FROM base AS builderaws
ENV GDK_KEEP_DOWNLOADS=1
RUN mkdir -p /prebuild/gcc
RUN ./tools/builddeps.sh --gcc --prefix /prebuild/gcc

FROM base AS final
# Remove copied/downloaded dependency sources
RUN rm -rf ./tools ./downloads ./cmake ./docker

COPY --from=builderaws /prebuild/gcc /prebuild/gcc

RUN chmod +xr /root
WORKDIR /root/gdk
VOLUME /root/gdk

# The following line allows the image to be used in CI configurations, but will
# cause the resulting image to not work in the lambda environment. This
# Dockerfile is for creating an image to build gdk with, not for deploying!
ENTRYPOINT ["/bin/bash", "-l", "-c"]
