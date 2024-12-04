# Local image for building a gdk compatible with aws lambda deployments.
# These use a custom Amazon Linux distro based on Fedora.
# This example is for the Python 3.10 image, adjust as needed.
# Build from the gdk root directory with e.g.:
# DOCKER_BUILDKIT=1 docker build . -t gdk-aws-build -f docker/aws_lambda/Dockerfile
#
# Once the image is built, you can build gdk inside of it with:
# $ git clone git clone https://github.com/Blockstream/gdk.git
# $ cd gdk
# $ ./tools/build.sh --gcc --python-version=3.10 --external-deps-dir=/prebuild/gcc --no-deps-rebuild
# $ The resulting wheel file will be in build-gcc/src/swig_python/green_gdk/dist/
#
FROM public.ecr.aws/lambda/python:3.10

WORKDIR /root
COPY ./tools ./tools
COPY ./cmake/profiles ./cmake/profiles
# Optionally copy dependency sources from the build directory if present
COPY ./downloads ./downloads
COPY ./docker/aws_lambda/install_deps.sh ./docker/aws_lambda/install_deps.sh
RUN ./docker/aws_lambda/install_deps.sh

ENV GDK_KEEP_DOWNLOADS=1
RUN mkdir -p /prebuild/gcc
RUN ./tools/builddeps.sh --gcc --prefix /prebuild/gcc

RUN chmod +xr /root
WORKDIR /root
VOLUME /root
