FROM fedora:29@sha256:5d27d0e080b1564d03a8754199bb898f212de167a2af3c97ecc23c9e2d669f46
COPY fedora30_deps.sh /deps.sh
COPY requirements.txt /requirements.txt
RUN /deps.sh && rm /deps.sh
CMD cd /sdk && ./tools/build.sh --clang

