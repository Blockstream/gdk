# GreenAddress C/C++ SDK

## Meson/Ninja build:

### Build dependencies:

For Debian Stretch:

* sudo apt update && sudo apt install build-essential python3-pip ninja-build clang wget autoconf pkg-config libtool swig (optional)
* sudo pip3 install -r tools/requirements.txt or pip3 install --user -r tools/requirements.txt

For Mac OSX:

Install Xcode and brew if not installed, then

* brew update && brew install ninja automake autoconf libtool gnu-sed python3 wget pkg-config swig (optional) gnu-getopt gnu-tar
* pip3 install --user meson
* xcode-select --install

You may also need to change your PATH environment variable to add $HOME/Library/Python/3.6/bin

If you want to target Android you will need to download the NDK and set the ANDROID_NDK env variable to the directory you uncompress it to, for example

* export ANDROID_NDK=$HOME/Downloads/ndk

or you can add it to your bash profile ~/.bash_profile

JAVA bindings can be built by installing swig as explained above and setting JAVA_HOME to the location of the JDK.

### To build:

* tools/build.sh <options>

Options exist to build for a particular configuration/platform (flags in squared brackets are optional):

--clang
--gcc
--ndk [armeabi-v7a arm64-v8a x86 x86_64]
--iphone [static]

for example

* tools/build.sh --gcc

Build output is placed in 'build-<target>', e.g. 'build-clang', 'build-gcc' sub-directories.

You can quickly run a single targets build from the 'build-<target>' sub-directory using:

* ninja

### To clean:

* tools/clean.sh

### To run tests:

#### Using testnet as backend:

From the 'build-<target>' sub-directory:

* ninja test

#### Using local backend (GreenAddress developers only):

* meson test --no-rebuild --print-errorlogs --test-args '\-l'

### Docker based deps & build

This doesn't require any of the previous steps but requires docker installed; it will build the project

* docker build -t greenaddress_sdk - < tools/Dockerfile
* docker run -v $PWD:/sdk greenaddress_sdk

or if you don't want to build it locally

* docker pull greenaddress/ci@sha256:d9f628bdfad8159aafd38139f6de91fa1040f3378ccb813893888dde5d80d13f
* docker run -v $PWD:/sdk greenaddress/ci

in both cases (built or fetched) this will build the sdk with clang by default

if you want to change it for example to ndk armeabi-v7a:

* docker run -v $PWD:/sdk greenaddress/ci bash -c "cd /sdk && ./tools/build.sh --ndk armeabi-v7a"

### Extra build options

#### Disable LTO

By default builds use link time optimisation. It can be disabled when invoking build.sh. For example

* tools/build.sh --lto=false --clang

#### Debug builds

By default the build type is release. A debug build can specified as

* tools/build.sh --buildtype=debug --clang

#### Clang Analyzer

To build using clang-analyzer use

* tools/build.sh --analyze --clang

#### Clang tidy

The clang-tidy targets are enabled if found in the PATH. Extra options exist to specify version of it,

* tools/build.sh --clang-tidy-version=5.0 --clang

then use as follows

* ninja src/compile_commands.json (reconstruct compilation commands database due to some options not being recognised by libTooling)
* ninja src/clang-tidy

#### Sanitizers

A sanitizer build can be invoked using

* tools/build.sh --sanitize=<type> --gcc

where <type> is any available sanitizer of your choice and available on the toolchain being used.

#### Compiler versions

A different compiler version can be specified as

* tools/build.sh --compiler-version=<version>

which allows for multiple side by side installs of compilers in common linux distributions.

### Build examples

Use clang-5.0, no LTO, enable clang-tidy and debug build

* ./tools/build.sh --compiler-version=5.0 --buildtype=debug --lto=false --clang-tidy-version=5.0 --clang

Use address sanitizer with gcc-7, no LTO, enable clang-tidy and debug build

* ./tools/build.sh --compiler-version=7 --buildtype=debug --lto=false --sanitize=address --clang-tidy-version=5.0 --gcc

Use clang-analyzer (it'll analyze GDK and its direct dependencies)

./tools/build.sh --analyze --clang

### Upgrading dependencies

Use tools/upgrade_deps.sh, for example to upgrade wally

* ./tools/upgrade_deps.sh -l libwally-core -s 987575025520d18bac31e6e2d27c8c936d812c64 -u https://github.com/ElementsProject/libwally-core/archive/987575025520d18bac31e6e2d27c8c936d812c64.tar.gz
