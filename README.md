# Green C/C++ SDK

GDK is a cross-platform, cross-language library for Blockstream Green wallets.

Read the API documentation at https://gdk.readthedocs.io/en/latest/

## Meson/Ninja build:

### Build dependencies:

For Debian Bullseye:

```
sudo ./tools/bullseye_deps.sh
```

For Mac OSX:

Install Xcode and brew if not installed, then

```
brew update && brew install ninja automake autoconf libtool gnu-sed python3 pkg-config swig (optional) gnu-getopt gnu-tar
pip3 install --user meson
xcode-select --install
```

Install rust dependencies:

  1. Install rustup: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

  2. Install default rust toolchain: `rustup install 1.56.0`

  3. Install additional rust targets: `rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android x86_64-pc-windows-gnu aarch64-apple-ios
x86_64-apple-ios`

You may also need to change your PATH environment variable to add `$HOME/Library/Python/3.X/bin`

If you want to target Android you will need to download the NDK and set the ANDROID_NDK env variable to the directory you uncompress it to, for example

`export ANDROID_NDK=$HOME/Downloads/ndk`

or you can add it to your bash profile `~/.bash_profile`

Java bindings can be built by installing swig as explained above and setting JAVA_HOME to the location of the JDK.

### To build:

`tools/build.sh <options>`

Options exist to build for a particular configuration/platform (flags in squared brackets are optional):

```
--clang
--gcc
--ndk [armeabi-v7a arm64-v8a x86 x86_64]
--iphone [static]
```

for example

`tools/build.sh --gcc`

Build output is placed in `build-<target>`, e.g. `build-clang`, `build-gcc` sub-directories.

You can quickly run a single targets build from the `build-<target>` sub-directory using:

`ninja`

### To clean:

`tools/clean.sh`

### Docker based deps & build

This doesn't require any of the previous steps but requires docker installed; it will build the project

```
docker build -t greenaddress_sdk - < tools/Dockerfile
docker run -v $PWD:/sdk greenaddress_sdk
```

This will build the sdk with clang by default

if you want to change it for example to ndk armeabi-v7a:

`docker run -v $PWD:/sdk greenaddress/ci bash -c "cd /sdk && ./tools/build.sh --ndk armeabi-v7a"`

### Extra build options

#### Debug builds

By default the build type is release. A debug build can specified as

`tools/build.sh --buildtype=debug --clang`

or

`tools/build.sh --buildtype=debugoptimized --clang`

for a debug optimized build.

#### Clang Analyzer

To build using clang-analyzer use

`tools/build.sh --analyze --clang`

#### Clang tidy

The clang-tidy targets are enabled if found in the PATH. Extra options exist to specify version of it,

`tools/build.sh --clang-tidy-version=7 --clang`

then use as follows

`ninja src/clang-tidy`

#### Sanitizers

A sanitizer build can be invoked using

`tools/build.sh --sanitizer=<type> --gcc`

where `<type>` is any available sanitizer of your choice and available on the toolchain being used.

#### Compiler versions

A different compiler version can be specified as

`tools/build.sh --compiler-version=<version>`

which allows for multiple side by side installs of compilers in common linux distributions.

### Build examples

Use clang-5.0, enable clang-tidy and debug build

`./tools/build.sh --compiler-version=5.0 --buildtype=debug --clang-tidy-version=5.0 --clang`

Use address sanitizer with gcc-7, enable clang-tidy and debug build

`./tools/build.sh --compiler-version=7 --buildtype=debug --sanitizer=address --clang-tidy-version=5.0 --gcc`

Use clang-analyzer (it'll analyze GDK and its direct dependencies)

`./tools/build.sh --analyze --clang`

### Upgrading dependencies

Use `tools/upgrade_deps.sh`, for example to upgrade wally

`./tools/upgrade_deps.sh -l libwally-core -s 987575025520d18bac31e6e2d27c8c936d812c64 -u https://github.com/ElementsProject/libwally-core/archive/987575025520d18bac31e6e2d27c8c936d812c64.tar.gz`

### Java and Python wrappers

Java and Python wrappers are available if [SWIG](http://www.swig.org/) is installed.

If JAVA_HOME is set while the library is built, a Java wrapper is built exposing the API.

Similarly, if `--python-version` is passed to `tools/build.sh` a Python wrapper is built, for example:

`./tools/build.sh --install $PWD --gcc --python-version 3.9`

### Swift wrapper

A swift wrapper is available at [GreenAddress.swift](https://github.com/Blockstream/gdk/blob/master/src/swift/GreenAddress/Sources/GreenAddress/GreenAddress.swift).
