# Green C/C++ SDK

GDK is a cross-platform, cross-language library for Blockstream Green wallets.

Read the API documentation at https://gdk.readthedocs.io/en/latest/

## building from source
### installing required software
#### Android ndk
If you want to target Android you will need to download the NDK and set the ANDROID_NDK env variable to the directory you uncompress it to, for example
`export ANDROID_NDK=$HOME/Downloads/ndk`
or you can add it to your bash profile `~/.bash_profile`

#### rust
  1. Install rustup: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

  2. Install default rust toolchain: `rustup install 1.68.0`

  3. Install additional rust targets for cross-building: `rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android x86_64-pc-windows-gnu aarch64-apple-ios x86_64-apple-ios`

### platform-specific dependencies
For Debian Bullseye:
```
sudo ./tools/bullseye_deps.sh
```


For Mac OSX:

Install Xcode and brew if not installed, then
```
brew update && brew install cmake automake autoconf libtool gnu-sed python3 pkg-config swig (optional) gnu-getopt gnu-tar
xcode-select --install
```
You may also need to change your PATH environment variable to add `$HOME/Library/Python/3.X/bin`

## cmake build:
#### building dependencies
Using the tool in ``tools`` you can build in one go all the required dependencies for gdk
```bash
$ ./tools/builddeps.sh <options> --prefix <absolute-destination-path>
```
``<options>`` are:
- ``--clang`` , ``--gcc`` , ``--ndk <arch>`` , ``-mingw-w64`` , ``--iphone`` , ``iphonesimulator`` : (cross-)build with different compilers, on different platforms. Android build supports following ``<arch>``s
    - ``armeabi-v7a``
    - ``arm64-v8a``
    - ``x86``
    - ``x86_64``
- ``--buildtype debug``: in case gdk must be built in debug mode
- ``--parallel <jobs>``: set the number of parallel process that the build-system can spawn, default to CPU count.
for example:
```bash
$ ./tools/builddeps.sh --clang --prefix $HOME/prebuilt/clang
```
downloads, builds and installs all dependencies using clang compiler under ``$HOME/prebuild/clang`` folder

### building gdk
A script located in tools is enough to cover most common build use cases
```bash 
$ tools/build.sh <options>
```
``<options>`` are:
- ``--clang`` , ``--gcc`` , ``--ndk <arch>`` , ``-mingw-w64`` , ``--iphone`` , ``iphonesimulator`` : (cross-)build with different compilers, on different platforms
- ``--enable-tests``: builds test that can be easily launched using ``ctest`` (if your cmake is <= 3.20 you need to ``cd`` into the build directory, otherwise just use ``--test-dir``)
- ``--python-version <version>``: builds python-wheels. ``<version>`` can be something as simple as ``3``, you let cmake pick the 3.X version present in your system for you. Or it can be ``venv`` to indicate cmake that you are using a virtual environment and cmake should pick whatever python interpreter you set up in it.
- ``--parallel <jobs>``: set the number of parallel process that the build-system can spawn, default to CPU count.
- ``--external-deps-dir <path>`` the folder specificied under ``--prefix`` option when running ``tools/buildddeps.sh``
- ``--install <path>``: have the script invoke ``cmake --install`` and install all\* artifacts produced into ``<path>``
for example
```bash
tools/build.sh --clang --external-deps-dir $HOME/prefix/clang
```

Build output is placed in `build-<target>`, e.g. `build-clang`, `build-gcc` sub-directories.


\* Cmake introduces the concept of ``COMPONENT``s .GDK install is now split into two components: ``gdk-runtime`` includes only the dynamic library (with symbol files) and the python-wheel (if built and available); ``gdk-dev`` includes static library libgreenaddress-full.a, header files and all the header files for languages bindings like java and swift. CI as well as ``tools/build.sh --install <path>`` will always install everything.

### To clean:

`tools/clean.sh`

### Docker based deps & build (apple platforms excluded)

This doesn't require any of the previous steps but requires docker installed; it will build the project

```
docker build -t greenaddress_sdk -f ./tools/Dockerfile .
docker run -v $PWD:/root/gdk -it greenaddress_sdk
```

This will open a bash shell into the container, where you can then launch builds for any platform.
The docker container provided by GreenAddress comes with dependencies already built under the ``/prebuid`` folder

```bash
root@bab682a071e6:~/gdk# ./tools/build.sh --gcc --external-deps-dir /prebuid/gcc
root@bab682a071e6:~/gdk# ./tools/build.sh --clang --external-deps-dir /prebuid/clang
```

#### Debug builds

By default the build type is release. A debug build can specified as

`tools/build.sh --buildtype=debug --clang`

or

`tools/build.sh --buildtype=debugoptimized --clang`

for a debug optimized build.


### Java and Python wrappers

Java and Python wrappers are available if [SWIG](http://www.swig.org/) is installed.

If JAVA_HOME is set while the library is built, a Java wrapper is built exposing the API.

Similarly, if `--python-version` is passed to `tools/build.sh` a Python wrapper is built, for example:

`./tools/build.sh --install $PWD --gcc --python-version 3.9`

### Swift wrapper

A swift wrapper is available at [GreenAddress.swift](https://github.com/Blockstream/gdk/blob/master/src/swift/GreenAddress/Sources/GreenAddress/GreenAddress.swift).
