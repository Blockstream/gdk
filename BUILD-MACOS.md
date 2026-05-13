# Building GDK Locally on macOS (Including macOS Tahoe)
The main challenge when building GDK on macOS is that macOS ships with **Apple Clang** by default, while GDK often requires the standard **LLVM Clang** toolchain to ensure cryptographic compatibility with protocols such as: BIP32, BIP39, BIP44.

This guide mirrors and extends the CI configuration defined [here](https://github.com/Blockstream/gdk/blob/e18d626a08185dc4172e3fd1656b230897d03189/gitlab/common.yml#L58).



### 1. Clone the Repository

```bash
git clone git@github.com:Blockstream/gdk.git
cd gdk
```

### 2. Install Required Build Tools
Install required dependencies using Homebrew:

```bash
brew update && brew install cmake automake autoconf libtool gnu-sed python3 pkg-config swig gnu-getopt gnu-tar
```
Install Xcode command line tools:

```sash
xcode-select --install
```

### 3. Configure the Environment

Generate the Prebuilt Dependency Directory

```bash
idx=($(shasum tools/* cmake/profiles/* | shasum))
export PREBUILT_SUBDIR="prebuilt-${idx}-${BUILD_IDX}"
echo "Prebuilt subdirectory is ${PREBUILT_SUBDIR}"
```

Create Shared Download Directory

```bash
mkdir -p $CI_BUILDS_DIR/downloads
ln -s $CI_BUILDS_DIR/downloads downloads
```
Install LLVM 17

```bash
brew install llvm@17
```

Configure LLVM Environment Variables

```bash
export BREW_PREFIX=$( [[ $(uname -m) == "arm64" ]] && echo "/opt/homebrew" || echo "/usr/local" )
export LLVM_PATH="$BREW_PREFIX/opt/llvm@17"
export PATH="$LLVM_PATH/bin:$PATH"
export CC="$LLVM_PATH/bin/clang"
export CXX="$LLVM_PATH/bin/clang++"
export LDFLAGS="-L$LLVM_PATH/lib"
export CPPFLAGS="-I$LLVM_PATH/include"
export CMAKE_PREFIX_PATH="$LLVM_PATH"
```

Install Python 3.9

> **Note:**\
> Python 3.9 is the version for which artifacts are provided.
> However, the same virtual environment workflow also works with newer Python versions.

```bash
brew install python@3.9
```

### 4. Create a Python Virtual Environment

Create a virtual environment named `gdk-env`. Copy the dollar sign as well.

```bash
$(brew --prefix python@3.9)/bin/python3.9 -m venv gdk-env
```

Activate the Virtual Environment

```bash
source gdk-env/bin/activate
```

Verify the Python Version

```bash
python --version
```

Expected output:

```text
Python 3.9.x
```

### 5. Fix Java headers
Check Whether `jni.h` Exists

```bash
echo $JAVA_HOME

ls $JAVA_HOME/include/jni.h
```

If `jni.h` is missing, configure `JAVA_HOME` to point to a valid JDK installation:

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 17)

export PATH="$JAVA_HOME/bin:$PATH"
```

### 6. Build 
Build Dependencies:

```bash
./tools/builddeps.sh --clang --prefix $HOME/prebuilt/clang
```

Build GDK:

> **Note:**\
> Using `--parallel` enables parallel builds across multiple CPU cores.

```bash
tools/build.sh --clang --external-deps-dir $HOME/prebuilt/clang
```

If build errors occur, ensure that `gnu-getopt` and `gnu-sed` are installed, then update your `PATH`:

```bash
export PATH="$(brew --prefix gnu-getopt)/bin:$PATH"
export PATH="$(brew --prefix gnu-sed)/gnubin:$PATH"
```


> **Note:**\
> To enable test, run the build with `--enable-tests flag`



### 7. Testing
To run a sample test (e.g.: `gdk/tests/test_aes_gcm.cpp`) use:

```bash
./build-clang/tests/test_aes_gcm
```

To create a custom C++ test:
1. Create your test source file inside `gdk/tests`
2. Register the Test in `gdk/tests/CMakeLists.txt` by adding the following lines:

    ```cmake
    add_executable(myTest myTest.cpp)

    add_test(NAME myTest COMMAND myTest)
    ```
3. Re-run the build with tests enabled, then execute your test.

---

### Troubleshooting

#### Boost Version Errors

If you encounter Boost-related build issues, install Boost `1.87.0` manually:

```bash
curl -LO https://archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.gz

tar -xzf boost_1_87_0.tar.gz

cd boost_1_87_0

./bootstrap.sh --prefix=/opt/boost_1_87

./b2 install -j4
```