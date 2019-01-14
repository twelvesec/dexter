## Libssh2 on Windows x64

### CMAKE Installation

* https://cmake.org/download/

### Repository cloning

```
git clone https://github.com/libssh2/libssh2.git
```

### Build

**Release**

```
cd libssh2
mkdir build
cd build
cmake -G "Visual Studio 15 2017 Win64" -DCRYPTO_BACKEND=WinCNG -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF ..
cmake --build . --config Release
```

**Debug**

```
cd libssh2
mkdir build
cd build
cmake -G "Visual Studio 15 2017 Win64" -DCRYPTO_BACKEND=WinCNG -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF ..
cmake --build . --config Debug
```
