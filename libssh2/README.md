## Libssh2 build on Windows 10 x64

### CMAKE Installation

* https://cmake.org/download/

### Repository cloning

```
git clone https://github.com/libssh2/libssh2.git
```

### Build (library)

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

### Build (dll)

**Release**

```
cd libssh2
mkdir build
cd build
cmake -G "Visual Studio 15 2017 Win64" -DCRYPTO_BACKEND=WinCNG -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON ..
cmake --build . --config Release
```

**Debug**

```
cd libssh2
mkdir build
cd build
cmake -G "Visual Studio 15 2017 Win64" -DCRYPTO_BACKEND=WinCNG -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=ON ..
cmake --build . --config Debug
```

### Installation

```
cd libssh2
mkdir install
cmake -G "Visual Studio 15 2017 Win64" -DCRYPTO_BACKEND=WinCNG -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=./install --build .
cmake --build . --target install
```
