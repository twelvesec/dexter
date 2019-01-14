## LibGit2 build on Windows 10 x64

### CMAKE Installation

* https://cmake.org/download/

### Repository cloning

```
git clone git@github.com:libgit2/libgit2.git
```

### Build

**Release**

```
cd libgit2
mkdir build
cd build
cmake -G "Visual Studio 15 2017 Win64" -DCMAKE_BUILD_TYPE=Release -DBUILD_CLAR=OFF -DSTDCALL=ON -DBUILD_SHARED_LIBS=OFF -DSTATIC_CRT=OFF -DUSE_SSH=OFF -DLIBSSH2_FOUND=TRUE -DLIBSSH2_INCLUDE_DIRS=C:/path/to/libssh2/include -DLIBSSH2_LIBRARY_DIRS=C:/path/to/libssh2/build/src/Release -DLIBSSH2_LIBRARIES=libssh2.lib ..
cmake --build . --config Release
```

**Debug**

```
cd libgit2
mkdir build
cd build
cmake -G "Visual Studio 15 2017 Win64" -DCMAKE_BUILD_TYPE=Debug -DBUILD_CLAR=OFF -DSTDCALL=ON -DBUILD_SHARED_LIBS=OFF -DSTATIC_CRT=OFF -DUSE_SSH=OFF -DLIBSSH2_FOUND=TRUE -DLIBSSH2_INCLUDE_DIRS=C:/path/to/libssh2/include -DLIBSSH2_LIBRARY_DIRS=C:/path/to/libssh2/build/src/Debug -DLIBSSH2_LIBRARIES=libssh2.lib ..
cmake --build . --config Debug
```
