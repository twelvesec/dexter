## Libgit on Windows x64

### CMAKE Installation

* https://cmake.org/download/

### Repository cloning

```
git clone git@github.com:libgit2/libgit2.git
```

### Build

```
mkdir build
cd build
cmake -G "Visual Studio 15 2017 Win64" -DCMAKE_BUILD_TYPE=Release -DBUILD_CLAR=OFF -DSTDCALL=ON -DBUILD_SHARED_LIBS=OFF -DSTATIC_CRT=OFF ..
cmake --build . --config Release
```