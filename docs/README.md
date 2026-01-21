# DLite(Disassembler Lite)
A lightweight C++ disassembly/decompilation research project.  

Target pipeline: **Binary → Disassembly**

# Build

```
cmake -S . -B build -G Ninja -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-mingw-dynamic -DCMAKE_C_COMPILER="C:/Program Files/LLVM/bin/clang.exe" -DCMAKE_CXX_COMPILER="C:/Program Files/LLVM/bin/clang++.exe" -DCMAKE_C_COMPILER_TARGET=x86_64-w64-windows-gnu -DCMAKE_CXX_COMPILER_TARGET=x86_64-w64-windows-gnu
cmake --build build
```