# DLite(Disassembler Lite)
A lightweight C++ disassembly/decompilation research project.  

Target pipeline: **Binary → Disassembly**

## Build

```
cmake -S . -B build -G Ninja
cmake --build build
```

## To-Do

- [ ] PE/COFF loader (.text/.rdata/.pdata/.xdata, imports, relocations)
- [ ] Function boundary discovery (prefer `.pdata` RUNTIME_FUNCTION)
- [ ] Disassembler integration
- [ ] Instruction IR (address, mnemonic, operands, bytes)
- [ ] CFG construction utilities
- [ ] Output formatting (text + JSON)

..ARM64?

