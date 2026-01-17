# DLite(Disassembler Lite)
A lightweight C++ disassembly/decompilation research project.  

Target pipeline: **Binary → Disassembly**

## Build

```
cmake -S . -B build -G Ninja
cmake --build build
```

## To-Do

- [x] Basic PE/COFF loader (headers, sections, entry point)
- [ ] PE data directories (.pdata/.xdata, imports, relocations)
- [ ] Function boundary discovery (prefer `.pdata` RUNTIME_FUNCTION)
- [x] Capstone disassembler integration (x86-64, `.text`)
- [x] Instruction IR (address, mnemonic, operands, bytes)
- [ ] CFG construction utilities
- [ ] Output formatting (text + JSON)

- [ ] Future: ARM64?

