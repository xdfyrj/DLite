#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <dlite/loader.hpp>

namespace dlite {

struct Instruction {
    std::uint64_t address{0};
    std::size_t size{0};
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string op_str;
};

class Disassembler {
public:
    explicit Disassembler(CpuArch arch, Bitness bitness);
    explicit Disassembler(const BinaryImage& image);
    ~Disassembler();

    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;
    Disassembler(Disassembler&&) noexcept;
    Disassembler& operator=(Disassembler&&) noexcept;

    std::vector<Instruction> disassemble(ByteView bytes, std::uint64_t address);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

std::vector<Instruction> disassemble_text_section(const BinaryImage& image);
std::vector<Instruction> disassemble_executable_sections(const BinaryImage& image);

} // namespace dlite
