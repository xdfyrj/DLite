#pragma once

#include <cstddef>
#include <cstdint>
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

std::vector<Instruction> disassemble_text_section(const BinaryImage& image);

} // namespace dlite
