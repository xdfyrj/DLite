#include <dlite/disasm.hpp>

#include <capstone/capstone.h>

#include <cstdint>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

cs_mode select_cs_mode(dlite::CpuArch arch, dlite::Bitness bitness) {
    if (bitness == dlite::Bitness::Bit32) {
        if (arch != dlite::CpuArch::Unk && arch != dlite::CpuArch::X86) {
            throw std::runtime_error("Bitness/arch mismatch for 32-bit disassembly");
        }
        return CS_MODE_32;
    }
    if (bitness == dlite::Bitness::Bit64) {
        if (arch != dlite::CpuArch::Unk && arch != dlite::CpuArch::X86_64) {
            throw std::runtime_error("Bitness/arch mismatch for 64-bit disassembly");
        }
        return CS_MODE_64;
    }
    if (arch == dlite::CpuArch::X86) {
        return CS_MODE_32;
    } else if (arch == dlite::CpuArch::X86_64) {
        return CS_MODE_64;
    }
    throw std::runtime_error("Unsupported CPU architecture for disassembly");
}

constexpr std::uint32_t kImageScnMemExecute = 0x20000000;

bool is_executable_section(const dlite::Section& section) {
    return (section.characteristics & kImageScnMemExecute) != 0;
}

} // namespace

namespace dlite {

struct Disassembler::Impl {
    explicit Impl(cs_mode mode) {
        if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
            throw std::runtime_error("Failed to initialize Capstone");
        }
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    }

    ~Impl() {
        if (handle != 0) {
            cs_close(&handle);
        }
    }

    std::vector<Instruction> disassemble(ByteView bytes, std::uint64_t address) {
        std::vector<Instruction> instructions;
        if (bytes.empty()) {
            return instructions;
        }

        cs_insn* insn = nullptr;
        const size_t count = cs_disasm(handle, bytes.data(), bytes.size(), address, 0, &insn);
        if (count == 0) {
            const cs_err err = cs_errno(handle);
            if (err != CS_ERR_OK) {
                throw std::runtime_error("Capstone disassembly failed");
            }
            return instructions;
        }

        instructions.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            Instruction inst;
            inst.address = insn[i].address;
            inst.size = insn[i].size;
            inst.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
            inst.mnemonic = insn[i].mnemonic;
            inst.op_str = insn[i].op_str;
            instructions.push_back(std::move(inst));
        }

        cs_free(insn, count);
        return instructions;
    }

    csh handle{0};
};

Disassembler::Disassembler(CpuArch arch, Bitness bitness)
    : impl_(std::make_unique<Impl>(select_cs_mode(arch, bitness))) {}

Disassembler::Disassembler(const BinaryImage& image)
    : Disassembler(image.arch, image.bitness) {}

Disassembler::~Disassembler() = default;
Disassembler::Disassembler(Disassembler&&) noexcept = default;
Disassembler& Disassembler::operator=(Disassembler&&) noexcept = default;

std::vector<Instruction> Disassembler::disassemble(ByteView bytes, std::uint64_t address) {
    return impl_->disassemble(bytes, address);
}

std::vector<Instruction> disassemble_text_section(const BinaryImage& image) {
    Disassembler disassembler(image);

    const Section* text_section = nullptr;
    for (const auto& section : image.sections) {
        if (section.name == ".text") {
            text_section = &section;
            break;
        }
    }

    if (!text_section) {
        throw std::runtime_error("No .text section found");
    }

    if (text_section->raw_size == 0) {
        return {};
    }

    const std::size_t text_size = static_cast<std::size_t>(text_section->raw_size);
    const auto bytes = view_rva(image, text_section->vaddr, text_size);
    if (!bytes) {
        throw std::runtime_error("Failed to map .text section bytes");
    }

    const std::uint64_t base_va = image.image_base + text_section->vaddr;
    return disassembler.disassemble(*bytes, base_va);
}

std::vector<Instruction> disassemble_executable_sections(const BinaryImage& image) {
    Disassembler disassembler(image);

    std::vector<Instruction> all;
    bool found_executable = false;

    for (const auto& section : image.sections) {
        if (!is_executable_section(section)) {
            continue;
        }
        found_executable = true;

        if (section.raw_size == 0) {
            continue;
        }

        const std::size_t size = static_cast<std::size_t>(section.raw_size);
        const auto bytes = view_rva(image, section.vaddr, size);
        if (!bytes) {
            throw std::runtime_error("Failed to map executable section bytes");
        }

        const std::uint64_t base_va = image.image_base + section.vaddr;
        auto instructions = disassembler.disassemble(*bytes, base_va);
        all.insert(all.end(),
                   std::make_move_iterator(instructions.begin()),
                   std::make_move_iterator(instructions.end()));
    }

    if (!found_executable) {
        throw std::runtime_error("No executable sections found");
    }

    return all;
}

} // namespace dlite
