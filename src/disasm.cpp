#include <dlite/disasm.hpp>

#include <capstone/capstone.h>

#include <stdexcept>
#include <string>
#include <utility>

namespace {

void ensure_x86_64(const dlite::BinaryImage& image) {
    if (image.arch != dlite::CpuArch::X86_64) {
        throw std::runtime_error("Unsupported CPU architecture for disassembly");
    }
}

std::vector<dlite::Instruction> disassemble_bytes(
    const dlite::ByteView& bytes,
    std::uint64_t address) {
    std::vector<dlite::Instruction> instructions;
    if (!bytes.data || bytes.size == 0) {
        return instructions;
    }

    csh handle = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone");
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn* insn = nullptr;
    const size_t count = cs_disasm(
        handle,
        bytes.data,
        bytes.size,
        address,
        0,
        &insn);
    if (count == 0) {
        const cs_err err = cs_errno(handle);
        cs_close(&handle);
        if (err != CS_ERR_OK) {
            throw std::runtime_error("Capstone disassembly failed");
        }
        return instructions;
    }

    instructions.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        dlite::Instruction inst;
        inst.address = insn[i].address;
        inst.size = insn[i].size;
        inst.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
        inst.mnemonic = insn[i].mnemonic;
        inst.op_str = insn[i].op_str;
        instructions.push_back(std::move(inst));
    }

    cs_free(insn, count);
    cs_close(&handle);

    return instructions;
}

} // namespace

namespace dlite {

std::vector<Instruction> disassemble_text_section(const BinaryImage& image) {
    ensure_x86_64(image);

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
    return disassemble_bytes(*bytes, base_va);
}

} // namespace dlite
