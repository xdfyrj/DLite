#include <dlite/disasm.hpp>
#include <dlite/loader.hpp>
#include <dlite/pe_loader.hpp>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {

const char* format_to_string(dlite::BinaryFormat format) {
    switch (format) {
    case dlite::BinaryFormat::Pe:
        return "PE";
    case dlite::BinaryFormat::Elf:
        return "ELF";
    default:
        return "Unknown";
    }
}

const char* arch_to_string(dlite::CpuArch arch) {
    switch (arch) {
    case dlite::CpuArch::X86:
        return "x86";
    case dlite::CpuArch::X86_64:
        return "x86-64";
    default:
        return "Unknown";
    }
}

const char* bitness_to_string(dlite::Bitness bitness) {
    switch (bitness) {
    case dlite::Bitness::Bit32:
        return "32bit";
    case dlite::Bitness::Bit64:
        return "64bit";
    default:
        return "Unknown";
    }
}

void print_hex(dlite::ByteView bytes) {
    for (std::uint8_t byte : bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec;
}

} // namespace

int main(int argc, char** argv) {
    std::string path;
    std::vector<std::uint8_t> bytes;
#ifdef _WIN32
    std::wstring wpath;
    bool used_dialog = false;
#endif

#ifdef _WIN32
    if (argc < 2) {
        bytes = dlite::read_file(&wpath);
        if (bytes.empty()) {
            std::cout << "Canceled or empty file.\n";
            return 0;
        }
        used_dialog = true;
    } else {
        path = argv[1];
        bytes = dlite::read_file_bytes(path);
    }
#else
    if (argc < 2) {
        std::cerr << "usage: dlite_test <path-to-pe>\n";
        return 2;
    }
    path = argv[1];
    bytes = dlite::read_file_bytes(path);
#endif

    const dlite::BinaryFormat format = dlite::detect_format(bytes);
    std::cout << "detect_format: " << format_to_string(format) << "\n";
    if (format != dlite::BinaryFormat::Pe) {
        std::cerr << "only PE is supported right now\n";
        return 1;
    }

    dlite::BinaryImage image = dlite::load_file(std::move(bytes));
    dlite::BinaryImage image_from_path;
    dlite::BinaryImage image_pe;
#ifdef _WIN32
    if (used_dialog) {
        image_from_path = dlite::load_file_from_path(wpath);
        image_pe = dlite::load_pe_from_path(wpath);
        std::wcout << L"path: " << wpath << L"\n";
    } else {
        image_from_path = dlite::load_file_from_path(path);
        image_pe = dlite::load_pe_from_path(path);
        std::cout << "path: " << path << "\n";
    }
#else
    image_from_path = dlite::load_file_from_path(path);
    image_pe = dlite::load_pe_from_path(path);
    std::cout << "path: " << path << "\n";
#endif

    std::cout << "format: " << format_to_string(image.format) << "\n";
    std::cout << "arch: " << arch_to_string(image.arch) << "\n";
    std::cout << "bitness: " << bitness_to_string(image.bitness) << "\n";
    std::cout << "image_base: 0x" << std::hex << image.image_base << std::dec << "\n";
    std::cout << "entry_point_rva: 0x" << std::hex << image.entry_point_rva << std::dec << "\n";

    const auto entry_section = dlite::find_section_by_rva(image, image.entry_point_rva);
    if (entry_section) {
        std::cout << "entry section: " << entry_section->name << "\n";
    } else {
        std::cout << "entry section: unknown\n";
    }

    const auto entry_offset = dlite::rva_to_file_offset(image, image.entry_point_rva);
    if (entry_offset) {
        std::cout << "entry file offset: 0x" << std::hex << *entry_offset << std::dec << "\n";
    } else {
        std::cout << "entry file offset: unknown\n";
    }

    std::cout << "sections: " << image.sections.size() << "\n";
    for (const auto& section : image.sections) {
        std::cout << "  [" << section.name << "] "
                  << "rva=0x" << std::hex << section.vaddr << " vsize=0x" << section.vsize
                  << " raw=0x" << section.raw_offset << " raw_size=0x" << section.raw_size
                  << std::dec << "\n";
    }

    if (const auto entry_bytes = dlite::view_rva(image, image.entry_point_rva, 16)) {
        std::cout << "entry bytes: ";
        print_hex(*entry_bytes);
        std::cout << "\n";
    }

    try {
        const auto instructions = dlite::disassemble_text_section(image);
        std::cout << "disasm .text count: " << instructions.size() << "\n";

        const std::size_t max_print = 32;
        for (std::size_t i = 0; i < instructions.size() && i < max_print; ++i) {
            const auto& insn = instructions[i];
            std::cout << "0x" << std::hex << insn.address << std::dec << ": ";
            print_hex(insn.bytes);
            std::cout << "  " << insn.mnemonic;
            if (!insn.op_str.empty()) {
                std::cout << " " << insn.op_str;
            }
            std::cout << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "disasm error: " << e.what() << "\n";
        return 1;
    }

    try {
        const auto exec_instructions = dlite::disassemble_executable_sections(image);
        std::cout << "disasm exec sections count: " << exec_instructions.size() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "exec disasm error: " << e.what() << "\n";
        return 1;
    }

    if (image_from_path.format != image.format) {
        std::cerr << "format mismatch between load_file and load_file_from_path\n";
    }
    if (image_pe.format != image.format) {
        std::cerr << "format mismatch between load_file and load_pe_from_path\n";
    }

    return 0;
}
