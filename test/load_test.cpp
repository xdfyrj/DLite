#include <dlite/loader.hpp>
#include <dlite/pe_loader.hpp>

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
    case dlite::CpuArch::X86_64:
        return "x86-64";
    default:
        return "Unknown";
    }
}

void print_hex(dlite::ByteView bytes) {
    for (std::size_t i = 0; i < bytes.size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(bytes.data[i]) << " ";
    }
    std::cout << std::dec;
}

} // namespace

int main(int argc, char** argv) {
    std::string path;
    dlite::BinaryImage image;
#ifdef _WIN32
    std::wstring wpath;
    bool has_wpath = false;
#endif

    try {
#ifdef _WIN32
        if (argc < 2) {
            std::vector<std::uint8_t> bytes = dlite::read_file(&wpath);
            if (bytes.empty()) {
                std::cout << "Canceled or empty file.\n";
                return 0;
            }
            image = dlite::load_pe(std::move(bytes));
            has_wpath = true;
        } else {
            path = argv[1];
            image = dlite::load_pe_from_path(path);
        }
#else
        if (argc < 2) {
            std::cerr << "usage: load_test <path-to-pe>\n";
            return 2;
        }
        path = argv[1];
        image = dlite::load_pe_from_path(path);
#endif
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }

#ifdef _WIN32
    if (!has_wpath) {
        std::cout << "path: " << path << "\n";
    } else {
        std::wcout << L"path: " << wpath << L"\n";
    }
#else
    std::cout << "path: " << path << "\n";
#endif
    std::cout << "format: " << format_to_string(image.format) << "\n";
    std::cout << "arch: " << arch_to_string(image.arch) << "\n";
    std::cout << "image_base: 0x" << std::hex << image.image_base << std::dec << "\n";
    std::cout << "entry_point_rva: 0x" << std::hex << image.entry_point_rva << std::dec << "\n";
    std::cout << "entry_point_va: 0x"
              << std::hex << (image.image_base + image.entry_point_rva) << std::dec << "\n";
    std::cout << "sections: " << image.sections.size() << "\n";

    for (const auto& section : image.sections) {
        std::cout << "  [" << section.name << "] "
                  << "rva=0x" << std::hex << section.vaddr
                  << " vsize=0x" << section.vsize
                  << " raw=0x" << section.raw_offset
                  << " raw_size=0x" << section.raw_size
                  << std::dec << "\n";
    }

    const auto entry_bytes = dlite::view_rva(image, image.entry_point_rva, 16);
    if (entry_bytes) {
        std::cout << "entry point bytes: ";
        print_hex(*entry_bytes);
        std::cout << "\n";
    } else {
        std::cout << "entry point bytes: unavailable\n";
    }

    const dlite::Section* text_section = nullptr;
    for (const auto& section : image.sections) {
        if (section.name == ".text") {
            text_section = &section;
            break;
        }
    }

    if (text_section) {
        const auto text_bytes = dlite::view_rva(image, text_section->vaddr, 16);
        if (text_bytes) {
            std::cout << ".text head: ";
            print_hex(*text_bytes);
            std::cout << "\n";
        } else {
            std::cout << ".text head: unavailable\n";
        }
    }

    return 0;
}
