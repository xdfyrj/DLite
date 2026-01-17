#include <dlite/loader.hpp>
#include <dlite/pe_loader.hpp>

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

int main() {
    std::wstring wpath;
    dlite::BinaryImage image;
    std::vector<std::uint8_t> bytes = dlite::read_file(&wpath);
    if (dlite::detect_format(bytes) == dlite::BinaryFormat::Pe) {
        image = dlite::load_pe(std::move(bytes));
    }
    if (image.format == dlite::BinaryFormat::Pe) {
        std::cout << "format: PE\n";
    } else {
        std::cout << "format: other\n";
    }
    if (image.arch == dlite::CpuArch::X86_64) {
        std::cout << "arch: x86-64\n";
    } else {
        std::cout << "arch: other\n";
    }
    if (image.bitness == dlite::Bitness::Bit64) {
        std::cout << "bitness: 64bit\n";
    } else if (image.bitness == dlite::Bitness::Bit32) {
        std::cout << "bitness: 32bit\n";
    } else {
        std::cout << "bitness: other\n";
    }
    std::cout << "image base: 0x" << std::hex << image.image_base << '\n';
    std::cout << "entry point rva: 0x" << image.entry_point_rva << std::dec << '\n';
    
    

}