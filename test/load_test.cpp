#include <dlite/loader.hpp>
#include <dlite/pe_loader.hpp>

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#define endl '\n'

int main() {
    std::wstring wpath;
    std::vector<std::uint8_t> bytes = dlite::read_file(&wpath);
    dlite::BinaryImage image = dlite::load_pe(std::move(bytes));
    if (image.format == dlite::BinaryFormat::Pe) {
        std::cout << "format: PE" << endl;
    } else {
        std::cout << "format: other" << endl;
    }
    if (image.arch == dlite::CpuArch::X86_64) {
        std::cout << "arch: x86-64" << endl;
    } else {
        std::cout << "arch: other" << endl;
    }
    
    

}