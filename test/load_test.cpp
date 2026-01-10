#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

#include <dlite/loader.hpp>

int main() {
    std::wstring path;
    std::vector<std::uint8_t> bytes;

    try {
        bytes = dlite::read_file(&path);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }

    if (bytes.empty()) {
        std::wcout << L"Canceled, or empty.\n";
        return 0;
    }

    std::wcout << L"path: " << path << L"\n";
    std::cout << "bytes size: " << bytes.size() << "\n";

    // 확인용: 앞 16바이트만 hex로 출력
    const std::size_t n = (bytes.size() < 16) ? bytes.size() : 16;
    std::cout << "head: ";
    for (std::size_t i = 0; i < n; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(bytes[i]) << " ";
    }
    std::cout << std::dec << "\n";

    return 0;
}
