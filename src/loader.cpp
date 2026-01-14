#include <dlite/loader.hpp>

#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <windows.h>
  #include <commdlg.h>
#endif

namespace dlite {

const Section* find_section_by_rva(const BinaryImage& image, std::uint64_t rva) {
    for (const auto& section : image.sections) {
        const std::uint64_t span =
            (section.vsize > section.raw_size) ? section.vsize : section.raw_size;
        if (span == 0) {
            continue;
        }
        if (rva >= section.vaddr && rva < section.vaddr + span) {
            return &section;
        }
    }
    return nullptr;
}

std::optional<std::uint64_t> rva_to_file_offset(const BinaryImage& image, std::uint64_t rva) {
    const Section* section = find_section_by_rva(image, rva);
    if (!section) {
        return std::nullopt;
    }

    const std::uint64_t delta = rva - section->vaddr;
    if (delta >= section->raw_size) {
        return std::nullopt;
    }

    const std::uint64_t offset = section->raw_offset + delta;
    if (offset >= image.data.size()) {
        return std::nullopt;
    }

    return offset;
}

std::optional<ByteView> view_rva(
    const BinaryImage& image,
    std::uint64_t rva,
    std::size_t size) {
    const Section* section = find_section_by_rva(image, rva);
    if (!section) {
        return std::nullopt;
    }

    const std::uint64_t delta = rva - section->vaddr;
    if (delta >= section->raw_size) {
        return std::nullopt;
    }

    const std::uint64_t available = section->raw_size - delta;
    const std::uint64_t request = static_cast<std::uint64_t>(size);
    if (request > available) {
        return std::nullopt;
    }

    const std::uint64_t offset = section->raw_offset + delta;
    if (offset + request > image.data.size()) {
        return std::nullopt;
    }

    return ByteView{image.data.data() + offset, size};
}

std::vector<std::uint8_t> read_file_bytes(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + path);
    }

    const std::streamsize size = file.tellg();
    if (size < 0) {
        throw std::runtime_error("Invalid file size");
    }
    if (static_cast<unsigned long long>(size) >
        static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
        throw std::runtime_error("File too large for memory buffer");
    }

    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        throw std::runtime_error("Failed to read file data");
    }

    return data;
}

#ifdef _WIN32
static std::runtime_error WinErr(const char* msg) {
    const DWORD code = ::GetLastError();
    return std::runtime_error(std::string(msg) + " (GetLastError=" + std::to_string(code) + ")");
}

static std::vector<std::uint8_t> read_all_data(const std::wstring& path) {
    struct Handle {
        HANDLE h{INVALID_HANDLE_VALUE};
        ~Handle() { if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h); }
    } file;

    file.h = ::CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file.h == INVALID_HANDLE_VALUE) {
        throw WinErr("CreateFileW failed");
    }

    LARGE_INTEGER sz{};
    if (!::GetFileSizeEx(file.h, &sz)) {
        throw WinErr("GetFileSizeEx failed");
    }
    if (sz.QuadPart < 0) {
        throw std::runtime_error("Invalid file size");
    }
    if (static_cast<unsigned long long>(sz.QuadPart) >
        static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
        throw std::runtime_error("File too large for memory buffer");
    }

    const std::size_t size = static_cast<std::size_t>(sz.QuadPart);
    std::vector<std::uint8_t> data(size);

    std::size_t off = 0;
    while (off < size) {
        const std::size_t remain = size - off;
        const DWORD chunk = (remain > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
            ? std::numeric_limits<DWORD>::max()
            : static_cast<DWORD>(remain);

        DWORD readBytes = 0;
        if (!::ReadFile(file.h, data.data() + off, chunk, &readBytes, nullptr)) {
            throw WinErr("ReadFile failed");
        }
        if (readBytes == 0) {
            throw std::runtime_error("ReadFile returned 0 bytes unexpectedly");
        }
        off += static_cast<std::size_t>(readBytes);
    }

    return data;
}

std::vector<std::uint8_t> read_file_bytes(const std::wstring& path) {
    return read_all_data(path);
}
#endif

std::vector<std::uint8_t> read_file(std::wstring* outPath) {
#ifdef _WIN32
    wchar_t filePath[MAX_PATH] = L"";

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"All Files (*.*)\0*.*\0\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (!::GetOpenFileNameW(&ofn)) {
        if (outPath) *outPath = L"";
        return {}; // canceled (or dialog error, treated as empty)
    }

    if (outPath) *outPath = filePath;
    return read_all_data(filePath);
#else
    (void)outPath;
    throw std::runtime_error("read_file is Windows-only");
#endif
}

} // namespace dlite
