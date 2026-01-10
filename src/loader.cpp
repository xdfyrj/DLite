#include <dlite/loader.hpp>

#include <stdexcept>
#include <string>
#include <vector>
#include <limits>

#ifdef _WIN32
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <windows.h>
  #include <commdlg.h>
#endif

namespace dlite {

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