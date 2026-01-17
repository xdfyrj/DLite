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

namespace {

constexpr std::uint16_t kMzSignature = 0x5A4D;
constexpr std::uint32_t kPeSignature = 0x00004550;
constexpr std::uint16_t kPe32Magic = 0x10B;
constexpr std::uint16_t kPe32PlusMagic = 0x20B;
constexpr std::size_t kDosHeaderPeOffset = 0x3C;
constexpr std::size_t kFileHeaderSize = 20;

constexpr std::uint8_t kElfMagic0 = 0x7F;
constexpr std::uint8_t kElfMagic1 = 0x45;
constexpr std::uint8_t kElfMagic2 = 0x4C;
constexpr std::uint8_t kElfMagic3 = 0x46;
constexpr std::size_t kElfIdentSize = 16;

bool has_range(const std::vector<std::uint8_t>& data, std::size_t offset, std::size_t size) {
    return offset <= data.size() && size <= data.size() - offset;
}

std::uint16_t read_u16_le(const std::vector<std::uint8_t>& data, std::size_t offset) {
    return static_cast<std::uint16_t>(data[offset]) |
        (static_cast<std::uint16_t>(data[offset + 1]) << 8);
}

std::uint32_t read_u32_le(const std::vector<std::uint8_t>& data, std::size_t offset) {
    return static_cast<std::uint32_t>(data[offset]) |
        (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
        (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
        (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

bool is_pe_format(const std::vector<std::uint8_t>& data) {
    if (!has_range(data, 0, 2) || read_u16_le(data, 0) != kMzSignature) {
        return false;
    }
    if (!has_range(data, kDosHeaderPeOffset, 4)) {
        return false;
    }

    const std::uint32_t pe_offset = read_u32_le(data, kDosHeaderPeOffset);
    if (!has_range(data, pe_offset, 4 + kFileHeaderSize)) {
        return false;
    }
    if (read_u32_le(data, pe_offset) != kPeSignature) {
        return false;
    }

    const std::size_t file_header_offset = pe_offset + 4;
    const std::uint16_t optional_header_size =
        read_u16_le(data, file_header_offset + 16);
    const std::size_t optional_offset = file_header_offset + kFileHeaderSize;
    if (!has_range(data, optional_offset, optional_header_size) || optional_header_size < 2) {
        return false;
    }

    const std::uint16_t magic = read_u16_le(data, optional_offset);
    return magic == kPe32Magic || magic == kPe32PlusMagic;
}

bool is_elf_format(const std::vector<std::uint8_t>& data) {
    if (!has_range(data, 0, kElfIdentSize)) {
        return false;
    }
    if (data[0] != kElfMagic0 || data[1] != kElfMagic1 ||
        data[2] != kElfMagic2 || data[3] != kElfMagic3) {
        return false;
    }

    const std::uint8_t elf_class = data[4];
    const std::uint8_t elf_data = data[5];
    const std::uint8_t elf_version = data[6];
    if ((elf_class != 1 && elf_class != 2) ||
        (elf_data != 1 && elf_data != 2) ||
        elf_version != 1) {
        return false;
    }

    return true;
}

} // namespace

BinaryFormat detect_format(const std::vector<std::uint8_t>& data) {
    if (is_elf_format(data)) {
        return BinaryFormat::Elf;
    }
    if (is_pe_format(data)) {
        return BinaryFormat::Pe;
    }
    return BinaryFormat::Unk;
}

} // namespace dlite
