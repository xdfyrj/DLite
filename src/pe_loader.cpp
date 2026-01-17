#include <dlite/pe_loader.hpp>

#include <stdexcept>
#include <string>

namespace {

constexpr std::uint16_t kMzSignature = 0x5A4D;
constexpr std::uint32_t kPeSignature = 0x00004550;
constexpr std::uint16_t kPe32PlusMagic = 0x20B;
constexpr std::uint16_t kMachineAmd64 = 0x8664;

constexpr std::size_t kDosHeaderPeOffset = 0x3C;
constexpr std::size_t kFileHeaderSize = 20;
constexpr std::size_t kSectionHeaderSize = 40;
constexpr std::size_t kOptionalHeaderMinSize = 0x70;

void require_range(
    const std::vector<std::uint8_t>& data,
    std::size_t offset,
    std::size_t size,
    const char* msg) {
    if (offset > data.size() || size > data.size() - offset) {
        throw std::runtime_error(msg);
    }
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& data, std::size_t offset) {
    require_range(data, offset, 2, "Unexpected end of file");
    return static_cast<std::uint16_t>(data[offset]) |
        (static_cast<std::uint16_t>(data[offset + 1]) << 8);
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& data, std::size_t offset) {
    require_range(data, offset, 4, "Unexpected end of file");
    return static_cast<std::uint32_t>(data[offset]) |
        (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
        (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
        (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& data, std::size_t offset) {
    require_range(data, offset, 8, "Unexpected end of file");
    return static_cast<std::uint64_t>(data[offset]) |
        (static_cast<std::uint64_t>(data[offset + 1]) << 8) |
        (static_cast<std::uint64_t>(data[offset + 2]) << 16) |
        (static_cast<std::uint64_t>(data[offset + 3]) << 24) |
        (static_cast<std::uint64_t>(data[offset + 4]) << 32) |
        (static_cast<std::uint64_t>(data[offset + 5]) << 40) |
        (static_cast<std::uint64_t>(data[offset + 6]) << 48) |
        (static_cast<std::uint64_t>(data[offset + 7]) << 56);
}

std::string read_section_name(const std::vector<std::uint8_t>& data, std::size_t offset) {
    require_range(data, offset, 8, "Invalid section name range");
    std::string name;
    name.reserve(8);
    for (std::size_t i = 0; i < 8; ++i) {
        const char c = static_cast<char>(data[offset + i]);
        if (c == '\0') {
            break;
        }
        name.push_back(c);
    }
    return name;
}

} // namespace

namespace dlite {

BinaryImage load_pe(std::vector<std::uint8_t> data) {
    if (data.size() < kDosHeaderPeOffset + 4) {
        throw std::runtime_error("File too small for DOS header");
    }

    if (read_u16(data, 0) != kMzSignature) {  // MZ signature check
        throw std::runtime_error("Missing MZ signature");
    }

    const std::uint32_t pe_offset = read_u32(data, kDosHeaderPeOffset);
    require_range(data, pe_offset, 4 + kFileHeaderSize, "Invalid PE header offset");

    if (read_u32(data, pe_offset) != kPeSignature) {
        throw std::runtime_error("Missing PE signature");
    }

    const std::size_t file_header_offset = pe_offset + 4;
    const std::uint16_t machine = read_u16(data, file_header_offset);
    if (machine != kMachineAmd64) {
        throw std::runtime_error("Unsupported machine type (expected x86-64)");
    }

    const std::uint16_t number_of_sections = read_u16(data, file_header_offset + 2);
    const std::uint16_t size_of_optional_header = read_u16(data, file_header_offset + 16);

    const std::size_t optional_offset = file_header_offset + kFileHeaderSize;
    require_range(data, optional_offset, size_of_optional_header, "Invalid optional header size");
    if (size_of_optional_header < kOptionalHeaderMinSize) {
        throw std::runtime_error("Optional header too small for PE32+");
    }

    if (read_u16(data, optional_offset) != kPe32PlusMagic) {
        throw std::runtime_error("Not a PE32+ (x64) binary");
    }

    const std::uint32_t entry_point_rva = read_u32(data, optional_offset + 0x10);
    const std::uint64_t image_base = read_u64(data, optional_offset + 0x18);

    const std::size_t section_table_offset = optional_offset + size_of_optional_header;
    if (number_of_sections > 0) {
        const std::size_t max_sections =
            (data.size() - section_table_offset) / kSectionHeaderSize;
        if (number_of_sections > max_sections) {
            throw std::runtime_error("Invalid section table size");
        }
    }

    BinaryImage image;
    image.format = BinaryFormat::Pe;  // Format
    image.arch = CpuArch::X86_64;  // Arch
    image.image_base = image_base;
    image.entry_point_rva = entry_point_rva;
    image.data = std::move(data);
    image.sections.reserve(number_of_sections);

    for (std::uint16_t i = 0; i < number_of_sections; ++i) {
        const std::size_t section_offset =
            section_table_offset + static_cast<std::size_t>(i) * kSectionHeaderSize;

        Section section;
        section.name = read_section_name(image.data, section_offset);
        section.vsize = read_u32(image.data, section_offset + 8);
        section.vaddr = read_u32(image.data, section_offset + 12);
        section.raw_size = read_u32(image.data, section_offset + 16);
        section.raw_offset = read_u32(image.data, section_offset + 20);
        section.characteristics = read_u32(image.data, section_offset + 36);

        if (section.raw_size > 0) {
            if (section.raw_offset > image.data.size() ||
                section.raw_size > image.data.size() - section.raw_offset) {
                throw std::runtime_error("Section raw data exceeds file size");
            }
        }

        image.sections.push_back(section);
    }

    return image;
}

BinaryImage load_pe_from_path(const std::string& path) {
    return load_pe(read_file_bytes(path));
}

#ifdef _WIN32
BinaryImage load_pe_from_path(const std::wstring& path) {
    return load_pe(read_file_bytes(path));
}
#endif

} // namespace dlite
