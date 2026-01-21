#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dlite {

enum class BinaryFormat { Unk, Pe, Elf };
enum class CpuArch { Unk, X86, X86_64 };
enum class Bitness { Unk, Bit64, Bit32 };

struct Section {
    std::string name;
    std::uint32_t vaddr{0};
    std::uint32_t vsize{0};
    std::uint32_t raw_offset{0};
    std::uint32_t raw_size{0};
    std::uint32_t characteristics{0};
};

struct BinaryImage {
    BinaryFormat format{BinaryFormat::Unk};
    CpuArch arch{CpuArch::Unk};
    Bitness bitness{Bitness::Unk};
    std::uint64_t image_base{0};
    std::uint64_t entry_point_rva{0};
    std::vector<Section> sections;
    std::vector<std::uint8_t> data;
};

struct ByteView {
    const std::uint8_t* data{nullptr};
    std::size_t size{0};
};

const Section* find_section_by_rva(const BinaryImage& image, std::uint64_t rva);
std::optional<std::uint64_t> rva_to_file_offset(const BinaryImage& image, std::uint64_t rva);
std::optional<ByteView> view_rva(const BinaryImage& image, std::uint64_t rva, std::size_t size);

std::vector<std::uint8_t> read_file_bytes(const std::string& path);
#ifdef _WIN32
std::vector<std::uint8_t> read_file_bytes(const std::wstring& path);
#endif

// Select a file, read all the byte data, and return it (Windows-only).
std::vector<std::uint8_t> read_file(std::wstring* outPath = nullptr);

BinaryFormat detect_format(const std::vector<std::uint8_t>& data);

BinaryImage load_file(std::vector<std::uint8_t> data);
BinaryImage load_file_from_path(const std::string& path);
#ifdef _WIN32
BinaryImage load_file_from_path(const std::wstring& path);
#endif

} // namespace dlite
