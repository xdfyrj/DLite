#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <dlite/loader.hpp>

namespace dlite {

BinaryImage load_pe(std::vector<std::uint8_t> data);
BinaryImage load_pe_from_path(const std::string& path);
#ifdef _WIN32
BinaryImage load_pe_from_path(const std::wstring& path);
#endif

} // namespace dlite
