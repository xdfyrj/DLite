#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dlite {

// Select a file, read all the byte data, and return it.
std::vector<std::uint8_t> read_file(std::wstring* outPath = nullptr);

} // namespace dlite