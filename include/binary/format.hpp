#pragma once
#include <expected>
#include <span>
#include <cstdint>
#include <string_view>
#include "../patimat.hpp"

class Format {
public:
    virtual std::expected<std::span<uint8_t>, patimat::error> get_section(std::string_view name = "") = 0;
    virtual ~Format() = default;
};