#pragma once
#include "format.hpp"
#include <string_view>

class Raw : public Format {
    private:
    std::span<uint8_t> _raw_content;
    public:
    Raw(std::span<uint8_t> raw_content) : _raw_content(raw_content) {}

    std::expected<std::span<uint8_t>, patimat::error> get_section(std::string_view name = "") override {
        (void)name;
        return _raw_content;
    }
};