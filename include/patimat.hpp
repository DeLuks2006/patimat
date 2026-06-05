#pragma once
#include <vector>
#include <ranges>
#include <charconv>
#include <string_view>
#include <expected>

namespace patimat {
    namespace stv = std::views;
    namespace str = std::ranges;
    using namespace std::string_literals;

    enum class error {
        ok,
        not_found,
        invalid_signature,
        no_memory,
        no_matches,
        missing_patch,
        invalid_format
    };

    struct ByteMatcher {
        enum class MatType { Exact, Wildcard, HighNibble, LowNibble, Range };

        MatType type;
        uint8_t val1 = 0; // for exact value, high/low nibbles or min range
        uint8_t val2 = 0; // for max range

        bool matches(uint8_t byte) const {
            switch (type) {
                case MatType::Wildcard:
                    return true;
                case MatType::Exact:
                    return byte == val1;
                case MatType::HighNibble:
                    return (byte & 0xf0) == (val1 & 0xf0);
                case MatType::LowNibble:
                    return (byte & 0x0f) == (val1 & 0x0f);
                case MatType::Range:
                    return byte >= val1 && byte <= val2;
            }
            return false;
        }
    };

    struct BytePatcher {
        enum class PatType { Exact, Skip, Index };
        PatType type;
        uint8_t val = 0;
        uint16_t idx = 0;
    };

    class pattern_matcher {
    protected:
        std::span<uint8_t> _memory;
        std::vector<ByteMatcher> _match_sig;
        std::vector<BytePatcher> _patch_sig;

        static uint8_t hex_char_to_val(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        }

        static uint8_t hex_str_to_val(std::string_view sv) {
            uint8_t val = 0;
            std::from_chars(sv.data(), sv.data() + sv.size(), val, 16);
            return val;
        }

        ByteMatcher parse_mat_token(std::string_view token) {
            if (token == "??" || token == "?") {
                return { ByteMatcher::MatType::Wildcard };
            }

            if (token.starts_with('(') && token.ends_with(')')) {
                auto inner = token.substr(1, token.size() - 2);
                auto dash = inner.find('-');
                auto min_str = inner.substr(0, dash);
                auto max_str = inner.substr(dash + 1);
                return {
                    ByteMatcher::MatType::Range,
                    hex_str_to_val(min_str),
                    hex_str_to_val(max_str)
                };
            }
            if (token.size() == 2) {
                if (token[1] == '?') {
                    uint8_t high = hex_char_to_val(token[0]) << 4;
                    return { ByteMatcher::MatType::HighNibble, high };
                }
                if (token[0] == '?') {
                    uint8_t low = hex_char_to_val(token[1]);
                    return { ByteMatcher::MatType::LowNibble, low };
                }
            }

            return { ByteMatcher::MatType::Exact, hex_str_to_val(token) };
        }

        BytePatcher parse_pat_token(std::string_view token) {
            if (token == "??" || token == "?") {
                return { BytePatcher::PatType::Skip };
            }
            if (token.starts_with('[') && token.ends_with(']')) {
                return { BytePatcher::PatType::Index, 0, hex_str_to_val(token.substr(1, token.size() - 2)) };
            }
            return { BytePatcher::PatType::Exact, hex_str_to_val(token) };
        }
    public:
        pattern_matcher(std::string_view mat_pattern, std::string_view pat_pattern, std::span<uint8_t> memory) {
            _memory = memory;
            this->set_pattern(mat_pattern);
            this->set_patch(pat_pattern);
        }

        pattern_matcher(std::string_view mat_pattern, std::span<uint8_t> memory) {
            _memory = memory;
            this->set_pattern(mat_pattern);
        }

        pattern_matcher(std::span<uint8_t> memory) {
            _memory = memory;
        }

        // Copy Semantics
        pattern_matcher(const pattern_matcher& other) 
        : _memory(other._memory),
          _match_sig(other._match_sig),
          _patch_sig(other._patch_sig)
        {}

        pattern_matcher& operator=(const pattern_matcher& other) {
            if (this != &other) {
                _memory = other._memory;
                _match_sig = other._match_sig;
                _patch_sig = other._patch_sig;
            }
            return *this;
        }

        // Move Semantics
        pattern_matcher(pattern_matcher&& other) noexcept 
        : _memory(other._memory),
          _match_sig(std::move(other._match_sig)),
          _patch_sig(std::move(other._patch_sig))
        {
            other._memory = std::span<uint8_t>();
        }

        pattern_matcher& operator=(pattern_matcher&& other) noexcept {
            if (this != &other) {
                _memory = other._memory;
                _match_sig = std::move(other._match_sig);
                _patch_sig = std::move(other._patch_sig);
                other._memory = std::span<uint8_t>();
            }
            return *this;
        }

        void set_pattern(std::string_view pattern) {
            auto match_view = pattern
                | stv::split(' ')
                | stv::transform([this](auto&& token){
                    return this->parse_mat_token(std::string_view(token));
                });
            _match_sig = str::to<std::vector<ByteMatcher>>(match_view);
        }

        void set_patch(std::string_view pattern) {
            auto patch_view = pattern
                | stv::split(' ')
                | stv::transform([this](auto&& token){
                    return this->parse_pat_token(std::string_view(token));
                });
            _patch_sig = str::to<std::vector<BytePatcher>>(patch_view);
        }

        void set_memory(std::span<uint8_t> memory) {
            _memory = memory;
        }

        std::expected<uint8_t*, error> find_pattern() {
            if (_match_sig.empty())
                return std::unexpected(error::invalid_signature);
            if (_memory.size() < _match_sig.size() || _memory.empty())
                return std::unexpected(error::no_memory);

            for (size_t i = 0; i <= _memory.size() - _match_sig.size(); ++i) {
                bool match_found = true;
                for (size_t j = 0; j < _match_sig.size(); ++j) {
                    if (!_match_sig[j].matches(_memory[i + j])) {
                        match_found = false;
                        break;
                    }
                }

                if (match_found) {
                    return &_memory[i];
                }
            }

            return std::unexpected(error::not_found);
        }

        std::expected<std::vector<uint8_t*>, error> find_patterns() {
            std::vector<uint8_t*> matches;

            if (_match_sig.empty())
                return std::unexpected(error::invalid_signature);
            if (_memory.size() < _match_sig.size() || _memory.empty())
                return std::unexpected(error::no_memory);

            size_t scan_end = _memory.size() - _match_sig.size();
            for (size_t i = 0; i <= scan_end; ++i) {
                bool match_found = true;
                for (size_t j = 0; j < _match_sig.size(); j++) {
                    if (!_match_sig[j].matches(_memory[i + j])) {
                        match_found = false;
                        break;
                    }
                }

                if (match_found) {
                    matches.push_back(&_memory[i]);
                }
            }

            if (matches.empty()) {
                return std::unexpected(error::not_found);
            }

            return matches;
        }

        error patch(uint8_t* match, bool padding = false) {
            if (_patch_sig.empty()) {
                return error::missing_patch;
            }
            if (_match_sig.empty()) {
                return error::no_matches;
            }
            auto copy = std::vector<uint8_t>(_patch_sig.size());
            std::memcpy(copy.data(), match, _patch_sig.size());

            for (int i = 0; i < _match_sig.size(); ++i) {
                if (i < _patch_sig.size()) {
                    auto current = _patch_sig[i];
                    if (current.type == BytePatcher::PatType::Exact) {
                        match[i] = _patch_sig[i].val;
                    }
                    if (current.type == BytePatcher::PatType::Skip) {
                        continue;
                    }
                    if (current.type == BytePatcher::PatType::Index) {
                        if (current.idx > _match_sig.size() - 1)
                            return error::invalid_signature;
                        match[i] = copy[current.idx];
                    }
                }
                else if (padding) {
                    match[i] = 0x90;
                }
            }

            return error::ok;
        }

        void patch_all(const std::vector<uint8_t*>& matches, bool padding = false) {
            for (auto& match : matches) {
                patch(match, padding);
            }
        }
    };
}
