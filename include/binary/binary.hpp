#pragma once
#include <vector>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <memory>   // Required for std::unique_ptr
#include <span>     // Required for std::span
#include <expected> // Required for std::expected

#include "elf.h"
#include "macho.h"
#include "pe.h"
#include "raw.h"
#include "format.hpp"

namespace patimat {
    
    class Binary {
    private:
        enum class FileFormat {
            ELF, MACHO, PE, RAW
        };
        FileFormat _file_format;
        std::vector<uint8_t> _raw_content;
        std::unique_ptr<Format> _format; // Polymorphic pointer fixes Object Slicing
        std::string _path;
        
    public:
        Binary(std::string path) : _path(path) { // Initialize path
            if (!std::filesystem::exists(_path) || !std::filesystem::is_regular_file(_path)) {
                std::cerr << "Error: File does not exist or is invalid: " << _path << std::endl;
                return;
            }
    
            auto len = std::filesystem::file_size(_path);
            if (len == 0) return;
    
            std::ifstream in_file(_path, std::ios::binary);
            if (!in_file.is_open()) {
                std::cerr << "Error: Failed to open file for reading: " << _path << std::endl;
                return;
            }
        
            _raw_content.resize(len);
            in_file.read(reinterpret_cast<char*>(_raw_content.data()), len);
            
            auto bytes_read = in_file.gcount();
            if (static_cast<size_t>(bytes_read) != len) {
                _raw_content.resize(bytes_read);
            }

            if (_raw_content.size() >= 4) {
                uint32_t magic32 = *reinterpret_cast<const uint32_t*>(_raw_content.data());
                uint16_t magic16 = *reinterpret_cast<const uint16_t*>(_raw_content.data());
            
                // Make sure Macho, Elf, Pe, and Raw constructors accept 'const std::vector<uint8_t>&' 
                // or 'std::span<const uint8_t>' to avoid lifetime/dangling pointer bugs.
                if (magic32 == 0xFEEDFACF || magic32 == 0xFEEDFACE) {
                    _file_format = FileFormat::MACHO;
                    _format = std::make_unique<Macho>(_raw_content);
                } 
                else if (magic32 == 0x464C457F) {
                    _file_format = FileFormat::ELF;
                    _format = std::make_unique<Elf>(_raw_content);
                } 
                else if (magic16 == 0x5A4D) {
                    _file_format = FileFormat::PE;
                    _format = std::make_unique<Pe>(_raw_content);
                } 
                else {
                    _file_format = FileFormat::RAW;
                    _format = std::make_unique<Raw>(_raw_content);
                }
            }
        }

        std::expected<std::span<uint8_t>, patimat::error> get_section(std::string_view section) {
            if (!_format) return std::unexpected(patimat::error::invalid_format); // safety check
            return _format->get_section(section);
        }

        std::expected<std::span<uint8_t>, patimat::error> get_section() {
            if (!_format) return std::unexpected(patimat::error::invalid_format);
            return _format->get_section();
        }

        bool write_changes(std::string path = "") {
            if (path.empty())
                path = _path + "_patched";
                
            if (std::filesystem::exists(path) && !std::filesystem::is_regular_file(path)) 
                return false;
                
            // Added std::ios::binary here to stop OS line-ending conversion bugs
            std::ofstream out_file(path, std::ios::out | std::ios::binary); 
            if (!out_file.is_open()) return false;
            
            out_file.write(reinterpret_cast<const char*>(_raw_content.data()), _raw_content.size());
            return true;
        }
    };
}