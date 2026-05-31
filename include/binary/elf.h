#pragma once
#include "format.hpp"
#include <string_view>

struct Elf64_Ehdr {
    unsigned char e_ident[16];
    uint16_t      e_type;
    uint16_t      e_machine;
    uint32_t      e_version;
    uint64_t      e_entry;
    uint64_t      e_phoff;
    uint64_t      e_shoff;
    uint32_t      e_flags;
    uint16_t      e_ehsize;
    uint16_t      e_phentsize;
    uint16_t      e_phnum;
    uint16_t      e_shentsize;
    uint16_t      e_shnum;
    uint16_t      e_shstrndx;
};

struct Elf32_Ehdr {
    unsigned char e_ident[16]; 
    uint16_t      e_type;      
    uint16_t      e_machine;   
    uint32_t      e_version;   
    uint32_t      e_entry;
    uint32_t      e_phoff;
    uint32_t      e_shoff;
    uint32_t      e_flags;     
    uint16_t      e_ehsize;    
    uint16_t      e_phentsize; 
    uint16_t      e_phnum;     
    uint16_t      e_shentsize; 
    uint16_t      e_shnum;     
    uint16_t      e_shstrndx;  
};

struct Elf64_Shdr {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint64_t   sh_flags;
    uint64_t   sh_addr;
    uint64_t   sh_offset;
    uint64_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint64_t   sh_addralign;
    uint64_t   sh_entsize;
};

struct Elf32_Shdr {
    uint32_t   sh_name;      
    uint32_t   sh_type;      
    uint32_t   sh_flags;
    uint32_t   sh_addr;
    uint32_t   sh_offset;
    uint32_t   sh_size;
    uint32_t   sh_link;      
    uint32_t   sh_info;      
    uint32_t   sh_addralign;
    uint32_t   sh_entsize;
};

class Elf : public Format {
    private:
        bool is_64bit = false;
        std::span<uint8_t> _raw_content;

        int sect_cnt = 0;
        int sect_sz = 0;
        int sect_offset = 0;
        int strtab_offset = 0;
        
        uint64_t offset;
        uint64_t size;

        template <typename ShdrType>
        bool find_section(std::string_view name) {
            const auto* sh_table = reinterpret_cast<const ShdrType*>(_raw_content.data() + sect_offset);
            const auto& str_table_hdr = sh_table[strtab_offset];
            const char* str_table = reinterpret_cast<const char*>(_raw_content.data() + str_table_hdr.sh_offset);
            for (uint16_t i = 0; i < sect_cnt; ++i) {
                const auto& shdr = sh_table[i];
                const char* sect_name = reinterpret_cast<const char*>(str_table + shdr.sh_name);
                if (sect_name && std::string_view(sect_name) == name) {
                    offset = shdr.sh_offset;
                    size = shdr.sh_size;
                    return true;
                }
            }
            return false;
        }
        
    public:
    Elf(std::span<uint8_t> raw_content) {
        _raw_content = raw_content;
        // check if 32 bit
        auto* elf = reinterpret_cast<Elf64_Ehdr*>(_raw_content.data());
        is_64bit = elf->e_ident[4] == 2;
        if (is_64bit) {
            sect_cnt = elf->e_shnum;
            sect_offset = elf->e_shoff;
            sect_sz = elf->e_shentsize;
            strtab_offset = elf->e_shstrndx;
        }
        else {
            auto* elf32 = reinterpret_cast<Elf32_Ehdr*>(_raw_content.data());
            sect_cnt = elf32->e_shnum;
            sect_offset = elf32->e_shoff;
            sect_sz = elf32->e_shentsize;
            strtab_offset = elf32->e_shstrndx;
        }
    }

    std::expected<std::span<uint8_t>, patimat::error> get_section(std::string_view name = ".text") override {
        if (name.empty())
            name = ".text";
        bool status = false;
        if (is_64bit) {
            status = find_section<Elf64_Shdr>(name);
        } else {
            status = find_section<Elf32_Shdr>(name);
        }
        if (!status)
            return std::unexpected(patimat::error::not_found);
        return _raw_content.subspan(offset, size);
    }
};