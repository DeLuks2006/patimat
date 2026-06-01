#pragma once
#include "format.hpp"
#include <string_view>

// insert macho file definitions for both 32 and 64 bit
typedef int cpu_type_t;
typedef int cpu_subtype_t;
typedef int vm_prot_t;

#define MH_MAGIC_64 0xfeedfacf
#define MH_MAGIC 0xfeedface

#define LC_SEGMENT 0x1
#define LC_SEGMENT_64 0x19

struct mach_header {
    uint32_t      magic; // feedface
    cpu_type_t    cputype;
    cpu_subtype_t cpusubtype;
    uint32_t      filetype;
    uint32_t      ncmds;
    uint32_t      sizeofcmds;
    uint32_t      flags;
};

struct mach_header_64 {
    uint32_t      magic; // feedfacf
    cpu_type_t    cputype;
    cpu_subtype_t cpusubtype;
    uint32_t      filetype;
    uint32_t      ncmds;
    uint32_t      sizeofcmds;
    uint32_t      flags;
    uint32_t      reserved;
};

struct load_command {
    uint32_t cmd;     // For 32-bit segments, look for LC_SEGMENT (0x1) instead of LC_SEGMENT_64
    uint32_t cmdsize; 
};

struct segment_command {
    uint32_t   cmd;          // LC_SEGMENT
    uint32_t   cmdsize;      
    char       segname[16];  // Still looks for "__TEXT"
    uint32_t   vmaddr;       // 32-bit address space
    uint32_t   vmsize;       // 32-bit size allocation
    uint32_t   fileoff;      // 32-bit file offset
    uint32_t   filesize;     // 32-bit file size
    vm_prot_t  maxprot;      
    vm_prot_t  initprot;     
    uint32_t   nsect;        // Number of 32-bit sections following this block
    uint32_t   flags;        
};

struct segment_command_64 {
    uint32_t   cmd;          // LC_SEGMENT_64
    uint32_t   cmdsize;      // Total size of this command + its sections
    char       segname[16];  // Name of the segment (Look for "__TEXT")
    uint64_t   vmaddr;       // Virtual memory address where segment is mapped
    uint64_t   vmsize;       // Virtual memory size allocated
    uint64_t   fileoff;      // Offset of this segment within the raw file bytes
    uint64_t   filesize;     // Amount of bytes to read from file descriptor
    vm_prot_t  maxprot;      // Maximum memory protection (Read/Write/Execute)
    vm_prot_t  initprot;     // Initial memory protection
    uint32_t   nsect;        // NUMBER OF SECTIONS PACKED DIRECTLY BENEATH THIS
    uint32_t   flags;        // Segment flags
};

struct section {
    char     sectname[16];   // Still looks for "__text"
    char     segname[16];    
    uint32_t addr;           // 32-bit virtual address
    uint32_t size;           // 32-bit size
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
};

struct section_64 {
    char     sectname[16];   // Name of this section (Look for "__text")
    char     segname[16];    // Name of the parent segment ("__TEXT")
    uint64_t addr;           // Virtual memory address of the code at runtime
    uint64_t size;           // Size of the executable code region in bytes
    uint32_t offset;         // File offset pointing to where raw code bytes begin
    uint32_t align;          // Section alignment power of 2
    uint32_t reloff;         // File offset to relocation entries
    uint32_t nreloc;         // Number of relocation entries
    uint32_t flags;          // Section attributes (S_ATTR_PURE_INSTRUCTIONS)
    uint32_t reserved1;      // Reserved
    uint32_t reserved2;      // Reserved
    uint32_t reserved3;      // Reserved (only in 64-bit structures)
};

////////////////////////////////////////////////////////////

class Macho : public Format {
    private:
    bool is_64bit = false;
    std::span<uint8_t> _raw_content;
    const uint8_t* cmd_ptr;
    int num_load_cmd;
    int size_cmds;

    uint64_t offset;
    uint64_t size;

    template<size_t Bits>
    struct macho_traits;

    template<>
    struct macho_traits<32> {
        using segment_t = segment_command;
        using section_t = section;
        static constexpr uint32_t segment_cmd_id = LC_SEGMENT;
    };

    template<>
    struct macho_traits<64> {
        using segment_t = segment_command_64;
        using section_t = section_64;
        static constexpr uint32_t segment_cmd_id = LC_SEGMENT_64;
    };

    template <size_t Bits>
    bool find_section(std::string_view name) {
        using traits = macho_traits<Bits>;
        using SegmentType = typename traits::segment_t;
        using SectionType = typename traits::section_t;

        const uint8_t* l_cmd_ptr = cmd_ptr;
        for (uint32_t i = 0; i < num_load_cmd; ++i) {
            auto* load_cmd = reinterpret_cast<const load_command*>(l_cmd_ptr);
            if (load_cmd->cmd == traits::segment_cmd_id) {
                auto* segment = reinterpret_cast<const SegmentType*>(cmd_ptr);
                if (std::string_view(segment->segname) == "__TEXT") {
                    const uint8_t* sect_ptr = l_cmd_ptr + sizeof(SegmentType);
                    for (uint32_t j = 0; j < segment->nsect; ++j) {
                        auto* sct = reinterpret_cast<const SectionType*>(sect_ptr);
                        if (std::string_view(sct->sectname) == name) {
                            offset = sct->offset;
                            size = sct->size;
                            return true;
                        }
                        sect_ptr += sizeof(SectionType);
                    }
                }
            }
            l_cmd_ptr += load_cmd->cmdsize;
        }
        return false;
    }

    public:
    Macho(std::span<uint8_t> raw_content) {
        _raw_content = raw_content;
        mach_header* mhdr = reinterpret_cast<mach_header*>(_raw_content.data());
        uint32_t magic = mhdr->magic;
        size_t header_size = 0;
        
        if (magic == 0xfeedfacf) { // MH_MAGIC_64
            is_64bit = true;
            header_size = sizeof(mach_header_64);
        } 
        else if (magic == 0xfeedface) { // MH_MAGIC
            is_64bit = false;
            header_size = sizeof(mach_header);
        }
        
        num_load_cmd = mhdr->ncmds;
        size_cmds = mhdr->sizeofcmds;
        cmd_ptr = _raw_content.data() + header_size;
    }
    
    std::expected<std::span<uint8_t>, patimat::error> get_section(std::string_view name = "__text") override {
        if (name.empty())
            name = "__text";
        bool status = false;
        if (is_64bit) {
            status = find_section<64>(name);
        } else {
            status = find_section<32>(name);
        }
        if (!status)
            return std::unexpected(patimat::error::not_found);
        return _raw_content.subspan(offset, size);
    }
};