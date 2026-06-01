#pragma once
#include "format.hpp"
#include <stdint.h>
#include <string_view>

#define IMAGE_DOS_SIGNATURE 0x5A4D // "MZ"
#define IMAGE_FILE_MACHINE_AMD64 0x8664

typedef struct {
    uint16_t e_magic;    // Magic number ("MZ")
    uint16_t e_cblp;     // Bytes on last page of file
    uint16_t e_cp;       // Pages in file
    uint16_t e_crlc;     // Relocations
    uint16_t e_cparhdr;  // Size of header in paragraphs
    uint16_t e_minalloc; // Minimum extra paragraphs needed
    uint16_t e_maxalloc; // Maximum extra paragraphs needed
    uint16_t e_ss;       // Initial (relative) SS value
    uint16_t e_sp;       // Initial SP value
    uint16_t e_csum;     // Checksum
    uint16_t e_ip;       // Initial IP value
    uint16_t e_cs;       // Initial (relative) CS value
    uint16_t e_lfarlc;   // File address of relocation table
    uint16_t e_ovno;     // Overlay number
    uint16_t e_res[4];   // Reserved words
    uint16_t e_oemid;    // OEM identifier
    uint16_t e_oeminfo;  // OEM information; oemid specific
    uint16_t e_res2[10]; // Reserved words
    int32_t  e_lfanew;   // File address of new exe header (NT Header offset)
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections; // Total number of sections (e.g., .text, .data)
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader; // Size of the Optional Header struct
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

#define IMAGE_NT_SIGNATURE 0x00004550 // "PE\0\0"
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct {
    // Standard fields
    uint16_t Magic; // 0x10B for 32-bit (PE32)
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData; // Specific to 32-bit

    // NT additional fields
    uint32_t BaseOfImage; // 32-bit Image Base
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint32_t Signature; // "PE\0\0"
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct {
    // Standard fields
    uint16_t Magic; // 0x20B for 64-bit (PE32+)
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode; // No BaseOfData here!

    // NT additional fields
    uint64_t BaseOfImage; // 64-bit Image Base
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint32_t Signature; // "PE\0\0"
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    char    Name[8];
    union {
            uint32_t   PhysicalAddress;
            uint32_t   VirtualSize;
    } Misc;
    uint32_t   VirtualAddress;
    uint32_t   SizeOfRawData;
    uint32_t   PointerToRawData;
    uint32_t   PointerToRelocations;
    uint32_t   PointerToLinenumbers;
    uint16_t    NumberOfRelocations;
    uint16_t    NumberOfLinenumbers;
    uint32_t   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

class Pe : public Format {
private:
    bool is_64bit = false;
    std::span<uint8_t> _raw_content;

    IMAGE_SECTION_HEADER* section;
    int num_sections = 0;

    uint64_t offset;
    uint64_t size;

    bool find_section(std::string_view name) {
        for (int i = 0; i < num_sections; ++i) {
            if (std::string_view(section[i].Name) == name) {
                offset = section[i].PointerToRawData;
                size = section[i].SizeOfRawData;
                return true;
            }
        }
        return false;
    }
    
public:
    Pe(std::span<uint8_t> raw_content) {
        _raw_content = raw_content;
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(_raw_content.data());
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(_raw_content.data() + dos->e_lfanew);
        auto file = nt->FileHeader;
        is_64bit = file.Machine == IMAGE_FILE_MACHINE_AMD64;
        num_sections = file.NumberOfSections;
        section = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            _raw_content.data() + dos->e_lfanew + (is_64bit ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32))
        );
    }

    std::expected<std::span<uint8_t>, patimat::error> get_section(std::string_view name = ".text") override {
        if (name.empty())
            name = ".text";
        bool status = find_section(name);
        if (!status)
            return std::unexpected(patimat::error::not_found);
        return _raw_content.subspan(offset, size);
    }
};