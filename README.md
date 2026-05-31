# Patimat 

Simple, header-only, pattern matching and patching class written in modern C++.
Includes also a mini-tool for ad-hoc patching from the command-line.

## Usage

```sh
# patch file according to json config, see patch.json for example
patimat patch.json 

# quick patch file 
patimat malware.exe '0f 84 ?? ?? ?? ??' '90 e9'
```

one does not need to worry about the executable file format, as it supports 
PEs, ELFs, Mach-Os and flat binaries. However one must note that the signature 
for Mach-Os must be manually fixed with the following command:

```sh
codesign --force -s - ./patched
# or if the binary has entitlements
codesign -d --entitlements ./binary.plist ./binary
codesign --force --entitlements ./binary.plist -s - ./patched
```

One must note however that the parsing is naive, so it is not resistant against,
malformed binary formats such as ELFs with malformed headers.

## Usage Library

Finding all patterns in a memory buffer:
```cpp
#include "patimat.hpp"

int main(void) {
    using namespace patimat;
    std::vector<uint8_t> memory = {
        0x00, 0x11, 0x22, 0xf0, 
        0xde, 0x43, 0x15, 0xba, 
        0xaa, 0xbb, 0xf0, 0x00, 
        0x49, 0x1a, 0xfa, 0x90, 
        0x90, 0x66, 0x78, 0x22
    };

    auto pm = pattern_matcher("f0 ?? 4? (10-20) ?a", memory);
    auto status = pm.find_patterns();
    
    const auto& results = status.value();
    std::println("Found {} matches in memory.", results.size());

    for (size_t i = 0; i < results.size(); ++i) {
        size_t offset = results[i] - memory.data();
        std::println("Match [{}] found at byte offset {}", i, offset);
    }
    
    return 0;
}
```

Patching all found signatures:

```cpp
#include "patimat.hpp"
#include <print>
#include <cstdint>

int main(void) {
    using namespace patimat;
    std::vector<uint8_t> memory = {
        0x00, 0x11, 0x22, 0xf0, 
        0xde, 0x43, 0x15, 0xba, 
        0xaa, 0xbb, 0xf0, 0x00, 
        0x49, 0x1a, 0xfa, 0x90, 
        0x90, 0x66, 0x78, 0x22
    };

    auto print_arr = [](std::vector<uint8_t>& a){
        for (auto& byte : a)
            std::print("{:02x} ", byte);
        std::println("");
    };
    
    std::println("before:");
    print_arr(memory);
    
    auto pm = pattern_matcher(
        "f0 ?? 4? (10-20) ?a", 
        "eb fe ?? [1] [2]",
        memory
    );
    auto status = pm.find_patterns();
    bool nop_pad = true;
    pm.patch_all(status.value(), nop_pad);

    std::println("after:");
    print_arr(memory);
    return 0;
}
```