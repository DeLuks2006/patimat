#include <print>
#include <vector>
#include <fstream>
#include "patimat.hpp"
#include "json.hpp"
#include "binary/binary.hpp"

struct PatchConfig {
    std::string signature;
    std::string patch;
    bool padding;
};

struct TargetConfig {
    std::string target;
    std::string output;
    std::vector<PatchConfig> patches;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(PatchConfig, signature, patch, padding)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(TargetConfig, target, output, patches)

std::expected<TargetConfig, int> read_config(std::string filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::println("Failed to open config file");
        return std::unexpected(-1);
    }
    try {
        nlohmann::json json_data;
        file >> json_data;
        auto config = json_data.get<TargetConfig>();
        return config;
    } catch (const nlohmann::json::exception& e) {
        std::println("Error: {}", e.what());
        return std::unexpected(-1);
    }
}

void print_help(const char* program_name) {
    std::println("Usage: ");
    std::println("  {} {:50} <- show this menu", program_name, "help");
    std::println("  {} {:50} <- patch according to config", program_name, "<config_file>.json");
    std::println("  {} {:50} <- adhoc patch one pattern", program_name, "<binary> '<match_pattern>' '<patch_pattern>'");
}

TargetConfig parse_args(int argc, char* argv[]) {
    if (argc < 2 || argc > 4 || std::string_view(argv[1]) == "help") {
        print_help(argv[0]);
        exit(-1);
    }
    if (argc == 2 && std::string_view(argv[1]).ends_with(".json")) {
        auto conf = read_config(argv[1]);
        if (!conf.has_value()) {
            std::println("Error: failed to read config file");
            exit(-1);
        }
        return conf.value();
    }
    else if (argc == 4) {
        return {
            argv[1],
            "",
            std::vector<PatchConfig>{ {argv[2], argv[3], false} }
        };
    }
    print_help(argv[0]);
    exit(-1); // should never be reached inshallah
}

// later use an argument to get the json file 
int main(int argc, char* argv[]) {
    // read config
    auto config = parse_args(argc, argv);

    // here read file and extract .text section as a span
    auto bin = patimat::Binary(config.target);

    auto memory = bin.get_section();
    if (!memory.has_value()) {
        std::println("Failed to find section");
    }

    auto pm = patimat::pattern_matcher(memory.value());

    int patched = 0;
    
    // perform patches
    for (auto& patch : config.patches) {
        pm.set_pattern(patch.signature);
        auto finds = pm.find_patterns();
        if (!finds.has_value())
            continue;
        patched += finds.value().size();
        pm.patch_all(finds.value(), patch.padding);
    }
    
    // patch file here
    bin.write_changes(config.output);
    
    return 0;
}
