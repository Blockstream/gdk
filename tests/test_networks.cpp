#include "src/network_parameters.hpp"
#include <iostream>
#include <nlohmann/json.hpp>
#include <set>

// Verify that liquid/non-liquid network parameters contain all expected keys

int main()
{
    bool failed = false;
    const nlohmann::json all_networks = ga::sdk::network_parameters::get_all();

    std::set<std::string> all_keys;
    std::set<std::string> all_liquid_keys;

    // Collect all keys
    for (const auto& network : all_networks.items()) {
        if (network.key() != "all_networks") {
            const bool is_liquid = network.value().value("liquid", false);
            for (const auto& item : network.value().items()) {
                (is_liquid ? all_liquid_keys : all_keys).insert(item.key());
            }
        }
    }

    // Note any missing keys
    for (const auto& network : all_networks.items()) {
        if (network.key() != "all_networks") {
            const bool is_liquid = network.value().value("liquid", false);
            for (const auto& key : (is_liquid ? all_liquid_keys : all_keys)) {
                if (!network.value().contains(key)) {
                    std::cerr << network.key() << " missing value " << key << std::endl;
                    failed = true;
                }
            }
        }
    }

    // Exit with an error if we failed
    return failed ? 1 : 0;
}
