#include "src/network_parameters.hpp"
#include "src/session.hpp"
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <set>

// Verify that liquid/non-liquid network parameters contain all expected keys

int main()
{
    using namespace ga::sdk;

    nlohmann::json init_config;
    init_config["datadir"] = ".";
    init_config["log_level"] = "none";
    init(init_config);

    bool failed = false;
    const nlohmann::json all_networks = network_parameters::get_all();

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

    // Verify URL overrides
    const auto& localtest = all_networks.at("localtest");
    for (auto item : localtest.items()) {
        if (item.key() == "wamp_onion_url") {
            continue; // WAMP url cannot be overloaded except by registering another network
        }
        if (item.key().find("onion_url") != std::string::npos) {
            auto url = boost::replace_all_copy(item.key(), "onion_url", "url");
            if (!localtest.contains(url)) {
                std::cerr << item.key() << " missing non-onion url " << url << std::endl;
                failed = true;
                continue;
            }

            auto defaults = localtest;
            nlohmann::json overrides{ { item.key(), "foo_onion" }, { url, "foo" } };
            network_parameters np{ overrides, defaults };
            auto& np_json = np.get_json();
            if (np_json.at(url) != "foo") {
                std::cerr << item.key() << " failed to fetch non-onion url, got " << np_json.at(url) << std::endl;
                failed = true;
                continue;
            }
            if (np_json.at(item.key()) != "foo_onion") {
                std::cerr << item.key() << " failed to fetch onion url, got " << np_json.at(item.key()) << std::endl;
                failed = true;
            }
        }
    }

    // Exit with an error if we failed
    return failed ? 1 : 0;
}
