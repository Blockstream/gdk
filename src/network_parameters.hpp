#ifndef GDK_NETWORK_PARAMETERS_HPP
#define GDK_NETWORK_PARAMETERS_HPP
#pragma once

#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "include/gdk.h"

namespace ga {
namespace sdk {

    class network_parameters final {
    public:
        static void add(const std::string& name, const nlohmann::json& details);
        static nlohmann::json get_all();
        static nlohmann::json get(const std::string& name);

        // Construct from raw network json
        explicit network_parameters(const nlohmann::json& details);
        // Construct from a user's overrides and raw network json
        network_parameters(const nlohmann::json& user_overrides, nlohmann::json& defaults);

        ~network_parameters();

        network_parameters(const network_parameters&) = default;
        network_parameters& operator=(const network_parameters&) = default;

        network_parameters(network_parameters&&) = default;
        network_parameters& operator=(network_parameters&&) = default;

        const nlohmann::json& get_json() const { return m_details; }

        std::string network() const;
        std::string gait_wamp_url() const;
        std::vector<std::string> gait_wamp_cert_pins() const;
        std::vector<std::string> gait_wamp_cert_roots() const;
        std::string block_explorer_address() const;
        std::string block_explorer_tx() const;
        std::string asset_registry_url() const;
        std::string asset_registry_onion_url() const;
        std::string chain_code() const;
        std::string electrum_url() const;
        std::string pub_key() const;
        std::string gait_onion() const;
        std::string policy_asset() const;
        std::string bip21_prefix() const;
        std::string bech32_prefix() const;
        std::string blech32_prefix() const;
        std::string log_level() const;
        unsigned char btc_version() const;
        unsigned char btc_p2sh_version() const;
        uint32_t blinded_prefix() const;
        int ct_exponent() const;
        int ct_bits() const;
        bool is_main_net() const;
        bool is_liquid() const;
        bool is_electrum() const;
        bool use_tor() const;
        std::string socks5() const;
        bool spv_enabled() const;
        bool electrum_tls() const;
        std::string user_agent() const;
        std::string get_connection_string() const;
        std::string get_registry_connection_string() const;
        bool is_tls_connection() const;
        std::vector<uint32_t> csv_buckets() const;
        uint32_t cert_expiry_threshold() const;
        uint32_t get_max_reorg_blocks() const;

    private:
        nlohmann::json m_details;
    };
} // namespace sdk
} // namespace ga

#endif
