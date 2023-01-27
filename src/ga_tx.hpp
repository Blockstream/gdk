#ifndef GDK_GA_TX_HPP
#define GDK_GA_TX_HPP
#pragma once

#include "ga_wally.hpp"
#include <nlohmann/json.hpp>

namespace ga {
namespace sdk {
    class session_impl;
    class network_parameters;
    class session_impl;

    std::array<unsigned char, SHA256_LEN> get_script_hash(const network_parameters& net_params,
        const nlohmann::json& utxo, const wally_tx_ptr& tx, size_t index, uint32_t sighash);

    void blind_address(
        const network_parameters& net_params, nlohmann::json& addr, const std::string& blinding_pubkey_hex);
    void unblind_address(const network_parameters& net_params, nlohmann::json& addr);

    nlohmann::json create_ga_transaction(session_impl& session, const nlohmann::json& details);

    void add_input_signature(
        const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u, const std::string& der_hex, bool is_low_r);

    void blind_output(session_impl& session, const nlohmann::json& details, const wally_tx_ptr& tx, uint32_t index,
        const nlohmann::json& output, const std::array<unsigned char, 33>& generator,
        const std::array<unsigned char, 33>& value_commitment, const std::array<unsigned char, 32>& abf,
        const std::array<unsigned char, 32>& vbf);

    nlohmann::json unblind_output(session_impl& session, const wally_tx_ptr& tx, uint32_t vout);

    std::vector<nlohmann::json> get_ga_signing_inputs(const nlohmann::json& details);

    std::pair<std::vector<std::string>, wally_tx_ptr> sign_ga_transaction(
        session_impl& session, const nlohmann::json& details, const std::vector<nlohmann::json>& inputs);
    nlohmann::json sign_ga_transaction(session_impl& session, const nlohmann::json& details);

    nlohmann::json blind_ga_transaction(session_impl& session, const nlohmann::json& details);

} // namespace sdk
} // namespace ga

#endif
