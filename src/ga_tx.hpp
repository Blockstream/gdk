#ifndef GDK_GA_TX_HPP
#define GDK_GA_TX_HPP
#pragma once

#include <ga_wally.hpp>
#include <nlohmann/json.hpp>

namespace ga {
namespace sdk {
    class ga_session;
    class network_parameters;
    class session_impl;

    nlohmann::json create_ga_transaction(ga_session& session, const nlohmann::json& details);

    void add_input_signature(
        const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u, const std::string& der_hex, bool is_low_r);

    void verify_ae_signature(const network_parameters& net_params, const pub_key_t& public_key, const wally_tx_ptr& tx,
        uint32_t index, const nlohmann::json& u, const std::string& signer_commitment_hex, const std::string& der_hex);

    void blind_output(session_impl& session, const nlohmann::json& details, const wally_tx_ptr& tx, uint32_t index,
        const nlohmann::json& output, const std::array<unsigned char, 33>& generator,
        const std::array<unsigned char, 33>& value_commitment, const std::array<unsigned char, 32>& abf,
        const std::array<unsigned char, 32>& vbf);

    std::vector<nlohmann::json> get_ga_signing_inputs(const nlohmann::json& details);

    std::pair<std::vector<std::string>, wally_tx_ptr> sign_ga_transaction(
        session_impl& session, const nlohmann::json& details, const std::vector<nlohmann::json>& inputs);
    nlohmann::json sign_ga_transaction(session_impl& session, const nlohmann::json& details);

    nlohmann::json blind_ga_transaction(ga_session& session, const nlohmann::json& details);

} // namespace sdk
} // namespace ga

#endif
