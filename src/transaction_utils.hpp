#ifndef GDK_TRANSACTION_UTILS_HPP
#define GDK_TRANSACTION_UTILS_HPP
#pragma once

#include <array>
#include <memory>
#include <optional>
#include <set>
#include <utility>

#include "amount.hpp"
#include "ga_wally.hpp"

namespace green {

    class green_pubkeys;
    class green_recovery_pubkeys;
    class network_parameters;
    class session_impl;
    class user_pubkeys;
    class Tx;

    using witness_ptr = std::unique_ptr<struct wally_tx_witness_stack, int (*)(struct wally_tx_witness_stack*)>;

    namespace address_type {
        extern const std::string p2pkh; // Not generated by the server, used for sweeping
        extern const std::string p2wpkh;
        extern const std::string p2sh_p2wpkh;
        extern const std::string p2sh;
        extern const std::string p2wsh; // Actually p2sh-p2wsh
        extern const std::string csv;
    } // namespace address_type

    bool address_type_is_segwit(const std::string& addr_type);

    std::string address_type_from_script_type(uint32_t script_type);

    uint32_t address_type_to_script_type(const std::string& addr_type);

    std::string get_address_from_scriptpubkey(const network_parameters& net_params, byte_span_t scriptpubkey);

    std::string get_address_from_utxo(session_impl& session, const nlohmann::json& utxo, bool verify_script = true);

    std::vector<unsigned char> multisig_output_script_from_utxo(const network_parameters& net_params,
        green_pubkeys& pubkeys, user_pubkeys& usr_pubkeys, green_recovery_pubkeys& recovery_pubkeys,
        const nlohmann::json& utxo);

    // Get scriptpubkey from address (address is expected to be valid)
    std::vector<unsigned char> scriptpubkey_from_address(
        const network_parameters& net_params, const std::string& address, bool allow_unconfidential);

    // Returns true if the UXTO is not a sweep UTXO and has a wallet address_type
    bool is_wallet_utxo(const nlohmann::json& utxo);

    // Set the error in a transaction, if it hasn't been set already
    void set_tx_error(nlohmann::json& result, const std::string& error, bool overwrite = false);

    // Add a UTXO to a transaction, and optionally to "transaction_inputs".
    // Sets "sequence" and "user_path" in the source UTXO, and creates dummy
    // script/witness items so that fee estimation is accurate.
    // Returns the amount of the added UTXO.
    amount add_tx_input(
        session_impl& session, nlohmann::json& result, Tx& tx, nlohmann::json& utxo, bool add_to_tx_inputs);

    // Compute the scriptsig and witness for a wallet input.
    // If either DER-encoded sig is empty, uses a dummy sig so fee estimation
    // is accurate.
    std::pair<std::vector<unsigned char>, witness_ptr> get_scriptsig_and_witness(
        session_impl& session, const nlohmann::json& utxo, byte_span_t user_der, byte_span_t green_der);

    // Set the users signature in a transaction input
    void tx_set_user_signature(
        session_impl& session, const nlohmann::json& result, Tx& tx, size_t index, byte_span_t user_der);

    // returns user_signed, server_signed, sweep_signed, has_sweep_inputs
    std::tuple<bool, bool, bool, bool> tx_get_user_server_sweep_signed(
        session_impl& session, const nlohmann::json& result, Tx& tx);

    std::string validate_tx_addressee(
        session_impl& session, const network_parameters& net_params, nlohmann::json& addressee);

    // Add an output from a JSON addressee
    void add_tx_addressee_output(session_impl& session, Tx& tx, nlohmann::json& addressee);

    // Add an output from a JSON change output.
    // Note the output is zero valued and is expected to be updated later
    void add_tx_change_output(session_impl& session, nlohmann::json& result, Tx& tx, const std::string& asset_id);

    // Add a fee output for the given value to a tx.
    void add_tx_fee_output(session_impl& session, Tx& tx, amount::value_type satoshi);

    // Update the json tx size/fee rate information from tx
    void update_tx_size_info(const network_parameters& net_params, const Tx& tx, nlohmann::json& result);

    // Get the output index of an assets change
    std::optional<int> get_tx_change_index(nlohmann::json& result, const std::string& asset_id);

    // Return whether all addressees and change outputs are unique (different addresses),
    // and if spk is given, return whether it would be unique if added
    bool are_tx_outputs_unique(const nlohmann::json& result, const std::string& spk = std::string());

    // Update the json tx representation with info from tx
    void update_tx_info(session_impl& session, const Tx& tx, nlohmann::json& result);

    // Compute the subaccounts a tx uses from its inputs
    std::set<uint32_t> get_tx_subaccounts(const nlohmann::json& details);

    // Return the single subaccount in subaccounts or throw an error
    uint32_t get_single_subaccount(const std::set<uint32_t>& subaccounts);

    // Returns true if a tx has AMP inputs
    bool tx_has_amp_inputs(session_impl& session, const nlohmann::json& details);

} // namespace green

#endif
