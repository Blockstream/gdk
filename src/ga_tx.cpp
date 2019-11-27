#include <algorithm>
#include <array>
#include <ctime>
#include <string>
#include <vector>

#include "amount.hpp"
#include "boost_wrapper.hpp"
#include "exception.hpp"
#include "ga_session.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "logging.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

namespace ga {
namespace sdk {
    namespace {
        // Dummy data for transaction creation with correctly sized data for fee estimation
        static const std::array<unsigned char, 3 + SHA256_LEN> DUMMY_WITNESS_SCRIPT{};

        static const std::string UTXO_SEL_DEFAULT("default"); // Use the default utxo selection strategy
        static const std::string UTXO_SEL_MANUAL("manual"); // Use manual utxo selection

        static void set_tx_error(nlohmann::json& result, const std::string& error)
        {
            if (json_get_value(result, "error").empty()) {
                result["error"] = error;
            }
        }

        static void add_paths(ga_session& session, nlohmann::json& utxo)
        {
            const uint32_t subaccount = json_get_value(utxo, "subaccount", 0u);
            const uint32_t pointer = utxo.at("pointer");

            if (utxo.find("user_path") == utxo.end()) {
                // Populate the full user path for h/w signing
                utxo["user_path"] = ga_user_pubkeys::get_full_path(subaccount, pointer);
            }

            if (utxo.find("service_xpub") == utxo.end()) {
                // Populate the service xpub for h/w signing
                utxo["service_xpub"] = session.get_service_xpub(subaccount);
            }

            if (utxo.find("recovery_xpub") == utxo.end() && session.has_recovery_pubkeys_subaccount(subaccount)) {
                // Populate the recovery xpub for h/w signing
                utxo["recovery_xpub"] = session.get_recovery_xpub(subaccount);
            }
        }

        // Add a UTXO to a transaction. Returns the amount added
        static amount add_utxo(ga_session& session, const wally_tx_ptr& tx, nlohmann::json& utxo)
        {
            const std::string txhash = utxo.at("txhash");
            const auto txid = h2b_rev(txhash);
            const uint32_t index = utxo.at("pt_idx");
            const auto type = script_type(utxo.at("script_type"));
            const bool low_r = session.supports_low_r();
            const uint32_t dummy_sig_type = low_r ? WALLY_TX_DUMMY_SIG_LOW_R : WALLY_TX_DUMMY_SIG;
            const bool external = !json_get_value(utxo, "private_key").empty();
            const uint32_t sequence = session.is_rbf_enabled() ? 0xFFFFFFFD : 0xFFFFFFFE;

            utxo["sequence"] = sequence;

            if (external) {
                tx_add_raw_input(
                    tx, txid, index, sequence, dummy_external_input_script(low_r, h2b(utxo.at("public_key"))));
            } else {
                // Populate the prevout script if missing so signing can use it later
                if (utxo.find("prevout_script") == utxo.end()) {
                    const auto script = session.output_script_from_utxo(utxo);
                    utxo["prevout_script"] = b2h(script);
                }
                const auto script = h2b(utxo["prevout_script"]);

                add_paths(session, utxo);

                wally_tx_witness_stack_ptr wit;

                if (is_segwit_script_type(type)) {
                    // TODO: If the UTXO is CSV and expired, spend it using the users key only (smaller)
                    wit = tx_witness_stack_init(4);
                    tx_witness_stack_add_dummy(wit, WALLY_TX_DUMMY_NULL);
                    tx_witness_stack_add_dummy(wit, dummy_sig_type);
                    tx_witness_stack_add_dummy(wit, dummy_sig_type);
                    tx_witness_stack_add(wit, script);
                }

                if (wit) {
                    tx_add_raw_input(tx, txid, index, sequence, DUMMY_WITNESS_SCRIPT, wit);
                } else {
                    tx_add_raw_input(tx, txid, index, sequence, dummy_input_script(low_r, script));
                }
            }

            return amount(utxo.at("satoshi"));
        }

        static void calculate_input_subtype(nlohmann::json& utxo, const wally_tx_ptr& tx, size_t i)
        {
            // Calculate the subtype of a tx input we wish to present as a utxo.
            uint32_t subtype = 0;
            if (utxo["address_type"] == address_type::csv) {
                // CSV inputs use the CSV time as the subtype: fetch this from the
                // redeem script in the inputs witness data. The user can change
                // their CSV time at any time, so we must use the value that was
                // originally used in the tx rather than the users current setting.
                GDK_RUNTIME_ASSERT(i < tx->num_inputs);
                const auto& witness = tx->inputs[i].witness;
                GDK_RUNTIME_ASSERT(witness != nullptr && witness->num_items != 0);
                // The redeem script is the last witness item
                const auto& witness_item = witness->items[witness->num_items - 1];
                GDK_RUNTIME_ASSERT(witness_item.witness != nullptr && witness_item.witness_len != 0);
                const auto redeem_script = gsl::make_span(witness_item.witness, witness_item.witness_len);
                subtype = get_csv_blocks_from_csv_redeem_script(redeem_script);
            }
            utxo["subtype"] = subtype;
        }

        void randomise_inputs(const wally_tx_ptr& tx, std::vector<nlohmann::json>& used_utxos)
        {
            std::vector<nlohmann::json> unshuffled_utxos(used_utxos.begin(), used_utxos.end());
            std::shuffle(used_utxos.begin(), used_utxos.end(), uniform_uint32_rng());

            // Update inputs in our created transaction to match the new random order
            std::map<nlohmann::json, size_t> new_position_of;
            for (size_t i = 0; i < used_utxos.size(); ++i) {
                new_position_of.emplace(used_utxos[i], i);
            }
            wally_tx_input* in_p = tx->inputs + (tx->num_inputs - used_utxos.size());
            std::vector<wally_tx_input> reordered_inputs(used_utxos.size());
            for (size_t i = 0; i < unshuffled_utxos.size(); ++i) {
                const size_t new_position = new_position_of[unshuffled_utxos[i]];
                reordered_inputs[new_position] = in_p[i];
            }
            std::copy(reordered_inputs.begin(), reordered_inputs.end(), in_p);
        }

        // Check if a tx to bump is present, and if so add the details required to bump it
        static std::pair<bool, bool> check_bump_tx(ga_session& session, nlohmann::json& result, uint32_t subaccount)
        {
            if (result.find("previous_transaction") == result.end()) {
                return std::make_pair(false, false);
            }

            // RBF or CPFP. The previous transaction must be in the format
            // returned from the get_transactions call
            const auto& prev_tx = result["previous_transaction"];
            bool is_rbf = false, is_cpfp = false;
            if (json_get_value(prev_tx, "can_rbf", false)) {
                is_rbf = true;
            } else if (json_get_value(prev_tx, "can_cpfp", false)) {
                is_cpfp = true;
            } else {
                // Transaction is confirmed or marked non-RBF
                GDK_RUNTIME_ASSERT_MSG(false, "Transaction can not be fee-bumped");
            }

            // You cannot bump a tx from another subaccount, this is a
            // programming error so assert it rather than returning in "error"
            bool subaccount_ok = false;
            for (const auto& io : prev_tx.at(is_rbf ? "inputs" : "outputs")) {
                const auto prev_subaccount = io.find("subaccount");
                if (prev_subaccount != io.end() && *prev_subaccount == subaccount) {
                    subaccount_ok = true;
                    break;
                }
            }
            GDK_RUNTIME_ASSERT(subaccount_ok);

            auto tx = tx_from_hex(prev_tx.at("transaction"));
            const auto min_fee_rate = session.get_min_fee_rate();

            // Store the old fee and fee rate to check if replacement
            // requirements are satisfied
            const amount old_fee = amount(prev_tx.at("fee"));
            const amount old_fee_rate = amount(prev_tx.at("fee_rate"));
            result["old_fee"] = old_fee.value();
            result["old_fee_rate"] = old_fee_rate.value();

            if (is_cpfp) {
                // For CPFP the network fee is the difference between the
                // fee the previous transaction currently pays, and the
                // fee it would pay at the desired new fee rate (adding
                // the network fee to the new transactions fee increases
                // the overall fee rate of the pair to the desired rate,
                // so that miners are incentivized to mine both together).
                const amount new_fee_rate = amount(result.at("fee_rate"));
                const auto new_fee = get_tx_fee(tx, min_fee_rate, new_fee_rate);
                const amount network_fee = new_fee <= old_fee ? amount() : new_fee;
                result["network_fee"] = network_fee.value();
            }

            if (is_rbf) {
                // Compute addressees and any change details from the old tx
                std::vector<nlohmann::json> addressees;
                const auto& outputs = prev_tx.at("outputs");
                addressees.reserve(outputs.size());
                uint32_t i = 0, change_index = NO_CHANGE_INDEX;

                for (const auto& output : outputs) {
                    const bool is_relevant = json_get_value(output, "is_relevant", false);
                    if (is_relevant && change_index == NO_CHANGE_INDEX) {
                        // Change output.
                        change_index = i;
                    } else {
                        // Not a change output, or there is already one:
                        // treat this as a regular output
                        addressees.emplace_back(nlohmann::json(
                            { { "address", output.at("address") }, { "satoshi", output.at("satoshi") } }));
                    }
                    ++i;
                }

                bool is_redeposit = false;
                if (change_index != NO_CHANGE_INDEX) {
                    // Found an output paying to ourselves.
                    const auto& output = prev_tx.at("outputs").at(change_index);
                    const std::string address = output.at("address");
                    if (addressees.empty()) {
                        // We didn't pay anyone else; this is actually a re-deposit
                        addressees.emplace_back(
                            nlohmann::json({ { "address", address }, { "satoshi", output.at("satoshi") } }));
                        change_index = NO_CHANGE_INDEX;
                        is_redeposit = true;
                    } else {
                        // We paid to someone else, so this output really was
                        // change. Save the change address to re-use it.
                        result["change_address"]["btc"] = output;
                        add_paths(session, result["change_address"]["btc"]);
                    }
                    // Save the change subaccount whether we found change or not
                    result["change_subaccount"] = output.at("subaccount");
                }

                result["is_redeposit"] = is_redeposit;
                result["addressees"] = addressees;

                result["have_change"]["btc"] = change_index != NO_CHANGE_INDEX;
                if (change_index == NO_CHANGE_INDEX && !is_redeposit) {
                    for (const auto in : prev_tx["inputs"]) {
                        if (json_get_value(in, "is_relevant", false)) {
                            // Use the first inputs subaccount as our change subaccount
                            // FIXME: When the server supports multiple subaccount sends,
                            // this will need to change to something smarter
                            const uint32_t subaccount = in.at("subaccount");
                            result["subaccount"] = subaccount;
                            result["change_subaccount"] = subaccount;
                            break;
                        }
                    }
                }

                if (result.find("old_used_utxos") == result.end()) {
                    // Create 'fake' utxos for the existing inputs
                    std::map<uint32_t, nlohmann::json> used_utxos_map;
                    for (const auto& input : prev_tx.at("inputs")) {
                        GDK_RUNTIME_ASSERT(json_get_value(input, "is_relevant", false));
                        nlohmann::json utxo(input);
                        // Note pt_idx on endpoints is the index within the tx, not the previous tx!
                        const uint32_t i = input.at("pt_idx");
                        GDK_RUNTIME_ASSERT(i < tx->num_inputs);
                        std::reverse(&tx->inputs[i].txhash[0], &tx->inputs[i].txhash[0] + WALLY_TXHASH_LEN);
                        utxo["txhash"] = b2h(tx->inputs[i].txhash);
                        utxo["pt_idx"] = tx->inputs[i].index;
                        calculate_input_subtype(utxo, tx, i);
                        used_utxos_map.emplace(i, utxo);
                    }
                    GDK_RUNTIME_ASSERT(used_utxos_map.size() == tx->num_inputs);
                    std::vector<nlohmann::json> old_used_utxos;
                    old_used_utxos.reserve(used_utxos_map.size());
                    for (const auto& input : used_utxos_map) {
                        old_used_utxos.emplace_back(input.second);
                    }
                    result["old_used_utxos"] = old_used_utxos;
                }
                if (json_get_value(result, "memo").empty()) {
                    result["memo"] = prev_tx["memo"];
                }
                // FIXME: Carry over payment request details?
            } else {
                // For CPFP construct a tx spending an input from prev_tx
                // to a wallet change address. Since this is exactly what
                // re-depositing requires, just create the input and mark
                // the tx as a redeposit to let the regular creation logic
                // handle it.
                result["is_redeposit"] = true;
                if (result.find("utxos") == result.end()) {
                    // Add a single output from the old tx as our new tx input
                    std::vector<nlohmann::json> utxos;
                    for (const auto& output : prev_tx.at("outputs")) {
                        if (json_get_value(output, "is_relevant", false)) {
                            // First output paying to us, use it as the new tx input
                            nlohmann::json utxo(output);
                            utxo["txhash"] = prev_tx.at("txhash");
                            utxos.emplace_back(utxo);
                            break;
                        }
                    }
                    GDK_RUNTIME_ASSERT(utxos.size() == 1u);
                    result["utxos"]["btc"] = utxos;
                }
            }
            return { is_rbf, is_cpfp };
        }

        static void create_ga_transaction_impl(ga_session& session, nlohmann::json& result)
        {
            const auto& net_params = session.get_network_parameters();

            auto& error = result["error"];
            error = std::string(); // Clear any previous error
            result["user_signed"] = false;
            result["server_signed"] = false;
            result["liquid"] = net_params.liquid();

            // Must specify subaccount to use
            const auto p_subaccount = result.find("subaccount");
            GDK_RUNTIME_ASSERT(p_subaccount != result.end());
            const uint32_t subaccount = *p_subaccount;
            result["subaccount_type"] = session.get_cached_subaccount(subaccount)["type"];

            // Check for RBF/CPFP
            bool is_rbf, is_cpfp;
            std::tie(is_rbf, is_cpfp) = check_bump_tx(session, result, subaccount);

            const bool is_redeposit = json_get_value(result, "is_redeposit", false);

            if (is_redeposit) {
                if (result.find("addressees") == result.end()) {
                    // For re-deposit/CPFP, create the addressee if not present already
                    const auto address = session.get_receive_address(subaccount, {}).at("address");
                    std::vector<nlohmann::json> addressees;
                    addressees.emplace_back(nlohmann::json({ { "address", address }, { "satoshi", 0 } }));
                    result["addressees"] = addressees;
                }
                // When re-depositing, send everything and don't create change
                result["send_all"] = true;
            }
            result["is_redeposit"] = is_redeposit;

            const bool is_sweep = result.find("private_key") != result.end();
            result["is_sweep"] = is_sweep;

            // Let the caller know if addressees should not be modified
            result["addressees_read_only"] = is_redeposit || is_rbf || is_cpfp || is_sweep;

            const bool is_liquid = net_params.liquid();

            auto addressees_p = result.find("addressees");
            if (is_sweep) {
                if (is_liquid) {
                    set_tx_error(result, "sweep not supported for liquid");
                    return;
                }

                if (result.find("utxos") != result.end() && !result["utxos"]["btc"].empty()) {
                    // check for sweep related keys
                    for (const auto& utxo : result["utxos"]["btc"]) {
                        GDK_RUNTIME_ASSERT(!json_get_value(utxo, "private_key").empty());
                    }
                } else {
                    nlohmann::json utxos;
                    try {
                        utxos = session.get_unspent_outputs_for_private_key(
                            result["private_key"], json_get_value(result, "passphrase"), 0);
                    } catch (const assertion_error& ex) {
                        set_tx_error(result, res::id_invalid_private_key); // Invalid private key
                    } catch (const std::exception& ex) {
                        GDK_LOG_SEV(log_level::error) << "Exception getting outputs for private key: " << ex.what();
                    }
                    result["utxos"]["btc"] = utxos;
                    if (utxos.empty()) {
                        set_tx_error(result, res::id_no_utxos_found); // No UTXOs found
                    }
                }
                result["send_all"] = true;
                if (addressees_p != result.end()) {
                    // Use the provided address
                    GDK_RUNTIME_ASSERT(addressees_p->size() == 1u);
                    addressees_p->at(0)["satoshi"] = 0;
                } else {
                    // Send to an address in the current subaccount
                    const auto address = session.get_receive_address(subaccount, {}).at("address");
                    std::vector<nlohmann::json> addressees;
                    addressees.emplace_back(nlohmann::json({ { "address", address }, { "satoshi", 0 } }));
                    result["addressees"] = addressees;
                    addressees_p = result.find("addressees");
                }
            }

            const bool confidential_utxos_only = json_add_if_missing(result, "confidential_utxos_only", false);
            if (!is_sweep && result.find("utxos") == result.end()) {
                // Fetch the users utxos from the current subaccount.
                // if RBF/cpfp, require 1 confirmation.
                const uint32_t num_confs = (is_rbf || is_cpfp) ? 1 : 0;
                result["utxos"] = session.get_unspent_outputs(nlohmann::json({ { "subaccount", subaccount },
                    { "num_confs", num_confs }, { "confidential", confidential_utxos_only } }));
            }

            const bool send_all = json_add_if_missing(result, "send_all", false);
            // For now, the amount can't be directly edited for the below actions
            // One we expose coin control, the amount will auto update as utxos are
            // selected/deselected
            result["amount_read_only"] = send_all || is_redeposit || is_rbf || is_cpfp || is_sweep;

            const std::string strategy = json_add_if_missing(result, "utxo_strategy", UTXO_SEL_DEFAULT);
            const bool manual_selection = strategy == UTXO_SEL_MANUAL;
            GDK_RUNTIME_ASSERT(strategy == UTXO_SEL_DEFAULT || manual_selection);
            if (!manual_selection) {
                // We will recompute the used utxos
                result.erase("used_utxos");
            }

            // We must have addressees to send to, and if sending everything, only one
            // Note that this error is set unconditionally and so overrides any others,
            // Since addressing transactions is normally done first by users
            size_t num_addressees = 0;
            if (addressees_p == result.end() || addressees_p->empty()) {
                set_tx_error(result, res::id_no_recipients); // No outputs
            } else {
                num_addressees = addressees_p->size();
            }

            // Send all should not be visible/set when RBFing
            GDK_RUNTIME_ASSERT(!is_rbf || (!send_all || is_redeposit));

            if (send_all && num_addressees > 1) {
                set_tx_error(result, res::id_send_all_requires_a_single); // Send all requires a single output
            }

            auto& utxos = result.at("utxos");
            const uint32_t current_block_height = session.get_block_height();
            const uint32_t num_extra_utxos = is_rbf ? result.at("old_used_utxos").size() : 0;
            wally_tx_ptr tx = tx_init(current_block_height, utxos.size() + num_extra_utxos, num_addressees + 1);
            if (!is_rbf) {
                set_anti_snipe_locktime(tx, current_block_height);
            }

            std::vector<nlohmann::json> used_utxos;
            used_utxos.reserve(utxos.size());

            std::set<std::string> asset_tags;
            if (num_addressees) {
                std::transform(std::begin(*addressees_p), std::end(*addressees_p),
                    std::inserter(asset_tags, asset_tags.end()), [&](const auto& addressee) {
                        return session.asset_id_from_string(addressee.value("asset_tag", "btc"));
                    });
            }

            auto create_tx_outputs = [&](const std::string& asset_tag) {
                const bool include_fee = asset_tag == "btc";

                std::vector<nlohmann::json> current_used_utxos;
                amount available_total, total, fee, v;

                if (is_rbf) {
                    // Add all the old utxos. Note we don't add them to used_utxos
                    // since the user can't choose to remove them, and we won't
                    // randomise them in the final transaction
                    for (auto& utxo : result.at("old_used_utxos")) {
                        v = add_utxo(session, tx, utxo);
                        available_total += v;
                        total += v;
                    }
                }

                // Add all outputs and compute the total amount of satoshi to be sent
                amount required_total{ 0 };

                if (num_addressees) {
                    for (auto& addressee : *addressees_p) {
                        const auto addressee_asset_tag
                            = session.asset_id_from_string(addressee.value("asset_tag", std::string{}));
                        if (addressee_asset_tag == asset_tag) {
                            required_total += add_tx_addressee(session, net_params, result, tx, addressee);
                        }
                    }
                }

                // TODO: filter per asset or assume always single asset
                if (manual_selection) {
                    // Add all selected utxos
                    for (auto& utxo : result.at("used_utxos")) {
                        v = add_utxo(session, tx, utxo);
                        available_total += v;
                        total += v;
                        current_used_utxos.emplace_back(utxo);
                    }
                } else {
                    // Collect utxos in order until we have covered the amount to send
                    // FIXME: Better coin selection algorithms (esp. minimum size)
                    const auto asset_utxos_p = utxos.find(asset_tag);
                    if (asset_utxos_p != utxos.end()) {
                        for (auto& utxo : utxos.at(asset_tag)) {
                            if (send_all || total < required_total) {
                                v = add_utxo(session, tx, utxo);
                                total += v;
                                current_used_utxos.emplace_back(utxo);
                            } else {
                                v = static_cast<amount::value_type>(utxo.at("satoshi"));
                            }
                            available_total += v;
                        }
                    }
                }

                // Return the available total for client insufficient fund handling
                result["available_total"] = available_total.value();

                bool have_change_output = false;
                bool have_fee_output = false;
                uint32_t change_index = NO_CHANGE_INDEX;
                uint32_t fee_index = NO_CHANGE_INDEX;

                if (is_rbf) {
                    const auto have_change_p = result.find("have_change");
                    have_change_output
                        = have_change_p != result.end() ? json_get_value(*have_change_p, "btc", false) : false;
                    if (have_change_output) {
                        add_tx_output(net_params, result, tx, result.at("change_address").at("btc").at("address"));
                        change_index = tx->num_outputs - 1;
                    }
                }

                if (result.find("fee_rate") == result.end()) {
                    result["fee_rate"] = session.get_default_fee_rate().value();
                }
                const amount dust_threshold = session.get_dust_threshold();
                const amount user_fee_rate = amount(result.at("fee_rate"));
                const amount min_fee_rate = session.get_min_fee_rate();
                const amount old_fee_rate = amount(json_get_value(result, "old_fee_rate", 0u));
                const amount old_fee = amount(json_get_value(result, "old_fee", 0u));
                const amount network_fee = amount(json_get_value(result, "network_fee", 0u));

                bool force_add_utxo = false;

                const size_t max_loop_iterations
                    = std::max(size_t(8), utxos.size() * 2 + 1); // +1 in case empty+send all
                size_t loop_iterations;

                for (loop_iterations = 0; loop_iterations < max_loop_iterations; ++loop_iterations) {
                    amount change, required_with_fee;

                    if (include_fee) {
                        // add fee output so is also part of size calculations
                        if (is_liquid) {
                            if (!have_fee_output) {
                                if (send_all && addressees_p->at(0).value("asset_tag", "btc") == asset_tag) {
                                    // the output commitment will be corrected below. this is a placeholder for the
                                    // blinding.
                                    set_tx_output_commitment(net_params, tx, 0, asset_tag, 1);
                                }
                                add_tx_fee_output(net_params, tx, 1);
                                have_fee_output = true;
                                fee_index = tx->num_outputs - 1;
                            }
                            update_tx_info(net_params, tx, result);
                            std::vector<nlohmann::json> used_utxos
                                = json_get_value(result, "used_utxos", std::vector<nlohmann::json>{});
                            used_utxos.insert(
                                used_utxos.end(), std::begin(current_used_utxos), std::end(current_used_utxos));
                            result["used_utxos"] = used_utxos;
                            const auto fee_tx = tx_from_hex(blind_ga_transaction(session, result)["transaction"],
                                WALLY_TX_FLAG_USE_WITNESS | WALLY_TX_FLAG_USE_ELEMENTS);
                            fee = get_tx_fee(fee_tx, min_fee_rate, user_fee_rate);
                        } else {
                            fee = get_tx_fee(tx, min_fee_rate, user_fee_rate);
                        }

                        fee += network_fee;
                    }

                    if (send_all && addressees_p->at(0).value("asset_tag", "btc") == asset_tag) {
                        if (available_total < fee + dust_threshold) {
                            // After paying the fee, we only have dust left, so
                            // the requested amount isn't payable
                            set_tx_error(result, res::id_insufficient_funds); // Insufficient funds
                        } else {
                            // We are sending everything without a change output,
                            // so compute what we can send (everything minus the
                            // fee) and exit the loop
                            required_total = available_total - fee;
                            if (is_liquid) {
                                set_tx_output_commitment(net_params, tx, 0, asset_tag, required_total.value());
                            } else {
                                tx->outputs[0].satoshi = required_total.value();
                            }
                            if (num_addressees == 1u) {
                                addressees_p->at(0)["satoshi"] = required_total.value();
                            }
                        }
                        goto leave_loop;
                    }

                    required_with_fee = required_total + fee;
                    if (total < required_with_fee || force_add_utxo) {
                        // We don't have enough funds to cover the fee yet, or we
                        // need to add more to avoid a dusty change output
                        force_add_utxo = false;
                        if (manual_selection || utxos.empty()
                            || current_used_utxos.size() == utxos.at(asset_tag).size()) {
                            // Used all inputs and do not have enough funds
                            set_tx_error(result, res::id_insufficient_funds); // Insufficient funds
                            goto leave_loop;
                        }

                        // FIXME: Use our strategy here when non-default implemented
                        auto& utxo = utxos.at(asset_tag).at(current_used_utxos.size());
                        total += add_utxo(session, tx, utxo);
                        current_used_utxos.emplace_back(utxo);
                        continue;
                    }

                    change = total - required_with_fee;

                    if ((!have_change_output && change < dust_threshold)
                        || (have_change_output && change >= dust_threshold)) {
                        // We don't have a change output, and have only dust left over, or
                        // we do have a change output and its not dust, so we're done
                        if (!have_change_output) {
                            // We don't have any change out, so donate the left
                            // over dust to the mining fee
                            fee += change;
                        }
                    leave_loop:
                        result["fee"] = fee.value();
                        result["network_fee"] = network_fee.value();
                        break;
                    }

                    // If we have change,its dust so we need to try adding a new utxo.
                    // This only happens if the fee increase from adding the change
                    // output made the change amount dusty.
                    // We could instead drop the change output and donate more than
                    // the dust to the miners, but that has to be a user preference
                    // (cost vs privacy), which isn't exposed yet, and besides, a
                    // better UTXO selection algorithm should prevent this rare case.
                    if (have_change_output) {
                        force_add_utxo = true;
                        continue;
                    }

                    // We have more than the dust amount of change. Add a change
                    // output to collect it, then loop again in case the amount
                    // this increases the fee by requires more UTXOs.
                    bool change_address = result.find("change_address") != result.end();
                    if (change_address) {
                        const auto asset_change_address
                            = result.at("change_address").value(asset_tag, nlohmann::json::object());
                        change_address = !asset_change_address.empty();
                    }
                    if (!change_address) {
                        // No previously generated change address found, so generate one.
                        // Find out where to send any change
                        const uint32_t change_subaccount = result.value("change_subaccount", subaccount);
                        result["change_subaccount"] = change_subaccount;
                        auto change_address = session.get_receive_address(change_subaccount, {});
                        if (is_liquid) {
                            // set a temporary blinding key, will be changed later through the resolvers. we need
                            // to have one because all our create_transaction logic relies on being able to blind
                            // the tx for a few things (fee estimation for instance).
                            const auto temp_pk = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

                            change_address["address"] = session.blind_address(change_address.at("address"), temp_pk);
                            change_address["is_blinded"] = false;
                        }

                        add_paths(session, change_address);
                        result["change_address"][asset_tag] = change_address;
                    }
                    add_tx_output(net_params, result, tx, result.at("change_address").at(asset_tag).at("address"),
                        is_liquid ? 1 : 0, asset_tag == "btc" ? std::string{} : asset_tag);
                    have_change_output = true;
                    change_index = tx->num_outputs - 1;
                    if (is_liquid && include_fee) {
                        std::swap(tx->outputs[fee_index], tx->outputs[change_index]);
                        std::swap(fee_index, change_index);
                    }
                    result["have_change"][asset_tag] = have_change_output;
                    result["change_index"][asset_tag] = change_index;
                }

                used_utxos.insert(used_utxos.end(), std::begin(current_used_utxos), std::end(current_used_utxos));

                if (loop_iterations >= max_loop_iterations) {
                    GDK_LOG_SEV(log_level::error) << "Endless tx loop building: " << result.dump();
                    GDK_RUNTIME_ASSERT(false);
                }

                auto&& update_change_output = [&](auto fee) {
                    amount::value_type change_amount = 0;
                    if (have_change_output) {
                        // Set the change amount
                        change_amount = (total - required_total - fee).value();
                        if (is_liquid) {
                            set_tx_output_commitment(net_params, tx, change_index, asset_tag, change_amount);
                        } else {
                            auto& change_output = tx->outputs[change_index];
                            change_output.satoshi = change_amount;
                            const uint32_t new_change_index = get_uniform_uint32_t(tx->num_outputs);
                            // Randomize change output
                            if (change_index != new_change_index) {
                                std::swap(tx->outputs[new_change_index], change_output);
                                change_index = new_change_index;
                            }
                        }
                    }
                    // TODO: change amount should be liquid specific (blinded)
                    result["change_amount"][asset_tag] = change_amount;
                    result["change_index"][asset_tag] = change_index;
                };

                update_change_output(fee);

                if (include_fee && is_liquid) {
                    set_tx_output_commitment(net_params, tx, fee_index, asset_tag, fee.value());
                }

                if (required_total == 0 && (!include_fee || !is_liquid)) {
                    set_tx_error(result, res::id_no_amount_specified); // // No amount specified
                } else if (user_fee_rate < min_fee_rate) {
                    set_tx_error(
                        result, res::id_fee_rate_is_below_minimum); // Fee rate is below minimum accepted fee rate
                }

                result["used_utxos"] = used_utxos;
                result["have_change"][asset_tag] = have_change_output;
                result["satoshi"] = required_total.value();

                update_tx_info(net_params, tx, result);

                if (is_rbf && json_get_value(result, "error").empty()) {
                    // Check if rbf requirements are met. When the user input a fee rate for the
                    // replacement, the transaction will be created according to the fee rate itself
                    // and the transaction construction policies. As a result it may occur that rbf
                    // requirements are not met, but, in general, it is not possible to check it
                    // before the transaction is actually constructed.
                    const uint32_t vsize = result.at("transaction_vsize");
                    const amount calculated_fee_rate = amount(result.at("calculated_fee_rate"));
                    const amount bandwith_fee = vsize * min_fee_rate / 1000;
                    if (fee < (old_fee + bandwith_fee) || calculated_fee_rate <= old_fee_rate) {
                        set_tx_error(result, res::id_invalid_replacement_fee_rate);
                    }
                }
            };

            if (is_liquid) {
                std::for_each(std::begin(asset_tags), std::end(asset_tags), [&](const auto& asset_tag) {
                    if (asset_tag != "btc") {
                        create_tx_outputs(asset_tag);
                    }
                });
            }
            // do fee output + L-BTC outputs
            create_tx_outputs("btc");

            if (used_utxos.size() > 1u && json_get_value(result, "randomize_inputs", true)) {
                randomise_inputs(tx, used_utxos);
            }

            if (is_liquid && json_get_value(result, "error").empty()) {
                result = blind_ga_transaction(session, result);
            }
        }

        static void sign_input(ga_session& session, const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u)
        {
            const auto txhash = u.at("txhash");
            const uint32_t subaccount = json_get_value(u, "subaccount", 0u);
            const uint32_t pointer = json_get_value(u, "pointer", 0u);
            const amount::value_type v = u.at("satoshi");
            const amount satoshi{ v };
            const auto type = script_type(u.at("script_type"));
            const std::string private_key = json_get_value(u, "private_key");

            const auto script = h2b(u.at("prevout_script"));

            std::array<unsigned char, SHA256_LEN> tx_hash;

            const uint32_t flags = is_segwit_script_type(type) ? WALLY_TX_FLAG_USE_WITNESS : 0;

            const auto& net_params = session.get_network_parameters();
            if (!net_params.liquid()) {
                tx_hash = tx_get_btc_signature_hash(tx, index, script, satoshi.value(), WALLY_SIGHASH_ALL, flags);
            } else {
                std::vector<unsigned char> ct_value(WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN);
                if (!u.value("commitment", std::string{}).empty()) {
                    ct_value = h2b(u.at("commitment"));
                } else {
                    const auto value = tx_confidential_value_from_satoshi(v);
                    std::copy(std::begin(value), std::end(value), ct_value.begin());
                }
                tx_hash = tx_get_elements_signature_hash(tx, index, script, ct_value, WALLY_SIGHASH_ALL, flags);
            }

            if (!private_key.empty()) {
                const auto private_key_bytes = h2b(private_key);
                const auto user_sig = ec_sig_from_bytes(private_key_bytes, tx_hash);
                tx_set_input_script(
                    tx, index, scriptsig_p2pkh_from_der(h2b(u.at("public_key")), ec_sig_to_der(user_sig, true)));
            } else {
                const auto path = ga_user_pubkeys::get_full_path(subaccount, pointer);
                const auto user_sig = session.sign_hash(path, tx_hash);

                if (is_segwit_script_type(type)) {
                    // TODO: If the UTXO is CSV and expired, spend it using the users key only (smaller)
                    // Note that this requires setting the inputs sequence number to the CSV time too
                    auto wit = tx_witness_stack_init(1);
                    tx_witness_stack_add(wit, ec_sig_to_der(user_sig, true));
                    tx_set_input_witness(tx, index, wit);
                    tx_set_input_script(tx, index, witness_script(script));
                } else {
                    tx_set_input_script(tx, index, input_script(session.supports_low_r(), script, user_sig));
                }
            }
        }
    } // namespace

    nlohmann::json create_ga_transaction(ga_session& session, const nlohmann::json& details)
    {
        // Copy all inputs into our result (they will be overridden below as needed)
        nlohmann::json result(details);
        try {
            // Wrap the actual processing in try/catch
            // The idea here is that result is populated with as much detail as possible
            // before returning any error to allow the caller to make iterative changes
            // fixes each error
            create_ga_transaction_impl(session, result);
        } catch (const std::exception& e) {
            set_tx_error(result, e.what());
        }
        return result;
    }

    void sign_input(ga_session& session, const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u,
        const std::string& der_hex)
    {
        GDK_RUNTIME_ASSERT(json_get_value(u, "private_key").empty());

        const auto type = script_type(u.at("script_type"));
        const auto script = h2b(u.at("prevout_script"));
        auto der = h2b(der_hex);

        if (is_segwit_script_type(type)) {
            // See above re: spending using the users key only
            auto wit = tx_witness_stack_init(1);
            tx_witness_stack_add(wit, der);
            tx_set_input_witness(tx, index, wit);
            tx_set_input_script(tx, index, witness_script(script));
        } else {
            constexpr bool has_sighash = true;
            const auto user_sig = ec_sig_from_der(der, has_sighash);
            tx_set_input_script(tx, index, input_script(session.supports_low_r(), script, user_sig));
        }
    }

    std::vector<nlohmann::json> get_ga_signing_inputs(const nlohmann::json& details)
    {
        const std::string error = json_get_value(details, "error");
        if (!error.empty()) {
            GDK_LOG_SEV(log_level::debug) << " attempt to sign with error: " << details.dump();
            GDK_RUNTIME_ASSERT_MSG(false, error);
        }

        const auto& used_utxos = details.at("used_utxos");
        const auto old_utxos = details.find("old_used_utxos");
        const bool have_old = old_utxos != details.end();

        std::vector<nlohmann::json> result;
        result.reserve(used_utxos.size() + (have_old ? old_utxos->size() : 0));

        if (have_old) {
            for (const auto& utxo : *old_utxos) {
                result.push_back(utxo);
            }
        }

        for (const auto& utxo : used_utxos) {
            result.push_back(utxo);
        }
        return result;
    }

    nlohmann::json sign_ga_transaction(ga_session& session, const nlohmann::json& details)
    {
        const auto inputs = get_ga_signing_inputs(details);
        const auto tx = tx_from_hex(details.at("transaction"),
            WALLY_TX_FLAG_USE_WITNESS | (details.at("liquid") ? WALLY_TX_FLAG_USE_ELEMENTS : 0));

        size_t i = 0;
        for (const auto& utxo : inputs) {
            sign_input(session, tx, i, utxo);
            ++i;
        }

        nlohmann::json result(details);
        result["user_signed"] = true;
        update_tx_info(tx, result);
        return result;
    }

    nlohmann::json blind_ga_transaction(ga_session& session, const nlohmann::json& details)
    {
        const auto& net_params = session.get_network_parameters();
        GDK_RUNTIME_ASSERT(net_params.liquid());

        const std::string error = json_get_value(details, "error");
        if (!error.empty()) {
            GDK_LOG_SEV(log_level::debug) << " attempt to blind with error: " << details.dump();
            GDK_RUNTIME_ASSERT_MSG(false, error);
        }

        const auto tx = tx_from_hex(details.at("transaction"), WALLY_TX_FLAG_USE_WITNESS | WALLY_TX_FLAG_USE_ELEMENTS);

        const auto num_inputs = details.at("used_utxos").size();

        std::vector<unsigned char> input_assets;
        std::vector<unsigned char> input_abfs;
        std::vector<unsigned char> input_vbfs;
        std::vector<unsigned char> input_ags;
        std::vector<uint64_t> input_values;
        for (const auto& utxo : details["used_utxos"]) {
            const auto asset_id = h2b_rev(utxo["asset_id"]);
            input_assets.insert(input_assets.end(), std::begin(asset_id), std::end(asset_id));
            const auto abf = h2b(utxo["abf"]);
            const auto generator = asset_generator_from_bytes(asset_id, abf);
            input_ags.insert(input_ags.end(), std::begin(generator), std::end(generator));
            input_abfs.insert(input_abfs.end(), std::begin(abf), std::end(abf));
            const auto vbf = h2b(utxo["vbf"]);
            input_vbfs.insert(input_vbfs.end(), std::begin(vbf), std::end(vbf));
            input_values.emplace_back(utxo["satoshi"]);
        }

        size_t num_outputs{ 0 };
        const auto transaction_outputs = details.at("transaction_outputs");
        for (const auto& output : transaction_outputs) {
            if (output.at("is_fee")) {
                continue;
            }
            input_values.emplace_back(output["satoshi"]);
            ++num_outputs;
        }

        std::vector<abf_t> output_abfs;
        output_abfs.reserve(num_outputs);
        for (size_t i = 0; i < num_outputs; ++i) {
            output_abfs.emplace_back(get_random_bytes<32>());
        }

        std::vector<vbf_t> output_vbfs;
        output_vbfs.reserve(num_outputs - 1);
        for (size_t i = 0; i < num_outputs - 1; ++i) {
            output_vbfs.emplace_back(get_random_bytes<32>());
        }

        output_vbfs.emplace_back(
            generate_final_vbf(input_abfs, input_vbfs, input_values, output_abfs, output_vbfs, num_inputs));

        size_t i = 0;
        const std::string subaccount_type = details["subaccount_type"];
        const bool authorized_assets = subaccount_type == "2of2_no_recovery";

        std::vector<std::string> blinding_nonces;

        for (const auto& output : transaction_outputs) {
            // IMPORTANT: we assume the fee is always the last output
            if (output.at("is_fee")) {
                if (authorized_assets) {
                    blinding_nonces.emplace_back(std::string{});
                }
                break;
            }

            const auto asset_id = h2b_rev(output.at("asset_id"));
            const auto pub_key = h2b(output.at("public_key"));
            const uint64_t value = output.at("satoshi");

            const auto generator = asset_generator_from_bytes(asset_id, output_abfs[i]);
            const auto value_commitment = asset_value_commitment(value, output_vbfs[i], generator);

            blind_output(session, details, tx, i, output, generator, value_commitment, output_abfs[i], output_vbfs[i]);

            if (authorized_assets) {
                const auto eph_keypair_sec = h2b(output.at("eph_keypair_sec"));
                const auto blinding_nonce = sha256(ecdh(pub_key, eph_keypair_sec));
                blinding_nonces.emplace_back(b2h(blinding_nonce));
            }

            ++i;
        }

        nlohmann::json result(details);
        result["blinded"] = true;
        if (authorized_assets) {
            result["blinding_nonces"] = blinding_nonces;
        }
        update_tx_info(tx, result);
        return result;
    }

    void blind_output(ga_session& session, const nlohmann::json& details, const wally_tx_ptr& tx, uint32_t index,
        const nlohmann::json& output, const std::array<unsigned char, 33>& generator,
        const std::array<unsigned char, 33>& value_commitment, const std::array<unsigned char, 32>& abf,
        const std::array<unsigned char, 32>& vbf)
    {
        const auto& net_params = session.get_network_parameters();
        GDK_RUNTIME_ASSERT(net_params.liquid());
        GDK_RUNTIME_ASSERT(!output.at("is_fee"));

        const std::string error = json_get_value(details, "error");
        if (!error.empty()) {
            GDK_LOG_SEV(log_level::debug) << " attempt to blind with error: " << details.dump();
            GDK_RUNTIME_ASSERT_MSG(false, error);
        }

        std::vector<unsigned char> input_assets;
        std::vector<unsigned char> input_abfs;
        std::vector<unsigned char> input_ags;
        for (const auto& utxo : details["used_utxos"]) {
            const auto asset_id = h2b_rev(utxo["asset_id"]);
            input_assets.insert(input_assets.end(), std::begin(asset_id), std::end(asset_id));
            const auto abf = h2b(utxo["abf"]);
            const auto generator = asset_generator_from_bytes(asset_id, abf);
            input_ags.insert(input_ags.end(), std::begin(generator), std::end(generator));
            input_abfs.insert(input_abfs.end(), std::begin(abf), std::end(abf));
        }

        const auto asset_id = h2b_rev(output.at("asset_id"));
        const auto script = h2b(output.at("script"));
        const auto pub_key = h2b(output.at("public_key"));
        const uint64_t value = output.at("satoshi");

        const auto eph_keypair_sec = h2b(output.at("eph_keypair_sec"));
        const auto eph_keypair_pub = h2b(output.at("eph_keypair_pub"));

        const auto rangeproof = asset_rangeproof(value, pub_key, eph_keypair_sec, asset_id, abf, vbf, value_commitment,
            script, generator, 1, std::min(std::max(net_params.ct_exponent(), -1), 18),
            std::min(std::max(net_params.ct_bits(), 1), 51));

        const auto surjectionproof = asset_surjectionproof(
            asset_id, abf, generator, get_random_bytes<32>(), input_assets, input_abfs, input_ags);

        tx_elements_output_commitment_set(
            tx, index, generator, value_commitment, eph_keypair_pub, surjectionproof, rangeproof);
    }

} // namespace sdk
} // namespace ga
