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
#include "signer.hpp"
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

        static void add_paths(ga_session& session, nlohmann::json& utxo)
        {
            const uint32_t subaccount = json_get_value(utxo, "subaccount", 0u);
            const uint32_t pointer = utxo.at("pointer");

            if (utxo.find("user_path") == utxo.end()) {
                // Populate the full user path for h/w signing
                utxo["user_path"] = session.get_subaccount_full_path(subaccount, pointer);
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
            const bool low_r = session.get_nonnull_signer()->supports_low_r();
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

        static ecdsa_sig_t ec_sig_from_witness(const wally_tx_ptr& tx, size_t input_index, size_t item_index)
        {
            constexpr bool has_sighash = true;
            const auto& witness = tx->inputs[input_index].witness;
            const auto& witness_item = witness->items[item_index];
            GDK_RUNTIME_ASSERT(witness_item.witness != nullptr && witness_item.witness_len != 0);
            const auto der_sig = gsl::make_span(witness_item.witness, witness_item.witness_len);
            return ec_sig_from_der(der_sig, has_sighash);
        }

        std::vector<ecdsa_sig_t> get_signatures_from_input(
            const nlohmann::json& utxo, const wally_tx_ptr& tx, size_t index, bool is_liquid)
        {
            GDK_RUNTIME_ASSERT(index < tx->num_inputs);
            // TODO: handle backup paths:
            // - 2of3 p2sh, backup key signing
            // - 2of3 p2wsh, backup key signing
            // - 2of2 csv, csv path
            const auto type = script_type(utxo.at("script_type"));
            if (!is_segwit_script_type(type)) {
                // 2of2 p2sh: script sig: OP_0 <ga_sig> <user_sig>
                // 2of3 p2sh: script sig: OP_0 <ga_sig> <user_sig>
                const auto& input = tx->inputs[index];
                return get_sigs_from_multisig_script_sig(gsl::make_span(input.script, input.script_len));
            }
            // 2of2 p2wsh: witness stack: <> <ga_sig> <user_sig> <redeem_script>
            // 2of2 csv:   witness stack: <ga_sig> <user_sig> <redeem_script>
            // 2of3 p2wsh: witness stack: <> <ga_sig> <user_sig> <redeem_script>
            const auto& witness = tx->inputs[index].witness;
            GDK_RUNTIME_ASSERT(witness != nullptr && witness->num_items > 2);

            auto user_sig = ec_sig_from_witness(tx, index, witness->num_items - 2);
            auto ga_sig = ec_sig_from_witness(tx, index, witness->num_items - 3);

            // Liquid outputs:
            // 2of2 csv:   witness stack: <user_sig> <ga_sig> <redeem_script> (not optimized)
            // 2of2 p2wsh: witness stack: <> <ga_sig> <user_sig> <redeem_script> (no recovery)
            if (is_liquid && type == script_type::ga_redeem_p2sh_p2wsh_csv_fortified) {
                std::swap(user_sig, ga_sig);
            }

            return std::vector<ecdsa_sig_t>({ ga_sig, user_sig });
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
            const std::string policy_asset("btc"); // FIXME: Bump/CPFP for liquid

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

            const auto tx = session.get_raw_transaction_details(prev_tx.at("txhash"));
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
                GDK_RUNTIME_ASSERT(tx->num_outputs == outputs.size());
                addressees.reserve(outputs.size());
                uint32_t i = 0, change_index = NO_CHANGE_INDEX;

                const auto& net_params = session.get_network_parameters();
                for (const auto& output : outputs) {
                    if (!output.at("address").empty()) {
                        // Validate address matches the transaction scriptpubkey
                        const auto spk_from_address
                            = scriptpubkey_from_address(net_params, session.get_block_height(), output["address"]);
                        const auto& o = tx->outputs[i];
                        const auto spk_from_tx = gsl::make_span(o.script, o.script_len);
                        GDK_RUNTIME_ASSERT(static_cast<size_t>(spk_from_tx.size()) == spk_from_address.size());
                        GDK_RUNTIME_ASSERT(
                            std::equal(spk_from_address.begin(), spk_from_address.end(), spk_from_tx.begin()));
                    }
                    const bool is_relevant = json_get_value(output, "is_relevant", false);
                    if (is_relevant) {
                        // Validate address is owned by the wallet
                        const auto output_script = session.output_script_from_utxo(output);
                        const std::string address
                            = get_address_from_script(net_params, output_script, output.at("address_type"));
                        GDK_RUNTIME_ASSERT(output["address"] == address);
                    }
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
                        result["change_address"][policy_asset] = output;
                        add_paths(session, result["change_address"][policy_asset]);
                    }
                    // Save the change subaccount whether we found change or not
                    result["change_subaccount"] = output.at("subaccount");
                }

                result["is_redeposit"] = is_redeposit;
                result["addressees"] = addressees;

                result["have_change"][policy_asset] = change_index != NO_CHANGE_INDEX;
                if (change_index == NO_CHANGE_INDEX && !is_redeposit) {
                    for (const auto& in : prev_tx["inputs"]) {
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
                        utxo["txhash"] = b2h_rev(tx->inputs[i].txhash);
                        utxo["pt_idx"] = tx->inputs[i].index;
                        calculate_input_subtype(utxo, tx, i);
                        const auto script = session.output_script_from_utxo(utxo);
                        utxo["prevout_script"] = b2h(script);
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

                // Verify the transaction signatures to prevent outputs
                // from being modified.
                uint32_t vin = 0;
                for (const auto& input : result["old_used_utxos"]) {
                    const auto sigs = get_signatures_from_input(input, tx, vin, net_params.is_liquid());
                    const auto pubkeys = session.pubkeys_from_utxo(input);
                    const auto script_hash = get_script_hash(net_params, input, tx, vin);
                    GDK_RUNTIME_ASSERT(ec_sig_verify(pubkeys.at(0), script_hash, sigs.at(0))); // ga
                    GDK_RUNTIME_ASSERT(ec_sig_verify(pubkeys.at(1), script_hash, sigs.at(1))); // user
                    ++vin;
                }
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
                    result["utxos"][policy_asset] = utxos;
                }
            }
            return { is_rbf, is_cpfp };
        }

        static void create_send_to_self(ga_session& session, uint32_t subaccount, nlohmann::json& result)
        {
            // Set addressees to a wallet address from the given subaccount
            const auto addr = session.get_receive_address({ { "subaccount", subaccount } });
            const auto address = addr.at("address");
            std::vector<nlohmann::json> addressees;
            addressees.emplace_back(nlohmann::json({ { "address", address }, { "satoshi", 0 } }));
            result["addressees"] = addressees;
        }

        static void create_ga_transaction_impl(ga_session& session, nlohmann::json& result)
        {
            const auto& net_params = session.get_network_parameters();
            const bool is_liquid = net_params.is_liquid();
            const auto policy_asset = is_liquid ? net_params.policy_asset() : std::string("btc");

            result["error"] = std::string(); // Clear any previous error
            result["user_signed"] = false;
            result["server_signed"] = false;

            // Must specify subaccount to use
            const auto p_subaccount = result.find("subaccount");
            GDK_RUNTIME_ASSERT(p_subaccount != result.end());
            const uint32_t subaccount = *p_subaccount;
            result["subaccount_type"] = session.get_subaccount(subaccount)["type"];

            // Check for RBF/CPFP
            bool is_rbf, is_cpfp;
            std::tie(is_rbf, is_cpfp) = check_bump_tx(session, result, subaccount);

            const bool is_redeposit = json_get_value(result, "is_redeposit", false);

            if (is_redeposit) {
                if (result.find("addressees") == result.end()) {
                    create_send_to_self(session, subaccount, result);
                }
                // When re-depositing, send everything and don't create change
                result["send_all"] = true;
            }
            result["is_redeposit"] = is_redeposit;

            const bool is_sweep = result.find("private_key") != result.end();
            result["is_sweep"] = is_sweep;

            // Let the caller know if addressees should not be modified
            result["addressees_read_only"] = is_redeposit || is_rbf || is_cpfp || is_sweep;

            auto addressees_p = result.find("addressees");
            if (is_sweep) {
                if (is_liquid) {
                    set_tx_error(result, "sweep not supported for liquid");
                    return;
                }

                if (result.contains("utxos") && !result["utxos"][policy_asset].empty()) {
                    // check for sweep related keys
                    for (const auto& utxo : result["utxos"][policy_asset]) {
                        GDK_RUNTIME_ASSERT(!json_get_value(utxo, "private_key").empty());
                    }
                } else {
                    nlohmann::json sweep_utxos;
                    try {
                        sweep_utxos = session.get_unspent_outputs_for_private_key(
                            result["private_key"], json_get_value(result, "passphrase"), 0);
                    } catch (const assertion_error& ex) {
                        set_tx_error(result, res::id_invalid_private_key); // Invalid private key
                    } catch (const std::exception& ex) {
                        GDK_LOG_SEV(log_level::error) << "Exception getting outputs for private key: " << ex.what();
                    }
                    result["utxos"][policy_asset] = sweep_utxos;
                    if (sweep_utxos.empty()) {
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
                    create_send_to_self(session, subaccount, result);
                    addressees_p = result.find("addressees");
                }
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

            std::set<std::string> asset_ids;
            bool have_assets = json_get_value(result, "addressees_have_assets", false);
            if (num_addressees) {
                for (auto& addressee : *addressees_p) {
                    const std::string asset_id_hex = validate_tx_addressee(net_params, result, addressee);
                    if (!json_get_value(result, "error").empty()) {
                        // FIXME: should probably either exit early or continue
                        // and not overwrite error here
                        break;
                    }
                    asset_ids.insert(asset_id_hex);
                }
            }

            if (is_liquid) {
                if (asset_ids.size() > 1) {
                    set_tx_error(result, "Multi-asset send not supported");
                }
                have_assets = true;
            } else {
                if (have_assets) {
                    set_tx_error(result, res::id_assets_cannot_be_used_on_bitcoin);
                }
            }
            result["addressees_have_assets"] = have_assets;

            std::vector<nlohmann::json> reordered_addressees;

            auto create_tx_outputs = [&](const std::string& asset_id) {
                const bool include_fee = asset_id == policy_asset;

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
                        const auto addressee_asset_id = asset_id_from_json(net_params, addressee);
                        if (addressee_asset_id == asset_id) {
                            required_total += add_tx_addressee(session, net_params, result, tx, addressee);
                            reordered_addressees.push_back(addressee);
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
                    const auto asset_utxos_p = utxos.find(asset_id);
                    if (asset_utxos_p == utxos.end()) {
                        if (!is_rbf) {
                            set_tx_error(result, res::id_insufficient_funds); // Insufficient funds
                        }
                    } else {
                        for (auto& utxo : utxos.at(asset_id)) {
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
                        = have_change_p != result.end() ? json_get_value(*have_change_p, policy_asset, false) : false;
                    if (have_change_output) {
                        const auto change_address = result.at("change_address").at(policy_asset).at("address");
                        add_tx_output(net_params, session.get_block_height(), result, tx, change_address);
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

                bool have_change_addr = result.find("change_address") != result.end();
                if (have_change_addr) {
                    const auto asset_change_address
                        = result.at("change_address").value(asset_id, nlohmann::json::object());
                    have_change_addr = !asset_change_address.empty();
                }
                if (!have_change_addr) {
                    // No previously generated change address found, so generate one.
                    // Find out where to send any change
                    const uint32_t change_subaccount = result.value("change_subaccount", subaccount);
                    result["change_subaccount"] = change_subaccount;
                    auto change_address = session.get_receive_address({ { "subaccount", change_subaccount } });
                    if (is_liquid) {
                        // set a temporary blinding key, will be changed later through the resolvers. we need
                        // to have one because all our create_transaction logic relies on being able to blind
                        // the tx for a few things (fee estimation for instance).
                        const auto blinded_prefix = session.get_network_parameters().blinded_prefix();
                        const auto public_key
                            = h2b("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
                        const auto& unblinded_addr = change_address.at("address");
                        change_address["address"]
                            = confidential_addr_from_addr(unblinded_addr, blinded_prefix, public_key);
                        change_address["is_blinded"] = false;
                    }

                    add_paths(session, change_address);
                    result["change_address"][asset_id] = change_address;
                }

                const size_t max_loop_iterations
                    = std::max(size_t(8), utxos.size() * 2 + 1); // +1 in case empty+send all
                size_t loop_iterations;

                for (loop_iterations = 0; loop_iterations < max_loop_iterations; ++loop_iterations) {
                    amount change, required_with_fee;

                    if (include_fee) {
                        // add fee output so is also part of size calculations
                        if (is_liquid) {
                            constexpr amount::value_type dummy_amount = 1;
                            if (!have_fee_output) {
                                if (send_all && addressees_p->at(0).value("asset_id", policy_asset) == asset_id) {
                                    // the output commitment will be corrected below. this is a placeholder for the
                                    // blinding.
                                    set_tx_output_commitment(tx, 0, asset_id, dummy_amount);
                                }
                                fee_index = add_tx_fee_output(net_params, tx, dummy_amount);
                                have_fee_output = true;
                            }
                            update_tx_info(net_params, tx, result);
                            std::vector<nlohmann::json> used = json_get_value<decltype(used)>(result, "used_utxos");
                            used.insert(used.end(), current_used_utxos.begin(), current_used_utxos.end());
                            result["used_utxos"] = used;
                            const auto blinded = blind_ga_transaction(session, result);
                            const auto fee_tx = tx_from_hex(blinded["transaction"], tx_flags(is_liquid));
                            fee = get_tx_fee(fee_tx, min_fee_rate, user_fee_rate);
                        } else {
                            fee = get_tx_fee(tx, min_fee_rate, user_fee_rate);
                        }

                        fee += network_fee;
                    }

                    if (send_all && addressees_p->at(0).value("asset_id", policy_asset) == asset_id) {
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
                                set_tx_output_commitment(tx, 0, asset_id, required_total.value());
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
                            || current_used_utxos.size() == utxos.at(asset_id).size()) {
                            // Used all inputs and do not have enough funds
                            set_tx_error(result, res::id_insufficient_funds); // Insufficient funds
                            goto leave_loop;
                        }

                        // FIXME: Use our strategy here when non-default implemented
                        auto& utxo = utxos.at(asset_id).at(current_used_utxos.size());
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
                    const auto change_address = result.at("change_address").at(asset_id).at("address");
                    add_tx_output(net_params, session.get_block_height(), result, tx, change_address, is_liquid ? 1 : 0,
                        asset_id);
                    have_change_output = true;
                    change_index = tx->num_outputs - 1;
                    if (is_liquid && include_fee) {
                        std::swap(tx->outputs[fee_index], tx->outputs[change_index]);
                        std::swap(fee_index, change_index);
                    }
                    result["have_change"][asset_id] = have_change_output;
                    result["change_index"][asset_id] = change_index;
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
                            set_tx_output_commitment(tx, change_index, asset_id, change_amount);
                        } else {
                            auto& change_output = tx->outputs[change_index];
                            change_output.satoshi = change_amount;
                            const uint32_t new_change_index = get_uniform_uint32_t(tx->num_outputs);
                            // Randomize change output
                            // Move change output to random offset in tx outputs while
                            // preserving the ordering of the other outputs
                            while (change_index < new_change_index) {
                                std::swap(tx->outputs[change_index], tx->outputs[change_index + 1]);
                                ++change_index;
                            }
                            while (change_index > new_change_index) {
                                std::swap(tx->outputs[change_index], tx->outputs[change_index - 1]);
                                --change_index;
                            }
                        }
                    }
                    // TODO: change amount should be liquid specific (blinded)
                    result["change_amount"][asset_id] = change_amount;
                    result["change_index"][asset_id] = change_index;
                };

                update_change_output(fee);

                if (include_fee && is_liquid) {
                    set_tx_output_commitment(tx, fee_index, asset_id, fee.value());
                }

                if (required_total == 0 && (!include_fee || !is_liquid)) {
                    set_tx_error(result, res::id_no_amount_specified); // // No amount specified
                } else if (user_fee_rate < min_fee_rate) {
                    set_tx_error(
                        result, res::id_fee_rate_is_below_minimum); // Fee rate is below minimum accepted fee rate
                }

                result["used_utxos"] = used_utxos;
                result["have_change"][asset_id] = have_change_output;
                result["satoshi"][asset_id] = required_total.value();

                update_tx_info(net_params, tx, result);

                if (is_rbf && json_get_value(result, "error").empty()) {
                    // Check if rbf requirements are met. When the user input a fee rate for the
                    // replacement, the transaction will be created according to the fee rate itself
                    // and the transaction construction policies. As a result it may occur that rbf
                    // requirements are not met, but, in general, it is not possible to check it
                    // before the transaction is actually constructed.
                    const uint32_t vsize = result.at("transaction_vsize");
                    const amount calculated_fee_rate = amount(result.at("calculated_fee_rate"));
                    const amount bandwidth_fee = vsize * min_fee_rate / 1000;
                    if (fee < (old_fee + bandwidth_fee) || calculated_fee_rate <= old_fee_rate) {
                        set_tx_error(result, res::id_invalid_replacement_fee_rate);
                    }
                }
            };

            if (is_liquid) {
                std::for_each(std::begin(asset_ids), std::end(asset_ids), [&](const auto& id) {
                    if (id != policy_asset) {
                        create_tx_outputs(id);
                    }
                });
            }
            // do fee output + L-BTC outputs
            create_tx_outputs(policy_asset);

            result["addressees"] = reordered_addressees;

            if (used_utxos.size() > 1u && json_get_value(result, "randomize_inputs", true)) {
                randomise_inputs(tx, used_utxos);
            }

            if (is_liquid && json_get_value(result, "error").empty()) {
                result = blind_ga_transaction(session, result);
            }
        }

        static std::string sign_input(
            session_impl& session, const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u)
        {
            const auto txhash = u.at("txhash");
            const uint32_t subaccount = json_get_value(u, "subaccount", 0u);
            const uint32_t pointer = json_get_value(u, "pointer", 0u);
            const auto type = script_type(u.at("script_type"));
            const auto script = h2b(u.at("prevout_script"));
            const std::string private_key = json_get_value(u, "private_key");
            auto signer = session.get_nonnull_signer();
            const bool low_r = signer->supports_low_r();

            std::array<unsigned char, SHA256_LEN> tx_hash;
            const auto& net_params = session.get_network_parameters();
            tx_hash = get_script_hash(net_params, u, tx, index);

            if (!private_key.empty()) {
                const auto private_key_bytes = h2b(private_key);
                const auto user_sig = ec_sig_from_bytes(private_key_bytes, tx_hash);
                const auto der = ec_sig_to_der(user_sig, true);
                tx_set_input_script(tx, index, scriptsig_p2pkh_from_der(h2b(u.at("public_key")), der));
                return b2h(der);
            } else {
                const auto path = session.get_subaccount_full_path(subaccount, pointer);
                const auto user_sig = signer->sign_hash(path, tx_hash);
                const auto der = ec_sig_to_der(user_sig, true);

                if (is_segwit_script_type(type)) {
                    // TODO: If the UTXO is CSV and expired, spend it using the users key only (smaller)
                    // Note that this requires setting the inputs sequence number to the CSV time too
                    auto wit = tx_witness_stack_init(1);
                    tx_witness_stack_add(wit, der);
                    tx_set_input_witness(tx, index, wit);
                    const uint32_t witness_ver = 0;
                    tx_set_input_script(tx, index, witness_script(script, witness_ver));
                } else {
                    tx_set_input_script(tx, index, input_script(low_r, script, user_sig));
                }
                return b2h(der);
            }
        }
    } // namespace

    std::array<unsigned char, SHA256_LEN> get_script_hash(
        const network_parameters& net_params, const nlohmann::json& utxo, const wally_tx_ptr& tx, size_t index)
    {
        const amount::value_type v = utxo.at("satoshi");
        const auto type = script_type(utxo.at("script_type"));
        const auto script = h2b(utxo.at("prevout_script"));

        const uint32_t flags = is_segwit_script_type(type) ? WALLY_TX_FLAG_USE_WITNESS : 0;

        if (!net_params.is_liquid()) {
            const amount satoshi{ v };
            return tx_get_btc_signature_hash(tx, index, script, satoshi.value(), WALLY_SIGHASH_ALL, flags);
        }

        // Liquid case - has a value-commitment in place of a satoshi value
        std::vector<unsigned char> ct_value;
        if (!utxo.value("commitment", std::string{}).empty()) {
            ct_value = h2b(utxo.at("commitment"));
        } else {
            const auto value = tx_confidential_value_from_satoshi(v);
            ct_value.assign(std::begin(value), std::end(value));
        }
        return tx_get_elements_signature_hash(tx, index, script, ct_value, WALLY_SIGHASH_ALL, flags);
    }

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

    void add_input_signature(
        const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u, const std::string& der_hex, bool is_low_r)
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
            const uint32_t witness_ver = 0;
            tx_set_input_script(tx, index, witness_script(script, witness_ver));
        } else {
            constexpr bool has_sighash = true;
            const auto user_sig = ec_sig_from_der(der, has_sighash);
            tx_set_input_script(tx, index, input_script(is_low_r, script, user_sig));
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

    std::pair<std::vector<std::string>, wally_tx_ptr> sign_ga_transaction(
        session_impl& session, const nlohmann::json& details, const std::vector<nlohmann::json>& inputs)
    {
        const bool is_liquid = session.get_network_parameters().is_liquid();
        wally_tx_ptr tx = tx_from_hex(details.at("transaction"), tx_flags(is_liquid));
        std::vector<std::string> sigs;
        sigs.reserve(inputs.size());

        size_t i = 0;
        for (const auto& utxo : inputs) {
            sigs.emplace_back(utxo.empty() ? std::string() : sign_input(session, tx, i, utxo));
            ++i;
        }
        return std::make_pair(sigs, std::move(tx));
    }

    // FIXME: Only used for sweep txs, refactor to remove
    nlohmann::json sign_ga_transaction(session_impl& session, const nlohmann::json& details)
    {
        auto tx = sign_ga_transaction(session, details, get_ga_signing_inputs(details)).second;
        nlohmann::json result(details);
        result.erase("utxos");
        result["user_signed"] = true;
        const auto& net_params = session.get_network_parameters();
        update_tx_size_info(net_params, tx, result);
        return result;
    }

    nlohmann::json blind_ga_transaction(ga_session& session, const nlohmann::json& details)
    {
        const auto& net_params = session.get_network_parameters();
        GDK_RUNTIME_ASSERT(net_params.is_liquid());

        const std::string error = json_get_value(details, "error");
        if (!error.empty()) {
            GDK_LOG_SEV(log_level::debug) << " attempt to blind with error: " << details.dump();
            GDK_RUNTIME_ASSERT_MSG(false, error);
        }

        constexpr bool is_liquid = true;
        const auto tx = tx_from_hex(details.at("transaction"), tx_flags(is_liquid));

        const auto num_inputs = details.at("used_utxos").size();

        std::vector<unsigned char> input_assets;
        std::vector<unsigned char> input_abfs;
        std::vector<unsigned char> input_vbfs;
        std::vector<unsigned char> input_ags;
        std::vector<uint64_t> input_values;
        for (const auto& utxo : details["used_utxos"]) {
            const auto asset_id = h2b_rev(utxo.at("asset_id"));
            input_assets.insert(input_assets.end(), std::begin(asset_id), std::end(asset_id));
            const auto abf = h2b_rev(utxo.at("assetblinder"));
            const auto generator = asset_generator_from_bytes(asset_id, abf);
            input_ags.insert(input_ags.end(), std::begin(generator), std::end(generator));
            input_abfs.insert(input_abfs.end(), std::begin(abf), std::end(abf));
            const auto vbf = h2b_rev(utxo.at("amountblinder"));
            input_vbfs.insert(input_vbfs.end(), std::begin(vbf), std::end(vbf));
            input_values.emplace_back(utxo.at("satoshi"));
        }

        size_t num_outputs{ 0 };
        const auto& transaction_outputs = details.at("transaction_outputs");

        for (const auto& output : transaction_outputs) {
            if (output.at("is_fee")) {
                continue;
            }
            input_values.emplace_back(output.at("satoshi"));
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
        update_tx_size_info(net_params, tx, result);
        return result;
    }

    void blind_output(session_impl& session, const nlohmann::json& details, const wally_tx_ptr& tx, uint32_t index,
        const nlohmann::json& output, const std::array<unsigned char, 33>& generator,
        const std::array<unsigned char, 33>& value_commitment, const std::array<unsigned char, 32>& abf,
        const std::array<unsigned char, 32>& vbf)
    {
        const auto& net_params = session.get_network_parameters();
        GDK_RUNTIME_ASSERT(net_params.is_liquid());
        GDK_RUNTIME_ASSERT(!output.at("is_fee"));

        const std::string error = json_get_value(details, "error");
        if (!error.empty()) {
            GDK_LOG_SEV(log_level::debug) << " attempt to blind with error: " << details.dump();
            GDK_RUNTIME_ASSERT_MSG(false, error);
        }

        // FIXME: Compute these up front
        std::vector<unsigned char> input_assets;
        std::vector<unsigned char> input_abfs;
        std::vector<unsigned char> input_ags;
        for (const auto& utxo : details["used_utxos"]) {
            const auto asset_id = h2b_rev(utxo["asset_id"]);
            input_assets.insert(input_assets.end(), std::begin(asset_id), std::end(asset_id));
            const auto abf = h2b_rev(utxo["assetblinder"]);
            input_abfs.insert(input_abfs.end(), std::begin(abf), std::end(abf));
            const auto asset_generator = asset_generator_from_bytes(asset_id, abf);
            input_ags.insert(input_ags.end(), std::begin(asset_generator), std::end(asset_generator));
        }

        const auto asset_id = h2b_rev(output.at("asset_id"));
        const auto script = h2b(output.at("script"));
        const auto pub_key = h2b(output.at("public_key"));
        const uint64_t value = output.at("satoshi");

        const auto eph_keypair_sec = h2b(output.at("eph_keypair_sec"));
        const auto eph_keypair_pub = h2b(output.at("eph_keypair_pub"));

        const auto rangeproof = asset_rangeproof(value, pub_key, eph_keypair_sec, asset_id, abf, vbf, value_commitment,
            script, generator, 1, std::min(std::max(net_params.ct_exponent(), -1), 18), net_params.ct_bits());

        const auto surjectionproof = asset_surjectionproof(
            asset_id, abf, generator, get_random_bytes<32>(), input_assets, input_abfs, input_ags);

        tx_elements_output_commitment_set(
            tx, index, generator, value_commitment, eph_keypair_pub, surjectionproof, rangeproof);
    }

} // namespace sdk
} // namespace ga
