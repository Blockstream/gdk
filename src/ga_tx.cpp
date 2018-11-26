#include <algorithm>
#include <array>
#include <ctime>
#include <string>
#include <vector>

#include "boost_wrapper.hpp"
#include "ga_strings.hpp"
#include "logging.hpp"
#include "session.hpp"
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

        static void add_paths(session& session, nlohmann::json& utxo)
        {
            const uint32_t subaccount = json_get_value(utxo, "subaccount", 0u);
            const uint32_t pointer = utxo.at("pointer");

            if (utxo.find("user_path") == utxo.end()) {
                // Populate the full user path for h/w signing
                utxo["user_path"] = ga_user_pubkeys::get_full_path(subaccount, pointer);
            }

            if (utxo.find("service_xpub") == utxo.end()) {
                // Populate the service xpub for h/w signing
                utxo["service_xpub"] = session.get_ga_pubkeys().get_subaccount(subaccount).to_base58();
            }

            if (utxo.find("recovery_xpub") == utxo.end()
                && session.get_recovery_pubkeys().have_subaccount(subaccount)) {
                // Populate the recovery xpub for h/w signing
                utxo["recovery_xpub"] = session.get_recovery_pubkeys().get_subaccount(subaccount).to_base58();
            }
        }

        // Add a UTXO to a transaction. Returns the amount added
        static amount add_utxo(session& session, const wally_tx_ptr& tx, nlohmann::json& utxo)
        {
            const std::string txhash = utxo.at("txhash");
            const auto txid = h2b_rev(txhash);
            const uint32_t index = utxo.at("pt_idx");
            const auto type = script_type(utxo.at("script_type"));
            const bool low_r = session.get_signer().supports_low_r();
            const uint32_t dummy_sig_type = low_r ? WALLY_TX_DUMMY_SIG_LOW_R : WALLY_TX_DUMMY_SIG;
            const bool external = !json_get_value(utxo, "private_key").empty();
            const uint32_t sequence = session.is_rbf_enabled() ? 0xFFFFFFFD : 0xFFFFFFFE;

            utxo["sequence"] = sequence;

            if (external) {
                tx_add_raw_input(tx, txid, index, sequence,
                    dummy_external_input_script(session.get_signer(), h2b(utxo.at("public_key"))));
            } else {
                // Populate the prevout script if missing so signing can use it later
                if (utxo.find("prevout_script") == utxo.end()) {
                    const auto script = output_script(
                        session.get_ga_pubkeys(), session.get_user_pubkeys(), session.get_recovery_pubkeys(), utxo);
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
                    tx_add_raw_input(tx, txid, index, sequence, dummy_input_script(session.get_signer(), script));
                }
            }

            return amount(utxo.at("satoshi"));
        }

        // Check if a tx to bump is present, and if so add the details required to bump it
        static std::pair<bool, bool> check_bump_tx(
            session& session, nlohmann::json& result, uint32_t current_subaccount)
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
                const auto subaccount = io.find("subaccount");
                if (subaccount != io.end() && *subaccount == current_subaccount) {
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
                        result["change_address"] = output;
                        add_paths(session, result["change_address"]);
                    }
                    // Save the change subaccount whether we found change or not
                    result["change_subaccount"] = output.at("subaccount");
                }

                result["is_redeposit"] = is_redeposit;
                result["addressees"] = addressees;

                result["have_change"] = change_index != NO_CHANGE_INDEX;
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
                    result["utxos"] = utxos;
                }
            }
            return std::make_pair(is_rbf, is_cpfp);
        }

        static void create_ga_transaction_impl(
            session& session, const network_parameters& net_params, nlohmann::json& result)
        {
            auto& error = result["error"];
            error = std::string(); // Clear any previous error
            result["user_signed"] = false;
            result["server_signed"] = false;

            const uint32_t current_subaccount = result.value("subaccount", session.get_current_subaccount());

            // Check for RBF/CPFP
            bool is_rbf, is_cpfp;
            std::tie(is_rbf, is_cpfp) = check_bump_tx(session, result, current_subaccount);

            const bool is_redeposit = json_get_value(result, "is_redeposit", false);

            if (is_redeposit) {
                if (result.find("addressees") == result.end()) {
                    // For re-deposit/CPFP, create the addressee if not present already
                    const auto address = session.get_receive_address(current_subaccount).at("address");
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

            auto addressees_p = result.find("addressees");
            if (is_sweep) {
                // create sweep transaction
                if (result.find("utxos") != result.end() && !result["utxos"].empty()) {
                    // check for sweep related keys
                    for (const auto& utxo : result["utxos"]) {
                        GDK_RUNTIME_ASSERT(!json_get_value(utxo, "private_key").empty());
                    }
                } else {
                    nlohmann::json utxos;
                    try {
                        utxos = session.get_unspent_outputs_for_private_key(
                            result["private_key"], json_get_value(result, "passphrase"), 0);
                    } catch (const std::exception&) {
                    }
                    result["utxos"] = utxos;
                    if (utxos.empty())
                        set_tx_error(result, res::id_no_utxos_found); // No UTXOs found
                }
                result["send_all"] = true;
                if (addressees_p != result.end()) {
                    // Use the provided address
                    GDK_RUNTIME_ASSERT(addressees_p->size() == 1u);
                    addressees_p->at(0)["satoshi"] = 0;
                } else {
                    // Send to an address in the current subaccount
                    const auto address = session.get_receive_address(current_subaccount).at("address");
                    std::vector<nlohmann::json> addressees;
                    addressees.emplace_back(nlohmann::json({ { "address", address }, { "satoshi", 0 } }));
                    result["addressees"] = addressees;
                    addressees_p = result.find("addressees");
                }
            }

            if (!is_sweep && result.find("utxos") == result.end()) {
                // Fetch the users utxos from the current subaccount.
                // Always spend utxos with 1 confirmation, unless we are in testnet.
                // Even in testnet, if RBFing, require 1 confirmation.
                const bool main_net = net_params.main_net();
                const uint32_t num_confs = (main_net || is_rbf || is_cpfp) && !is_sweep ? 1 : 0;
                result["utxos"] = session.get_unspent_outputs(current_subaccount, num_confs);
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

            // Add all outputs and compute the total amount of satoshi to be sent
            amount required_total{ 0 };

            if (num_addressees) {
                for (auto& addressee : *addressees_p) {
                    required_total += add_tx_addressee(session, net_params, result, tx, addressee);
                }
            }

            std::vector<uint32_t> used_utxos;
            used_utxos.reserve(utxos.size());
            uint32_t utxo_index = 0;

            amount available_total, total, fee, v;

            if (is_rbf) {
                // Add all the old utxos. Note we don't add them to used_utxos
                // since the user can't choose to remove them
                for (auto& utxo : result.at("old_used_utxos")) {
                    v = add_utxo(session, tx, utxo);
                    available_total += v;
                    total += v;
                }
            }

            if (manual_selection) {
                // Add all selected utxos
                for (const auto& ui : result.at("used_utxos")) {
                    utxo_index = ui;
                    v = add_utxo(session, tx, utxos.at(utxo_index));
                    available_total += v;
                    total += v;
                    used_utxos.emplace_back(utxo_index);
                }
            } else {
                // Collect utxos in order until we have covered the amount to send
                // FIXME: Better coin selection algorithms (esp. minimum size)
                for (auto& utxo : utxos) {
                    if (send_all || total < required_total) {
                        v = add_utxo(session, tx, utxo);
                        total += v;
                        used_utxos.emplace_back(utxo_index);
                        ++utxo_index;
                    } else {
                        v = static_cast<amount::value_type>(utxo.at("satoshi"));
                    }
                    available_total += v;
                }
            }

            // Return the available total for client insufficient fund handling
            result["available_total"] = available_total.value();

            bool have_change_output = false;
            uint32_t change_index = NO_CHANGE_INDEX;
            if (is_rbf) {
                have_change_output = json_get_value(result, "have_change", false);
                if (have_change_output) {
                    add_tx_output(net_params, result, tx, result.at("change_address").at("address"));
                    change_index = tx->num_outputs - 1;
                }
            }

            const amount dust_threshold = session.get_dust_threshold();
            const amount user_fee_rate = amount(result.at("fee_rate"));
            const amount min_fee_rate = session.get_min_fee_rate();
            const amount old_fee_rate = amount(json_get_value(result, "old_fee_rate", 0u));
            const amount old_fee = amount(json_get_value(result, "old_fee", 0u));
            const amount network_fee = amount(json_get_value(result, "network_fee", 0u));

            bool force_add_uxto = false;

            const size_t max_loop_iterations = utxos.size() * 2 + 1; // +1 in case empty+send all
            size_t loop_iterations;

            for (loop_iterations = 0; loop_iterations < max_loop_iterations; ++loop_iterations) {
                amount change, required_with_fee;

                fee = get_tx_fee(tx, min_fee_rate, user_fee_rate);
                fee += network_fee;

                if (send_all) {
                    if (available_total < fee + dust_threshold) {
                        // After paying the fee, we only have dust left, so
                        // the requested amount isn't payable
                        set_tx_error(result, res::id_insufficient_funds); // Insufficient funds
                    } else {
                        // We are sending everything without a change output,
                        // so compute what we can send (everything minus the
                        // fee) and exit the loop
                        required_total = available_total - fee;
                        tx->outputs[0].satoshi = required_total.value();
                        if (num_addressees == 1u) {
                            addressees_p->at(0)["satoshi"] = required_total.value();
                        }
                    }
                    goto leave_loop;
                }

                required_with_fee = required_total + fee;
                if (total < required_with_fee || force_add_uxto) {
                    // We don't have enough funds to cover the fee yet, or we
                    // need to add more to avoid a dusty change output
                    force_add_uxto = false;
                    if (manual_selection || used_utxos.size() == utxos.size()) {
                        // Used all inputs and do not have enough funds
                        set_tx_error(result, res::id_insufficient_funds); // Insufficient funds
                        goto leave_loop;
                    }

                    // FIXME: Use our strategy here when non-default implemented
                    total += add_utxo(session, tx, utxos.at(utxo_index));
                    used_utxos.emplace_back(utxo_index);
                    ++utxo_index;
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
                    force_add_uxto = true;
                    continue;
                }

                // We have more than the dust amount of change. Add a change
                // output to collect it, then loop again in case the amount
                // this increases the fee by requires more UTXOs.
                auto change_address_p = result.find("change_address");
                if (change_address_p == result.end()) {
                    // No previously generated change address found, so generate one.
                    // Find out where to send any change
                    const uint32_t change_subaccount = result.value("change_subaccount", current_subaccount);
                    result["change_subaccount"] = change_subaccount;
                    auto change_address = session.get_receive_address(change_subaccount);
                    add_paths(session, change_address);
                    result["change_address"] = change_address;
                    change_address_p = result.find("change_address");
                }
                add_tx_output(net_params, result, tx, change_address_p->at("address"));
                have_change_output = true;
                change_index = tx->num_outputs - 1;
            }

            if (loop_iterations >= max_loop_iterations) {
                GDK_LOG_SEV(log_level::error) << "Endless tx loop building: " << result.dump();
                GDK_RUNTIME_ASSERT(false);
            }

            result["used_utxos"] = used_utxos;
            result["have_change"] = have_change_output;
            result["satoshi"] = required_total.value();

            amount::value_type change_amount = 0;
            if (have_change_output) {
                // Set the change amount
                auto& change_output = tx->outputs[change_index];
                change_output.satoshi = (total - required_total - fee).value();
                change_amount = change_output.satoshi;
                const uint32_t new_change_index = get_uniform_uint32_t(tx->num_outputs);
                if (change_index != new_change_index) {
                    // Randomize change output
                    std::swap(tx->outputs[new_change_index], change_output);
                    change_index = new_change_index;
                }
            }
            result["change_amount"] = change_amount;
            result["change_index"] = change_index;

            if (required_total == 0) {
                set_tx_error(result, res::id_no_amount_specified); // // No amount specified
            } else if (user_fee_rate < min_fee_rate) {
                set_tx_error(result, res::id_fee_rate_is_below_minimum); // Fee rate is below minimum accepted fee rate
            }
            update_tx_info(tx, result);

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
        } // namespace
    } // namespace

    nlohmann::json create_ga_transaction(
        session& session, const network_parameters& net_params, const nlohmann::json& details)
    {
        // Copy all inputs into our result (they will be overridden below as needed)
        nlohmann::json result(details);
        try {
            // Wrap the actual processing in try/catch
            // The idea here is that result is populated with as much detail as possible
            // before returning any error to allow the caller to make iterative changes
            // fixes each error
            create_ga_transaction_impl(session, net_params, result);
        } catch (const std::exception& e) {
            set_tx_error(result, e.what());
        }
        return result;
    }

    static void sign_input(session& session, const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u)
    {
        const auto txhash = u.at("txhash");
        const uint32_t subaccount = json_get_value(u, "subaccount", 0u);
        const uint32_t pointer = json_get_value(u, "pointer", 0u);
        const amount::value_type v = u.at("satoshi");
        const amount satoshi{ v };
        const auto type = script_type(u.at("script_type"));
        const std::string private_key = json_get_value(u, "private_key");

        const auto script = h2b(u.at("prevout_script"));

        const uint32_t flags = is_segwit_script_type(type) ? WALLY_TX_FLAG_USE_WITNESS : 0;
        const auto tx_hash = tx_get_btc_signature_hash(tx, index, script, satoshi.value(), WALLY_SIGHASH_ALL, flags);

        if (!private_key.empty()) {
            const auto private_key_bytes = h2b(private_key);
            const auto user_sig = ec_sig_from_bytes(private_key_bytes, tx_hash);
            tx_set_input_script(
                tx, index, scriptsig_p2pkh_from_der(h2b(u.at("public_key")), ec_sig_to_der(user_sig, true)));
        } else {
            const auto path = ga_user_pubkeys::get_full_path(subaccount, pointer);
            const auto user_sig = session.get_signer().sign_hash(path, tx_hash);

            if (is_segwit_script_type(type)) {
                // TODO: If the UTXO is CSV and expired, spend it using the users key only (smaller)
                // Note that this requires setting the inputs sequence number to the CSV time too
                auto wit = tx_witness_stack_init(1);
                tx_witness_stack_add(wit, ec_sig_to_der(user_sig, true));
                tx_set_input_witness(tx, index, wit);
                tx_set_input_script(tx, index, witness_script(script));
            } else {
                tx_set_input_script(tx, index, input_script(session.get_signer(), script, user_sig));
            }
        }
    }

    void sign_input(
        session& session, const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u, const std::string& der_hex)
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
            tx_set_input_script(tx, index, input_script(session.get_signer(), script, user_sig));
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

        const auto& utxos = details.at("utxos");
        for (const auto& ui : used_utxos) {
            const uint32_t utxo_index = ui;
            result.push_back(utxos.at(utxo_index));
        }
        return result;
    }

    nlohmann::json sign_ga_transaction(session& session, const nlohmann::json& details)
    {
        const auto inputs = get_ga_signing_inputs(details);
        const auto tx = tx_from_hex(details.at("transaction"));

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
} // namespace sdk
} // namespace ga
