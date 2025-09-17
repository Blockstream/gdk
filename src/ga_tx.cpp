#include <algorithm>
#include <array>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/endian/conversion.hpp>
#include <ctime>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "amount.hpp"
#include "containers.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "json_utils.hpp"
#include "logging.hpp"
#include "session_impl.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

#include <wally_coinselection.h>

namespace green {

    namespace {
        static const std::string UTXO_SEL_DEFAULT("default"); // Use the default utxo selection strategy
        static const std::string UTXO_SEL_MANUAL("manual"); // Use manual utxo selection

        static const std::string ZEROS(64, '0');

        static bool is_explicit(const wally_tx_output& output)
        {
            return output.asset_len == WALLY_TX_ASSET_CT_ASSET_LEN
                && output.value_len == WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN;
        }

        static bool is_blinded(const wally_tx_output& output)
        {
            return output.asset_len == WALLY_TX_ASSET_CT_ASSET_LEN && output.value_len == WALLY_TX_ASSET_CT_VALUE_LEN
                && output.nonce_len == WALLY_TX_ASSET_CT_NONCE_LEN && output.rangeproof_len > 0;
        }

        static auto der_validate(byte_span_t der_sig)
        {
            constexpr bool has_sighash_byte = true;
            ec_sig_from_der(der_sig, has_sighash_byte);
            return der_sig;
        }

        // Return a DER encoded sig from a tx witness, including sighash byte
        static auto der_from_witness(const struct wally_tx_witness_stack* witness, size_t index)
        {
            GDK_USER_ASSERT(index < witness->num_items, "Malformed witness");
            const auto& item = witness->items[index];
            return der_validate({ item.witness, item.witness_len });
        }

        static auto schnorr_validate(byte_span_t sig)
        {
            // secp doesn't have a validation function; just check the size
            GDK_USER_ASSERT(
                sig.size() == EC_SIGNATURE_LEN || sig.size() == EC_SIGNATURE_LEN + 1, "Malformed taproot signature");
            return sig;
        }

        // Return a schnorr sig from a tx witness, including sighash byte if present
        static auto schnorr_from_witness(const struct wally_tx_witness_stack* witness, size_t index)
        {
            GDK_USER_ASSERT(index < witness->num_items, "Malformed witness");
            const auto& item = witness->items[index];
            return schnorr_validate({ item.witness, item.witness_len });
        }

        static auto der_from_push(byte_span_t push)
        {
            const size_t push_len = !push.empty() ? push[0] : 0;
            GDK_RUNTIME_ASSERT(push_len && push_len <= EC_SIGNATURE_DER_MAX_LEN + 1);
            GDK_RUNTIME_ASSERT(static_cast<size_t>(push.size()) >= push_len + 2);
            return der_validate(push.subspan(1, push_len));
        }

        static std::vector<byte_span_t> ders_from_multisig_scriptsig(byte_span_t scriptsig)
        {
            // OP_0 <ga_sig> <user_sig> <redeem_script>
            GDK_RUNTIME_ASSERT(!scriptsig.empty() && scriptsig.front() == OP_0);
            auto green_sig = der_from_push({ scriptsig.data() + 1, scriptsig.size() - 1 });
            const auto remainder = scriptsig.subspan(1 + 1 + green_sig.size());
            return { green_sig, der_from_push(remainder) };
        }

        static void calculate_input_subtype(nlohmann::json& utxo, const Tx& tx, size_t i)
        {
            // Calculate the subtype of a tx input we wish to present as a utxo.
            uint32_t subtype = 0;
            if (j_strref(utxo, "address_type") == address_type::csv) {
                // CSV inputs use the CSV time as the subtype: fetch this from the
                // redeem script in the inputs witness data. The user can change
                // their CSV time at any time, so we must use the value that was
                // originally used in the tx rather than the users current setting.
                const auto* witness = tx.get_input(i).witness;
                GDK_RUNTIME_ASSERT(witness && witness->num_items != 0);
                // The redeem script is the last witness item
                const auto& witness_item = witness->items[witness->num_items - 1];
                GDK_RUNTIME_ASSERT(witness_item.witness && witness_item.witness_len != 0);
                subtype = get_csv_blocks_from_csv_script({ witness_item.witness, witness_item.witness_len });
            }
            utxo["subtype"] = subtype;
        }

        static void cleanup_tx_addressee(session_impl& session, nlohmann::json& addressee)
        {
            // Fix fields from a bumped tx output or receive address to what addressees expect
            for (const auto& key : { "is_output", "is_relevant", "is_spent", "script_type", "pt_idx" }) {
                j_erase(addressee, key);
            }
            if (j_str_is_empty(addressee, "address_type")) {
                j_erase(addressee, "address_type");
            } else {
                utxo_add_paths(session, addressee);
                if (!addressee.contains("scriptpubkey")) {
                    const auto& net_params = session.get_network_parameters();
                    const bool allow_unconfidential = true; // Change may not yet be blinded
                    const auto spk
                        = scriptpubkey_from_address(net_params, addressee.at("address"), allow_unconfidential);
                    addressee["scriptpubkey"] = b2h(spk);
                }
            }
        }

        using map_ptr = std::shared_ptr<struct wally_map>;

        static map_ptr map_init(size_t alloc_size)
        {
            wally_map* m = nullptr;
            if (alloc_size) {
                GDK_VERIFY(wally_map_init_alloc(alloc_size, nullptr, &m));
            }
            return { m, wally_map_free };
        }

        static std::tuple<map_ptr, map_ptr, map_ptr> get_signing_data(
            session_impl& session, const std::vector<nlohmann::json>& utxos)
        {
            using namespace address_type;
            const bool is_liquid = session.get_network_parameters().is_liquid();
            auto scripts = map_init(utxos.size());
            auto values = map_init(utxos.size());
            auto assets = map_init(is_liquid ? utxos.size() : 0);

            for (size_t i = 0; i < utxos.size(); ++i) {
                const auto& utxo = utxos.at(i);

                if (auto script = j_bytes_or_empty(utxo, "scriptpubkey"); !script.empty()) {
                    GDK_VERIFY(wally_map_add_integer(scripts.get(), i, script.data(), script.size()));
                }

                if (is_liquid) {
                    const auto asset_tag = j_bytesref(utxo, "asset_tag");
                    GDK_VERIFY(wally_map_add_integer(assets.get(), i, asset_tag.data(), asset_tag.size()));
                    auto ct_value = j_bytes_or_empty(utxo, "commitment");
                    if (ct_value.empty()) {
                        const auto value = tx_confidential_value_from_satoshi(j_amountref(utxo).value());
                        ct_value.assign(std::begin(value), std::end(value));
                    }
                    GDK_VERIFY(wally_map_add_integer(values.get(), i, ct_value.data(), ct_value.size()));
                } else {
                    const auto satoshi = j_amountref(utxo).value();
                    const auto value = boost::endian::native_to_little(satoshi);
                    const auto value_p = reinterpret_cast<const unsigned char*>(&value);
                    GDK_VERIFY(wally_map_add_integer(values.get(), i, value_p, sizeof(value)));
                }
            }
            return { scripts, assets, values };
        }

        // Check if a tx to bump is present, and if so add the details required to bump it
        // FIXME: Support bump/CPFP for liquid
        static std::pair<bool, bool> check_bump_tx(
            session_impl& session, const std::set<uint32_t>& subaccounts, nlohmann::json& result)
        {
            const auto& net_params = session.get_network_parameters();
            const bool is_electrum = net_params.is_electrum();
            const auto policy_asset = net_params.get_policy_asset();

            const auto prev_tx_p = result.find("previous_transaction");
            if (prev_tx_p == result.end()) {
                return std::make_pair(false, false);
            }

            // RBF or CPFP. The previous transaction must be in the format
            // returned from the get_transactions call
            const auto& prev_tx = *prev_tx_p;
            bool is_rbf = false, is_cpfp = false;
            if (j_bool_or_false(prev_tx, "can_rbf")) {
                is_rbf = true;
            } else if (j_bool_or_false(prev_tx, "can_cpfp")) {
                is_cpfp = true;
            } else {
                // Transaction is confirmed or marked non-RBF
                GDK_RUNTIME_ASSERT_MSG(false, "Transaction can not be fee-bumped");
            }

            // TODO: Remove this check once cross subaccount bumps/full RBF is tested.
            // You cannot bump a tx from another subaccount, this is a
            // programming error so assert it rather than returning in "error"
            bool subaccount_ok = false;
            for (const auto& io : prev_tx.at(is_rbf ? "inputs" : "outputs")) {
                const auto p = io.find("subaccount");
                if (p != io.end() && subaccounts.find(p->get<uint32_t>()) != subaccounts.end()) {
                    subaccount_ok = true;
                    break;
                }
            }
            GDK_RUNTIME_ASSERT_MSG(subaccount_ok, "No suitable subaccount UTXOs found");

            for (auto& output : result.at("previous_transaction").at("outputs")) {
                if (j_str_is_empty(output, "address_type")) {
                    // FIXME: These keys should be removed from the transaction
                    // itself before it is returned from get_transactions
                    utxo_remove_wallet_keys(output);
                } else if (!is_electrum) {
                    // Add the branch which is missing from transaction outputs
                    // FIXME: Should be added to get_transactions results or replaced
                    // with a descriptor going forward
                    output["branch"] = 1;
                } else {
                    // Remove subtype which is not returned in transaction outputs
                    // FIXME: Should be added to get_transactions results or replaced
                    // with a descriptor going forward
                    j_erase(output, "subtype");
                }
            }

            const auto tx = session.get_raw_transaction_details(prev_tx.at("txhash"));
            const auto min_fee_rate = session.get_min_fee_rate();

            // Store the old fee and fee rate to check if replacement
            // requirements are satisfied
            const auto old_fee = j_amountref(prev_tx, "fee");
            const auto old_fee_rate = j_amountref(prev_tx, "fee_rate");
            result["old_fee"] = old_fee.value();
            result["old_fee_rate"] = old_fee_rate.value();

            if (is_cpfp) {
                // For CPFP the network fee is the difference between the
                // fee the previous transaction currently pays, and the
                // fee it would pay at the desired new fee rate (adding
                // the network fee to the new transactions fee increases
                // the overall fee rate of the pair to the desired rate,
                // so that miners are incentivized to mine both together).
                const auto new_fee_rate = j_amountref(result, "fee_rate");
                const auto fee_rate = std::max(min_fee_rate.value(), new_fee_rate.value());
                const auto new_fee = tx.get_fee(net_params, fee_rate);
                result["network_fee"] = new_fee <= old_fee ? 0 : new_fee;
            }

            if (is_rbf) {
                const auto tx_version = tx.get_version();
                result["transaction_version"] = tx_version;
                result["transaction_locktime"] = tx.get_locktime();

                // Compute addressees and any change details from the old tx
                const auto& outputs = prev_tx.at("outputs");
                GDK_RUNTIME_ASSERT(tx.get_num_outputs() == outputs.size());
                nlohmann::json::array_t addressees;
                addressees.reserve(outputs.size());
                size_t out_index = 0;
                std::optional<size_t> change_index;
                bool have_explicit_change = false; // True if we found an explicit change output

                if (is_electrum) {
                    // single sig: determine if we have explicit change; if not
                    // we use any found wallet output as change below.
                    for (const auto& output : outputs) {
                        const bool is_relevant = j_bool_or_false(output, "is_relevant");
                        const bool is_internal = j_bool_or_false(output, "is_internal");
                        if (is_relevant && is_internal) {
                            have_explicit_change = true;
                            break;
                        }
                    }
                }

                for (const auto& output : outputs) {
                    const std::string out_addr = output.at("address");
                    if (!out_addr.empty()) {
                        // Validate address matches the transaction scriptpubkey
                        const bool allow_unconfidential = false;
                        const auto spk = scriptpubkey_from_address(net_params, out_addr, allow_unconfidential);
                        GDK_RUNTIME_ASSERT(tx.get_output(out_index).script_len == spk.size());
                        GDK_RUNTIME_ASSERT(!memcmp(tx.get_output(out_index).script, &spk[0], spk.size()));
                    }
                    const bool is_relevant = j_bool_or_false(output, "is_relevant");
                    if (is_relevant) {
                        // Validate address is owned by the wallet
                        GDK_RUNTIME_ASSERT(out_addr == get_address_from_utxo(session, output));
                    }

                    bool is_change = false;
                    if (is_relevant && !change_index.has_value()) {
                        // No change found so far; this output is possibly change
                        if (!is_electrum) { // NOLINT (bugprone-branch-clone fixes)
                            // Multisig: Treat the first wallet output as change, as we
                            // don't have internal addresses to mark change explicitly
                            is_change = true;
                        } else if (!have_explicit_change || j_bool_or_false(output, "is_internal")) {
                            // Singlesig: Either we don't have explicit change, and
                            // this is the first wallet output, or we do have explicit
                            // change and this is the first explicit change output
                            is_change = true;
                        }
                    }
                    if (is_change) {
                        // Change output.
                        change_index = out_index;
                    } else {
                        // Not a change output, or there is already one:
                        // treat this as a regular output
                        addressees.emplace_back(output);
                        cleanup_tx_addressee(session, addressees.back());
                    }
                    ++out_index;
                }

                bool is_redeposit = false;
                if (change_index.has_value()) {
                    // Found an output paying to ourselves.
                    const auto& output = prev_tx.at("outputs").at(change_index.value()); // NOLINT (unchecked optional)
                    GDK_RUNTIME_ASSERT(output.contains("address"));
                    if (addressees.empty()) {
                        // We didn't pay anyone else; this is actually a re-deposit
                        addressees.emplace_back(output);
                        cleanup_tx_addressee(session, addressees.back());
                        addressees.back()["is_greedy"] = true;
                        change_index.reset();
                        is_redeposit = true;
                    } else {
                        // We paid to someone else, so this output really was
                        // change. Save the change address to re-use it.
                        auto& change_address = result["change_address"][policy_asset];
                        change_address = output;
                        cleanup_tx_addressee(session, change_address);
                    }
                    // Save the change subaccount whether we found change or not
                    result["change_subaccount"] = output.at("subaccount");
                }

                result["addressees"] = std::move(addressees);

                const auto& prev_inputs = prev_tx.at("inputs");
                if (!change_index.has_value() && !is_redeposit) {
                    for (const auto& in : prev_inputs) {
                        if (j_bool_or_false(in, "is_relevant")) {
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

                // Add the existing inputs as UTXOs
                auto&& is_tr
                    = [](const auto& in) -> bool { return j_str_or_empty(in, "address_type") == address_type::p2tr; };
                const bool are_signing_p2tr = std::any_of(prev_inputs.begin(), prev_inputs.end(), is_tr);

                // Fetch them from the inputs and re-order them as required
                std::map<uint32_t, nlohmann::json> tx_inputs_map;
                for (const auto& input : prev_inputs) {
                    if (!j_bool_or_false(input, "is_relevant")) {
                        // FIXME: Allow RBF of mixed wallet/non-wallet input txs
                        throw_user_error("Cannot RBF a transaction with non-wallet inputs");
                    }
                    nlohmann::json utxo(input);
                    // Note pt_idx on endpoints is the index within the tx, not the previous tx!
                    const uint32_t i = utxo.at("pt_idx");
                    GDK_RUNTIME_ASSERT(i < tx.get_num_inputs());
                    utxo["txhash"] = b2h_rev(tx.get_input(i).txhash);
                    utxo["pt_idx"] = tx.get_input(i).index;
                    utxo["sequence"] = tx.get_input(i).sequence;
                    calculate_input_subtype(utxo, tx, i);
                    utxo_add_paths(session, utxo);
                    if (is_electrum) {
                        const auto user_key = session.keys_from_utxo(utxo).at(0);
                        utxo["public_key"] = b2h(user_key.get_public_key());
                    }
                    const auto script = session.output_script_from_utxo(utxo);
                    utxo["prevout_script"] = b2h(script);
                    if (are_signing_p2tr && !utxo.contains("scriptpubkey")) {
                        const auto scriptpubkey = get_scriptpubkey_from_utxo(session, utxo);
                        if (!scriptpubkey.empty()) {
                            utxo["scriptpubkey"] = b2h(scriptpubkey);
                        }
                    }
                    tx_inputs_map.emplace(i, std::move(utxo));
                }

                std::vector<nlohmann::json> inputs;
                inputs.reserve(tx_inputs_map.size());
                for (auto& item : tx_inputs_map) {
                    inputs.push_back(std::move(item.second));
                }
                constexpr bool for_rbf = true;
                tx.validate_user_signatures(session, inputs, for_rbf);
                result["transaction_inputs"] = std::move(inputs);

                if (j_str_is_empty(result, "memo")) {
                    result["memo"] = prev_tx["memo"];
                }
            } else {
                // For CPFP construct a tx spending an input from prev_tx
                // to a wallet change address. Since this is exactly what
                // re-depositing requires, just create the input and mark
                // the tx as a redeposit to let the regular creation logic
                // handle it.
                // FIXME: Create a greedy receive address
                if (!result.contains("utxos")) {
                    // Add a single output from the old tx as our new tx input
                    std::vector<nlohmann::json> utxos;
                    for (const auto& output : prev_tx.at("outputs")) {
                        if (j_bool_or_false(output, "is_relevant")) {
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

        struct addressee_details_t {
            std::string asset_id;
            amount required_total;
            amount utxo_sum;
            amount fee; // Only non-zero for the policy asset
            std::vector<size_t> addressee_indices;
            std::vector<uint32_t> utxo_indices;
            std::optional<size_t> greedy_index;
        };

        static bool update_greedy_output(
            Tx& tx, nlohmann::json& result, addressee_details_t& addressee, amount::value_type change_amount)
        {
            if (!addressee.greedy_index.has_value()) {
                return false;
            }
            if (!change_amount) {
                // Greedy outputs are not optional: they must have a value
                throw user_error("No available value for greedy output");
            }
            // Fill the greedy output with the left over value
            const auto greedy_idx = addressee.greedy_index.value();
            auto& json_addressee = result.at("addressees").at(greedy_idx);
            json_addressee["satoshi"] = change_amount;
            tx.set_output_satoshi(greedy_idx, addressee.asset_id, change_amount);
            // FIXME: account for another non-greedy addressee
            addressee.required_total = addressee.utxo_sum - addressee.fee;
            return true;
        }

        static void create_change_output(session_impl& session, Tx& tx, nlohmann::json& result,
            const std::string& asset_id, amount::value_type change_amount, bool add_to_tx = true)
        {
            if (!result.contains("change_address")) {
                result["change_address"] = nlohmann::json::object();
            }
            if (result["change_address"].value(asset_id, nlohmann::json::object()).empty()) {
                // No previously generated change address, so generate one.
                if (!result.contains("change_subaccount")) {
                    // Find out where to send any change
                    const auto subaccounts = get_tx_subaccounts(result);
                    result["change_subaccount"] = get_single_subaccount(subaccounts);
                }
                const uint32_t change_subaccount = result.at("change_subaccount");
                nlohmann::json details = { { "subaccount", change_subaccount }, { "is_internal", true } };
                auto new_change_address = session.get_receive_address(details);
                cleanup_tx_addressee(session, new_change_address);

                if (session.get_network_parameters().is_electrum()) {
                    constexpr size_t default_gap_limit = 20;
                    bool is_duplicate_spk = false;
                    for (size_t i = 0; i < default_gap_limit * 2u; ++i) {
                        const auto spk = j_str_or_empty(new_change_address, "scriptpubkey");
                        is_duplicate_spk = !are_tx_outputs_unique(result, spk);
                        if (!is_duplicate_spk) {
                            break;
                        }
                        details["ignore_gap_limit"] = i >= default_gap_limit;
                        new_change_address = session.get_receive_address(details);
                        cleanup_tx_addressee(session, new_change_address);
                        is_duplicate_spk = false;
                    }
                    GDK_RUNTIME_ASSERT_MSG(!is_duplicate_spk, "unable to get unique change address");
                }
                result["change_address"][asset_id] = std::move(new_change_address);
            }
            result["change_address"][asset_id]["satoshi"] = change_amount;
            if (add_to_tx) {
                add_tx_change_output(session, result, tx, asset_id);
            }
            const auto change_idx = tx.get_num_outputs() - 1;
            tx.set_output_satoshi(change_idx, asset_id, change_amount);
        }

        static void pick_asset_utxos(session_impl& session, Tx& tx, nlohmann::json& result, nlohmann::json& utxos,
            addressee_details_t& addressee)
        {
            amount::value_type total = 0;

            // Perform asset UTXO selection
            std::vector<std::pair<size_t, amount>> indexed_values;
            for (size_t i = 0; i < utxos.size(); ++i) {
                const auto satoshi = j_amountref(utxos[i]);
                indexed_values.emplace_back(std::make_pair(i, satoshi));
                total += satoshi.value();
            }
            auto required_total = addressee.required_total.value();
            if (total < required_total) {
                throw user_error(res::id_insufficient_funds);
            }
            if (addressee.greedy_index.has_value()) {
                required_total = total; // We require all the available value
            }
            auto&& sort_2nd = [](auto& l, auto& r) { return l.second < r.second; };
            std::sort(indexed_values.begin(), indexed_values.end(), sort_2nd);
            std::vector<amount::value_type> values;
            values.reserve(indexed_values.size());
            for (const auto& v : indexed_values) {
                values.push_back(v.second.value());
            }
            const size_t attempts = 1000000; /* FIXME: dynamic? */
            const uint32_t io_ratio = 2;
            size_t written;
            addressee.utxo_indices.resize(indexed_values.size());
            int ret = wally_coinselect_assets(values.data(), values.size(), required_total, attempts, io_ratio,
                addressee.utxo_indices.data(), addressee.utxo_indices.size(), &written);
            addressee.utxo_indices.resize(written);
            GDK_RUNTIME_ASSERT(ret == WALLY_OK);

            for (auto& i : addressee.utxo_indices) {
                i = indexed_values[i].first; // Set to the index of the chosen UTXO
                addressee.utxo_sum += add_tx_input(session, result, tx, utxos[i], true);
            }
        }

        static void pick_policy_asset_utxos(session_impl& session, Tx& tx, nlohmann::json& result,
            nlohmann::json& utxos, addressee_details_t& addressee, const amount& fee_rate, bool manual_selection)
        {
            const auto& net_params = session.get_network_parameters();
            const auto policy_asset = net_params.get_policy_asset();
            const amount dust_threshold = session.get_dust_threshold(policy_asset);
            const auto network_fee = j_amount_or_zero(result, "network_fee");
            const ssize_t num_utxos = manual_selection ? 0 : gsl::narrow<ssize_t>(utxos.size());
            const bool is_greedy = addressee.greedy_index.has_value();
            bool added_change = false;

            for (ssize_t i = 0; i <= num_utxos; ++i) {
                const bool no_more_utxos = i == num_utxos;
                bool have_dusty_change = false; // TODO: Allow donating dusty fees

                addressee.fee = tx.get_fee(net_params, fee_rate.value());
                addressee.fee += network_fee;
                auto required_total = addressee.required_total + addressee.fee;

                if ((!is_greedy && addressee.utxo_sum >= required_total) || (is_greedy && no_more_utxos)) {
                    // We have enough to cover the amount to send plus any fee
                    amount::value_type change_amount = 0;
                    if (addressee.utxo_sum >= required_total) {
                        change_amount = (addressee.utxo_sum - required_total).value();
                        if (change_amount) {
                            if (update_greedy_output(tx, result, addressee, change_amount)) {
                                if (change_amount <= dust_threshold) {
                                    have_dusty_change = true;
                                    goto add_more_utxos;
                                }
                                change_amount = 0;
                            } else {
                                // Generate a change address for the left over asset value
                                create_change_output(
                                    session, tx, result, addressee.asset_id, change_amount, !added_change);
                                if (!added_change) {
                                    added_change = true;
                                    --i;
                                    continue; // Loop again to include the change output
                                }
                                if (change_amount <= dust_threshold) {
                                    have_dusty_change = true;
                                    goto add_more_utxos;
                                }
                            }
                        }
                    } else {
                        throw user_error(res::id_insufficient_funds); // Cant cover fee
                    }
                    result["change_amount"][addressee.asset_id] = change_amount;
                    result["fee"] = addressee.fee.value();
                    result["network_fee"] = network_fee.value();
                    return;
                }
            add_more_utxos:
                if (no_more_utxos) {
                    if (addressee.utxo_sum < addressee.required_total) {
                        throw user_error(res::id_insufficient_funds);
                    }
                    if (have_dusty_change) {
                        // Caller requres more fee utxos to avoid dusty change
                        throw user_error("Fee change below the dust threshold"); // FIXME res::
                    }
                    result["fee"] = addressee.fee.value();
                    throw user_error("Insufficient funds for fees"); // FIXME res::
                }
                // Add the next input
                addressee.utxo_indices.push_back(i);
                addressee.utxo_sum += add_tx_input(session, result, tx, utxos[i], true);
            }
        }

        static void pick_utxos(session_impl& session, Tx& tx, nlohmann::json& result, nlohmann::json& src_utxos,
            addressee_details_t& addressee, const amount& fee_rate, bool manual_selection)
        {
            // Select the inputs to use
            nlohmann::json empty = nlohmann::json::array_t{};
            const auto& net_params = session.get_network_parameters();
            const bool is_policy_asset = addressee.asset_id == net_params.get_policy_asset();
            bool use_empty = false;
            if (!manual_selection && !src_utxos.contains(addressee.asset_id)) {
                // No UTXOs for the asset found
                if (addressee.utxo_sum >= addressee.required_total) {
                    use_empty = true;
                } else {
                    throw user_error(res::id_insufficient_funds);
                }
            }
            auto& utxos = manual_selection ? src_utxos : use_empty ? empty : src_utxos.at(addressee.asset_id);

            addressee.utxo_indices.reserve(utxos.size());
            if (is_policy_asset) {
                pick_policy_asset_utxos(session, tx, result, utxos, addressee, fee_rate, manual_selection);
            } else {
                pick_asset_utxos(session, tx, result, utxos, addressee);
            }
        }

        static void create_transaction_impl(session_impl& session, nlohmann::json& result)
        {
            const auto& net_params = session.get_network_parameters();
            const bool is_liquid = net_params.is_liquid();
            const auto policy_asset = net_params.get_policy_asset();

            const auto subaccounts = get_tx_subaccounts(result);
            const bool is_partial = j_bool_or_false(result, "is_partial");

            result["transaction_outputs"] = nlohmann::json::array();
            result["fee"] = 0u;
            result["network_fee"] = 0u;
            j_erase(result, "change_amount");

            auto fee_rate = j_amount(result, "fee_rate");
            if (!fee_rate) {
                fee_rate = session.get_default_fee_rate();
                result["fee_rate"] = fee_rate.value().value();
            }
            if (fee_rate < session.get_min_fee_rate()) {
                set_tx_error(result, res::id_fee_rate_is_below_minimum);
                return;
            }

            // Check for RBF/CPFP
            const auto [is_rbf, is_cpfp] = check_bump_tx(session, subaccounts, result);
            if (is_rbf) {
                result["randomize_inputs"] = false;
            }

            if (auto p = result.find("change_address"); p != result.end()) {
                for (auto& it : p->items()) {
                    it.value()["satoshi"] = 0u;
                }
            }

            if (is_partial) {
                GDK_RUNTIME_ASSERT(!is_rbf && !is_cpfp);
            }

            // We must have addressees to send to, and if sending everything, only one
            // Note that this error is set unconditionally and so overrides any others,
            // Since addressing transactions is normally done first by users
            auto addressees_p = result.find("addressees");
            if (addressees_p == result.end() || addressees_p->empty()) {
                set_tx_error(result, res::id_no_recipients);
                return;
            }

            const std::string strategy = json_add_if_missing(result, "utxo_strategy", UTXO_SEL_DEFAULT);
            const bool manual_selection = strategy == UTXO_SEL_MANUAL;
            GDK_RUNTIME_ASSERT(strategy == UTXO_SEL_DEFAULT || manual_selection);
            if (is_partial) {
                GDK_RUNTIME_ASSERT(manual_selection);
            }
            if (manual_selection) {
                // Manual selection cannot currently be used with RBF
                GDK_RUNTIME_ASSERT(!is_rbf);

                if (!result.contains("transaction_inputs") || !result["transaction_inputs"].is_array()
                    || result["transaction_inputs"].empty()) {
                    set_tx_error(result, res::id_no_utxos_found);
                }
            } else if (!is_rbf) {
                // We will recompute the used utxos
                result["transaction_inputs"] = nlohmann::json::array();
            }

            auto& utxos = result.at("utxos");
            const uint32_t current_block_height = session.get_block_height();
            const uint32_t locktime = result.value("transaction_locktime", current_block_height);
            const uint32_t tx_version = result.value("transaction_version", WALLY_TX_VERSION_2);
            result["transaction_version"] = tx_version;
            Tx tx(locktime, tx_version, is_liquid);
            if (!is_rbf && !result.contains("transaction_locktime")) {
                tx.set_anti_snipe_locktime(current_block_height);
            }

            std::map<std::string, addressee_details_t> asset_addressees;

            // Make sure we have details for the policy asset
            auto& btc_details = asset_addressees[policy_asset];
            btc_details.asset_id = policy_asset;

            // Validate the given addressees
            for (size_t i = 0; i < addressees_p->size(); ++i) {
                auto& addressee = addressees_p->at(i);
                if (auto error = validate_tx_addressee(session, net_params, addressee); !error.empty()) {
                    set_tx_error(result, error);
                    return;
                }
                auto asset_id = j_assetref(is_liquid, addressee);
                auto& a = asset_addressees[asset_id];
                a.asset_id = asset_id;
                if (j_bool_or_false(addressee, "is_greedy")) {
                    if (a.greedy_index.has_value()) {
                        set_tx_error(result, "only one output per asset type can be greedy");
                        return;
                    } else if (is_partial) {
                        set_tx_error(result, "greedy outputs cannot be used with partial transactions");
                        return;
                    }
                    a.greedy_index = i;
                    addressee["satoshi"] = amount::value_type(0);
                }
                a.addressee_indices.push_back(i);
                // Add the value of this output to the required total
                a.required_total += j_amountref(addressee);
                // Add the addressee to our transaction
                add_tx_addressee_output(session, tx, addressee);
            }

            if (!are_tx_outputs_unique(result)) {
                // Addressees must be unique
                set_tx_error(result, "multiple outputs share the same address");
                return;
            }

            if (manual_selection || is_rbf) {
                // Add all of the given inputs
                auto& tx_inputs = result.at("transaction_inputs");
                for (size_t i = 0; i < tx_inputs.size(); ++i) {
                    const auto asset_id = j_assetref(is_liquid, tx_inputs[i]);
                    const bool is_policy_asset = asset_id == policy_asset;
                    if (is_liquid && !is_partial && !is_policy_asset) {
                        // Ensure this UTXO has a corresponding recipient
                        // (ignoring the policy asset, which is required for fees)
                        if (asset_addressees.find(asset_id) == asset_addressees.end()) {
                            set_tx_error(result, "Missing recipient for asset " + asset_id);
                            return;
                        }
                    }
                    auto& addressee = asset_addressees[asset_id];
                    addressee.utxo_indices.push_back(i);
                    addressee.utxo_sum += add_tx_input(session, result, tx, tx_inputs[i], false);
                }
            }

            // We process all assets first, then the policy asset last
            for (bool process_policy_asset : { false, true }) {
                if (is_partial) {
                    continue;
                }
                for (auto& a : asset_addressees) {
                    auto& addressee = a.second;
                    const bool is_policy_asset = addressee.asset_id == policy_asset;
                    if (process_policy_asset != is_policy_asset) {
                        continue;
                    }
                    if (is_policy_asset || !manual_selection) {
                        // Compute the UTXOs to use and their sum
                        pick_utxos(session, tx, result, utxos, addressee, *fee_rate, manual_selection);
                    }
                    if (addressee.utxo_sum < addressee.required_total) {
                        set_tx_error(result, res::id_insufficient_funds);
                        return;
                    } else if (addressee.utxo_sum < addressee.required_total + addressee.fee) {
                        GDK_RUNTIME_ASSERT(is_policy_asset); // Fee only present for policy asset
                        result["fee"] = addressee.fee.value();
                        set_tx_error(result, "Insufficient funds for fees"); // FIXME res::
                        return;
                    }
                    if (!is_policy_asset) {
                        // Check input vs output values. Add excess to any
                        // greedy output or change, as needed.
                        amount::value_type change_amount = 0;
                        change_amount = (addressee.utxo_sum - addressee.required_total).value();
                        if (change_amount) {
                            if (update_greedy_output(tx, result, addressee, change_amount)) {
                                change_amount = 0;
                            } else {
                                // Generate a change address for the left over asset value
                                const bool add_to_tx = true;
                                create_change_output(session, tx, result, addressee.asset_id, change_amount, add_to_tx);
                            }
                        }
                        result["change_amount"][addressee.asset_id] = change_amount;
                    }
                }
            }

            if (is_liquid && !is_partial) {
                add_tx_fee_output(session, tx, btc_details.fee.value());
            }
            auto& tx_inputs = result.at("transaction_inputs");
            if (tx_inputs.size() > 1u && j_bool(result, "randomize_inputs").value_or(true)) {
                tx.randomize_inputs(tx_inputs);
            }
            update_tx_info(session, tx, result);

            if (is_rbf && j_str_is_empty(result, "error")) {
                // Check if rbf requirements are met. When the user input a fee rate for the
                // replacement, the transaction will be created according to the fee rate itself
                // and the transaction construction policies. As a result it may occur that rbf
                // requirements are not met, but, in general, it is not possible to check it
                // before the transaction is actually constructed.
                const auto old_fee = j_amount_or_zero(result, "old_fee");
                const auto old_fee_rate = j_amount_or_zero(result, "old_fee_rate");
                const auto calculated_fee_rate = j_amountref(result, "calculated_fee_rate");
                const auto vsize = j_amountref(result, "transaction_vsize").value();
                const amount::value_type bandwidth_fee = vsize * session.get_min_fee_rate().value() / 1000;
                if (btc_details.fee.value() < (old_fee + bandwidth_fee) || calculated_fee_rate <= old_fee_rate) {
                    set_tx_error(result, res::id_invalid_replacement_fee_rate);
                }
            }
        }

        static void validate_sighash_flags(uint32_t sighash_flags, bool is_p2tr, bool is_liquid)
        {
            if (sighash_flags == WALLY_SIGHASH_ALL || (is_p2tr && sighash_flags == WALLY_SIGHASH_DEFAULT)) {
                return;
            }
            const bool is_valid = is_liquid && sighash_flags == SIGHASH_SINGLE_ANYONECANPAY;
            GDK_USER_ASSERT(is_valid, "Unsupported sighash type");
        }
    } // namespace

    void Tx::tx_deleter::operator()(struct wally_tx* p) { wally_tx_free(p); }

    Tx::Tx(uint32_t locktime, uint32_t version, bool is_liquid)
        : m_is_liquid(is_liquid)
    {
        struct wally_tx* p;
        GDK_VERIFY(wally_tx_init_alloc(version, locktime, 16, 16, &p));
        m_tx.reset(p);
    }

    Tx::Tx(byte_span_t tx_bin, bool is_liquid)
        : m_is_liquid(is_liquid)
    {
        struct wally_tx* p;
        GDK_VERIFY(wally_tx_from_bytes(tx_bin.data(), tx_bin.size(), get_flags(), &p));
        m_tx.reset(p);
    }

    Tx::Tx(const std::string& tx_hex, bool is_liquid)
        : m_is_liquid(is_liquid)
    {
        struct wally_tx* p;
        GDK_VERIFY(wally_tx_from_hex(tx_hex.c_str(), get_flags(), &p));
        m_tx.reset(p);
    }

    Tx::Tx(struct wally_tx* tx, bool is_liquid)
        : m_tx(tx)
        , m_is_liquid(is_liquid)
    {
        GDK_RUNTIME_ASSERT(m_tx);
    }

    void Tx::swap(Tx& rhs)
    {
        std::swap(m_is_liquid, rhs.m_is_liquid);
        std::swap(m_tx, rhs.m_tx);
    }

    uint32_t Tx::get_flags() const
    {
        return WALLY_TX_FLAG_USE_WITNESS | (m_is_liquid ? WALLY_TX_FLAG_USE_ELEMENTS : 0);
    }

    std::vector<unsigned char> Tx::to_bytes() const
    {
        size_t written;
        GDK_VERIFY(wally_tx_get_length(m_tx.get(), get_flags(), &written));
        std::vector<unsigned char> buff(written);
        GDK_VERIFY(wally_tx_to_bytes(m_tx.get(), get_flags(), buff.data(), buff.size(), &written));
        GDK_RUNTIME_ASSERT(written == buff.size());
        return buff;
    }

    std::string Tx::to_hex() const { return b2h(to_bytes()); }

    std::array<unsigned char, WALLY_TXHASH_LEN> Tx::get_txid() const
    {
        std::array<unsigned char, WALLY_TXHASH_LEN> txid;
        GDK_VERIFY(wally_tx_get_txid(m_tx.get(), txid.data(), txid.size()));
        return txid;
    }

    struct wally_tx_input& Tx::get_input(size_t index)
    {
        return const_cast<struct wally_tx_input&>(std::as_const(*this).get_input(index));
    }

    const struct wally_tx_input& Tx::get_input(size_t index) const
    {
        GDK_RUNTIME_ASSERT(index < m_tx->num_inputs);
        return m_tx->inputs[index];
    }

    nlohmann::json Tx::input_to_json(size_t index) const
    {
        const auto& in = get_input(index);
        nlohmann::json result = { { "txhash", b2h_rev({ in.txhash, sizeof(in.txhash) }) }, { "pt_idx", in.index },
            { "sequence", in.sequence } };

        const auto wit = in.witness;
        if (wit && wit->num_items) {
            auto& wit_array = result["witness"];
            for (const auto& item : gsl::make_span(wit->items, wit->num_items)) {
                const byte_span_t data{ item.witness, item.witness_len };
                wit_array.emplace_back(!data.empty() ? b2h(data) : std::string());
            }
        }
        if (in.script_len) {
            result["script_sig"] = b2h({ in.script, in.script_len });
        }
        return result;
    }

    std::optional<uint32_t> Tx::find_input_spending(byte_span_t txid, uint32_t vout) const
    {
        GDK_RUNTIME_ASSERT(txid.size() == WALLY_TXHASH_LEN);
        for (size_t i = 0; i < m_tx->num_inputs; ++i) {
            const auto& tx_in = m_tx->inputs[i];
            if (tx_in.index == vout && !memcmp(tx_in.txhash, txid.data(), txid.size())) {
                return { i };
            }
        }
        return {};
    }

    void Tx::add_input(byte_span_t txhash, uint32_t index, uint32_t sequence, byte_span_t script,
        const struct wally_tx_witness_stack* witness)
    {
        constexpr uint32_t flags = 0;
        const unsigned char* script_p = script.empty() ? nullptr : script.data();
        if (!m_is_liquid) {
            GDK_VERIFY(wally_tx_add_raw_input(
                m_tx.get(), txhash.data(), txhash.size(), index, sequence, script_p, script.size(), witness, flags));
            return;
        }
        GDK_VERIFY(wally_tx_add_elements_raw_input(m_tx.get(), txhash.data(), txhash.size(), index, sequence, script_p,
            script.size(), witness, nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0, nullptr,
            flags));
    }

    void Tx::set_input_script(size_t index, byte_span_t script)
    {
        const unsigned char* data = !script.empty() ? script.data() : nullptr;
        GDK_VERIFY(wally_tx_set_input_script(m_tx.get(), index, data, script.size()));
    }

    void Tx::set_input_witness(size_t index, const struct wally_tx_witness_stack* witness)
    {
        GDK_VERIFY(wally_tx_set_input_witness(m_tx.get(), index, witness));
    }

    void Tx::randomize_inputs(nlohmann::json& tx_inputs)
    {
        // Permute positions
        std::vector<size_t> positions(tx_inputs.size());
        std::iota(positions.begin(), positions.end(), 0);
        std::shuffle(positions.begin(), positions.end(), uniform_uint32_rng());
        // Apply permutation
        nlohmann::json::array_t reordered_utxos(tx_inputs.size());
        std::vector<wally_tx_input> reordered_inputs(tx_inputs.size());
        // We start at txin_offset to avoid permuting any existing rbf inputs
        const size_t txin_offset = get_num_inputs() - tx_inputs.size();
        for (size_t i = 0; i < tx_inputs.size(); ++i) {
            reordered_utxos[i].swap(tx_inputs[positions[i]]);
            reordered_inputs[i] = m_tx->inputs[txin_offset + positions[i]];
        }
        tx_inputs.swap(reordered_utxos);
        const size_t n = reordered_inputs.size() * sizeof(wally_tx_input);
        memcpy(m_tx->inputs + txin_offset, reordered_inputs.data(), n);
    }

    std::vector<byte_span_t> Tx::get_input_signatures(
        const network_parameters& net_params, const nlohmann::json& utxo, size_t index) const
    {
        using namespace address_type;
        const auto& addr_type = j_strref(utxo, "address_type");
        const auto& input = get_input(index);

        if (!is_wallet_utxo(utxo)) {
            return {};
        }
        // TODO: handle backup paths:
        // - 2of3 p2sh, user + backup key signing
        // - 2of3 p2wsh, user + backup key signing
        if (addr_type == p2pkh) {
            // p2pkh: script sig: <user_sig> <pubkey>
            return { der_from_push({ input.script, input.script_len }) };
        }
        if (addr_type == p2sh) {
            // 2of2 p2sh: script sig: OP_0 <ga_sig> <user_sig>
            // 2of3 p2sh: script sig: OP_0 <ga_sig> <user_sig>
            return ders_from_multisig_scriptsig({ input.script, input.script_len });
        }

        const size_t num_items = input.witness ? input.witness->num_items : 0;

        if (addr_type == p2sh_p2wpkh || addr_type == p2wpkh) {
            // p2sh-p2wpkh: witness stack: <user_sig> <pubkey>
            GDK_RUNTIME_ASSERT(num_items == 2);
            return { der_from_witness(input.witness, 0) };
        }
        if (addr_type == p2tr) {
            // p2tr: witness stack: <user_sig> (keypath spend, user_sig is schnorr)
            GDK_RUNTIME_ASSERT(num_items == 1);
            return { schnorr_from_witness(input.witness, 0) };
        }

        // 2of2 p2wsh:       witness stack: <> <ga_sig> <user_sig> <redeem_script>
        // 2of2 csv:         witness stack: <user_sig> <ga_sig> <redeem_script> (Liquid, not optimized)
        // 2of2 csv:         witness stack: <ga_sig> <user_sig> <redeem_script>
        // 2of2 expired csv: witness stack: <> <user_sig> <redeem_script>
        // 2of2 expired csv: witness stack: <user_sig> <redeem_script> (Liquid, not optimized)
        // 2of3 p2wsh:       witness stack: <> <ga_sig> <user_sig> <redeem_script>
        // 2of2_no_recovery p2wsh: witness stack: <> <ga_sig> <user_sig> <redeem_script> (Liquid)
        GDK_RUNTIME_ASSERT(num_items >= 2 && num_items <= 4);
        size_t user_index = num_items - 2, green_index = num_items - 3;
        if (addr_type == csv) {
            const bool may_be_expired
                = get_version() >= WALLY_TX_VERSION_2 && net_params.is_valid_csv_value(input.sequence);
            if (m_is_liquid) {
                if (may_be_expired && input.witness->num_items == 2) {
                    // Expired csv utxo with just the users sig
                    return { byte_span_t{}, der_from_witness(input.witness, user_index) };
                } else {
                    // Liquid 2of2 csv: sigs are inverted in the witness stack
                    std::swap(user_index, green_index);
                }
            } else {
                if (may_be_expired && input.witness->items[0].witness_len == 0) {
                    // Expired csv utxo with just the users sig
                    return { byte_span_t{}, der_from_witness(input.witness, user_index) };
                }
            }
        }
        return { der_from_witness(input.witness, green_index), der_from_witness(input.witness, user_index) };
    }

    struct wally_tx_output& Tx::get_output(size_t index)
    {
        return const_cast<struct wally_tx_output&>(std::as_const(*this).get_output(index));
    }

    const struct wally_tx_output& Tx::get_output(size_t index) const
    {
        GDK_RUNTIME_ASSERT(index < m_tx->num_outputs);
        return m_tx->outputs[index];
    }

    void Tx::add_output(uint64_t satoshi, byte_span_t script)
    {
        constexpr uint32_t flags = 0;
        GDK_VERIFY(wally_tx_add_raw_output(m_tx.get(), satoshi, script.data(), script.size(), flags));
    }

    void Tx::add_elements_output_at(size_t index, byte_span_t script, byte_span_t asset, byte_span_t value,
        byte_span_t nonce, byte_span_t surjectionproof, byte_span_t rangeproof)
    {
        constexpr uint32_t flags = 0;
        GDK_VERIFY(wally_tx_add_elements_raw_output_at(m_tx.get(), index, script.data(), script.size(), asset.data(),
            asset.size(), value.data(), value.size(), nonce.data(), nonce.size(), surjectionproof.data(),
            surjectionproof.size(), rangeproof.data(), rangeproof.size(), flags));
    }

    void Tx::set_output_commitments(size_t index, byte_span_t asset, byte_span_t value, byte_span_t nonce,
        byte_span_t surjectionproof, byte_span_t rangeproof)
    {
        GDK_RUNTIME_ASSERT(index < get_num_outputs());
        GDK_VERIFY(wally_tx_elements_output_commitment_set(&m_tx->outputs[index], asset.data(), asset.size(),
            value.data(), value.size(), nonce.data(), nonce.size(), surjectionproof.data(), surjectionproof.size(),
            rangeproof.data(), rangeproof.size()));
    }

    void Tx::set_output_satoshi(size_t index, const std::string& asset_id, uint64_t satoshi)
    {
        auto& txout = get_output(index);
        txout.satoshi = satoshi;
        if (m_is_liquid) {
            // The given asset must match the txout we are updating
            const auto asset_bytes = h2b_rev(asset_id, 0x1);
            GDK_RUNTIME_ASSERT(txout.asset && txout.asset_len == asset_bytes.size()
                && !memcmp(txout.asset, asset_bytes.data(), asset_bytes.size()));
            set_output_commitments(index, asset_bytes, tx_confidential_value_from_satoshi(satoshi), {}, {}, {});
        }
    }

    void Tx::set_anti_snipe_locktime(uint32_t current_block_height)
    {
        // We use cores algorithm to randomly use an older locktime for delayed tx privacy
        if (current_block_height > 100 && get_uniform_uint32_t(10) == 0) {
            current_block_height -= get_uniform_uint32_t(100);
        }
        m_tx->locktime = current_block_height;
    }

    bool Tx::has_witnesses() const
    {
        size_t witness_count;
        GDK_VERIFY(wally_tx_get_witness_count(m_tx.get(), &witness_count));
        return witness_count != 0;
    }

    size_t Tx::get_weight(bool with_discount) const
    {
        size_t weight, discount = 0;
        GDK_VERIFY(wally_tx_get_weight(m_tx.get(), &weight));
        if (with_discount) {
            GDK_VERIFY(wally_tx_get_elements_weight_discount(m_tx.get(), 0, &discount));
            GDK_RUNTIME_ASSERT(discount < weight);
        }
        return weight - discount;
    }

    size_t Tx::vsize_from_weight(size_t weight)
    {
        size_t written;
        GDK_VERIFY(wally_tx_vsize_from_weight(weight, &written));
        return written;
    }

    size_t Tx::get_adjusted_weight(const network_parameters& net_params) const
    {
        GDK_RUNTIME_ASSERT(m_is_liquid == net_params.is_liquid());
        size_t weight = get_weight(m_is_liquid);
        if (m_is_liquid) {
            // Add the weight of any missing blinding data
            size_t blinding_weight = 0;

            if (!has_witnesses()) {
                // Tx has no segwit inputs, and no blinded outputs, i.e.
                // it's being constructed via create_transaction et al.
                // Since we will be blinding the tx, this will create
                // output witnesses and so force witnesses to be serialized.
                // Account for this here with a zero byte for each witness:
                // inputs:
                // issuance_amount_rangeproof, inflation_keys_rangeproof, witness, pegin_witness
                const amount::value_type input_wit_weight = 1 + 1 + 1 + 1;
                blinding_weight += get_num_inputs() * input_wit_weight;
                // outputs:
                // surjectionproof, rangeproof
                const amount::value_type output_wit_weight = 1 + 1;
                blinding_weight += get_num_outputs() * output_wit_weight;
            }

            const auto num_fees
                = std::count_if(get_outputs().begin(), get_outputs().end(), [](const auto& o) { return !o.script; });
            GDK_RUNTIME_ASSERT(num_fees <= 1);
            if (num_fees) {
                // FIXME: Fee must be the last output
                GDK_RUNTIME_ASSERT(!get_outputs().back().script);
            } else {
                // Add weight for a fee output (which is always unblinded):
                // base: explicit asset, explicit value, empty nonce, empty script
                const amount::value_type fee_output_vbytes = 33 + 9 + 1 + 1;
                weight += fee_output_vbytes * 4;
                // witness: empty surjectionproof, empty rangeproof
                weight += 2;

                constexpr size_t VI_MAX_8 = 252; // Max single-byte varint value
                if (get_num_outputs() == VI_MAX_8) {
                    // Encoding num_outputs+1 will require an extra byte of base weight
                    weight += 1ul * 4ul;
                }
            }
            weight += blinding_weight;
        }
        return weight;
    }

    uint64_t Tx::get_fee(const network_parameters& net_params, uint64_t fee_rate) const
    {
        const size_t weight = get_adjusted_weight(net_params);
        const size_t vsize = Tx::vsize_from_weight(weight);
        const auto fee = static_cast<double>(vsize) * static_cast<double>(fee_rate) / 1000.0;
        return static_cast<uint64_t>(std::ceil(fee));
    }

    std::vector<unsigned char> Tx::get_signature_hash(
        session_impl& session, const std::vector<nlohmann::json>& utxos, size_t index, uint32_t sighash_flags) const
    {
        const auto& net_params = session.get_network_parameters();
        std::vector<unsigned char> ret(SHA256_LEN);
        const nlohmann::json& utxo = utxos.at(index);
        const auto& addr_type = j_strref(utxo, "address_type");
        const bool is_p2tr = addr_type == address_type::p2tr;

        GDK_RUNTIME_ASSERT(m_is_liquid == net_params.is_liquid());
        validate_sighash_flags(sighash_flags, is_p2tr, m_is_liquid);

        if (is_p2tr) {
            map_ptr scripts, assets, values;
            std::tie(scripts, assets, values) = get_signing_data(session, utxos);
            const auto genesis = net_params.get_genesis_hash();
            const uint32_t key_version = 0;
            GDK_VERIFY(wally_tx_get_input_signature_hash(m_tx.get(), index, scripts.get(), assets.get(), values.get(),
                NULL, 0, key_version, WALLY_NO_CODESEPARATOR, NULL, 0, genesis.empty() ? NULL : genesis.data(),
                genesis.size(), sighash_flags, WALLY_SIGTYPE_SW_V1, nullptr, ret.data(), ret.size()));
            return ret;
        }

        const bool is_segwit = address_type_is_segwit(addr_type);
        const uint32_t flags = is_segwit ? WALLY_TX_FLAG_USE_WITNESS : 0;
        const auto satoshi = j_amountref(utxo).value();
        const auto script = j_bytesref(utxo, "prevout_script");
        if (!m_is_liquid) {
            GDK_VERIFY(wally_tx_get_btc_signature_hash(m_tx.get(), index, script.data(), script.size(), satoshi,
                sighash_flags, flags, ret.data(), ret.size()));
        } else {
            // Liquid case - has a value-commitment in place of a satoshi value
            auto ct_value = j_bytes_or_empty(utxo, "commitment");
            if (ct_value.empty()) {
                const auto value = tx_confidential_value_from_satoshi(satoshi);
                ct_value.assign(std::begin(value), std::end(value));
            }
            GDK_VERIFY(wally_tx_get_elements_signature_hash(m_tx.get(), index, script.data(), script.size(),
                ct_value.data(), ct_value.size(), sighash_flags, flags, ret.data(), ret.size()));
        }
        return ret;
    }

    void Tx::validate_user_signatures(session_impl& session, std::vector<nlohmann::json>& inputs, bool for_rbf) const
    {
        const auto& net_params = session.get_network_parameters();
        const bool is_electrum = net_params.is_electrum();
        const bool is_liquid = net_params.is_liquid();
        const auto block_height = session.get_block_height();

        GDK_RUNTIME_ASSERT(get_num_inputs() == inputs.size());

        for (size_t i = 0; i < inputs.size(); ++i) {
            auto& input = inputs.at(i);
            if (!is_wallet_utxo(input)) {
                GDK_LOG(debug) << "Tx input " << i << " does not belog to the wallet";
                continue;
            }
            const bool is_p2tr = j_strref(input, "address_type") == address_type::p2tr;

            const auto& txin = get_input(i);
            // Verify the transaction signatures to prevent outputs
            // from being modified. Also store the users sighash in
            // case it wasn't SIGHASH_ALL.
            const auto der_sigs = get_input_signatures(net_params, input, i);
            GDK_RUNTIME_ASSERT(!der_sigs.empty());
            const auto keys = session.keys_from_utxo(input);
            for (size_t sig_i = 0; sig_i < der_sigs.size(); ++sig_i) {
                const auto& der_sig = der_sigs.at(sig_i);
                if (!is_electrum && get_version() >= WALLY_TX_VERSION_2 && sig_i == 0 && der_sig.empty()
                    && net_params.is_valid_csv_value(txin.sequence)) {
                    // Expired csv spend. Ignore the missing green sig, and
                    // ensure we have a user sig to verify/get the sighash.
                    GDK_LOG(debug) << "Tx input " << i << " spent via expiry";
                    GDK_RUNTIME_ASSERT(der_sigs.size() == 2);
                    // We must set a block and expiry height in order to
                    // recognise the input as expired when signing. Note
                    // the sequence is what is set in the tx so the actual
                    // values don't matter; just that the expiry height is
                    // at least sequence blocks before the block height.
                    if (for_rbf) {
                        input["block_height"] = block_height;
                        input["expiry_height"] = block_height - txin.sequence;
                    }
                    continue;
                }
                GDK_RUNTIME_ASSERT(!der_sig.empty()); // Must have a signature
                uint32_t sighash_flags;
                uint32_t flags;
                ec_sig_t sig;
                std::vector<unsigned char> public_key;

                if (is_p2tr) {
                    const auto sig_len = der_sig.size();
                    GDK_RUNTIME_ASSERT(sig_len == EC_SIGNATURE_LEN || sig_len == EC_SIGNATURE_LEN + 1);
                    sighash_flags = sig_len == EC_SIGNATURE_LEN ? WALLY_SIGHASH_DEFAULT : der_sig.back();
                    memcpy(&sig, der_sig.data(), EC_SIGNATURE_LEN);
                    public_key = keys.at(sig_i).get_tweaked_xonly_key(is_liquid);
                    flags = EC_FLAG_SCHNORR;
                } else {
                    sighash_flags = der_sig.back();
                    constexpr bool has_sighash_byte = true;
                    sig = ec_sig_from_der(der_sig, has_sighash_byte);
                    const auto pk = keys.at(sig_i).get_public_key();
                    public_key = { pk.begin(), pk.end() };
                    flags = EC_FLAG_ECDSA;
                }
                if (for_rbf) {
                    input["user_sighash"] = sighash_flags;
                }
                const auto signature_hash = get_signature_hash(session, inputs, i, sighash_flags);
                GDK_RUNTIME_ASSERT(ec_sig_verify(public_key, signature_hash, sig, flags));
            }
        }
    }

    void utxo_add_paths(session_impl& session, nlohmann::json& utxo)
    {
        const auto subaccount = j_uint32_or_zero(utxo, "subaccount");

        if (!utxo.contains("user_path")) {
            // Populate the full user path for signing
            const auto pointer = j_uint32ref(utxo, "pointer");
            const auto is_internal = j_bool_or_false(utxo, "is_internal");
            utxo["user_path"] = session.get_user_pubkeys().get_full_path(subaccount, pointer, is_internal);
        }

        if (session.get_network_parameters().is_electrum()) {
            // Electrum sessions currently only support single sig
            return;
        }

        if (!utxo.contains("service_xpub")) {
            // Populate the service xpub for h/w signing
            utxo["service_xpub"] = session.get_green_pubkeys().get_subaccount(subaccount).to_base58();
        }

        if (!utxo.contains("recovery_xpub") && session.get_recovery_pubkeys().have_subaccount(subaccount)) {
            // Populate the recovery xpub for h/w signing
            utxo["recovery_xpub"] = session.get_recovery_pubkeys().get_subaccount(subaccount).to_base58();
        }
    }

    void confidentialize_address(
        const network_parameters& net_params, nlohmann::json& addr, const std::string& blinding_pubkey_hex)
    {
        GDK_RUNTIME_ASSERT(addr.at("is_confidential") == false);
        const std::string bech32_prefix = net_params.bech32_prefix();
        auto& address = addr.at("address");
        addr["unconfidential_address"] = address;
        if (boost::starts_with(address.get<std::string>(), bech32_prefix)) {
            const std::string blech32_prefix = net_params.blech32_prefix();
            address = confidential_addr_from_addr_segwit(address, bech32_prefix, blech32_prefix, blinding_pubkey_hex);
        } else {
            address = confidential_addr_from_addr(address, net_params.blinded_prefix(), blinding_pubkey_hex);
        }
        addr["blinding_key"] = blinding_pubkey_hex;
        addr["is_confidential"] = true;
    }

    void create_transaction(session_impl& session, nlohmann::json& details)
    {
        try {
            // Wrap the actual processing in try/catch
            // The idea here is that result is populated with as much detail as possible
            // before returning any error to allow the caller to make iterative changes
            // fixing each error
            details["error"] = std::string(); // Clear any existing error
            create_transaction_impl(session, details);
        } catch (const std::exception& e) {
            set_tx_error(details, e.what());
        }
    }

    std::vector<std::string> sign_transaction(
        session_impl& session, const Tx& tx, const std::vector<nlohmann::json>& inputs)
    {
        const auto& net_params = session.get_network_parameters();
        const bool is_liquid = net_params.is_liquid();
        std::vector<std::string> sigs(inputs.size());

        for (size_t i = 0; i < inputs.size(); ++i) {
            const auto& utxo = inputs.at(i);
            GDK_RUNTIME_ASSERT(j_str_is_empty(utxo, "private_key"));
            if (utxo.value("skip_signing", false)) {
                continue;
            }
            const bool is_p2tr = j_strref(utxo, "address_type") == address_type::p2tr;
            const auto default_sighash = is_p2tr ? WALLY_SIGHASH_DEFAULT : WALLY_SIGHASH_ALL;
            const auto sighash_flags = j_uint32(utxo, "user_sighash").value_or(default_sighash);
            const auto message = tx.get_signature_hash(session, inputs, i, sighash_flags);

            const uint32_t subaccount = j_uint32_or_zero(utxo, "subaccount");
            const uint32_t pointer = j_uint32_or_zero(utxo, "pointer");
            const bool is_internal = j_bool_or_false(utxo, "is_internal");
            const auto path = session.get_user_pubkeys().get_full_path(subaccount, pointer, is_internal);
            if (is_p2tr) {
                const auto sig = session.get_nonnull_signer()->schnorr_sign(path, message, is_liquid);
                std::vector<unsigned char> sig_with_sighash{ sig.begin(), sig.end() };
                if (sighash_flags != WALLY_SIGHASH_DEFAULT) {
                    // Include the sighash flags when non-default, per BIP 341
                    sig_with_sighash.push_back(static_cast<unsigned char>(sighash_flags));
                }
                sigs[i] = b2h(sig_with_sighash);
            } else {
                const auto sig = session.get_nonnull_signer()->ecdsa_sign(path, message);
                sigs[i] = b2h(ec_sig_to_der(sig, sighash_flags));
            }
        }
        return sigs;
    }

    static std::array<unsigned char, SHA256_LEN> hash_prevouts_from_utxos(const nlohmann::json& details)
    {
        const auto& tx_inputs = j_arrayref(details, "transaction_inputs");
        std::vector<unsigned char> txhashes;
        std::vector<uint32_t> output_indices;
        txhashes.reserve(tx_inputs.size() * WALLY_TXHASH_LEN);
        output_indices.reserve(tx_inputs.size());
        for (const auto& utxo : tx_inputs) {
            const auto txhash_bin = j_rbytesref(utxo, "txhash", WALLY_TXHASH_LEN);
            txhashes.insert(txhashes.end(), txhash_bin.begin(), txhash_bin.end());
            output_indices.emplace_back(j_uint32ref(utxo, "pt_idx"));
        }
        return get_hash_prevouts(txhashes, output_indices);
    }

    nlohmann::json get_blinding_factors(const blinding_key_t& master_blinding_key, const nlohmann::json& details)
    {
        const auto& transaction_outputs = details.at("transaction_outputs");

        const auto hash_prevouts = hash_prevouts_from_utxos(details);
        const bool is_partial = details.at("is_partial");

        nlohmann::json::array_t abfs, vbfs;
        abfs.reserve(transaction_outputs.size());
        vbfs.reserve(transaction_outputs.size());

        for (size_t i = 0; i < transaction_outputs.size(); ++i) {
            auto& output = transaction_outputs[i];
            bool need_bfs = output.contains("blinding_key");

            abf_vbf_t abf_vbf;
            if (need_bfs) {
                abf_vbf = asset_blinding_key_to_abf_vbf(master_blinding_key, hash_prevouts, i);
                abfs.emplace_back(b2h_rev({ abf_vbf.data(), BLINDING_FACTOR_LEN }));
            } else {
                abfs.emplace_back(std::string());
            }
            // Skip final vbf for non-partial txs; it is calculated by gdk
            if (need_bfs && (is_partial || i != transaction_outputs.size() - 1)) {
                vbfs.emplace_back(b2h_rev({ abf_vbf.data() + BLINDING_FACTOR_LEN, BLINDING_FACTOR_LEN }));
            } else {
                vbfs.emplace_back(std::string());
            }
        }
        return { { "amountblinders", std::move(vbfs) }, { "assetblinders", std::move(abfs) } };
    }

    void blind_transaction(session_impl& session, nlohmann::json& details, const nlohmann::json& blinding_data)
    {
        const auto& net_params = session.get_network_parameters();
        const bool is_liquid = net_params.is_liquid();
        GDK_RUNTIME_ASSERT(is_liquid);

        const std::string error = j_str_or_empty(details, "error");
        if (!error.empty()) {
            GDK_LOG(debug) << " attempt to blind with error: " << details.dump();
            throw user_error(error);
        }
        const auto& assetblinders = blinding_data.at("assetblinders");
        const auto& amountblinders = blinding_data.at("amountblinders");

        const auto& tx_inputs = details.at("transaction_inputs");
        auto& transaction_outputs = details.at("transaction_outputs");

        Tx tx(j_strref(details, "transaction"), is_liquid);
        const bool is_partial = j_bool_or_false(details, "is_partial");
        const bool blinding_nonces_required = j_boolref(details, "blinding_nonces_required");

        // We must have at least a regular output and a fee output, unless partial
        GDK_RUNTIME_ASSERT(transaction_outputs.size() >= (is_partial ? 1 : 2));
        const auto num_fees = std::count_if(transaction_outputs.begin(), transaction_outputs.end(),
            [](const auto& o) { return j_str_is_empty(o, "scriptpubkey"); });
        if (is_partial) {
            // We must not have a fee output as the transaction is incomplete
            GDK_RUNTIME_ASSERT(num_fees == 0);
        } else {
            // We must have a fee output, and it must be the last one
            GDK_RUNTIME_ASSERT(num_fees == 1 && j_str_is_empty(transaction_outputs.back(), "scriptpubkey"));
        }
        std::vector<unsigned char> assets, generators, abfs, all_abfs, vbfs;
        std::vector<uint64_t> values;
        size_t num_inputs = 0;

        const size_t num_in_outs = tx_inputs.size() + transaction_outputs.size();
        assets.reserve(num_in_outs * WALLY_TX_ASSET_TAG_LEN);
        generators.reserve(num_in_outs * ASSET_GENERATOR_LEN);
        abfs.reserve(num_in_outs * BLINDING_FACTOR_LEN);
        all_abfs.reserve(num_in_outs * BLINDING_FACTOR_LEN);
        vbfs.reserve(num_in_outs * BLINDING_FACTOR_LEN);
        values.reserve(num_in_outs);

        for (const auto& utxo : tx_inputs) {
            const auto asset_id = j_rbytesref(utxo, "asset_id");
            assets.insert(assets.end(), std::begin(asset_id), std::end(asset_id));
            const auto abf = j_rbytesref(utxo, "assetblinder");
            const auto generator = asset_generator_from_bytes(asset_id, abf);
            generators.insert(generators.end(), std::begin(generator), std::end(generator));
            all_abfs.insert(all_abfs.end(), std::begin(abf), std::end(abf));

            // If the input has a vbf, it contributes to the final vbf calculation.
            // If not, it has been previously blinded; its contribution is
            // captured with a scalar offset in the tx level element "scalars".
            if (const auto vbf = j_rbytes_or_empty(utxo, "amountblinder"); !vbf.empty()) {
                vbfs.insert(vbfs.end(), std::begin(vbf), std::end(vbf));
                abfs.insert(abfs.end(), std::begin(abf), std::end(abf));
                values.emplace_back(j_amountref(utxo, "satoshi").value());
                ++num_inputs;
            }
        }
        // We must have at least one input in the tx
        GDK_RUNTIME_ASSERT(num_inputs);

        nlohmann::json::array_t blinding_nonces;
        if (blinding_nonces_required) {
            blinding_nonces.reserve(transaction_outputs.size());
        }

        for (size_t i = 0; i < transaction_outputs.size(); ++i) {
            auto& output = transaction_outputs[i];
            if (j_str_is_empty(output, "scriptpubkey")) {
                continue; // Fee
            }
            const auto asset_id = j_rbytesref(output, "asset_id");
            const auto value = j_amountref(output, "satoshi");

            // If an output has a vbf, it contributes to the final vbf calculation.
            // If not, it either:
            //  1) Is belongs to this wallet and is due to be blinded below, OR
            //  2) Has been previously blinded; its contribution comes from "scalars" as above.
            // We distinguish between (1) from (2) by the presence of "blinding_key".
            const bool is_ours = output.contains("blinding_key");
            const bool is_partially_blinded = output.contains("assetblinder");
            const bool is_fully_blinded = is_partially_blinded && output.contains("amountblinder");
            const bool for_final_vbf = is_fully_blinded || is_ours;
            if (is_ours) {
                // We only blind once; this output must not have been blinded before
                GDK_RUNTIME_ASSERT(!is_partially_blinded && !is_fully_blinded);
            } else {
                // Must have an asset blinder, may not have an amount blinder
                GDK_RUNTIME_ASSERT(is_partially_blinded);
            }
            if (for_final_vbf) {
                values.emplace_back(value.value());
            }

            auto abf = j_rbytes_or_empty(output, "assetblinder");
            if (for_final_vbf) {
                if (abf.empty()) {
                    const auto abf_hex = assetblinders.at(i);
                    output["assetblinder"] = abf_hex;
                    abf = h2b_rev(abf_hex);
                }
                abfs.insert(abfs.end(), std::begin(abf), std::end(abf));
            }
            GDK_RUNTIME_ASSERT_MSG(abf.size() == 32u, "Invalid tx output assetblinder");

            vbf_t vbf{ 0 };
            if (is_partial || i < transaction_outputs.size() - 2) {
                if (for_final_vbf) {
                    auto vbf_hex = j_str(output, "amountblinder").value_or(amountblinders.at(i));
                    vbf = h2b_rev<32>(vbf_hex);
                }
                // Leave the vbf to 0, below this value will not be used.
            } else {
                // This is the final non-fee output: compute the final vbf
                GDK_RUNTIME_ASSERT(for_final_vbf);
                vbf = asset_final_vbf(values, num_inputs, abfs, vbfs);

                // Add the scalar offsets from any pre-blinded outputs in
                // order to capture their contribution to the final vbf.
                if (const auto scalars = j_array(details, "scalars"); scalars.has_value()) {
                    // TODO: Allow for multiple scalars as per e.g. PSET.
                    // Currently we only allow one scalar per pre-blinded
                    // input to avoid the potential for footguns.
                    const auto& a = details.at("addressees");
                    const size_t num_blinded = std::count_if(
                        a.begin(), a.end(), [](const auto& ad) { return j_bool_or_false(ad, "is_blinded"); });
                    GDK_RUNTIME_ASSERT(scalars.value().size() == num_blinded);
                    for (const auto& scalar : scalars.value()) {
                        vbf = ec_scalar_add(vbf, h2b(scalar));
                    }
                }
            }
            if (for_final_vbf) {
                output["amountblinder"] = b2h_rev(vbf);
                vbfs.insert(vbfs.end(), std::begin(vbf), std::end(vbf));
            }

            const auto& o = tx.get_output(i);
            const auto generator = asset_generator_from_bytes(asset_id, abf);
            std::vector<unsigned char> value_commitment;
            if (for_final_vbf) {
                value_commitment = asset_value_commitment(value.value(), vbf, generator);
            } else {
                value_commitment = { o.value, o.value + o.value_len };
            }

            const auto scriptpubkey = j_bytesref(output, "scriptpubkey");

            std::vector<unsigned char> eph_public_key;
            std::vector<unsigned char> rangeproof;

            if (is_blinded(o) && !memcmp(o.asset, generator.data(), o.asset_len)
                && !memcmp(o.value, value_commitment.data(), o.value_len)) {
                // Rangeproof already created for the same commitments
                eph_public_key.assign(o.nonce, o.nonce + o.nonce_len);
                rangeproof.assign(o.rangeproof, o.rangeproof + o.rangeproof_len);
                if (blinding_nonces_required) {
                    // Add the pre-blinded outputs blinding nonce
                    GDK_RUNTIME_ASSERT(output.contains("blinding_nonce"));
                    blinding_nonces.emplace_back(std::move(output.at("blinding_nonce")));
                }
            } else {
                GDK_RUNTIME_ASSERT(!output.contains("nonce_commitment"));
                priv_key_t eph_private_key;
                std::tie(eph_private_key, eph_public_key) = get_ephemeral_keypair();
                output["eph_public_key"] = b2h(eph_public_key);
                const auto blinding_pubkey = j_bytesref(output, "blinding_key");
                GDK_RUNTIME_ASSERT(!output.contains("blinding_nonce"));
                if (blinding_nonces_required) {
                    // Generate the blinding nonce for the caller
                    const auto nonce = sha256(ecdh(blinding_pubkey, eph_private_key));
                    blinding_nonces.emplace_back(b2h(nonce));
                }

                rangeproof = asset_rangeproof(value.value(), blinding_pubkey, eph_private_key, asset_id, abf, vbf,
                    value_commitment, scriptpubkey, generator);
            }

            std::vector<unsigned char> surjectionproof;
            if (!is_partial) {
                const auto entropy = get_random_bytes<32>();
                surjectionproof
                    = asset_surjectionproof(asset_id, abf, generator, entropy, assets, all_abfs, generators);
            }

            tx.set_output_commitments(i, generator, value_commitment, eph_public_key, surjectionproof, rangeproof);
        }

        details["is_blinded"] = true;
        if (blinding_nonces_required) {
            if (!is_partial) {
                blinding_nonces.emplace_back(std::string{}); // Add an empty fee nonce
            }
            details["blinding_nonces"] = std::move(blinding_nonces);
        }
        // Update tx size information with the exact proof sizes
        update_tx_size_info(net_params, tx, details);
    }

    nlohmann::json unblind_output(session_impl& session, const Tx& tx, uint32_t vout)
    {
        // FIXME: this is another place where unblinding is performed (the other is ga_session::unblind_utxo).
        //        This is not ideal and we should aim to have a single place to perform unblinding,
        //        but unfortunately it is quite complex so for now we have this duplication.
        const auto& net_params = session.get_network_parameters();
        GDK_RUNTIME_ASSERT(net_params.is_liquid());
        GDK_RUNTIME_ASSERT(vout < tx.get_num_outputs());

        nlohmann::json result = nlohmann::json::object();
        const auto& o = tx.get_output(vout);
        if (is_explicit(o)) {
            result["satoshi"] = tx_confidential_value_to_satoshi({ o.value, o.value_len });
            result["assetblinder"] = ZEROS;
            result["amountblinder"] = ZEROS;
            GDK_RUNTIME_ASSERT(o.asset && *o.asset == 1);
            result["asset_id"] = b2h_rev({ o.asset + 1, o.asset_len - 1 });
        } else if (is_blinded(o)) {
            const auto scriptpubkey = gsl::make_span(o.script, o.script_len);
            const auto blinding_private_key = session.get_nonnull_signer()->get_blinding_key_from_script(scriptpubkey);
            const auto asset_commitment = gsl::make_span(o.asset, o.asset_len);
            const auto value_commitment = gsl::make_span(o.value, o.value_len);
            const auto nonce_commitment = gsl::make_span(o.nonce, o.nonce_len);
            const auto rangeproof = gsl::make_span(o.rangeproof, o.rangeproof_len);

            unblind_t unblinded;
            try {
                unblinded = asset_unblind(blinding_private_key, rangeproof, value_commitment, nonce_commitment,
                    scriptpubkey, asset_commitment);
            } catch (const std::exception&) {
                result["error"] = "failed to unblind utxo";
                return result;
            }
            result["satoshi"] = std::get<3>(unblinded);
            result["assetblinder"] = b2h_rev(std::get<2>(unblinded));
            result["amountblinder"] = b2h_rev(std::get<1>(unblinded));
            result["asset_id"] = b2h_rev(std::get<0>(unblinded));
        } else {
            // Mixed case is not handled
            GDK_RUNTIME_ASSERT_MSG(false, "Output is not fully blinded or not fully explicit");
        }

        return result;
    }

} // namespace green
