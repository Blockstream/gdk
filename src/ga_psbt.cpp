#include "ga_psbt.hpp"
#include "exception.hpp"
#include "ga_tx.hpp"
#include "json_utils.hpp"
#include "logging.hpp"
#include "session_impl.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"

#include <nlohmann/json.hpp>

#include <wally_psbt.h>
#include <wally_psbt_members.h>

namespace ga {
namespace sdk {
    namespace {
        // PSBT input/output field constants from
        // https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
        constexpr uint32_t in_redeem_script = 0x04;

        // PSET input/output field constants from
        // https://github.com/ElementsProject/elements/blob/master/doc/pset.mediawiki

        // constexpr uint32_t in_issuance_value = 0x00;
        // constexpr uint32_t in_issuance_value_commitment = 0x01;
        // constexpr uint32_t in_issuance_value_rangeproof = 0x02;
        // constexpr uint32_t in_issuance_inflation_keys_rangeproof = 0x03;
        // constexpr uint32_t in_peg_in_tx = 0x04;
        // constexpr uint32_t in_peg_in_txout_proof = 0x05;
        // constexpr uint32_t in_peg_in_genesis_hash = 0x06;
        // constexpr uint32_t in_peg_in_claim_script = 0x07;
        // constexpr uint32_t in_peg_in_value = 0x08;
        // constexpr uint32_t in_peg_in_witness = 0x09;
        // constexpr uint32_t in_issuance_inflation_keys_amount = 0x0a;
        // constexpr uint32_t in_issuance_inflation_keys_commitment = 0x0b;
        // constexpr uint32_t in_issuance_blinding_nonce = 0x0c;
        // constexpr uint32_t in_issuance_asset_entropy = 0x0d;
        // constexpr uint32_t in_utxo_rangeproof = 0x0e;
        // constexpr uint32_t in_issuance_blind_value_proof = 0x0f;
        // constexpr uint32_t in_issuance_blind_inflation_keys_proof = 0x10;
        // constexpr uint32_t in_explicit_value = 0x11;
        constexpr uint32_t in_value_proof = 0x12;
        constexpr uint32_t in_explicit_asset = 0x13;
        constexpr uint32_t in_asset_proof = 0x14;

        constexpr uint32_t out_value_commitment = 0x01;
        constexpr uint32_t out_asset = 0x02;
        constexpr uint32_t out_asset_commitment = 0x03;
        constexpr uint32_t out_value_rangeproof = 0x04;
        constexpr uint32_t out_asset_surjection_proof = 0x05;
        constexpr uint32_t out_blinding_pubkey = 0x06;
        constexpr uint32_t out_ecdh_pubkey = 0x07;
        // constexpr uint32_t out_blinder_index = 0x08;
        constexpr uint32_t out_blind_value_proof = 0x09;
        constexpr uint32_t out_blind_asset_proof = 0x0a;

        using optional_bytes_t = std::optional<gsl::span<const unsigned char>>;

        static optional_bytes_t get_field(const struct wally_map* m, uint32_t k)
        {
            const auto p = wally_map_get_integer(m, k);
            if (p) {
                return gsl::make_span(p->value, p->value_len);
            }
            return {};
        }

        template <typename T> static inline optional_bytes_t psbt_field(const T& src, uint32_t k)
        {
            return get_field(&src.psbt_fields, k);
        }

        template <typename T> static inline optional_bytes_t pset_field(const T& src, uint32_t k)
        {
            return get_field(&src.pset_fields, k);
        }

        template <typename T>
        static void set_pset_field(
            const T& src, nlohmann::json& dst, const char* key, uint32_t k, bool do_reverse = false)
        {
            const auto val = pset_field(src, k);
            if (!val.has_value()) {
                throw user_error(std::string(key) + " not found");
            }
            dst[key] = (do_reverse ? b2h_rev : b2h)(val.value());
        }
    } // namespace

    void Psbt::psbt_deleter::operator()(struct wally_psbt* p) { wally_psbt_free(p); }

    Psbt::Psbt(const std::string& psbt_base64, bool is_liquid)
        : m_original_version(0)
        , m_is_liquid(is_liquid)
    {
        struct wally_psbt* p;
        constexpr uint32_t b64_flags = 0;
        GDK_VERIFY(wally_psbt_from_base64(psbt_base64.c_str(), b64_flags, &p));
        m_psbt.reset(p);
        size_t val;
        GDK_VERIFY(wally_psbt_is_elements(m_psbt.get(), &val));
        if (m_is_liquid != !!val) {
            throw user_error("PSBT/PSET mismatch");
        }
        GDK_VERIFY(wally_psbt_get_version(m_psbt.get(), &val));
        m_original_version = static_cast<uint32_t>(val);
        // Upgrade to version 2 so our processing in gdk is identical
        constexpr uint32_t ver_flags = 0;
        GDK_VERIFY(wally_psbt_set_version(m_psbt.get(), ver_flags, WALLY_PSBT_VERSION_2));
    }

    Psbt::~Psbt() {}

    void Psbt::swap(Psbt& rhs)
    {
        std::swap(m_is_liquid, rhs.m_is_liquid);
        std::swap(m_original_version, rhs.m_original_version);
        std::swap(m_psbt, rhs.m_psbt);
    }

    Tx Psbt::extract() const
    {
        struct wally_tx* p;
        /* Extract any finalized input data, but don't require it */
        constexpr uint32_t flags = WALLY_PSBT_EXTRACT_OPT_FINAL;
        GDK_VERIFY(wally_psbt_extract(m_psbt.get(), flags, &p));
        return Tx(p, m_is_liquid);
    }

    std::string Psbt::to_base64(bool include_redundant) const
    {
        std::unique_ptr<struct wally_psbt> tmp;
        struct wally_psbt* psbt = m_psbt.get();
        if (m_original_version != WALLY_PSBT_VERSION_2) {
            // Clone and downgrade the PSBT
            constexpr uint32_t clone_flags = 0, ver_flags = 0;
            GDK_VERIFY(wally_psbt_clone_alloc(psbt, clone_flags, &psbt));
            tmp.reset(psbt);
            GDK_VERIFY(wally_psbt_set_version(psbt, ver_flags, m_original_version));
        }
        const uint32_t b64_flags = include_redundant ? WALLY_PSBT_SERIALIZE_FLAG_REDUNDANT : 0;
        char* output = nullptr;
        GDK_VERIFY(wally_psbt_to_base64(psbt, b64_flags, &output));
        wally_string_ptr tmp_str(output);
        return std::string(tmp_str.get());
    }

    size_t Psbt::get_num_inputs() const { return m_psbt->num_inputs; }

    struct wally_psbt_input& Psbt::get_input(size_t index)
    {
        return const_cast<struct wally_psbt_input&>(std::as_const(*this).get_input(index));
    }

    const struct wally_psbt_input& Psbt::get_input(size_t index) const
    {
        GDK_RUNTIME_ASSERT(index < m_psbt->num_inputs);
        return m_psbt->inputs[index];
    }

    void Psbt::set_input_finalization_data(size_t index, const Tx& tx)
    {
        const auto& txin = tx.get_input(index);
        GDK_VERIFY(wally_psbt_set_input_final_witness(m_psbt.get(), index, txin.witness));
        GDK_VERIFY(wally_psbt_set_input_final_scriptsig(m_psbt.get(), index, txin.script, txin.script_len));
    }

    size_t Psbt::get_num_outputs() const { return m_psbt->num_outputs; }

    struct wally_psbt_output& Psbt::get_output(size_t index)
    {
        return const_cast<struct wally_psbt_output&>(std::as_const(*this).get_output(index));
    }

    const struct wally_psbt_output& Psbt::get_output(size_t index) const
    {
        GDK_RUNTIME_ASSERT(index < m_psbt->num_outputs);
        return m_psbt->outputs[index];
    }

    nlohmann::json Psbt::get_details(session_impl& session, nlohmann::json details) const
    {
        const auto& net_params = session.get_network_parameters();
        const auto policy_asset = net_params.get_policy_asset();
        Tx tx(extract());

        auto inputs_and_assets = inputs_to_json(session, tx, std::move(details.at("utxos")));
        auto outputs = outputs_to_json(session, tx, inputs_and_assets.second);
        amount sum, explicit_fee;
        bool use_error = false;
        std::string error;
        for (const auto& input : inputs_and_assets.first) {
            auto txin_error = j_str_or_empty(input, "error");
            if (!txin_error.empty()) {
                error = std::move(txin_error);
                if (!j_bool_or_false(input, "skip_signing")) {
                    /* We aren't skipping this input while signing, so mark
                     * the overall tx as in error (results can't be trusted) */
                    use_error = true;
                }
                continue;
            }
            if (!m_is_liquid || j_asset(net_params, input) == policy_asset) {
                sum += j_amountref(input);
            }
        }
        for (const auto& txout : outputs) {
            if (!m_is_liquid || j_asset(net_params, txout) == policy_asset) {
                if (m_is_liquid && j_str_is_empty(txout, "scriptpubkey")) {
                    explicit_fee += j_amountref(txout);
                } else {
                    sum -= j_amountref(txout);
                }
            }
        }
        // Calculated fee must match fee output for Liquid unless an error occurred
        GDK_RUNTIME_ASSERT(!m_is_liquid || sum == explicit_fee || !error.empty());

        nlohmann::json result
            = { { "transaction", tx.to_hex() }, { "transaction_inputs", std::move(inputs_and_assets.first) },
                  { "transaction_outputs", std::move(outputs) } };
        result["fee"] = m_is_liquid ? explicit_fee.value() : sum.value();
        result["network_fee"] = 0;
        update_tx_info(session, tx, result);
        result["txhash"] = b2h_rev(tx.get_txid());
        if (use_error)
            result.emplace("error", std::move(error));
        return result;
    }

    std::pair<nlohmann::json, std::set<std::string>> Psbt::inputs_to_json(
        session_impl& session, Tx& tx, nlohmann::json utxos) const
    {
        const auto& net_params = session.get_network_parameters();
        std::set<std::string> wallet_assets;
        nlohmann::json::array_t inputs;
        inputs.resize(get_num_inputs());
        for (size_t i = 0; i < inputs.size(); ++i) {
            const auto& psbt_input = get_input(i);
            auto& txin = tx.get_input(i);
            auto& utxo = inputs[i];
            utxo = tx.input_to_json(i);
            const std::string txhash_hex = j_strref(utxo, "txhash"); // Note as-value

            bool is_wallet_utxo = false;
            for (auto& u : utxos) {
                if (!u.empty() && j_uint32ref(u, "pt_idx") == psbt_input.index && j_strref(u, "txhash") == txhash_hex) {
                    // Wallet UTXO
                    utxo = std::move(u);
                    wallet_assets.insert(j_asset(net_params, utxo));
                    is_wallet_utxo = true;
                    break;
                }
            }
            if (is_wallet_utxo) {
                // Wallet UTXO
                utxo["user_sighash"] = psbt_input.sighash ? psbt_input.sighash : WALLY_SIGHASH_ALL;
                for (const auto& key : { "user_status", "witness", "script_sig" }) {
                    utxo.erase(key);
                }
                utxo_add_paths(session, utxo);
                if (!txin.script || !txin.witness) {
                    // FIXME: get the sigs from the PSBT, uses dummy sigs for now
                    byte_span_t user_der, green_der;
                    auto [scriptsig, witness] = get_scriptsig_and_witness(session, utxo, user_der, green_der);
                    if (!txin.script) {
                        GDK_VERIFY(wally_tx_input_set_script(&txin, scriptsig.data(), scriptsig.size()));
                    }
                    if (!txin.witness) {
                        GDK_VERIFY(wally_tx_input_set_witness(&txin, witness.get()));
                    }
                }
            } else {
                // Non-wallet UTXO
                utxo["skip_signing"] = true;
                const struct wally_tx_output* txin_utxo;
                GDK_VERIFY(wally_psbt_get_input_best_utxo(m_psbt.get(), i, &txin_utxo));
                if (!txin_utxo) {
                    auto utxo_tx = session.get_raw_transaction_details(txhash_hex);
                    GDK_VERIFY(wally_psbt_set_input_utxo(m_psbt.get(), i, utxo_tx.get()));
                    GDK_VERIFY(wally_psbt_get_input_best_utxo(m_psbt.get(), i, &txin_utxo));
                }
                GDK_RUNTIME_ASSERT(txin_utxo);
                if (!m_is_liquid) {
                    utxo["satoshi"] = txin_utxo->satoshi;
                } else {
                    if (psbt_input.has_amount) {
                        // An explicit value/asset, along with its proofs
                        utxo["satoshi"] = psbt_input.amount;
                        set_pset_field(psbt_input, utxo, "asset_id", in_explicit_asset, true);
                        set_pset_field(psbt_input, utxo, "value_blind_proof", in_value_proof);
                        set_pset_field(psbt_input, utxo, "asset_blind_proof", in_asset_proof);
                    } else {
                        utxo["error"] = "failed to unblind utxo";
                    }
                }
                const auto redeem_script = psbt_field(psbt_input, in_redeem_script);
                if (redeem_script.has_value()) {
                    utxo["redeem_script"] = b2h(redeem_script.value());
                }
            }
        }
        return std::make_pair(std::move(inputs), std::move(wallet_assets));
    }

    nlohmann::json Psbt::outputs_to_json(
        session_impl& session, const Tx& tx, const std::set<std::string>& wallet_assets) const
    {
        const auto& net_params = session.get_network_parameters();
        const bool is_electrum = net_params.is_electrum();
        std::set<std::string> spent_assets;
        std::map<std::string, std::vector<size_t>> asset_outputs;

        nlohmann::json::array_t outputs;
        outputs.resize(get_num_outputs());
        for (size_t i = 0; i < outputs.size(); ++i) {
            const auto& txout = get_output(i);
            auto& jsonout = outputs[i];
            if (!m_is_liquid) {
                GDK_RUNTIME_ASSERT(txout.has_amount);
                GDK_RUNTIME_ASSERT(txout.script && txout.script_len);
                jsonout["satoshi"] = txout.amount;
                jsonout["scriptpubkey"] = b2h({ txout.script, txout.script_len });
            } else {
                // Even if blinded, the PSET must have an explicit value/asset
                set_pset_field(txout, jsonout, "asset_id", out_asset, true);
                GDK_RUNTIME_ASSERT(txout.has_amount);
                jsonout["satoshi"] = txout.amount;

                size_t blinding_status;
                GDK_VERIFY(wally_psbt_get_output_blinding_status(m_psbt.get(), i, 0, &blinding_status));
                if (blinding_status == WALLY_PSET_BLINDED_NONE) {
                    // If this output is unblinded, it must be the fee
                    GDK_RUNTIME_ASSERT(!txout.script);
                    jsonout["scriptpubkey"] = std::string();
                    continue;
                }
                GDK_RUNTIME_ASSERT(blinding_status == WALLY_PSET_BLINDED_FULL);
                set_pset_field(txout, jsonout, "commitment", out_value_commitment);
                set_pset_field(txout, jsonout, "asset_tag", out_asset_commitment);
                set_pset_field(txout, jsonout, "range_proof", out_value_rangeproof);
                set_pset_field(txout, jsonout, "surj_proof", out_asset_surjection_proof);
                set_pset_field(txout, jsonout, "blinding_key", out_blinding_pubkey);
                set_pset_field(txout, jsonout, "nonce_commitment", out_ecdh_pubkey);
                set_pset_field(txout, jsonout, "value_blind_proof", out_blind_value_proof);
                // out_blinder_index unused
                set_pset_field(txout, jsonout, "asset_blind_proof", out_blind_asset_proof);

                GDK_RUNTIME_ASSERT(txout.script);
                jsonout["scriptpubkey"] = b2h({ txout.script, txout.script_len });
            }
            auto output_data = session.get_scriptpubkey_data({ txout.script, txout.script_len });
            const bool is_wallet_output = !output_data.empty();
            if (!is_wallet_output) {
                jsonout["address"] = get_address_from_scriptpubkey(net_params, { txout.script, txout.script_len });
            } else {
                if (m_is_liquid) {
                    const auto unblinded = unblind_output(session, tx, i);
                    if (unblinded.contains("error")) {
                        GDK_LOG(warning) << "output " << i << ": " << unblinded.at("error");
                        // FIXME: store blinded
                        continue; // Failed to unblind
                    }
                    output_data.update(unblinded);
                }
                jsonout.update(output_data);
                jsonout["address"] = get_address_from_utxo(session, jsonout);
                utxo_add_paths(session, jsonout);
            }
            if (m_is_liquid) {
                // Confidentialize the address
                nlohmann::json unconf_addr = { { "address", jsonout.at("address") }, { "is_confidential", false } };
                confidentialize_address(net_params, unconf_addr, jsonout.at("blinding_key"));
                jsonout["address"] = std::move(unconf_addr.at("address"));
            }
            // Change detection
            auto asset_id = j_asset(net_params, jsonout);
            if (wallet_assets.count(asset_id)) {
                if (!is_electrum) {
                    // Multisig: Collect info to compute change below
                    if (is_wallet_output) {
                        asset_outputs[asset_id].push_back(i);
                    } else {
                        spent_assets.emplace(std::move(asset_id));
                    }
                } else if (is_wallet_output) {
                    // Singlesig: Outputs on the internal chain are change
                    jsonout["is_change"] = j_bool_or_false(jsonout, "is_internal");
                }
            }
        }
        if (!is_electrum) {
            // Multisig change detection (heuristic)
            for (const auto& o : asset_outputs) {
                if (wallet_assets.count(o.first)) {
                    // This is an asset that we contributed an input to
                    const bool is_spent_externally = spent_assets.count(o.first) != 0;
                    const auto num_wallet_outputs = o.second.size();
                    if (is_spent_externally || num_wallet_outputs > 1) {
                        // We sent this asset elsewhere and also to the wallet, or
                        // we have multiple wallet outputs for the same asset.
                        // Mark the first (possibly only) wallet output as change.
                        outputs[o.second.front()]["is_change"] = true;
                    }
                }
            }
        }
        return outputs;
    }

    nlohmann::json Psbt::to_json(session_impl& session, nlohmann::json utxos) const
    {
        auto result = get_details(session, { { "utxos", std::move(utxos) } });
        const auto& inputs = result.at("transaction_inputs");
        const size_t num_wallet_inputs = std::count_if(inputs.begin(), inputs.end(), is_wallet_utxo);
        result["is_partial"] = num_wallet_inputs != inputs.size();
        return result;
    }

} // namespace sdk
} // namespace ga
