#include "ga_psbt.hpp"
#include "containers.hpp"
#include "exception.hpp"
#include "ga_tx.hpp"
#include "logging.hpp"
#include "session_impl.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"

#include <nlohmann/json.hpp>

#define BUILD_ELEMENTS
#include <wally_psbt.h>
#include <wally_psbt_members.h>

namespace ga {
namespace sdk {
    namespace {
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
        GDK_VERIFY(wally_psbt_extract(m_psbt.get(), WALLY_PSBT_EXTRACT_NON_FINAL, &p));
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
        const Tx tx(extract());

        auto inputs = inputs_to_json(session, std::move(details.at("utxos")));
        auto outputs = outputs_to_json(session, tx);
        amount fee, fee_output;
        for (const auto& txin : inputs) {
            const auto asset_id = j_asset(net_params, txin);
            if (asset_id == policy_asset) {
                fee += json_get_amount(txin, "satoshi");
            }
        }
        for (const auto& txout : outputs) {
            const auto asset_id = j_asset(net_params, txout);
            if (asset_id == policy_asset) {
                if (m_is_liquid && json_get_value(txout, "scriptpubkey").empty()) {
                    fee_output = json_get_amount(txout, "satoshi");
                } else {
                    fee -= json_get_amount(txout, "satoshi");
                }
            }
        }
        GDK_RUNTIME_ASSERT(!m_is_liquid || fee == fee_output);
        nlohmann::json result = { { "transaction", tx.to_hex() }, { "transaction_inputs", std::move(inputs) },
            { "transaction_outputs", std::move(outputs) } };
        result["fee"] = fee.value();
        result["network_fee"] = 0;
        update_tx_info(session, tx, result);
        return result;
    }

    nlohmann::json Psbt::inputs_to_json(session_impl& session, nlohmann::json utxos) const
    {
        nlohmann::json::array_t inputs;
        inputs.resize(get_num_inputs());
        for (size_t i = 0; i < inputs.size(); ++i) {
            const auto& txin = get_input(i);
            const std::string txhash_hex = b2h_rev(txin.txhash);
            auto& input_utxo = inputs[i];
            for (auto& utxo : utxos) {
                if (!utxo.empty() && utxo.at("pt_idx") == txin.index && utxo.at("txhash") == txhash_hex) {
                    // Wallet UTXO
                    utxo["user_sighash"] = txin.sighash ? txin.sighash : WALLY_SIGHASH_ALL;
                    utxo.erase("user_status");
                    utxo_add_paths(session, utxo);
                    input_utxo = std::move(utxo);
                    break;
                }
            }
            if (input_utxo.empty()) {
                // Non-wallet UTXO
                input_utxo = { { "txhash", txhash_hex }, { "pt_idx", txin.index }, { "skip_signing", true } };
                const struct wally_tx_output* txin_utxo;
                GDK_VERIFY(wally_psbt_get_input_best_utxo(m_psbt.get(), i, &txin_utxo));
                if (!txin_utxo) {
                    auto utxo_tx = session.get_raw_transaction_details(txhash_hex);
                    GDK_VERIFY(wally_psbt_set_input_utxo(m_psbt.get(), i, utxo_tx.get()));
                    GDK_VERIFY(wally_psbt_get_input_best_utxo(m_psbt.get(), i, &txin_utxo));
                }
                GDK_RUNTIME_ASSERT(txin_utxo);
                if (!m_is_liquid) {
                    input_utxo["satoshi"] = txin_utxo->satoshi;
                } else {
                    // FIXME: Check value/asset proof
                    GDK_RUNTIME_ASSERT(txin.has_amount); // Must have an explicit value
                    input_utxo["satoshi"] = txin.amount;
                    set_pset_field(txin, input_utxo, "asset_id", in_explicit_asset, true);
                    set_pset_field(txin, input_utxo, "value_blind_proof", in_value_proof);
                    set_pset_field(txin, input_utxo, "asset_blind_proof", in_asset_proof);
                }
            }
        }
        return inputs;
    }

    nlohmann::json Psbt::outputs_to_json(session_impl& session, const Tx& tx) const
    {
        const auto& net_params = session.get_network_parameters();

        nlohmann::json::array_t outputs;
        outputs.resize(get_num_outputs());
        for (size_t i = 0; i < outputs.size(); ++i) {
            // TODO: change identification
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
                set_pset_field(txout, jsonout, "blinding_pubkey", out_blinding_pubkey);
                set_pset_field(txout, jsonout, "nonce_commitment", out_ecdh_pubkey);
                set_pset_field(txout, jsonout, "value_blind_proof", out_blind_value_proof);
                // out_blinder_index unused
                set_pset_field(txout, jsonout, "asset_blind_proof", out_blind_asset_proof);

                GDK_RUNTIME_ASSERT(txout.script);
                jsonout["scriptpubkey"] = b2h({ txout.script, txout.script_len });
            }
            auto output_data = session.get_scriptpubkey_data({ txout.script, txout.script_len });
            if (output_data.empty()) {
                jsonout["address"] = get_address_from_scriptpubkey(net_params, { txout.script, txout.script_len });
            } else {
                if (m_is_liquid) {
                    const auto unblinded = unblind_output(session, tx, i);
                    if (unblinded.contains("error")) {
                        GDK_LOG_SEV(log_level::warning) << "output " << i << ": " << unblinded.at("error");
                        // FIXME: store blinded
                        continue; // Failed to unblind
                    }
                    output_data.update(unblinded);
                }
                jsonout.update(output_data);
                jsonout["address"] = get_address_from_utxo(session, jsonout);
                utxo_add_paths(session, jsonout);
            }
        }
        return outputs;
    }

    // FIXME: duplicated from transaction_utils.cpp
    static bool is_wallet_input(const nlohmann::json& utxo)
    {
        return json_get_value(utxo, "private_key").empty() && !json_get_value(utxo, "address_type").empty();
    }

    nlohmann::json Psbt::to_json(session_impl& session, nlohmann::json utxos) const
    {
        auto result = get_details(session, { { "utxos", std::move(utxos) } });
        const auto& inputs = result.at("transaction_inputs");
        const size_t num_wallet_inputs = std::count_if(inputs.begin(), inputs.end(), is_wallet_input);
        result["is_partial"] = num_wallet_inputs != inputs.size();
        return result;
    }

} // namespace sdk
} // namespace ga
