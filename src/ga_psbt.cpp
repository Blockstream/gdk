#include "ga_psbt.hpp"
#include "exception.hpp"
#include "ga_tx.hpp"
#include "json_utils.hpp"
#include "logging.hpp"
#include "session_impl.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

#include <nlohmann/json.hpp>

#include <wally_psbt.h>
#include <wally_psbt_members.h>

namespace green {

    namespace {
        // PSBT input/output field constants from
        // https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
        constexpr uint32_t in_redeem_script = 0x04;
        constexpr uint32_t in_witness_script = 0x05;

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

        static void set_field(struct wally_map& m, uint32_t k, byte_span_t value)
        {
            GDK_VERIFY(wally_map_add_integer(&m, k, value.data(), value.size()));
        }

        static optional_bytes_t get_field(const struct wally_map& m, uint32_t k)
        {
            const auto p = wally_map_get_integer(&m, k);
            if (p) {
                return gsl::make_span(p->value, p->value_len);
            }
            return {};
        }

        template <typename T> static inline optional_bytes_t psbt_field(const T& src, uint32_t k)
        {
            return get_field(src.psbt_fields, k);
        }

        template <typename T> static inline optional_bytes_t pset_field(const T& src, uint32_t k)
        {
            return get_field(src.pset_fields, k);
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

        static void add_keypath(wally_map& keypaths, xpub_hdkeys& pubkeys, byte_span_t fingerprint,
            const xpub_hdkey& key, uint32_t subaccount, uint32_t pointer, bool is_internal)
        {
            const auto public_key = key.get_public_key();
            const auto path = pubkeys.get_full_path(subaccount, pointer, is_internal);
            GDK_VERIFY(wally_map_keypath_add(&keypaths, public_key.data(), public_key.size(), fingerprint.data(),
                fingerprint.size(), path.data(), path.size()));
        }

        static auto add_keypaths(session_impl& session, struct wally_psbt_input* psbt_input, wally_map& keypaths,
            const nlohmann::json& details, const nlohmann::json& utxo)
        {
            const bool is_electrum = session.get_network_parameters().is_electrum();
            auto keys = session.keys_from_utxo(utxo);
            size_t user_key_index = 0;
            const auto subaccount = j_uint32ref(utxo, "subaccount");
            const auto pointer = j_uint32ref(utxo, "pointer");
            const auto is_internal = j_bool_or_false(utxo, "is_internal");
            bool is_expired_csv = false;

            if (!is_electrum) {
                if (psbt_input && j_strref(utxo, "address_type") == address_type::csv
                    && j_uint32ref(details, "transaction_version") >= WALLY_TX_VERSION_2) {
                    const auto expiry_height = j_uint32_or_zero(utxo, "expiry_height");
                    if (expiry_height && expiry_height <= session.get_block_height()
                        && session.get_network_parameters().is_valid_csv_value(psbt_input->sequence)) {
                        GDK_RUNTIME_ASSERT(psbt_input->sequence == j_uint32ref(utxo, "sequence"));
                        is_expired_csv = true;
                    }
                }

                if (!is_expired_csv) {
                    // First key returned is the Green key, add it
                    const auto green_fp = session.get_green_pubkeys().get_master_xpub().get_fingerprint();
                    const auto& green_key = keys.at(user_key_index);
                    add_keypath(
                        keypaths, session.get_green_pubkeys(), green_fp, green_key, subaccount, pointer, is_internal);
                }
                user_key_index = 1;
            }

            // Add the user's pubkey
            auto master_fp = session.get_nonnull_signer()->get_master_fingerprint();
            const auto& user_key = keys.at(user_key_index);
            add_keypath(keypaths, session.get_user_pubkeys(), master_fp, user_key, subaccount, pointer, is_internal);

            if (!is_electrum && keys.size() > 2) {
                // 2of3: Add the recovery pubkey
                auto& recovery_pubkeys = session.get_recovery_pubkeys();
                const auto recovery_fp = recovery_pubkeys.get_subaccount(subaccount).get_parent_fingerprint();
                const auto& recovery_key = keys.back();
                add_keypath(keypaths, recovery_pubkeys, recovery_fp, recovery_key, subaccount, pointer, is_internal);
            }
            return keys;
        }

        static void add_input_scripts(
            wally_map& psbt_fields, const nlohmann::json& utxo, const std::vector<xpub_hdkey>& keys)
        {
            using namespace address_type;
            std::optional<std::vector<unsigned char>> redeem_script;
            const auto& addr_type = j_strref(utxo, "address_type");

            if (addr_type == p2sh_p2wpkh) {
                const auto pub_key = keys.at(0).get_public_key();
                redeem_script = witness_script(pub_key, WALLY_SCRIPT_HASH160);
            } else if (addr_type == csv || addr_type == p2wsh) {
                const auto prevout_script = j_bytesref(utxo, "prevout_script");
                set_field(psbt_fields, in_witness_script, prevout_script);
                redeem_script = witness_script(prevout_script, WALLY_SCRIPT_SHA256);
            } else if (addr_type == p2sh) {
                redeem_script = j_bytesref(utxo, "prevout_script");
            }
            if (redeem_script) {
                set_field(psbt_fields, in_redeem_script, *redeem_script);
            }
        }

        static void add_input_utxo(session_impl& session, struct wally_psbt* psbt, size_t i,
            const std::string& txhash_hex, uint32_t vout, bool add_full_utxo, bool add_witness_utxo)
        {
            const auto utxo_tx = session.get_raw_transaction_details(txhash_hex);
            if (add_full_utxo) {
                GDK_VERIFY(wally_psbt_set_input_utxo(psbt, i, utxo_tx.get()));
            }
            if (add_witness_utxo) {
                GDK_VERIFY(wally_psbt_set_input_witness_utxo_from_tx(psbt, i, utxo_tx.get(), vout));
            }
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

    Psbt::Psbt(session_impl& session, const nlohmann::json& details, bool is_liquid)
        : m_is_liquid(is_liquid)
    {
        from_json(session, details);
    }

    Psbt::~Psbt() {}

    void Psbt::swap(Psbt& rhs)
    {
        std::swap(m_is_liquid, rhs.m_is_liquid);
        std::swap(m_original_version, rhs.m_original_version);
        std::swap(m_psbt, rhs.m_psbt);
    }

    void Psbt::finalize(bool allow_partial)
    {
        // Do not clear finalization data after finalizing. This does not
        // comply with the PSBT BIP but is required due to how the Green
        // backend identifies segwit inputs.
        constexpr uint32_t flags = WALLY_PSBT_FINALIZE_NO_CLEAR;

        // Finalize inputs individually for more detailed errors on failure
        for (size_t i = 0; i < get_num_inputs(); ++i) {
            const auto& psbt_input = get_input(i);
            const char* error = nullptr;
            size_t is_finalized;
            if (wally_psbt_finalize_input(m_psbt.get(), i, flags) != WALLY_OK) {
                error = "Error finalizing input ";
            } else if (!allow_partial) {
                if (wally_psbt_input_is_finalized(&psbt_input, &is_finalized) != WALLY_OK || !is_finalized) {
                    error = "Could not finalize input ";
                }
            }
            if (error) {
                throw user_error(std::string(error) + std::to_string(i));
            }
        }
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
        decltype(m_psbt) tmp;
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
            if (!m_is_liquid || j_assetref(m_is_liquid, input) == policy_asset) {
                sum += j_amountref(input);
            }
        }
        for (const auto& txout : outputs) {
            if (!m_is_liquid || j_assetref(m_is_liquid, txout) == policy_asset) {
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
        if (use_error) {
            result.emplace("error", std::move(error));
        }
        /* Make PSBT details more consistent with create_transaction */
        result["fee_rate"] = j_uint32ref(result, "calculated_fee_rate");
        if (m_is_liquid) {
            // Only blinded PSBTs are currently supported, so we can hard
            // code this. TODO: Update when we support unblinded txs.
            result["is_blinded"] = true;
        }
        result["utxo_strategy"] = "manual";
        return result;
    }

    // If a UTXO matching txhash_hex:vout is found in utxos, move it into dst.
    // Returns whether a match was found.
    static bool take_matching_utxo(
        const nlohmann::json& utxos, const std::string& txhash_hex, uint32_t vout, nlohmann::json& dst)
    {
        for (auto& u : utxos) {
            if (!u.empty() && j_uint32ref(u, "pt_idx") == vout && j_strref(u, "txhash") == txhash_hex) {
                dst = std::move(u);
                return true;
            }
        }
        return false;
    }

    // Fetch any signatures present in a PSBT input.
    static auto get_input_signatures(
        session_impl& session, const struct wally_psbt_input& psbt_input, const nlohmann::json& utxo)
    {
        byte_span_t user_der, green_der;
        auto keys = session.keys_from_utxo(utxo);
        size_t sig_index;

        const auto user_pubkey = keys.at(0).get_public_key();
        GDK_VERIFY(wally_psbt_input_find_signature(&psbt_input, user_pubkey.data(), user_pubkey.size(), &sig_index));
        if (sig_index) {
            const auto* item = psbt_input.signatures.items + sig_index - 1;
            user_der = { item->value, item->value_len };
        }

        return std::make_pair(user_der, green_der);
    }

    std::pair<nlohmann::json, std::set<std::string>> Psbt::inputs_to_json(
        session_impl& session, Tx& tx, nlohmann::json utxos) const
    {
        std::set<std::string> wallet_assets;
        nlohmann::json::array_t inputs;
        inputs.resize(get_num_inputs());
        for (size_t i = 0; i < inputs.size(); ++i) {
            const auto& psbt_input = get_input(i);
            auto& txin = tx.get_input(i);
            auto& utxo = inputs[i];
            utxo = tx.input_to_json(i);
            const std::string txhash_hex = j_strref(utxo, "txhash"); // Note as-value
            const auto vout = psbt_input.index;

            bool belongs_to_wallet = false;
            if (utxos.is_array()) {
                // utxos in a flat array (deprecated)
                belongs_to_wallet = take_matching_utxo(utxos, txhash_hex, vout, utxo);
            } else {
                // utxos in the standard format "{ asset: [utxo, utxo. ,,,] }"
                for (auto& it : utxos.items()) {
                    belongs_to_wallet = take_matching_utxo(it.value(), txhash_hex, vout, utxo);
                    if (belongs_to_wallet) {
                        break;
                    }
                }
            }

            if (!psbt_input.utxo && !psbt_input.witness_utxo) {
                // Add a witness UTXO if we know this input is segwit.
                // Add a full UTXO for Bitcoin txs (to mitigate fee attacks), or
                // if we havent added a witness utxo.
                const bool add_witness_utxo
                    = belongs_to_wallet && address_type_is_segwit(j_strref(utxo, "address_type"));
                const bool add_full_utxo = !m_is_liquid || !add_witness_utxo;
                add_input_utxo(session, m_psbt.get(), i, txhash_hex, vout, add_full_utxo, add_witness_utxo);
            }
            const struct wally_tx_output* txin_utxo;
            GDK_VERIFY(wally_psbt_get_input_best_utxo(m_psbt.get(), i, &txin_utxo));
            GDK_RUNTIME_ASSERT(txin_utxo);

            if (belongs_to_wallet) {
                // Wallet UTXO
                wallet_assets.insert(j_assetref(m_is_liquid, utxo));
                if (psbt_input.sighash && psbt_input.sighash != WALLY_SIGHASH_ALL) {
                    utxo["user_sighash"] = psbt_input.sighash;
                }
                for (const auto& key : { "user_status", "witness", "script_sig" }) {
                    utxo.erase(key);
                }
                utxo_add_paths(session, utxo);
                if (!txin.script || !txin.witness) {
                    // Get the sigs from the PSBT input
                    auto [user_der, green_der] = get_input_signatures(session, psbt_input, utxo);
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
                set_pset_field(txout, jsonout, "eph_public_key", out_ecdh_pubkey);
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
                if (is_electrum) {
                    // Singlesig: Outputs on the internal chain are change
                    j_rename(jsonout, "is_internal", "is_change");
                    for (const auto& key : { "branch", "subtype" }) {
                        jsonout.erase(key);
                    }
                }
            }
            if (m_is_liquid) {
                // Confidentialize the address if possible
                jsonout["is_confidential"] = false;
                const auto blinding_key = j_str(jsonout, "blinding_key");
                if (blinding_key.has_value()) {
                    confidentialize_address(net_params, jsonout, blinding_key.value());
                }
                if (!is_wallet_output) {
                    // FIXME: wallet and non-wallet outputs are inconsistent
                    for (const auto& key : { "is_confidential", "unconfidential_address" }) {
                        jsonout.erase(key);
                    }
                }
            }
            // Change detection
            auto asset_id = j_assetref(m_is_liquid, jsonout);
            if (!is_electrum && wallet_assets.count(asset_id)) {
                // Multisig: Collect info to compute change below
                if (is_wallet_output) {
                    asset_outputs[asset_id].push_back(i);
                } else {
                    spent_assets.emplace(std::move(asset_id));
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
                    bool is_change = false;
                    if (is_spent_externally || num_wallet_outputs > 1) {
                        // We sent this asset elsewhere and also to the wallet, or
                        // we have multiple wallet outputs for the same asset.
                        // Mark the first (possibly only) wallet output as change.
                        is_change = true;
                    }
                    outputs[o.second.front()]["is_change"] = is_change;
                }
            }
        }
        return outputs;
    }

    nlohmann::json Psbt::to_json(session_impl& session, nlohmann::json utxos) const
    {
        auto result = get_details(session, { { "utxos", std::move(utxos) } });
        const auto& inputs = j_arrayref(result, "transaction_inputs");
        const size_t num_wallet_inputs = std::count_if(inputs.begin(), inputs.end(), is_wallet_utxo);
        result["is_partial"] = num_wallet_inputs != inputs.size();
        return result;
    }

    void Psbt::from_json(session_impl& session, const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(!m_psbt);
        GDK_RUNTIME_ASSERT(j_str_is_empty(details, "error"));

        const Tx tx(j_bytesref(details, "transaction"), m_is_liquid);
        m_original_version = tx.get_version() < 2 ? 0 : 2;
        {
            // Create the base PSBT from the tx
            const uint32_t flags = m_is_liquid ? WALLY_PSBT_INIT_PSET : 0;
            struct wally_psbt* p;
            GDK_VERIFY(wally_psbt_from_tx(tx.get(), m_original_version, flags, &p));
            m_psbt.reset(p);
            if (m_original_version == 0) {
                // Upgrade to version 2 so our processing in gdk is identical
                constexpr uint32_t ver_flags = 0;
                GDK_VERIFY(wally_psbt_set_version(m_psbt.get(), ver_flags, 2));
            }
        }

        const auto& inputs = j_arrayref(details, "transaction_inputs");
        for (size_t i = 0; i < tx.get_num_inputs(); ++i) {
            const auto& input = inputs.at(i);
            auto& psbt_input = get_input(i);
            amount::value_type satoshi;
            std::vector<unsigned char> asset_id;

            const bool belongs_to_wallet = is_wallet_utxo(input);
            if (belongs_to_wallet) {
                // Wallet UTXO. Add the relevant keypaths
                auto keys = add_keypaths(session, &psbt_input, psbt_input.keypaths, details, input);
                add_input_scripts(psbt_input.psbt_fields, input, keys);
            }
            if (m_is_liquid) {
                // Add the input asset and amount
                asset_id = j_rbytesref(input, "asset_id");
                GDK_VERIFY(wally_psbt_set_input_asset(m_psbt.get(), i, asset_id.data(), asset_id.size()));
                satoshi = j_amountref(input).value();
                GDK_VERIFY(wally_psbt_set_input_amount(m_psbt.get(), i, satoshi));
            }
            if (!psbt_input.utxo && !psbt_input.witness_utxo) {
                // Add a witness UTXO if we know this input is segwit.
                // Add a full UTXO for Bitcoin txs (to mitigate fee attacks), or
                // if we havent added a witness utxo.
                const auto& txhash_hex = j_strref(input, "txhash");
                const auto vout = psbt_input.index;
                const bool add_witness_utxo
                    = belongs_to_wallet && address_type_is_segwit(j_strref(input, "address_type"));
                const bool add_full_utxo = !m_is_liquid || !add_witness_utxo;
                add_input_utxo(session, m_psbt.get(), i, txhash_hex, vout, add_full_utxo, add_witness_utxo);
            }
            if (m_is_liquid) {
                // Create asset and value explicit proofs
                const auto abf = j_rbytesref(input, "assetblinder");
                const auto nonce = get_random_bytes<32>();
                const auto vbf = j_rbytesref(input, "amountblinder");
                GDK_VERIFY(wally_psbt_generate_input_explicit_proofs(m_psbt.get(), i, satoshi, asset_id.data(),
                    asset_id.size(), abf.data(), abf.size(), vbf.data(), vbf.size(), nonce.data(), nonce.size()));
            }
        }

        const auto& outputs = j_arrayref(details, "transaction_outputs");
        for (size_t i = 0; i < tx.get_num_outputs(); ++i) {
            const auto& output = outputs.at(i);
            auto& psbt_output = get_output(i);

            if (is_wallet_utxo(output)) {
                // Wallet UTXO. Add the relevant keypaths
                add_keypaths(session, nullptr, psbt_output.keypaths, details, output);
            }

            if (m_is_liquid) {
                // Add the output asset and amount
                const auto asset_id = j_rbytesref(output, "asset_id");
                GDK_VERIFY(wally_psbt_set_output_asset(m_psbt.get(), i, asset_id.data(), asset_id.size()));
                const auto satoshi = j_amountref(output).value();
                GDK_VERIFY(wally_psbt_set_output_amount(m_psbt.get(), i, satoshi));

                if (j_str_is_empty(output, "scriptpubkey")) {
                    continue; // Skip remaining fields for fee outputs
                }

                // Assume the blinder index is 1-1. FIXME: This isn't true for swaps
                GDK_VERIFY(wally_psbt_set_output_blinder_index(m_psbt.get(), i, i));

                const auto blinding_pubkey = j_bytesref(output, "blinding_key");
                GDK_VERIFY(wally_psbt_set_output_blinding_public_key(
                    m_psbt.get(), i, blinding_pubkey.data(), blinding_pubkey.size()));

                // Create asset and value explicit proofs
                const auto vbf = j_rbytesref(output, "amountblinder");
                const byte_span_t asset_commitment
                    = pset_field(psbt_output, out_asset_commitment).value_or(byte_span_t{});
                const auto abf = j_rbytesref(output, "assetblinder");
                GDK_RUNTIME_ASSERT(!asset_commitment.empty());
                std::array<unsigned char, ASSET_EXPLICIT_SURJECTIONPROOF_LEN> sj_proof;
                GDK_VERIFY(wally_explicit_surjectionproof(asset_id.data(), asset_id.size(), abf.data(), abf.size(),
                    asset_commitment.data(), asset_commitment.size(), sj_proof.data(), sj_proof.size()));
                GDK_VERIFY(wally_psbt_set_output_asset_blinding_surjectionproof(
                    m_psbt.get(), i, sj_proof.data(), sj_proof.size()));

                const auto nonce = get_random_bytes<32>();
                const byte_span_t value_commitment
                    = pset_field(psbt_output, out_value_commitment).value_or(byte_span_t{});
                GDK_RUNTIME_ASSERT(!value_commitment.empty());
                std::array<unsigned char, ASSET_EXPLICIT_RANGEPROOF_MAX_LEN> range_proof;
                size_t written;
                GDK_VERIFY(wally_explicit_rangeproof(satoshi, nonce.data(), nonce.size(), vbf.data(), vbf.size(),
                    value_commitment.data(), value_commitment.size(), asset_commitment.data(), asset_commitment.size(),
                    range_proof.data(), range_proof.size(), &written));
                GDK_RUNTIME_ASSERT(written && written <= range_proof.size());
                GDK_VERIFY(
                    wally_psbt_set_output_value_blinding_rangeproof(m_psbt.get(), i, range_proof.data(), written));
            }
        }
    }

} // namespace green
