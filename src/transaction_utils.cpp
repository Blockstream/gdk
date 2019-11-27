#include "boost_wrapper.hpp"

#include "assertion.hpp"
#include "exception.hpp"
#include "ga_session.hpp"
#include "ga_strings.hpp"
#include "memory.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

#include <cctype>

namespace {
bool isupper(const std::string& s)
{
    return std::all_of(std::begin(s), std::end(s), [](int c) { return std::islower(c) == 0; });
}
} // namespace

namespace ga {
namespace sdk {
    namespace address_type {
        const std::string p2pkh("p2pkh");
        const std::string p2sh("p2sh");
        const std::string p2wsh("p2wsh");
        const std::string csv("csv");
    }; // namespace address_type

        // Dummy signatures are needed for correctly sizing transactions. If our signer supports
        // low-R signatures, we estimate on a 71 byte signature, and occasionally produce 70 byte
        // signatures. Otherwise, we estimate on 72 bytes and occasionally produce 70 or 71 byte
        // signatures. Worst-case overestimation is therefore 2 bytes per input * 2 sigs, or
        // 1 vbyte per input for segwit transactions.

        // We construct our dummy sigs R, S from OP_SUBSTR/OP_INVALIDOPCODE.
#define SIG_SLED(INITIAL, B) INITIAL, B, B, B, B, B, B, B, B, B, B, B, B, B, B, B
#define SIG_BYTES(INITIAL, B) SIG_SLED(INITIAL, B), SIG_SLED(B, B)

#define SIG_HIGH SIG_BYTES(OP_INVALIDOPCODE, OP_SUBSTR)
#define SIG_LOW SIG_BYTES(OP_SUBSTR, OP_SUBSTR)

#define SIG_72(INITIAL, B) SIG_HIGH, SIG_HIGH
#define SIG_71(INITIAL, B) SIG_LOW, SIG_HIGH

    static const ecdsa_sig_t DUMMY_GA_SIG = { { SIG_HIGH, SIG_HIGH } };
    static const ecdsa_sig_t DUMMY_GA_SIG_LOW_R = { { SIG_LOW, SIG_HIGH } };

    // DER encodings of the above
    static const std::vector<unsigned char> DUMMY_GA_SIG_DER_PUSH
        = { { 0x00, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00, SIG_HIGH, 0x02, 0x21, 0x00, SIG_HIGH, 0x01 } };
    static const std::vector<unsigned char> DUMMY_GA_SIG_DER_PUSH_LOW_R
        = { { 0x00, 0x48, 0x30, 0x45, 0x02, 0x20, SIG_LOW, 0x02, 0x21, 0x00, SIG_HIGH, 0x01 } };

    static const std::array<unsigned char, 3> OP_0_PREFIX = { { 0x00, 0x01, 0x00 } };

    inline auto p2sh_address_from_bytes(const network_parameters& net_params, byte_span_t script)
    {
        std::array<unsigned char, HASH160_LEN + 1> addr;
        const auto hash = hash160(script);
        addr[0] = net_params.btc_p2sh_version();
        std::copy(hash.begin(), hash.end(), addr.begin() + 1);
        return addr;
    }

    inline auto p2sh_p2wsh_address_from_bytes(const network_parameters& net_params, byte_span_t script)
    {
        return p2sh_address_from_bytes(net_params, witness_program_from_bytes(script, WALLY_SCRIPT_SHA256));
    }

    std::string get_address_from_script(
        const network_parameters& net_params, byte_span_t script, const std::string& addr_type)
    {
        if (addr_type == address_type::p2sh) {
            return base58check_from_bytes(p2sh_address_from_bytes(net_params, script));
        }
        if (addr_type == address_type::p2wsh || addr_type == address_type::csv) {
            return base58check_from_bytes(p2sh_p2wsh_address_from_bytes(net_params, script));
        }
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    std::vector<unsigned char> output_script_for_address(
        const network_parameters& net_params, const std::string& address)
    {
        if (boost::starts_with(address, net_params.bech32_prefix())) {
            // Segwit v0 P2WPKH or P2WSH
            return addr_segwit_v0_to_bytes(address, net_params.bech32_prefix());
        }
        // Base58 encoded bitcoin address
        const auto addr_bytes = base58check_to_bytes(address);
        GDK_RUNTIME_ASSERT(addr_bytes.size() == 1 + HASH160_LEN);
        const auto script_hash = gsl::make_span(addr_bytes).subspan(1, HASH160_LEN);

        if (addr_bytes.front() == net_params.btc_p2sh_version()) {
            return scriptpubkey_p2sh_from_hash160(script_hash);
        }
        if (addr_bytes.front() == net_params.btc_version()) {
            return scriptpubkey_p2pkh_from_hash160(script_hash);
        }
        return std::vector<unsigned char>(); // Unknown address version
    }

    static std::vector<unsigned char> output_script(const pub_key_t& ga_pub_key, const pub_key_t& user_pub_key,
        gsl::span<const unsigned char> backup_pub_key, script_type type, uint32_t subtype)
    {
        const bool is_2of3 = !backup_pub_key.empty();

        size_t n_pubkeys = 2, threshold = 2;
        std::vector<unsigned char> keys;
        keys.reserve(3 * ga_pub_key.size());
        keys.insert(keys.end(), std::begin(ga_pub_key), std::end(ga_pub_key));
        keys.insert(keys.end(), std::begin(user_pub_key), std::end(user_pub_key));
        if (is_2of3) {
            GDK_RUNTIME_ASSERT(static_cast<size_t>(backup_pub_key.size()) == ga_pub_key.size());
            keys.insert(keys.end(), std::begin(backup_pub_key), std::end(backup_pub_key));
            ++n_pubkeys;
        }

        const size_t max_script_len = 13 + n_pubkeys * (ga_pub_key.size() + 1) + 4;
        std::vector<unsigned char> script(max_script_len);

        if (type == script_type::p2sh_p2wsh_csv_fortified_out && is_2of3) {
            // CSV 2of3, subtype is the number of CSV blocks
            scriptpubkey_csv_2of3_then_2_from_bytes(keys, subtype, script);
        } else if (type == script_type::p2sh_p2wsh_csv_fortified_out) {
            // CSV 2of2, subtype is the number of CSV blocks
            scriptpubkey_csv_2of2_then_1_from_bytes(keys, subtype, script);
        } else {
            // P2SH or P2SH-P2WSH standard 2of2/2of3 multisig
            scriptpubkey_multisig_from_bytes(keys, threshold, script);
        }
        return script;
    }

    std::vector<unsigned char> output_script_from_utxo(const network_parameters& net_params, ga_pubkeys& pubkeys,
        ga_user_pubkeys& user_pubkeys, ga_user_pubkeys& recovery_pubkeys, const nlohmann::json& utxo)
    {
        const uint32_t subaccount = json_get_value(utxo, "subaccount", 0u);
        const uint32_t pointer = utxo.at("pointer");
        script_type type;

        type = utxo.at("script_type");
        uint32_t subtype = 0;
        if (type == script_type::p2sh_p2wsh_csv_fortified_out) {
            // subtype indicates the number of csv blocks and must be one of the known bucket values
            subtype = utxo.at("subtype");
            const auto csv_buckets = net_params.csv_buckets();
            const auto csv_bucket_p = std::find(std::begin(csv_buckets), std::end(csv_buckets), subtype);
            GDK_RUNTIME_ASSERT_MSG(csv_bucket_p != csv_buckets.end(), "Unknown csv bucket");
        }

        const auto ga_pub_key = pubkeys.derive(subaccount, pointer);
        const auto user_pub_key = user_pubkeys.derive(subaccount, pointer);

        if (recovery_pubkeys.have_subaccount(subaccount)) {
            // 2of3
            return output_script(ga_pub_key, user_pub_key, recovery_pubkeys.derive(subaccount, pointer), type, subtype);
        }
        // 2of2
        return output_script(ga_pub_key, user_pub_key, empty_span(), type, subtype);
    }

    std::vector<unsigned char> input_script(bool low_r, const std::vector<unsigned char>& prevout_script,
        const ecdsa_sig_t& user_sig, const ecdsa_sig_t& ga_sig)
    {
        const std::array<uint32_t, 2> sighashes = { { WALLY_SIGHASH_ALL, WALLY_SIGHASH_ALL } };
        std::array<unsigned char, sizeof(ecdsa_sig_t) * 2> sigs;
        init_container(sigs, ga_sig, user_sig);
        const uint32_t sig_len = low_r ? EC_SIGNATURE_DER_MAX_LEN : EC_SIGNATURE_DER_MAX_LOW_R_LEN;
        std::vector<unsigned char> script(1 + (sig_len + 2) * 2 + 3 + prevout_script.size());
        scriptsig_multisig_from_bytes(prevout_script, sigs, sighashes, script);
        return script;
    }

    std::vector<unsigned char> input_script(
        bool low_r, const std::vector<unsigned char>& prevout_script, const ecdsa_sig_t& user_sig)
    {
        const ecdsa_sig_t& dummy_sig = low_r ? DUMMY_GA_SIG_LOW_R : DUMMY_GA_SIG;
        const std::vector<unsigned char>& dummy_push = low_r ? DUMMY_GA_SIG_DER_PUSH_LOW_R : DUMMY_GA_SIG_DER_PUSH;

        std::vector<unsigned char> full_script = input_script(low_r, prevout_script, user_sig, dummy_sig);
        // Replace the dummy sig with PUSH(0)
        GDK_RUNTIME_ASSERT(std::search(full_script.begin(), full_script.end(), dummy_push.begin(), dummy_push.end())
            == full_script.begin());
        auto suffix = gsl::make_span(full_script).subspan(dummy_push.size());

        std::vector<unsigned char> script(OP_0_PREFIX.size() + suffix.size());
        init_container(script, OP_0_PREFIX, suffix);
        return script;
    }

    std::vector<unsigned char> dummy_input_script(bool low_r, const std::vector<unsigned char>& prevout_script)
    {
        const ecdsa_sig_t& dummy_sig = low_r ? DUMMY_GA_SIG_LOW_R : DUMMY_GA_SIG;
        return input_script(low_r, prevout_script, dummy_sig, dummy_sig);
    }

    std::vector<unsigned char> dummy_external_input_script(bool low_r, byte_span_t pub_key)
    {
        const ecdsa_sig_t& dummy_sig = low_r ? DUMMY_GA_SIG_LOW_R : DUMMY_GA_SIG;
        return scriptsig_p2pkh_from_der(pub_key, ec_sig_to_der(dummy_sig, true));
    }

    std::vector<unsigned char> witness_script(const std::vector<unsigned char>& script)
    {
        return witness_program_from_bytes(script, WALLY_SCRIPT_SHA256 | WALLY_SCRIPT_AS_PUSH);
    }

    amount get_tx_fee(const wally_tx_ptr& tx, amount min_fee_rate, amount fee_rate)
    {
        const amount rate = fee_rate < min_fee_rate ? min_fee_rate : fee_rate;

        const size_t vsize = tx_get_vsize(tx);
        const auto fee = static_cast<double>(vsize) * rate.value() / 1000.0;
        const auto rounded_fee = static_cast<amount::value_type>(std::ceil(fee));
        return amount(rounded_fee);
    }

    amount add_tx_output(const network_parameters& net_params, nlohmann::json& result, wally_tx_ptr& tx,
        const std::string& address, amount::value_type satoshi, const std::string& asset_tag)
    {
        const auto is_liquid = net_params.liquid();

        auto output_address = address;
        // TODO: Support OP_RETURN outputs
        std::vector<unsigned char> script;
        bool confidential_addr = is_liquid;
        try {
            if (is_liquid) {
                try {
                    output_address = confidential_addr_to_addr(output_address, net_params.blinded_prefix());
                } catch (const std::exception& ex) {
                    confidential_addr = false;
                }
            }
            script = output_script_for_address(net_params, output_address);
        } catch (const std::exception& e) {
        }

        const bool is_liquid_unconfidential = is_liquid && !confidential_addr && !script.empty();
        if (script.empty() || is_liquid_unconfidential) {
            // Overwite any existing error in the transaction as addressees
            // are entered and should be corrected first.
            result["error"]
                = is_liquid_unconfidential ? res::id_nonconfidential_addresses_not : res::id_invalid_address;
            // Create a dummy script so that the caller gets back a reasonable
            // estimate of the tx size/fee etc when the address is corrected.
            script.resize(HASH160_LEN);
        }

        if (net_params.liquid()) {
            const auto ct_value = tx_confidential_value_from_satoshi(satoshi);
            const auto asset_bytes
                = h2b_rev(!asset_tag.empty() && asset_tag != "btc" ? asset_tag : net_params.policy_asset(), 0x1);
            tx_add_elements_raw_output(tx, script, asset_bytes, ct_value, {}, {}, {});
        } else {
            tx_add_raw_output(tx, satoshi, script);
        }
        return amount(satoshi);
    }

    amount add_tx_fee_output(const network_parameters& net_params, wally_tx_ptr& tx, amount::value_type satoshi)
    {
        const auto ct_value = tx_confidential_value_from_satoshi(satoshi);
        auto asset_bytes = h2b_rev(net_params.policy_asset());
        asset_bytes.insert(asset_bytes.begin(), 0x1);
        tx_add_elements_raw_output(tx, {}, asset_bytes, ct_value, {}, {}, {});
        return amount{ satoshi };
    }

    void set_tx_output_commitment(const network_parameters& net_params, wally_tx_ptr& tx, uint32_t index,
        const std::string& asset_tag, amount::value_type satoshi)
    {
        const auto ct_value = tx_confidential_value_from_satoshi(satoshi);
        const auto asset_bytes = h2b_rev(asset_tag == "btc" ? net_params.policy_asset() : asset_tag, 0x1);
        tx_elements_output_commitment_set(tx, index, asset_bytes, ct_value, {}, {}, {});
    }

    amount add_tx_addressee(ga_session& session, const network_parameters& net_params, nlohmann::json& result,
        wally_tx_ptr& tx, nlohmann::json& addressee)
    {
        std::string address = addressee.at("address"); // Assume its a standard address

        nlohmann::json uri_params = parse_bitcoin_uri(address);
        if (!uri_params.is_null()) {
            // Address is a BIP21 style payment URI
            address = uri_params.at("address");
            addressee["address"] = address;
            const auto& bip21_params = uri_params["bip21-params"];
            addressee["bip21-params"] = bip21_params;
            const auto uri_amount_p = bip21_params.find("amount");
            if (uri_amount_p != bip21_params.end()) {
                // Use the amount specified in the URI
                const nlohmann::json uri_amount = { { "btc", uri_amount_p->get<std::string>() } };
                addressee["satoshi"] = session.convert_amount(uri_amount)["satoshi"];
                amount::strip_non_satoshi_keys(addressee);
            }
        }

        // Convert uppercase bech32 alphanumeric strings to lowercase
        // Only convert all uppercase strings, BIP-173 specifically disallows mixed case strings
        const std::string bech32_prefix = net_params.bech32_prefix() + "1";
        if (boost::istarts_with(address, bech32_prefix) && isupper(address)) {
            boost::to_lower(address);
            addressee["address"] = address;
        }

        // Convert the users entered value into satoshi
        amount satoshi;
        try {
            satoshi = session.convert_amount(addressee)["satoshi"].get<amount::value_type>();
        } catch (const std::exception&) {
            // Note the error, and create a 0 satoshi output
            result["error"] = res::id_invalid_amount;
        }

        // Transactions with outputs below the dust threshold (except OP_RETURN)
        // are not relayed by network nodes
        if (!result.value("send_all", false) && satoshi.value() < session.get_dust_threshold()) {
            result["error"] = res::id_invalid_amount;
        }

        amount::strip_non_satoshi_keys(addressee);
        addressee["satoshi"] = satoshi.value(); // Sets to 0 if not present

        return add_tx_output(
            net_params, result, tx, address, satoshi.value(), addressee.value("asset_tag", std::string{}));
    }

    void update_tx_info(const wally_tx_ptr& tx, nlohmann::json& result)
    {
        const bool valid = tx->num_inputs != 0u && tx->num_outputs != 0u;
        result["transaction"] = valid ? b2h(tx_to_bytes(tx)) : std::string();
        const auto weight = tx_get_weight(tx);
        result["transaction_size"] = valid ? tx_get_length(tx, WALLY_TX_FLAG_USE_WITNESS) : 0;
        result["transaction_weight"] = valid ? weight : 0;
        const uint32_t tx_vsize = valid ? tx_vsize_from_weight(weight) : 0;
        result["transaction_vsize"] = tx_vsize;
        result["transaction_version"] = tx->version;
        result["transaction_locktime"] = tx->locktime;
        const bool is_liquid = tx_is_elements(tx);
        result["liquid"] = is_liquid;
        if (result.find("fee") != result.end()) {
            if (is_liquid) {
                result["calculated_fee_rate"] = result["fee"];
            } else {
                const amount::value_type fee = result["fee"];
                result["calculated_fee_rate"] = valid ? (fee * 1000 / tx_vsize) : 0;
            }
        }
    }

    vbf_t generate_final_vbf(byte_span_t input_abfs, byte_span_t input_vbfs, uint64_span_t input_values,
        const std::vector<abf_t>& output_abfs, const std::vector<vbf_t>& output_vbfs, uint32_t num_inputs)
    {
        auto&& flatten_into = [](auto& bfs, const auto& out_bfs) {
            std::for_each(std::begin(out_bfs), std::end(out_bfs),
                [&bfs](const auto& bf) { bfs.insert(bfs.end(), std::begin(bf), std::end(bf)); });
        };

        std::vector<unsigned char> abfs(std::begin(input_abfs), std::end(input_abfs));
        flatten_into(abfs, output_abfs);

        std::vector<unsigned char> vbfs(std::begin(input_vbfs), std::end(input_vbfs));
        flatten_into(vbfs, output_vbfs);

        return asset_final_vbf(input_values, num_inputs, abfs, vbfs);
    }

    void update_tx_info(const network_parameters& net_params, const wally_tx_ptr& tx, nlohmann::json& result)
    {
        update_tx_info(tx, result);

        const bool valid = tx->num_inputs != 0u && tx->num_outputs != 0U;

        if (net_params.liquid() && result.contains("used_utxos")) {
            std::vector<unsigned char> input_abfs;
            std::vector<unsigned char> input_vbfs;
            std::vector<uint64_t> input_values;

            for (const auto& utxo : result["used_utxos"]) {
                const auto abf = h2b(utxo["abf"]);
                input_abfs.insert(input_abfs.end(), std::begin(abf), std::end(abf));
                const auto vbf = h2b(utxo["vbf"]);
                input_vbfs.insert(input_vbfs.end(), std::begin(vbf), std::end(vbf));
                input_values.emplace_back(utxo["satoshi"]);
            }

            for (size_t i = 0; i < tx->num_outputs; ++i) {
                const auto& o = tx->outputs[i];
                if (!o.script && !o.script_len) {
                    continue;
                }

                amount::value_type satoshi = o.satoshi;
                GDK_RUNTIME_ASSERT(o.value);
                if (*o.value == 1) {
                    satoshi = tx_confidential_value_to_satoshi(gsl::make_span(o.value, o.value_len));
                }

                input_values.emplace_back(satoshi);
            }
        }

        // Note that outputs may be empty if the constructed tx is incomplete
        std::vector<nlohmann::json> outputs;
        if (valid && json_get_value(result, "error").empty() && result.find("addressees") != result.end()) {
            outputs.reserve(tx->num_outputs);
            size_t addressee_index = 0;
            for (size_t i = 0; i < tx->num_outputs; ++i) {
                const auto& o = tx->outputs[i];
                // TODO: we're only handling assets here when they're still explicit
                auto asset_id = o.asset != nullptr && o.asset_len != 0u
                    ? b2h_rev(gsl::make_span(o.asset + 1, o.asset_len - 1))
                    : "btc";
                if (asset_id == net_params.policy_asset()) {
                    asset_id = "btc";
                }
                const bool is_fee = o.script == nullptr && o.script_len == 0u;
                const auto script_hex = !is_fee ? b2h(gsl::make_span(o.script, o.script_len)) : std::string{};

                const bool have_change = result.find("have_change") != result.end()
                    ? result.at("have_change").value(asset_id, false)
                    : false;
                const uint32_t change_index
                    = have_change ? result.at("change_index").at(asset_id).get<uint32_t>() : NO_CHANGE_INDEX;

                amount::value_type satoshi = o.satoshi;
                if (net_params.liquid()) {
                    GDK_RUNTIME_ASSERT(o.value);
                    if (*o.value == 1) {
                        satoshi = tx_confidential_value_to_satoshi(gsl::make_span(o.value, o.value_len));
                    }
                }

                const auto output_asset_id
                    = net_params.liquid() && asset_id == "btc" ? net_params.policy_asset() : asset_id;
                nlohmann::json output{ { "satoshi", satoshi }, { "script", script_hex },
                    { "is_change", i == change_index }, { "is_fee", is_fee }, { "asset_id", output_asset_id } };

                if (is_fee) {
                    // Nothing to do
                } else if (i == change_index) {
                    // Insert our change meta-data for the change output
                    const auto& change_address = result.at("change_address").at(asset_id);
                    output.insert(change_address.begin(), change_address.end());
                    if (net_params.liquid()) {
                        output["public_key"] = b2h(confidential_addr_to_ec_public_key(
                            change_address.at("address"), net_params.blinded_prefix()));
                    }
                } else {
                    const auto& addressee = result.at("addressees").at(addressee_index);
                    const auto& address = addressee.at("address");
                    output["address"] = address;
                    if (net_params.liquid()) {
                        output["public_key"]
                            = b2h(confidential_addr_to_ec_public_key(address, net_params.blinded_prefix()));
                    }
                    ++addressee_index;
                }

                if (net_params.liquid() && !is_fee && !output.contains("eph_keypair_sec")) {
                    auto ephemeral_keypair = get_ephemeral_keypair();
                    output["eph_keypair_sec"] = b2h(ephemeral_keypair.first);
                    output["eph_keypair_pub"] = b2h(ephemeral_keypair.second);
                }

                outputs.emplace_back(output);
            }
        }
        result["transaction_outputs"] = outputs;
    }

    void set_anti_snipe_locktime(const wally_tx_ptr& tx, uint32_t current_block_height)
    {
        // We use cores algorithm to randomly use an older locktime for delayed tx privacy
        tx->locktime = current_block_height;
        if (get_uniform_uint32_t(10) == 0) {
            tx->locktime -= get_uniform_uint32_t(100);
        }
    }

} // namespace sdk
} // namespace ga
