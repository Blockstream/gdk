#include "boost_wrapper.hpp"

#include "assertion.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "memory.hpp"
#include "session_impl.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

#include <cctype>

namespace {
bool isupper(const std::string& s)
{
    return std::all_of(std::begin(s), std::end(s), [](int c) { return std::islower(c) == 0; });
}

using namespace ga::sdk;

static std::vector<unsigned char> output_script_for_address(
    const network_parameters& net_params, std::string address, std::string& error)
{
    // bech32 is a vanilla bech32 address, blech32 is a confidential liquid address
    const bool is_bech32 = boost::starts_with(address, net_params.bech32_prefix());
    const bool is_blech32 = net_params.is_liquid() && boost::starts_with(address, net_params.blech32_prefix());

    if (net_params.is_liquid()) {
        if (is_bech32) {
            error = res::id_nonconfidential_addresses_not;
        } else if (is_blech32) {
            address
                = confidential_addr_to_addr_segwit(address, net_params.blech32_prefix(), net_params.bech32_prefix());
        } else {
            try {
                address = confidential_addr_to_addr(address, net_params.blinded_prefix());
            } catch (const std::exception& e) {
                error = res::id_nonconfidential_addresses_not;
            }
        }
    }

    if (is_bech32 || is_blech32) {
        std::vector<unsigned char> ret;
        try {
            ret = addr_segwit_to_bytes(address, net_params.bech32_prefix());
        } catch (const std::exception&) {
            error = res::id_invalid_address;
        }
        return ret;
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

    error = res::id_invalid_address;
    return std::vector<unsigned char>();
}

static std::vector<unsigned char> output_script_for_address(
    const network_parameters& net_params, const std::string& address, nlohmann::json& result)
{
    std::vector<unsigned char> script;
    std::string error;
    try {
        script = output_script_for_address(net_params, address, error);
    } catch (const std::exception& e) {
        error = res::id_invalid_address;
    }

    if (!error.empty()) {
        // Overwite any existing error in the transaction as addressees
        // are entered and should be corrected first.
        result["error"] = error;
        // Create a dummy script so that the caller gets back a reasonable
        // estimate of the tx size/fee etc when the address is corrected.
        std::vector<unsigned char>(HASH160_LEN).swap(script);
    }

    return script;
}
} // namespace

namespace ga {
namespace sdk {
    namespace address_type {
        const std::string p2pkh("p2pkh");
        const std::string p2wpkh("p2wpkh");
        const std::string p2sh_p2wpkh("p2sh-p2wpkh");
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

    static const ecdsa_sig_t DUMMY_GA_SIG = { { SIG_HIGH, SIG_HIGH } };
    static const ecdsa_sig_t DUMMY_GA_SIG_LOW_R = { { SIG_LOW, SIG_HIGH } };

    // DER encodings of the above
    static const std::vector<unsigned char> DUMMY_GA_SIG_DER_PUSH
        = { { 0x00, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00, SIG_HIGH, 0x02, 0x21, 0x00, SIG_HIGH, 0x01 } };
    static const std::vector<unsigned char> DUMMY_GA_SIG_DER_PUSH_LOW_R
        = { { 0x00, 0x48, 0x30, 0x45, 0x02, 0x20, SIG_LOW, 0x02, 0x21, 0x00, SIG_HIGH, 0x01 } };

    static const std::array<unsigned char, 3> OP_0_PREFIX = { { 0x00, 0x01, 0x00 } };

    static auto base58_address_from_bytes(unsigned char version, byte_span_t script_or_pubkey)
    {
        std::array<unsigned char, HASH160_LEN + 1> addr_bytes;
        addr_bytes[0] = version;
        GDK_VERIFY(
            wally_hash160(script_or_pubkey.data(), script_or_pubkey.size(), addr_bytes.begin() + 1, HASH160_LEN));
        return base58check_from_bytes(addr_bytes);
    }

    inline auto p2sh_address_from_bytes(const network_parameters& net_params, byte_span_t script)
    {
        return base58_address_from_bytes(net_params.btc_p2sh_version(), script);
    }

    inline auto p2pkh_address_from_public_key(const network_parameters& net_params, byte_span_t public_key)
    {
        return base58_address_from_bytes(net_params.btc_version(), public_key);
    }

    static auto p2sh_wrapped_address_from_bytes(
        const network_parameters& net_params, byte_span_t script_or_pubkey, uint32_t flags)
    {
        const uint32_t witness_ver = 0;
        return p2sh_address_from_bytes(net_params, witness_program_from_bytes(script_or_pubkey, witness_ver, flags));
    }

    inline auto p2sh_p2wsh_address_from_bytes(const network_parameters& net_params, byte_span_t script)
    {
        return p2sh_wrapped_address_from_bytes(net_params, script, WALLY_SCRIPT_SHA256);
    }

    inline auto p2sh_p2wpkh_address_from_public_key(const network_parameters& net_params, byte_span_t public_key)
    {
        return p2sh_wrapped_address_from_bytes(net_params, public_key, WALLY_SCRIPT_HASH160);
    }

    inline auto p2wpkh_address_from_public_key(const network_parameters& net_params, byte_span_t public_key)
    {
        const uint32_t witness_ver = 0;
        const auto witness_program = witness_program_from_bytes(public_key, witness_ver, WALLY_SCRIPT_HASH160);
        return addr_segwit_from_bytes(witness_program, net_params.bech32_prefix());
    }

    std::string get_address_from_script(
        const network_parameters& net_params, byte_span_t script, const std::string& addr_type)
    {
        if (addr_type == address_type::p2sh) {
            return p2sh_address_from_bytes(net_params, script);
        }
        GDK_RUNTIME_ASSERT(addr_type == address_type::p2wsh || addr_type == address_type::csv);
        return p2sh_p2wsh_address_from_bytes(net_params, script);
    }

    std::string get_address_from_public_key(
        const network_parameters& net_params, byte_span_t public_key, const std::string& addr_type)
    {
        GDK_VERIFY(wally_ec_public_key_verify(public_key.data(), public_key.size()));

        if (addr_type == address_type::p2sh_p2wpkh) {
            return p2sh_p2wpkh_address_from_public_key(net_params, public_key);
        } else if (addr_type == address_type::p2wpkh) {
            return p2wpkh_address_from_public_key(net_params, public_key);
        }
        GDK_RUNTIME_ASSERT(addr_type == address_type::p2pkh);
        return p2pkh_address_from_public_key(net_params, public_key);
    }

    static std::vector<unsigned char> output_script(const network_parameters& net_params, const pub_key_t& ga_pub_key,
        const pub_key_t& user_pub_key, byte_span_t backup_pub_key, const std::string& addr_type, uint32_t subtype)
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

        if (addr_type == address_type::csv && !is_2of3) {
            // CSV 2of2, subtype is the number of CSV blocks
            const bool optimize = !net_params.is_liquid(); // Liquid uses old style CSV
            scriptpubkey_csv_2of2_then_1_from_bytes(keys, subtype, optimize, script);
        } else {
            // P2SH or P2SH-P2WSH standard 2of2/2of3 multisig
            scriptpubkey_multisig_from_bytes(keys, threshold, script);
        }
        return script;
    }

    std::vector<unsigned char> output_script_from_utxo(const network_parameters& net_params, ga_pubkeys& pubkeys,
        user_pubkeys& usr_pubkeys, user_pubkeys& recovery_pubkeys, const nlohmann::json& utxo)
    {
        const uint32_t subaccount = json_get_value(utxo, "subaccount", 0u);
        const uint32_t pointer = utxo.at("pointer");
        const uint32_t version = utxo.value("version", 1u);
        const std::string addr_type = utxo.at("address_type");

        uint32_t subtype = 0;
        if (addr_type == address_type::csv) {
            // subtype indicates the number of csv blocks and must be one of the known bucket values
            subtype = utxo.at("subtype");
            const auto csv_buckets = net_params.csv_buckets();
            const auto csv_bucket_p = std::find(std::begin(csv_buckets), std::end(csv_buckets), subtype);
            GDK_RUNTIME_ASSERT_MSG(csv_bucket_p != csv_buckets.end(), "Unknown csv bucket");
        }

        pub_key_t ga_pub_key;
        if (version == 0) {
            // Service keys for legacy version 0 addresses are not derived from the user's GA path
            ga_pub_key = h2b<EC_PUBLIC_KEY_LEN>(net_params.pub_key());
        } else {
            ga_pub_key = pubkeys.derive(subaccount, pointer);
        }
        const auto user_pub_key = usr_pubkeys.derive(subaccount, pointer);

        if (recovery_pubkeys.have_subaccount(subaccount)) {
            // 2of3
            return output_script(
                net_params, ga_pub_key, user_pub_key, recovery_pubkeys.derive(subaccount, pointer), addr_type, subtype);
        }
        // 2of2
        return output_script(net_params, ga_pub_key, user_pub_key, empty_span(), addr_type, subtype);
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

    bool is_segwit_address_type(const nlohmann::json& utxo)
    {
        const std::string addr_type = utxo.at("address_type");
        if (addr_type == address_type::csv || addr_type == address_type::p2wsh || addr_type == address_type::p2wpkh
            || addr_type == address_type::p2sh_p2wpkh) {
            return true;
        }
        if (addr_type == address_type::p2sh || addr_type == address_type::p2pkh) {
            return false;
        }
        GDK_RUNTIME_ASSERT_MSG(false, std::string("unknown address_type ") + addr_type);
        return false;
    }

    std::string asset_id_from_json(const network_parameters& net_params, const nlohmann::json& json)
    {
        if (net_params.is_liquid()) {
            // Input asset_ids must only be valid hex asset ids
            std::string asset_id_hex = json_get_value(json, "asset_id");
            if (!validate_hex(asset_id_hex, ASSET_TAG_LEN)) {
                throw user_error(res::id_invalid_asset_id);
            }
            return asset_id_hex;
        } else {
            if (json.contains("asset_id")) {
                throw user_error(res::id_assets_cannot_be_used_on_bitcoin);
            }
            return "btc";
        }
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

    std::vector<unsigned char> witness_script(byte_span_t script, uint32_t witness_ver)
    {
        return witness_program_from_bytes(script, witness_ver, WALLY_SCRIPT_SHA256 | WALLY_SCRIPT_AS_PUSH);
    }

    amount get_tx_fee(const wally_tx_ptr& tx, amount min_fee_rate, amount fee_rate)
    {
        const amount rate = fee_rate < min_fee_rate ? min_fee_rate : fee_rate;

        const size_t vsize = tx_get_vsize(tx);
        const auto fee = static_cast<double>(vsize) * rate.value() / 1000.0;
        const auto rounded_fee = static_cast<amount::value_type>(std::ceil(fee));
        return amount(rounded_fee);
    }

    std::vector<unsigned char> scriptpubkey_from_address(
        const network_parameters& net_params, const std::string& address, bool confidential)
    {
        std::string error;
        std::vector<unsigned char> script = output_script_for_address(net_params, address, error);
        GDK_RUNTIME_ASSERT(error.empty() || (!confidential && error == res::id_nonconfidential_addresses_not));
        return script;
    }

    void set_tx_error(nlohmann::json& result, const std::string& error)
    {
        auto error_p = result.find("error");
        if (error_p == result.end() || error_p->get<std::string>().empty()) {
            result["error"] = error;
        }
    }

    amount add_tx_output(const network_parameters& net_params, nlohmann::json& result, wally_tx_ptr& tx,
        const std::string& address, amount::value_type satoshi, const std::string& asset_id)
    {
        std::vector<unsigned char> script = output_script_for_address(net_params, address, result);

        if (net_params.is_liquid()) {
            const auto ct_value = tx_confidential_value_from_satoshi(satoshi);
            const auto asset_bytes = h2b_rev(asset_id, 0x1);
            tx_add_elements_raw_output(tx, script, asset_bytes, ct_value, {}, {}, {});
        } else {
            tx_add_raw_output(tx, satoshi, script);
        }
        return amount(satoshi);
    }

    size_t add_tx_fee_output(const network_parameters& net_params, wally_tx_ptr& tx, amount::value_type satoshi)
    {
        const auto ct_value = tx_confidential_value_from_satoshi(satoshi);
        auto asset_bytes = h2b_rev(net_params.policy_asset(), 0x1);
        tx_add_elements_raw_output(tx, {}, asset_bytes, ct_value, {}, {}, {});
        return tx->num_outputs - 1;
    }

    void set_tx_output_commitment(
        wally_tx_ptr& tx, uint32_t index, const std::string& asset_id, amount::value_type satoshi)
    {
        const auto ct_value = tx_confidential_value_from_satoshi(satoshi);
        const auto asset_bytes = h2b_rev(asset_id, 0x1);
        tx_elements_output_commitment_set(tx, index, asset_bytes, ct_value, {}, {}, {});
    }

    // TODO: Merge this validation with add_tx_addressee to avoid re-parsing?
    std::string validate_tx_addressee(
        const network_parameters& net_params, nlohmann::json& result, nlohmann::json& addressee)
    {
        std::string address = addressee.at("address"); // Assume its a standard address

        const auto uri = parse_bitcoin_uri(address, net_params.bip21_prefix());
        if (net_params.is_liquid() && uri.is_object()) {
            const auto& bip21_params = uri["bip21-params"];
            const bool has_assetid = bip21_params.contains("assetid");

            if (!has_assetid && bip21_params.contains("amount")) {
                set_tx_error(result, res::id_invalid_payment_request_assetid);
                return std::string();
            } else if (has_assetid) {
                const std::string assetid_hex = bip21_params["assetid"];
                if (!validate_hex(assetid_hex, ASSET_TAG_LEN)) {
                    set_tx_error(result, res::id_invalid_payment_request_assetid);
                    return std::string();
                }
                addressee["asset_id"] = assetid_hex;
            }
        }

        return asset_id_from_json(net_params, addressee);
    }

    amount add_tx_addressee(session_impl& session, const network_parameters& net_params, nlohmann::json& result,
        wally_tx_ptr& tx, nlohmann::json& addressee)
    {
        std::string address = addressee.at("address"); // Assume its a standard address

        nlohmann::json uri = parse_bitcoin_uri(address, net_params.bip21_prefix());
        if (!uri.is_null()) {
            // Address is a BIP21 style payment URI. Validation is done in
            // validate_tx_addressee(), assume everything is good here
            address = uri.at("address");
            addressee["address"] = address;
            const auto& bip21_params = uri["bip21-params"];
            addressee["bip21-params"] = bip21_params;

            // In Liquid amounts should be encoded in the "consensus form"
            // For instance, assuming an invoice for qty 1 of an asset with precision `2`, the amount in the URI
            // should be 0.00000100
            const auto uri_amount_p = bip21_params.find("amount");
            if (uri_amount_p != bip21_params.end()) {
                // Use the amount specified in the URI
                const nlohmann::json uri_amount = { { "btc", uri_amount_p->get<std::string>() } };
                addressee["satoshi"] = session.convert_amount(uri_amount)["satoshi"];
                amount::strip_non_satoshi_keys(addressee);
            }
        }

        // Convert uppercase b(l)ech32 alphanumeric strings to lowercase
        // Only convert all uppercase strings, BIP-173 specifically disallows mixed case strings
        const std::string bech32_prefix = net_params.bech32_prefix() + "1";
        if ((boost::istarts_with(address, bech32_prefix)
                || (net_params.is_liquid() && boost::istarts_with(address, net_params.blech32_prefix() + "1")))
            && isupper(address)) {
            boost::to_lower(address);
            addressee["address"] = address;
        }

        // Convert the users entered value into satoshi
        amount satoshi;
        try {
            satoshi = session.convert_amount(addressee)["satoshi"].get<amount::value_type>();
        } catch (const user_error& ex) {
            // Note the error, and create a 0 satoshi output
            set_tx_error(result, ex.what());
        } catch (const std::exception&) {
            // Note the error, and create a 0 satoshi output
            set_tx_error(result, res::id_invalid_amount);
        }

        // Transactions with outputs below the dust threshold (except OP_RETURN)
        // are not relayed by network nodes
        if (!result.value("send_all", false) && satoshi.value() < session.get_dust_threshold()) {
            set_tx_error(result, res::id_invalid_amount);
        }

        amount::strip_non_satoshi_keys(addressee);
        addressee["satoshi"] = satoshi.value(); // Sets to 0 if not present

        return add_tx_output(
            net_params, result, tx, address, satoshi.value(), asset_id_from_json(net_params, addressee));
    }

    void update_tx_size_info(const network_parameters& net_params, const wally_tx_ptr& tx, nlohmann::json& result)
    {
        const bool valid = tx->num_inputs != 0u && tx->num_outputs != 0u;
        result["transaction"] = valid ? tx_to_hex(tx) : std::string();
        const auto weight = tx_get_weight(tx);
        result["transaction_size"] = valid ? tx_get_length(tx, WALLY_TX_FLAG_USE_WITNESS) : 0;
        result["transaction_weight"] = valid ? weight : 0;
        const uint32_t tx_vsize = valid ? tx_vsize_from_weight(weight) : 0;
        result["transaction_vsize"] = tx_vsize;
        result["transaction_version"] = tx->version;
        result["transaction_locktime"] = tx->locktime;
        const auto fee_p = result.find("fee");
        if (fee_p != result.end()) {
            if (net_params.is_liquid()) {
                result["calculated_fee_rate"] = *fee_p;
            } else {
                const amount::value_type fee = *fee_p;
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
        update_tx_size_info(net_params, tx, result);

        const bool is_liquid = net_params.is_liquid();
        const bool valid = tx->num_inputs != 0u && tx->num_outputs != 0U;

        // Note that outputs may be empty if the constructed tx is incomplete
        std::vector<nlohmann::json> outputs;
        if (valid && json_get_value(result, "error").empty() && result.find("addressees") != result.end()) {
            outputs.reserve(tx->num_outputs);
            size_t addressee_index = 0;
            for (size_t i = 0; i < tx->num_outputs; ++i) {
                const auto& o = tx->outputs[i];
                // TODO: we're only handling assets here when they're still explicit
                std::string asset_id = "btc";
                if (is_liquid) {
                    if (o.asset && o.asset_len) {
                        asset_id = b2h_rev(gsl::make_span(o.asset, o.asset_len).subspan(1));
                    } else {
                        asset_id = net_params.policy_asset();
                    }
                }
                const bool is_fee = o.script == nullptr && o.script_len == 0u;
                const auto script_hex = !is_fee ? b2h(gsl::make_span(o.script, o.script_len)) : std::string{};

                const bool have_change = result.find("have_change") != result.end()
                    ? result.at("have_change").value(asset_id, false)
                    : false;
                const uint32_t change_index
                    = have_change ? result.at("change_index").at(asset_id).get<uint32_t>() : NO_CHANGE_INDEX;

                amount::value_type satoshi = o.satoshi;
                if (is_liquid) {
                    GDK_RUNTIME_ASSERT(o.value);
                    if (*o.value == 1) {
                        satoshi = tx_confidential_value_to_satoshi(gsl::make_span(o.value, o.value_len));
                    }
                }

                nlohmann::json output{ { "satoshi", satoshi }, { "script", script_hex },
                    { "is_change", i == change_index }, { "is_fee", is_fee }, { "asset_id", asset_id } };

                auto&& blinding_key_from_addr = [&net_params](const std::string& address) {
                    if (boost::starts_with(address, net_params.blech32_prefix())) {
                        return b2h(confidential_addr_segwit_to_ec_public_key(address, net_params.blech32_prefix()));
                    } else {
                        return b2h(confidential_addr_to_ec_public_key(address, net_params.blinded_prefix()));
                    }
                };

                if (is_fee) {
                    // Nothing to do
                } else if (i == change_index) {
                    // Insert our change meta-data for the change output
                    const auto& change_address = result.at("change_address").at(asset_id);
                    output.insert(change_address.begin(), change_address.end());
                    if (is_liquid) {
                        output["blinding_key"] = blinding_key_from_addr(change_address.at("address"));
                    }
                } else {
                    const auto& addressee = result.at("addressees").at(addressee_index);
                    const auto& address = addressee.at("address");
                    output["address"] = address;
                    if (is_liquid) {
                        output["blinding_key"] = blinding_key_from_addr(address);
                    }
                    ++addressee_index;
                }

                if (is_liquid && !is_fee && !output.contains("eph_keypair_sec")) {
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
