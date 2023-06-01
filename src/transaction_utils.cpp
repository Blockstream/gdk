#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "assertion.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "memory.hpp"
#include "session_impl.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

#include <cctype>

namespace {
static bool isupper(const std::string& s)
{
    // String is upper case if no lower case characters are found
    return std::none_of(std::cbegin(s), std::cend(s), [](int c) { return std::islower(c) != 0; });
}

static bool islower(const std::string& s)
{
    // String is lower case if no upper case characters are found
    return std::none_of(std::cbegin(s), std::cend(s), [](int c) { return std::isupper(c) != 0; });
}

using namespace ga::sdk;

// Note that if id_nonconfidential_addresses_not is returned in 'error', this
// call still returns the resulting script. This behaviour is used by
// add_tx_addressee_output when adding preblinded outputs (where is_blinded=true).
static std::vector<unsigned char> output_script_for_address(
    const network_parameters& net_params, std::string address, std::string& error)
{
    // bech32 is a vanilla bech32 address, blech32 is a confidential liquid address
    const bool is_bech32 = boost::istarts_with(address, net_params.bech32_prefix());
    const bool is_blech32 = net_params.is_liquid() && boost::istarts_with(address, net_params.blech32_prefix());
    const bool is_base58 = !is_bech32 && !is_bech32 && validate_base58check(address);

    if (!is_bech32 && !is_blech32 && !is_base58) {
        error = res::id_invalid_address; // Unknown address type
        return {};
    }

    if ((is_bech32 || is_blech32) && !(islower(address) || isupper(address))) {
        // BIP-173 specifically disallows mixed case
        error = res::id_invalid_address;
        return {};
    }

    if (net_params.is_liquid()) {
        if (is_bech32) {
            error = res::id_nonconfidential_addresses_not;
        } else {
            try {
                if (is_blech32) {
                    address = confidential_addr_to_addr_segwit(
                        address, net_params.blech32_prefix(), net_params.bech32_prefix());
                } else if (is_possible_confidential_addr(address)) {
                    address = confidential_addr_to_addr(address, net_params.blinded_prefix());
                } else {
                    error = res::id_nonconfidential_addresses_not;
                }
            } catch (const std::exception& e) {
                // If the address isn't blech32, its base58 with the wrong prefix byte
                error = is_blech32 ? res::id_invalid_address : res::id_nonconfidential_addresses_not;
            }
        }
    }

    try {
        if (is_bech32 || is_blech32) {
            // Segwit address
            return addr_segwit_to_bytes(address, net_params.bech32_prefix());
        } else {
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
        }
    } catch (const std::exception&) {
        // Return id_invalid_address below
    }
    if (error.empty()) {
        error = res::id_invalid_address;
    }
    return {};
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
    } // namespace address_type

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

    std::string get_address_from_scriptpubkey(const network_parameters& net_params, byte_span_t scriptpubkey)
    {
        // TODO: Fix wally_scriptpubkey_to_address and use that
        const auto script_type = scriptpubkey_get_type(scriptpubkey);
        if (script_type == WALLY_SCRIPT_TYPE_P2PKH || script_type == WALLY_SCRIPT_TYPE_P2SH) {
            std::array<unsigned char, HASH160_LEN + 1> addr_bytes;
            const size_t offset = script_type == WALLY_SCRIPT_TYPE_P2PKH ? 3 : 2;
            const auto p2pkh_ver = net_params.btc_version(), p2sh_ver = net_params.btc_p2sh_version();
            addr_bytes[0] = script_type == WALLY_SCRIPT_TYPE_P2PKH ? p2pkh_ver : p2sh_ver;
            memcpy(&addr_bytes[0] + 1, scriptpubkey.data() + offset, HASH160_LEN);
            return base58check_from_bytes(addr_bytes);
        } else if (script_type == WALLY_SCRIPT_TYPE_P2WPKH || script_type == WALLY_SCRIPT_TYPE_P2WSH
            || script_type == WALLY_SCRIPT_TYPE_P2TR) {
            return addr_segwit_from_bytes(scriptpubkey, net_params.bech32_prefix());
        }
        GDK_RUNTIME_ASSERT_MSG(false, std::string("unhandled scriptpubkey ") + b2h(scriptpubkey));
        return std::string();
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
        return output_script(net_params, ga_pub_key, user_pub_key, {}, addr_type, subtype);
    }

    std::vector<unsigned char> input_script(bool low_r, const std::vector<unsigned char>& prevout_script,
        const ecdsa_sig_t& user_sig, const ecdsa_sig_t& ga_sig, uint32_t user_sighash, uint32_t ga_sighash)
    {
        const std::array<uint32_t, 2> sighashes = { { ga_sighash, user_sighash } };
        std::array<unsigned char, sizeof(ecdsa_sig_t) * 2> sigs;
        init_container(sigs, ga_sig, user_sig);
        const uint32_t sig_len = low_r ? EC_SIGNATURE_DER_MAX_LOW_R_LEN : EC_SIGNATURE_DER_MAX_LEN;
        // OP_O [sig + sighash_byte] [sig + sighash_byte] [prevout_script]
        // 3 below allows for up to an OP_PUSHDATA2 prevout script size.
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

    std::vector<unsigned char> input_script(bool low_r, const std::vector<unsigned char>& prevout_script,
        const ecdsa_sig_t& user_sig, uint32_t user_sighash)
    {
        const ecdsa_sig_t& dummy_sig = low_r ? DUMMY_GA_SIG_LOW_R : DUMMY_GA_SIG;
        const std::vector<unsigned char>& dummy_push = low_r ? DUMMY_GA_SIG_DER_PUSH_LOW_R : DUMMY_GA_SIG_DER_PUSH;

        std::vector<unsigned char> full_script
            = input_script(low_r, prevout_script, user_sig, dummy_sig, user_sighash, WALLY_SIGHASH_ALL);
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
        return input_script(low_r, prevout_script, dummy_sig, dummy_sig, WALLY_SIGHASH_ALL, WALLY_SIGHASH_ALL);
    }

    std::vector<unsigned char> dummy_external_input_script(bool low_r, byte_span_t pub_key)
    {
        const ecdsa_sig_t& dummy_sig = low_r ? DUMMY_GA_SIG_LOW_R : DUMMY_GA_SIG;
        return scriptsig_p2pkh_from_der(pub_key, ec_sig_to_der(dummy_sig, WALLY_SIGHASH_ALL));
    }

    std::vector<unsigned char> witness_script(byte_span_t script, uint32_t witness_ver)
    {
        return witness_program_from_bytes(script, witness_ver, WALLY_SCRIPT_SHA256 | WALLY_SCRIPT_AS_PUSH);
    }

    static size_t get_tx_adjusted_weight(const network_parameters& net_params, const wally_tx_ptr& tx)
    {
        size_t weight = tx_get_weight(tx);
        if (net_params.is_liquid()) {
            // Add the weight of any missing blinding data
            const auto policy_asset_bytes = h2b_rev(net_params.get_policy_asset(), 0x1);
            const auto num_inputs = tx->num_inputs ? tx->num_inputs : 1; // Assume at least 1 input
            const size_t sjp_size = varbuff_get_length(asset_surjectionproof_size(num_inputs));
            size_t blinding_weight = 0;

            for (size_t i = 0; i < tx->num_outputs; ++i) {
                auto& output = tx->outputs[i];
                uint64_t satoshi = 0;

                if (!output.script) {
                    GDK_RUNTIME_ASSERT(i + 1 == tx->num_outputs);
                    continue; // Fee: Must be the last output
                }
                GDK_RUNTIME_ASSERT(output.asset_len);
                GDK_RUNTIME_ASSERT(output.value_len);
                if (!output.nonce) {
                    blinding_weight += WALLY_TX_ASSET_CT_NONCE_LEN * 4;
                }
                if (!output.surjectionproof_len) {
                    blinding_weight += sjp_size;
                }
                if (output.value[0] == 1) {
                    // An explicit value; use it for a better estimate
                    auto conf_value = gsl::make_span(output.value, output.value_len);
                    satoshi = tx_confidential_value_to_satoshi(conf_value);
                    // Add the difference between the explicit and blinded value size
                    blinding_weight -= WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN * 4;
                    blinding_weight += WALLY_TX_ASSET_CT_VALUE_LEN * 4;
                }
                if (!output.rangeproof_len) {
                    if (!satoshi) {
                        // We don't know the value, or its a zero placeholder;
                        // assume its the maximum for estimation purposes.
                        if (output.asset_len == policy_asset_bytes.size()
                            && !memcmp(output.asset, policy_asset_bytes.data(), output.asset_len)) {
                            // L-BTC: Limited by the policy asset coin supply
                            satoshi = amount::get_max_satoshi();
                        } else {
                            // Asset: Any valid uint64 value is possible
                            satoshi = std::numeric_limits<uint64_t>::max();
                        }
                    }
                    blinding_weight += varbuff_get_length(asset_rangeproof_max_size(satoshi));
                }
            }
            weight += blinding_weight;
        }
        return weight;
    }

    amount get_tx_fee(
        const network_parameters& net_params, const wally_tx_ptr& tx, amount min_fee_rate, amount fee_rate)
    {
        const amount rate = fee_rate < min_fee_rate ? min_fee_rate : fee_rate;
        const size_t weight = get_tx_adjusted_weight(net_params, tx);
        const size_t vsize = (weight + 3) / 4;
        const auto fee = static_cast<double>(vsize) * rate.value() / 1000.0;
        const auto rounded_fee = static_cast<amount::value_type>(std::ceil(fee));
        return amount(rounded_fee);
    }

    std::vector<unsigned char> scriptpubkey_from_address(
        const network_parameters& net_params, const std::string& address, bool allow_unconfidential)
    {
        std::string error;
        auto script = output_script_for_address(net_params, address, error);
        GDK_RUNTIME_ASSERT(error.empty() || (allow_unconfidential && error == res::id_nonconfidential_addresses_not));
        return script;
    }

    void set_tx_error(nlohmann::json& result, const std::string& error, bool overwrite)
    {
        auto& e = result["error"];
        if (overwrite || e.empty() || e.get<std::string>().empty()) {
            e = error;
        }
    }

    void set_tx_output_commitment(
        wally_tx_ptr& tx, uint32_t index, const std::string& asset_id, amount::value_type satoshi)
    {
        const auto ct_value = tx_confidential_value_from_satoshi(satoshi);
        const auto asset_bytes = h2b_rev(asset_id, 0x1);
        tx_elements_output_commitment_set(tx, index, asset_bytes, ct_value, {}, {}, {});
    }

    // TODO: Merge this validation with add_tx_addressee_output to avoid re-parsing?
    std::string validate_tx_addressee(session_impl& session, nlohmann::json& addressee)
    {
        const auto& net_params = session.get_network_parameters();
        const bool is_liquid = net_params.is_liquid();
        const auto blech32_prefix = net_params.blech32_prefix();

        try {
            std::string address = json_get_value(addressee, "address");
            if (address.empty()) {
                throw user_error(res::id_invalid_address);
            }
            const bool is_blinded = is_liquid && addressee.value("is_blinded", false);
            if (is_blinded && !session.get_nonnull_signer()->supports_external_blinding()) {
                throw user_error("Signing device does not support externally blinded transactions");
            }

            // BIP21
            auto uri = parse_bitcoin_uri(net_params, address);
            if (!uri.empty()) {
                GDK_RUNTIME_ASSERT(!is_blinded);

                // Address is a BIP21 style payment URI.
                auto& bip21 = uri["bip21-params"];
                if (auto p = bip21.find("assetid"); p != bip21.end()) {
                    addressee["asset_id"] = *p;
                }
                address = uri.at("address");
                addressee["address"] = address;
                if (auto p = bip21.find("amount"); p != bip21.end()) {
                    // Note liquid amounts are also encoded just as BTC amounts
                    amount::strip_non_satoshi_keys(addressee);
                    addressee.erase("satoshi");
                    addressee["btc"] = p->get<std::string>();
                }
                addressee["bip21-params"] = std::move(bip21);
            }

            // Validate the address
            std::string error;
            auto scriptpubkey = output_script_for_address(net_params, address, error);
            if (is_blinded && error == res::id_nonconfidential_addresses_not) {
                // Existing outputs which are already blinded are OK
                error.clear();
            }
            if (!error.empty()) {
                return error;
            }
            addressee["scriptpubkey"] = b2h(scriptpubkey);

            // Convert all-uppercase b(l)ech32 addresses to lowercase
            if (isupper(address)) {
                if (boost::istarts_with(address, net_params.bech32_prefix() + "1")
                    || (is_liquid && boost::istarts_with(address, blech32_prefix + "1"))) {
                    boost::to_lower(address);
                    addressee["address"] = address;
                }
            }

            // Validate the asset (or lack of it)
            asset_id_from_json(net_params, addressee);

            // Validate and convert the amount to satoshi
            try {
                addressee["satoshi"] = session.convert_amount(addressee)["satoshi"].get<amount::value_type>();
                amount::strip_non_satoshi_keys(addressee);
            } catch (const user_error& ex) {
                return ex.what();
            } catch (const std::exception& ex) {
                return res::id_invalid_amount;
            }

            if (is_liquid && !is_blinded) {
                // Fetch the blinding key from the confidential address
                std::string blinding_key;
                if (boost::starts_with(address, blech32_prefix)) {
                    blinding_key = b2h(confidential_addr_segwit_to_ec_public_key(address, blech32_prefix));
                } else {
                    blinding_key = b2h(confidential_addr_to_ec_public_key(address, net_params.blinded_prefix()));
                }
                addressee["blinding_key"] = std::move(blinding_key);
            }
        } catch (const std::exception& e) {
            return e.what();
        }
        return std::string();
    }

    static amount add_tx_output(
        const network_parameters& net_params, nlohmann::json& result, wally_tx_ptr& tx, const nlohmann::json& output)
    {
        std::string old_error = json_get_value(result, "error");
        const amount::value_type satoshi = output.at("satoshi").get<amount::value_type>();
        std::vector<unsigned char> script;
        if (!output.value("is_fee", false)) {
            script = h2b(output.at("scriptpubkey"));
        }
        if (!net_params.is_liquid()) {
            tx_add_raw_output(tx, satoshi, script);
            return amount(satoshi);
        }
        if (output.value("is_change", false)
            && json_get_value(result, "error") == res::id_nonconfidential_addresses_not) {
            // This is an unblinded change output, allow it
            result["error"] = old_error;
        }
        const uint32_t index = tx->num_outputs; // Append to outputs
        const auto asset_id = asset_id_from_json(net_params, output);
        const auto asset_bytes = h2b_rev(asset_id, 0x1);
        const auto ct_value = tx_confidential_value_from_satoshi(satoshi);
        tx_add_elements_raw_output_at(tx, index, script, asset_bytes, ct_value, {}, {}, {});
        return amount(satoshi);
    }

    amount add_tx_addressee_output(
        session_impl& session, nlohmann::json& result, wally_tx_ptr& tx, nlohmann::json& addressee)
    {
        const auto& net_params = session.get_network_parameters();
        std::string address = addressee.at("address"); // Assume its a standard address
        const bool is_blinded = addressee.value("is_blinded", false);
        const auto asset_id_hex = asset_id_from_json(net_params, addressee);

        if (is_blinded) {
            // The case of an existing blinded output
            auto scriptpubkey = h2b(addressee.at("scriptpubkey"));
            const auto asset_id = h2b_rev(asset_id_hex);
            const amount::value_type satoshi = addressee.at("satoshi");
            const auto abf = h2b_rev(addressee.at("assetblinder"));
            if (std::all_of(abf.begin(), abf.end(), [](auto b) { return b == 0; })) {
                throw user_error("pre-blinded input asset is not blinded");
            }
            const auto asset_commitment = asset_generator_from_bytes(asset_id, abf);
            std::array<unsigned char, 33> value_commitment;
            if (addressee.contains("amountblinder")) {
                const auto vbf = h2b_rev(addressee.at("amountblinder"));
                if (std::all_of(vbf.begin(), vbf.end(), [](auto b) { return b == 0; })) {
                    throw user_error("pre-blinded input value is not blinded");
                }
                value_commitment = asset_value_commitment(satoshi, vbf, asset_commitment);
            } else {
                value_commitment = h2b<33>(addressee.at("commitment"));
            }

            const auto nonce_commitment = h2b(addressee.at("nonce_commitment"));

            std::vector<unsigned char> surjectionproof;
            if (addressee.contains("surj_proof")) {
                surjectionproof = h2b(addressee.at("surj_proof"));
            }

            std::vector<unsigned char> rangeproof;
            if (addressee.contains("range_proof")) {
                rangeproof = h2b(addressee.at("range_proof"));
            }

            const uint32_t index = addressee.at("index");
            tx_add_elements_raw_output_at(tx, index, scriptpubkey, asset_commitment, value_commitment, nonce_commitment,
                surjectionproof, rangeproof);
            return amount(satoshi);
        }

        if (!result.value("send_all", false)) {
            const auto satoshi = addressee["satoshi"].get<amount::value_type>();
            if (satoshi < session.get_dust_threshold(asset_id_hex)) {
                // Output is below the dust threshold. TODO: Allow 0 OP_RETURN.
                set_tx_error(result, res::id_invalid_amount);
            }
        }
        return add_tx_output(net_params, result, tx, addressee);
    }

    size_t add_tx_change_output(
        session_impl& session, nlohmann::json& result, wally_tx_ptr& tx, const std::string& asset_id)
    {
        const auto& net_params = session.get_network_parameters();
        auto& output = result.at("change_address").at(asset_id);
        output["is_change"] = true;
        output["asset_id"] = asset_id;
        output["satoshi"] = 0;
        std::string error;
        const bool allow_unconfidential = true; // Change may not yet be blinded
        const auto spk = scriptpubkey_from_address(net_params, output.at("address"), allow_unconfidential);
        output["scriptpubkey"] = b2h(spk);
        add_tx_output(net_params, result, tx, output);
        return tx->num_outputs - 1;
    }

    size_t add_tx_fee_output(session_impl& session, nlohmann::json& result, wally_tx_ptr& tx)
    {
        const auto& net_params = session.get_network_parameters();
        nlohmann::json output{ { "satoshi", 0 }, { "scriptpubkey", nlohmann::json::array() }, { "is_change", false },
            { "is_fee", true }, { "asset_id", net_params.get_policy_asset() } };
        add_tx_output(net_params, result, tx, output);
        return tx->num_outputs - 1;
    }

    void update_tx_size_info(const network_parameters& net_params, const wally_tx_ptr& tx, nlohmann::json& result)
    {
        const bool valid = tx->num_inputs != 0u && tx->num_outputs != 0u;
        result["transaction"] = valid ? tx_to_hex(tx, tx_flags(net_params.is_liquid())) : std::string();
        const auto weight = get_tx_adjusted_weight(net_params, tx);
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

    uint32_t get_tx_change_index(nlohmann::json& result, const std::string& asset_id)
    {
        const auto index_p = result.find("change_index");
        if (index_p != result.end()) {
            return index_p->value(asset_id, NO_CHANGE_INDEX);
        }
        return NO_CHANGE_INDEX;
    }

    void update_tx_info(session_impl& session, const wally_tx_ptr& tx, nlohmann::json& result)
    {
        const auto& net_params = session.get_network_parameters();
        update_tx_size_info(net_params, tx, result);

        const bool is_liquid = net_params.is_liquid();
        const bool valid = tx->num_inputs != 0u && tx->num_outputs != 0U;

        // Note that outputs may be empty if the constructed tx is incomplete
        nlohmann::json::array_t outputs;
        if (valid && json_get_value(result, "error").empty() && result.find("addressees") != result.end()) {
            outputs.reserve(tx->num_outputs);

            size_t addressee_index = 0;
            for (size_t i = 0; i < tx->num_outputs; ++i) {
                const auto& o = tx->outputs[i];
                auto addressee = nlohmann::json::object();
                GDK_RUNTIME_ASSERT(!is_liquid || o.asset);
                const bool is_blinded = is_liquid && *o.asset != 1 && o.value && *o.value != 1;
                std::string asset_id;

                if (is_blinded) {
                    // Find the addressee with the same index as the current output
                    for (const auto& addr : result.at("addressees")) {
                        if (addr.value("is_blinded", false) && addr.at("index") == i) {
                            addressee = addr;
                        }
                    }
                    GDK_RUNTIME_ASSERT(!addressee.empty());
                    asset_id = addressee.at("asset_id");
                } else if (is_liquid) {
                    asset_id = b2h_rev(gsl::make_span(o.asset, o.asset_len).subspan(1));
                } else {
                    asset_id = net_params.get_policy_asset();
                }
                const bool is_fee = o.script == nullptr && o.script_len == 0u;
                const auto scriptpubkey_hex = !is_fee ? b2h(gsl::make_span(o.script, o.script_len)) : std::string{};

                const uint32_t change_index = get_tx_change_index(result, asset_id);

                amount::value_type satoshi = o.satoshi;
                if (is_liquid) {
                    GDK_RUNTIME_ASSERT(o.value);
                    if (*o.value == 1) {
                        satoshi = tx_confidential_value_to_satoshi(gsl::make_span(o.value, o.value_len));
                    } else {
                        GDK_RUNTIME_ASSERT(is_blinded);
                        satoshi = addressee.at("satoshi");
                    }
                }

                nlohmann::json output{ { "satoshi", satoshi }, { "scriptpubkey", scriptpubkey_hex },
                    { "is_change", i == change_index }, { "is_fee", is_fee }, { "asset_id", asset_id } };

                if (is_fee) {
                    // Nothing to do
                } else if (i == change_index) {
                    // Insert our change meta-data for the change output
                    const auto& change_address = result.at("change_address").at(asset_id);
                    output.insert(change_address.begin(), change_address.end());
                } else {
                    if (!is_blinded) {
                        // Go to the next not blinded addressee
                        while (addressee_index < result.at("addressees").size()) {
                            const auto& addr = result.at("addressees").at(addressee_index);
                            ++addressee_index;
                            if (!addr.value("is_blinded", false)) {
                                addressee = addr;
                                break;
                            }
                        }
                    }
                    GDK_RUNTIME_ASSERT(!addressee.empty());
                    output.insert(addressee.begin(), addressee.end());
                }

                outputs.emplace_back(std::move(output));
            }
        }
        result["transaction_outputs"] = std::move(outputs);
    }

    static bool is_wallet_input(const nlohmann::json& utxo)
    {
        if (!json_get_value(utxo, "private_key").empty()) {
            return false; // Sweep input
        }
        if (utxo.contains("script_sig") && utxo.contains("witness")) {
            return false; // External input (e.g. in a swap)
        }
        return true; // Wallet input
    }

    std::set<uint32_t> get_tx_subaccounts(const nlohmann::json& details)
    {
        std::set<uint32_t> ret;
        if (auto utxos_p = details.find("used_utxos"); utxos_p != details.end()) {
            for (auto& utxo : *utxos_p) {
                if (is_wallet_input(utxo)) {
                    ret.insert(utxo.at("subaccount").get<uint32_t>());
                }
            }
        }
        if (auto utxos_p = details.find("utxos"); utxos_p != details.end()) {
            for (auto& asset : utxos_p->items()) {
                if (asset.key() != "error") {
                    for (auto& utxo : asset.value()) {
                        if (is_wallet_input(utxo)) {
                            ret.insert(utxo.at("subaccount").get<uint32_t>());
                        }
                    }
                }
            }
        }
        // TODO: Don't require subaccount for sweeping/bumping
        if (auto p = details.find("subaccount"); p != details.end()) {
            ret.insert(p->get<uint32_t>());
        }
        if (auto p = details.find("change_subaccount"); p != details.end()) {
            ret.insert(p->get<uint32_t>());
        }
        return ret;
    }

    uint32_t get_single_subaccount(const std::set<uint32_t>& subaccounts)
    {
        if (subaccounts.size() > 1)
            throw user_error("Cannot determine subaccount");
        if (subaccounts.size() == 0)
            throw user_error("Cannot determine subaccount");
        return *subaccounts.begin();
    }

    bool tx_has_amp_inputs(session_impl& session, const nlohmann::json& details)
    {
        if (!session.get_network_parameters().is_electrum()) {
            // Multisig: check if we have any AMP inputs
            for (auto subaccount : get_tx_subaccounts(details)) {
                // Subaccount 0 can never be amp so don't bother checking it
                if (subaccount && session.get_subaccount_type(subaccount) == "2of2_no_recovery") {
                    return true;
                }
            }
        }
        return false;
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
