#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "assertion.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "json_utils.hpp"
#include "memory.hpp"
#include "session_impl.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

#include <cctype>

namespace ga {
namespace sdk {
    namespace {
        // Script types returned by the Green backend server
        constexpr uint32_t ga_p2sh_fortified_out = 10;
        constexpr uint32_t ga_p2sh_p2wsh_fortified_out = 14;
        constexpr uint32_t ga_p2sh_p2wsh_csv_fortified_out = 15;
        constexpr uint32_t ga_redeem_p2sh_fortified = 150;
        constexpr uint32_t ga_redeem_p2sh_p2wsh_fortified = 159;
        constexpr uint32_t ga_redeem_p2sh_p2wsh_csv_fortified = 162;

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

        using witness_ptr = std::unique_ptr<struct wally_tx_witness_stack>;

        static void witness_stack_add(const witness_ptr& stack, std::initializer_list<byte_span_t> items)
        {
            for (const auto& item : items) {
                GDK_VERIFY(wally_tx_witness_stack_add(stack.get(), item.data(), item.size()));
            }
        }

        static witness_ptr witness_stack(std::initializer_list<byte_span_t> items, size_t num_expected = 0)
        {
            struct wally_tx_witness_stack* p;
            GDK_VERIFY(wally_tx_witness_stack_init_alloc(num_expected ? num_expected : items.size(), &p));
            auto wit = witness_ptr(p);
            witness_stack_add(wit, items);
            return wit;
        }

        // Dummy signatures are needed for correctly sizing transactions.
        // All signers are required to produce Low-S signatures to comply with
        // Bitcoin's standardness rules.
        // If our signer supports low-R, we estimate on a 71 byte signature
        // (low-R, low-S plus sighash byte).
        // Otherwise, we estimate on 72 bytes (high-R, low-S plus sighash byte).
        // We occasionally produce smaller signatures, with decreasing probability
        // as the signature size gets smaller.

        // We construct our dummy sigs R, S from OP_SUBSTR/OP_INVALIDOPCODE.
#define SIG_SLED(INITIAL, B) INITIAL, B, B, B, B, B, B, B, B, B, B, B, B, B, B, B
#define SIG_BYTES(INITIAL, B) SIG_SLED(INITIAL, B), SIG_SLED(B, B)

#define SIG_HIGH SIG_BYTES(OP_INVALIDOPCODE, OP_SUBSTR)
#define SIG_LOW SIG_BYTES(OP_SUBSTR, OP_SUBSTR)

        static const ecdsa_sig_t DUMMY_SIG = { { SIG_HIGH, SIG_LOW } };
        static const ecdsa_sig_t DUMMY_SIG_LOW_R = { { SIG_LOW, SIG_LOW } };

        // Script pushes of DER encodings of the above sigs including sighash byte
        static const std::vector<unsigned char> DUMMY_SIG_DER_PUSH
            = { { 0x00, 0x48, 0x30, 0x45, 0x02, 0x21, 0x00, SIG_HIGH, 0x02, 0x20, SIG_LOW, WALLY_SIGHASH_ALL } };
        static const std::vector<unsigned char> DUMMY_SIG_DER_PUSH_LOW_R
            = { { 0x00, 0x47, 0x30, 0x44, 0x02, 0x20, SIG_LOW, 0x02, 0x20, SIG_LOW, WALLY_SIGHASH_ALL } };

        // DER encodings of the above sigs including sighash byte
        static const byte_span_t DUMMY_SIG_DER{ byte_span_t(DUMMY_SIG_DER_PUSH).subspan(2) };
        static const byte_span_t DUMMY_SIG_DER_LOW_R{ byte_span_t(DUMMY_SIG_DER_PUSH_LOW_R).subspan(2) };

        static inline byte_span_t dummy_sig(bool is_low_r) { return is_low_r ? DUMMY_SIG_LOW_R : DUMMY_SIG; }

        static inline byte_span_t dummy_sig_der(bool is_low_r)
        {
            return is_low_r ? DUMMY_SIG_DER_LOW_R : DUMMY_SIG_DER;
        }

        static inline byte_span_t dummy_sig_der_push(bool is_low_r)
        {
            return is_low_r ? DUMMY_SIG_DER_PUSH_LOW_R : DUMMY_SIG_DER_PUSH;
        }

        static const std::array<unsigned char, 3> OP_0_PREFIX = { { 0x00, 0x01, 0x00 } };

        static auto segwit_address(const network_parameters& net_params, byte_span_t bytes)
        {
            constexpr uint32_t flags = 0;
            const auto family = net_params.bech32_prefix();
            char* ret = 0;
            GDK_VERIFY(wally_addr_segwit_from_bytes(bytes.data(), bytes.size(), family.c_str(), flags, &ret));
            return make_string(ret);
        }

        static auto segwit_address_decode(const network_parameters& net_params, const std::string& addr)
        {
            constexpr uint32_t flags = 0;
            const auto family = net_params.bech32_prefix();
            std::vector<unsigned char> ret(WALLY_WITNESSSCRIPT_MAX_LEN);
            size_t written;
            bool valid = wally_addr_segwit_to_bytes(addr.c_str(), family.c_str(), flags, &ret[0], ret.size(), &written)
                == WALLY_OK;
            if (valid && ret[0] == OP_0) {
                // v0 (p2wpkh or p2wsh)
                valid = written == WALLY_SCRIPTPUBKEY_P2WSH_LEN || written == WALLY_SCRIPTPUBKEY_P2WPKH_LEN;
            } else if (valid && ret[0] == OP_1) {
                // v1 (p2tr).
                valid = written == WALLY_SCRIPTPUBKEY_P2TR_LEN;
            } else {
                valid = false; // Failed to parse or Unknown version
            }
            if (!valid) {
                throw user_error(res::id_invalid_address);
            }
            ret.resize(written);
            return ret;
        }

        static auto base58_address(unsigned char version, byte_span_t bytes)
        {
            std::array<unsigned char, HASH160_LEN + 1> addr_bytes;
            addr_bytes[0] = version;
            GDK_VERIFY(wally_hash160(bytes.data(), bytes.size(), addr_bytes.begin() + 1, HASH160_LEN));
            return base58check_from_bytes(addr_bytes);
        }

        // Note that if id_nonconfidential_addresses_not is returned in 'error', this
        // call still returns the resulting script. This behaviour is used by
        // add_tx_addressee_output when adding preblinded outputs (where is_blinded=true).
        static std::vector<unsigned char> output_script_for_address(
            const network_parameters& net_params, std::string address, std::string& error)
        {
            // bech32 is a vanilla bech32 address, blech32 is a confidential liquid address
            const bool is_bech32 = boost::istarts_with(address, net_params.bech32_prefix());
            const bool is_blech32 = net_params.is_liquid() && boost::istarts_with(address, net_params.blech32_prefix());
            const bool is_base58 = !is_blech32 && !is_bech32 && validate_base58check(address);

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
                    return segwit_address_decode(net_params, address);
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

    namespace address_type {
        const std::string p2pkh("p2pkh");
        const std::string p2wpkh("p2wpkh");
        const std::string p2sh_p2wpkh("p2sh-p2wpkh");
        const std::string p2sh("p2sh");
        const std::string p2wsh("p2wsh");
        const std::string csv("csv");
    } // namespace address_type

    bool address_type_is_segwit(const std::string& addr_type)
    {
        using namespace address_type;
        if (addr_type == csv || addr_type == p2wsh || addr_type == p2wpkh || addr_type == p2sh_p2wpkh) {
            return true;
        }
        if (addr_type == p2sh || addr_type == p2pkh) {
            return false;
        }
        GDK_RUNTIME_ASSERT_MSG(false, std::string("unknown address_type ") + addr_type);
        return false;
    }

    std::string address_type_from_script_type(uint32_t script_type)
    {
        switch (script_type) {
        case ga_p2sh_p2wsh_csv_fortified_out:
        case ga_redeem_p2sh_p2wsh_csv_fortified:
            return address_type::csv;
            break;
        case ga_p2sh_p2wsh_fortified_out:
        case ga_redeem_p2sh_p2wsh_fortified:
            return address_type::p2wsh;
            break;
        case ga_p2sh_fortified_out:
        case ga_redeem_p2sh_fortified:
            return address_type::p2sh;
            break;
        }
        return {};
    }

    uint32_t address_type_to_script_type(const std::string& addr_type)
    {
        if (addr_type == address_type::csv) {
            return ga_p2sh_p2wsh_csv_fortified_out;
        } else if (addr_type == address_type::p2wsh) {
            return ga_p2sh_p2wsh_fortified_out;
        }
        GDK_RUNTIME_ASSERT(addr_type == address_type::p2sh)
        return ga_p2sh_fortified_out;
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
            return segwit_address(net_params, scriptpubkey);
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

    std::vector<unsigned char> multisig_output_script_from_utxo(const network_parameters& net_params,
        ga_pubkeys& pubkeys, user_pubkeys& usr_pubkeys, user_pubkeys& recovery_pubkeys, const nlohmann::json& utxo)
    {
        using namespace address_type;
        const auto& addr_type = j_strref(utxo, "address_type");
        const auto subaccount = j_uint32ref(utxo, "subaccount");
        const auto pointer = j_uint32ref(utxo, "pointer");

        uint32_t subtype = 0;
        if (addr_type == csv) {
            // subtype indicates the number of csv blocks and must be one of the known bucket values
            subtype = utxo.at("subtype");
            const auto csv_buckets = net_params.csv_buckets();
            const auto csv_bucket_p = std::find(std::begin(csv_buckets), std::end(csv_buckets), subtype);
            GDK_RUNTIME_ASSERT_MSG(csv_bucket_p != csv_buckets.end(), "Unknown csv bucket");
        } else {
            GDK_RUNTIME_ASSERT(addr_type == p2wsh || addr_type == p2sh);
        }

        pub_key_t ga_pub_key;
        constexpr uint32_t default_addr_version = 1;
        if (j_uint32(utxo, "version").value_or(default_addr_version) == 0) {
            // Service keys for legacy version 0 addresses are not derived from the user's GA path
            ga_pub_key = h2b<EC_PUBLIC_KEY_LEN>(net_params.pub_key());
        } else {
            ga_pub_key = pubkeys.derive(subaccount, pointer);
        }
        const auto user_pub_key = usr_pubkeys.derive(subaccount, pointer);

        if (recovery_pubkeys.have_subaccount(subaccount)) {
            // 2of3
            const auto recovery_pub_key = recovery_pubkeys.derive(subaccount, pointer);
            return output_script(net_params, ga_pub_key, user_pub_key, recovery_pub_key, addr_type, subtype);
        }
        // 2of2
        return output_script(net_params, ga_pub_key, user_pub_key, {}, addr_type, subtype);
    }

    std::string get_address_from_utxo(session_impl& session, const nlohmann::json& utxo, bool verify_script)
    {
        using namespace address_type;
        const auto& net_params = session.get_network_parameters();
        const auto& addr_type = j_strref(utxo, "address_type");
        if (addr_type == p2sh_p2wpkh || addr_type == p2wpkh || addr_type == p2pkh) {
            const auto pub_key = session.pubkeys_from_utxo(utxo).at(0);
            if (addr_type == p2pkh) {
                return base58_address(net_params.btc_version(), pub_key);
            }
            const auto witness_program = witness_script(pub_key, WALLY_SCRIPT_HASH160);
            if (addr_type == p2sh_p2wpkh) {
                return base58_address(net_params.btc_p2sh_version(), witness_program);
            }
            return segwit_address(net_params, witness_program);
        }
        const auto out_script = session.output_script_from_utxo(utxo);
        if (verify_script) {
            // Verify the generated script must match the "script" element.
            // Used to validate scripts returned by the Green backend.
            // Once all sessions can generate addresses, the backend will
            // be simplified to not provide them. Hence, check for that here.
            if (auto script_hex = j_str(utxo, "script"); script_hex.has_value()) {
                GDK_RUNTIME_ASSERT(h2b(script_hex.value()) == out_script);
            }
        }
        if (addr_type == address_type::p2sh) {
            return base58_address(net_params.btc_p2sh_version(), out_script);
        }
        GDK_RUNTIME_ASSERT(addr_type == address_type::p2wsh || addr_type == address_type::csv);
        const auto witness_program = witness_script(out_script, WALLY_SCRIPT_SHA256);
        return base58_address(net_params.btc_p2sh_version(), witness_program);
    }

    static std::vector<unsigned char> scriptsig_multisig(byte_span_t prevout_script, byte_span_t user_sig,
        byte_span_t green_sig, uint32_t user_sighash_flags = WALLY_SIGHASH_ALL,
        uint32_t ga_sighash_flags = WALLY_SIGHASH_ALL)
    {
        const std::array<uint32_t, 2> sighash_flags = { { ga_sighash_flags, user_sighash_flags } };
        std::array<unsigned char, sizeof(ecdsa_sig_t) * 2> sigs;
        init_container(sigs, green_sig, user_sig);
        // OP_O [sig + sighash_flags] [sig + sighash_flags] [prevout_script]
        // 3 below allows for up to an OP_PUSHDATA2 prevout script size.
        std::vector<unsigned char> script;
        script.resize(1 + (EC_SIGNATURE_DER_MAX_LEN + 2) * 2 + 3 + prevout_script.size());
        size_t written;
        GDK_VERIFY(wally_scriptsig_multisig_from_bytes(prevout_script.data(), prevout_script.size(), sigs.data(),
            sigs.size(), sighash_flags.data(), sighash_flags.size(), 0, &script[0], script.size(), &written));
        GDK_RUNTIME_ASSERT(written <= script.size());
        script.resize(written);
        return script;
    }

    std::vector<unsigned char> scriptsig_multisig_for_backend(bool /*is_low_r*/,
        const std::vector<unsigned char>& prevout_script, const ecdsa_sig_t& user_sig, uint32_t user_sighash_flags)
    {
        const auto green_sig = dummy_sig(true); /* Green backend is always low-R */
        auto script = scriptsig_multisig(prevout_script, user_sig, green_sig, user_sighash_flags);

        // Replace the dummy sig with PUSH(0)
        const auto ga_push = dummy_sig_der_push(true);
        GDK_RUNTIME_ASSERT(std::search(script.begin(), script.end(), ga_push.begin(), ga_push.end()) == script.begin());
        auto suffix = gsl::make_span(script).subspan(ga_push.size());

        std::vector<unsigned char> backend_script(OP_0_PREFIX.size() + suffix.size());
        init_container(backend_script, OP_0_PREFIX, suffix);
        return backend_script;
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
        GDK_RUNTIME_ASSERT(!error.empty());
        auto& e = result["error"];
        if (overwrite || e.empty() || e.get<std::string>().empty()) {
            e = error;
        }
        if (!result.contains("transaction_inputs")) {
            // Callers expect to have transaction_inputs present even when an
            // error occurs. TODO: See if this can be removed
            result.emplace("transaction_inputs", std::vector<nlohmann::json>());
        }
    }

    amount add_tx_input(
        session_impl& session, nlohmann::json& result, Tx& tx, nlohmann::json& utxo, bool add_to_tx_inputs)
    {
        using namespace address_type;

        // Ensure this input hasn't been added before
        const auto txid = h2b_rev(j_strref(utxo, "txhash"));
        const auto vout = j_uint32ref(utxo, "pt_idx");
        GDK_RUNTIME_ASSERT(!tx.find_input_spending(txid, vout).has_value());

        const bool is_low_r = session.get_nonnull_signer()->supports_low_r();

        const uint32_t seq_default = session.is_rbf_enabled() ? 0xFFFFFFFD : 0xFFFFFFFE;
        const auto sequence = j_uint32(utxo, "sequence").value_or(seq_default);
        utxo["sequence"] = sequence;

        std::vector<unsigned char> script;
        witness_ptr witness;

        if (utxo.contains("script_sig") && utxo.contains("witness")) {
            // An external or already finalized input
            script = h2b(j_strref(utxo, "script_sig"));
            const auto& witness_items = j_arrayref(utxo, "witness");
            witness = witness_stack({}, witness_items.size());
            for (const auto& item : witness_items) {
                witness_stack_add(witness, { h2b(item) });
            }
        } else {
            const auto& addr_type = j_strref(utxo, "address_type");

            utxo_add_paths(session, utxo);

            // Populate the prevout script if missing so signing can use it later
            if (utxo.find("prevout_script") == utxo.end()) {
                utxo["prevout_script"] = b2h(session.output_script_from_utxo(utxo));
            }

            // Dummy sigs for fee estimation. User is low-R according to
            // the signer. Green is always low-R.
            const auto user_sig = dummy_sig(is_low_r);
            const auto user_der = dummy_sig_der(is_low_r);
            const auto green_sig = dummy_sig(true);
            const auto green_der = dummy_sig_der(true);

            if (addr_type == p2pkh || addr_type == p2sh_p2wpkh || addr_type == p2wpkh) {
                // Singlesig
                const auto pub_key = h2b(j_strref(utxo, "public_key"));
                if (addr_type == p2pkh) {
                    // Singlesig or sweep p2pkh
                    script = scriptsig_p2pkh_from_der(pub_key, user_der);
                } else {
                    // Singlesig segwit
                    witness = witness_stack({ user_der, pub_key });
                    if (addr_type == p2sh_p2wpkh) {
                        script = scriptsig_p2sh_p2wpkh_from_bytes(pub_key);
                    }
                    // For p2wpkh, the script is empty
                }
            } else {
                // Multisig
                const auto prevout_script = h2b(j_strref(utxo, "prevout_script"));

                if (addr_type == csv || addr_type == p2wsh) {
                    // Multisig segwit
                    if (addr_type == address_type::p2wsh) {
                        // p2sh-p2wsh has a preceeding OP_0 for OP_CHECKMULTISIG
                        witness = witness_stack({ byte_span_t{}, user_der, green_der, prevout_script });
                    } else {
                        witness = witness_stack({ user_der, green_der, prevout_script });
                    }
                    script.resize(3 + SHA256_LEN); // Dummy witness script
                } else {
                    // Multisig pre-segwit
                    GDK_RUNTIME_ASSERT(addr_type == p2sh);
                    script = scriptsig_multisig(prevout_script, user_sig, green_sig);
                }
            }
        }
        // Add the input to the tx
        tx.add_input(txid, vout, sequence, script, witness.get());
        if (add_to_tx_inputs) {
            result["transaction_inputs"].push_back(utxo);
        }
        return j_amountref(utxo);
    }

    void add_tx_user_signature(
        session_impl& /*session*/, const nlohmann::json& result, Tx& tx, size_t index, byte_span_t der, bool is_low_r)
    {
        using namespace address_type;
        const nlohmann::json& utxo = j_arrayref(result, "transaction_inputs").at(index);

        const auto& addr_type = j_strref(utxo, "address_type");
        if (addr_type == p2pkh || addr_type == p2sh_p2wpkh || addr_type == p2wpkh) {
            const auto pub_key = h2b(utxo.at("public_key"));

            if (addr_type == p2pkh) {
                // Singlesig (or sweep) p2pkh
                tx.set_input_script(index, scriptsig_p2pkh_from_der(pub_key, der));
                return;
            }
            // Singlesig segwit
            tx.set_input_witness(index, witness_stack({ der, pub_key }).get());
            if (addr_type == p2sh_p2wpkh) {
                tx.set_input_script(index, scriptsig_p2sh_p2wpkh_from_bytes(pub_key));
            } else {
                // for native segwit ensure the scriptsig is empty
                tx.set_input_script(index, byte_span_t());
            }
            return;
        }
        const auto script = h2b(utxo.at("prevout_script"));
        if (addr_type == csv || addr_type == p2wsh) {
            // Multisig segwit
            tx.set_input_witness(index, witness_stack({ der }).get());
            constexpr uint32_t flags = WALLY_SCRIPT_SHA256 | WALLY_SCRIPT_AS_PUSH;
            tx.set_input_script(index, witness_script(script, flags));
        } else {
            // Multisig pre-segwit
            GDK_RUNTIME_ASSERT(addr_type == p2sh);
            constexpr bool has_sighash_byte = true;
            const auto user_sig = ec_sig_from_der(der, has_sighash_byte);
            const uint32_t user_sighash_flags = der.back();
            auto scriptsig = scriptsig_multisig_for_backend(is_low_r, script, user_sig, user_sighash_flags);
            tx.set_input_script(index, scriptsig);
        }
    }

    std::string validate_tx_addressee(
        session_impl& session, const network_parameters& net_params, nlohmann::json& addressee)
    {
        const bool override_network = session.get_network_parameters().network() != net_params.network();
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
            j_asset(net_params, addressee);

            // Validate and convert the amount to satoshi, but only if we are
            // validating for the sessions network (i.e. we have the
            // corresponding prices available).
            if (!override_network) {
                try {
                    const auto satoshi = j_amountref(session.convert_amount(addressee));
                    addressee["satoshi"] = satoshi.value();
                    amount::strip_non_satoshi_keys(addressee);
                } catch (const user_error& ex) {
                    return ex.what();
                } catch (const std::exception& ex) {
                    return res::id_invalid_amount;
                }
            }

            if (is_liquid && !is_blinded) {
                // Fetch the blinding key from the confidential address
                pub_key_t blinding_key;
                if (boost::starts_with(address, blech32_prefix)) {
                    blinding_key = confidential_addr_segwit_to_ec_public_key(address, blech32_prefix);
                } else {
                    blinding_key = confidential_addr_to_ec_public_key(address, net_params.blinded_prefix());
                }
                addressee["blinding_key"] = b2h(blinding_key);
            }
        } catch (const std::exception& e) {
            return e.what();
        }
        return std::string();
    }

    static amount add_tx_output(
        const network_parameters& net_params, nlohmann::json& result, Tx& tx, const nlohmann::json& output)
    {
        std::string old_error = json_get_value(result, "error");
        const auto satoshi = j_amountref(output);
        std::string script_hex = output.at("scriptpubkey");
        std::vector<unsigned char> script;
        if (!script_hex.empty()) {
            script = h2b(script_hex);
        }
        if (!net_params.is_liquid()) {
            tx.add_output(satoshi.value(), script);
            return satoshi;
        }
        if (output.value("is_change", false)
            && json_get_value(result, "error") == res::id_nonconfidential_addresses_not) {
            // This is an unblinded change output, allow it
            result["error"] = old_error;
        }
        const size_t index = tx.get_num_outputs(); // Append to outputs
        const auto asset_id = j_asset(net_params, output);
        const auto asset_bytes = h2b_rev(asset_id, 0x1);
        const auto ct_value = tx_confidential_value_from_satoshi(satoshi.value());
        tx.add_elements_output_at(index, script, asset_bytes, ct_value, {}, {}, {});
        return satoshi;
    }

    void add_tx_addressee_output(session_impl& session, nlohmann::json& result, Tx& tx, nlohmann::json& addressee)
    {
        const auto& net_params = session.get_network_parameters();
        std::string address = addressee.at("address"); // Assume its a standard address
        const bool is_blinded = addressee.value("is_blinded", false);
        const auto asset_id_hex = j_asset(net_params, addressee);

        if (is_blinded) {
            // The case of an existing blinded output
            auto scriptpubkey = h2b(addressee.at("scriptpubkey"));
            const auto asset_id = h2b_rev(asset_id_hex);
            const auto satoshi = j_amountref(addressee);
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
                value_commitment = asset_value_commitment(satoshi.value(), vbf, asset_commitment);
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
            tx.add_elements_output_at(
                index, scriptpubkey, asset_commitment, value_commitment, nonce_commitment, surjectionproof, rangeproof);
            return;
        }

        if (!addressee.value("is_greedy", false)) {
            const auto satoshi = j_amountref(addressee);
            if (satoshi < session.get_dust_threshold(asset_id_hex)) {
                // Output is below the dust threshold. TODO: Allow 0 OP_RETURN.
                throw user_error(res::id_invalid_amount);
            }
        }
        add_tx_output(net_params, result, tx, addressee);
    }

    size_t add_tx_change_output(session_impl& session, nlohmann::json& result, Tx& tx, const std::string& asset_id)
    {
        const auto& net_params = session.get_network_parameters();
        auto& output = result.at("change_address").at(asset_id);
        output["is_change"] = true;
        if (net_params.is_liquid()) {
            output["asset_id"] = asset_id;
        }
        output["satoshi"] = 0;
        std::string error;
        const bool allow_unconfidential = true; // Change may not yet be blinded
        const auto spk = scriptpubkey_from_address(net_params, output.at("address"), allow_unconfidential);
        output["scriptpubkey"] = b2h(spk);
        add_tx_output(net_params, result, tx, output);
        return tx.get_num_outputs() - 1;
    }

    size_t add_tx_fee_output(session_impl& session, nlohmann::json& result, Tx& tx, amount::value_type satoshi)
    {
        const auto& net_params = session.get_network_parameters();
        nlohmann::json output{ { "satoshi", satoshi }, { "scriptpubkey", "" }, { "is_change", false },
            { "asset_id", net_params.get_policy_asset() } };
        add_tx_output(net_params, result, tx, output);
        return tx.get_num_outputs() - 1;
    }

    void update_tx_size_info(const network_parameters& net_params, const Tx& tx, nlohmann::json& result)
    {
        const bool valid = tx.get_num_inputs() != 0u && tx.get_num_outputs() != 0u;
        result["transaction"] = valid ? tx.to_hex() : std::string();
        const auto weight = tx.get_adjusted_weight(net_params);
        result["transaction_weight"] = valid ? weight : 0;
        const uint32_t tx_vsize = valid ? Tx::vsize_from_weight(weight) : 0;
        result["transaction_vsize"] = tx_vsize;
        result["transaction_version"] = tx.get_version();
        result["transaction_locktime"] = tx.get_locktime();
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

    std::optional<int> get_tx_change_index(nlohmann::json& result, const std::string& asset_id)
    {
        const auto change_address_p = result.find("change_address");
        if (change_address_p != result.end()) {
            const auto p = change_address_p->find(asset_id);
            if (p != change_address_p->end()) {
                const std::string spk = p->at("scriptpubkey");
                auto& transaction_outputs = result.at("transaction_outputs");
                for (size_t i = 0; i < transaction_outputs.size(); ++i) {
                    if (transaction_outputs.at(i).at("scriptpubkey") == spk) {
                        return { static_cast<int>(i) };
                    }
                }
            }
        }
        return {};
    }

    bool are_tx_outputs_unique(const nlohmann::json& result, const std::string& spk)
    {
        std::set<std::string> spks;
        // Addressee
        for (const auto& addressee : result.at("addressees")) {
            if (!spks.insert(addressee.at("scriptpubkey").get<std::string>()).second) {
                return false;
            }
        }

        // Change output
        if (const auto p = result.find("change_address"); p != result.end()) {
            for (const auto& it : p->items()) {
                if (!spks.insert(it.value().at("scriptpubkey").get<std::string>()).second) {
                    return false;
                }
            }
        }
        if (!spk.empty() && !spks.insert(spk).second) {
            return false;
        }
        return true;
    }

    static const nlohmann::json& get_tx_output_source(const nlohmann::json& result, const Tx& tx, size_t i)
    {
        const auto& o = tx.get_output(i);
        const std::string spk = b2h({ o.script, o.script_len });
        auto&& match_spk = [&spk](const auto& a) { return a.at("scriptpubkey") == spk; };
        const auto& addressees = result.at("addressees");

        // Addressee
        auto p = std::find_if(addressees.begin(), addressees.end(), match_spk);
        if (p != addressees.end()) {
            return *p;
        }
        // Change output
        for (const auto& it : result.at("change_address").items()) {
            if (match_spk(it.value())) {
                return it.value();
            }
        }
        throw user_error("No matching addressee or change for transaction output");
    }

    static void update_summary(nlohmann::json& summary, const std::string& asset_id, const nlohmann::json& src,
        const char* key, amount::signed_value_type multiplier = 1)
    {
        auto total = summary.value(asset_id, amount::signed_value_type(0));
        total += j_amountref(src, key).signed_value() * multiplier;
        summary[asset_id] = total;
    }

    void update_tx_info(session_impl& session, const Tx& tx, nlohmann::json& result)
    {
        const auto& net_params = session.get_network_parameters();
        update_tx_size_info(net_params, tx, result);

        const bool is_liquid = net_params.is_liquid();
        const auto policy_asset = net_params.get_policy_asset();

        if (!tx.get_num_inputs() || !tx.get_num_outputs() || !j_str_is_empty(result, "error")) {
            // The tx is not valid/is incomplete
            result["transaction_outputs"] = nlohmann::json::array_t();
            return;
        }

        if (result.contains("addressees")) {
            // Populate any missing output data from our addressees
            nlohmann::json::array_t outputs;
            outputs.reserve(tx.get_num_outputs());
            nlohmann::json empty;

            for (size_t i = 0; i < tx.get_num_outputs(); ++i) {
                const auto& o = tx.get_output(i);
                const bool is_fee = !o.script;
                const auto& src = is_fee ? empty : get_tx_output_source(result, tx, i);

                auto addressee = nlohmann::json::object();
                GDK_RUNTIME_ASSERT(!is_liquid || o.asset);
                const bool is_blinded = is_liquid && *o.asset != 1 && o.value && *o.value != 1;
                std::string asset_id;

                if (is_blinded) {
                    GDK_RUNTIME_ASSERT(!is_fee && src.at("index") == i);
                    asset_id = src.at("asset_id");
                } else if (is_liquid) {
                    asset_id = b2h_rev(gsl::make_span(o.asset, o.asset_len).subspan(1));
                    if (is_fee) {
                        GDK_RUNTIME_ASSERT(asset_id == policy_asset);
                    } else {
                        GDK_RUNTIME_ASSERT(src.at("asset_id") == asset_id);
                    }
                } else {
                    asset_id = policy_asset;
                }

                amount::value_type satoshi = o.satoshi;
                if (is_liquid) {
                    GDK_RUNTIME_ASSERT(o.value);
                    if (*o.value == 1) {
                        satoshi = tx_confidential_value_to_satoshi({ o.value, o.value_len });
                    } else {
                        GDK_RUNTIME_ASSERT(is_blinded);
                        satoshi = j_amountref(src).value();
                    }
                }
                // FIXME: Change addresses do not have their satoshi values set
                GDK_RUNTIME_ASSERT(is_fee || src.value("is_change", false) || j_amountref(src) == satoshi);

                auto spk = is_fee ? std::string() : b2h({ o.script, o.script_len });
                if (!is_fee) {
                    GDK_RUNTIME_ASSERT(spk == src.at("scriptpubkey"));
                }
                nlohmann::json output{ { "satoshi", satoshi }, { "scriptpubkey", std::move(spk) } };
                if (is_liquid) {
                    output.emplace("asset_id", asset_id);
                }

                if (!is_fee) {
                    // Add the fields from the source addressee/change output
                    output.insert(src.begin(), src.end());
                }
                outputs.emplace_back(std::move(output));
            }
            result["transaction_outputs"] = std::move(outputs);
        }

        // Set "satoshi" per-asset elements to the net effect on the wallet
        auto& summary = result["satoshi"];
        summary = { { policy_asset, 0u } };
        bool have_input_paying_fee = false;
        if (auto p = result.find("transaction_inputs"); p != result.end()) {
            for (const auto& input : *p) {
                if (input.contains("address_type") && !input.contains("private_key")) {
                    // Wallet input
                    const auto asset_id = j_asset(net_params, input);
                    update_summary(summary, asset_id, input, "satoshi", -1);
                    have_input_paying_fee |= asset_id == policy_asset;
                }
            }
        }
        for (const auto& output : result.at("transaction_outputs")) {
            if (output.contains("address_type") && !j_str_is_empty(output, "scriptpubkey")) {
                // Non-fee output to a wallet address
                const auto asset_id = j_asset(net_params, output);
                update_summary(summary, asset_id, output, "satoshi");
            }
        }
        if (have_input_paying_fee) {
            // Remove fee and network fee from the net effect.
            update_summary(summary, policy_asset, result, "fee");
            update_summary(summary, policy_asset, result, "network_fee");
        }
    }

    bool is_wallet_utxo(const nlohmann::json& utxo)
    {
        return j_str_is_empty(utxo, "private_key") && !j_str_is_empty(utxo, "address_type");
    }

    std::set<uint32_t> get_tx_subaccounts(const nlohmann::json& details)
    {
        std::set<uint32_t> ret;
        if (auto utxos_p = details.find("transaction_inputs"); utxos_p != details.end()) {
            for (auto& utxo : *utxos_p) {
                if (is_wallet_utxo(utxo)) {
                    ret.insert(utxo.at("subaccount").get<uint32_t>());
                }
            }
        }
        if (auto utxos_p = details.find("utxos"); utxos_p != details.end()) {
            for (auto& asset : utxos_p->items()) {
                if (asset.key() != "error") {
                    for (auto& utxo : asset.value()) {
                        if (is_wallet_utxo(utxo)) {
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
} // namespace sdk
} // namespace ga
