#include "ga_wally.hpp"
#include "boost_wrapper.hpp"
#include "memory.hpp"
#include "utils.hpp"

namespace ga {
namespace sdk {

    std::array<unsigned char, HASH160_LEN> hash160(byte_span_t data)
    {
        std::array<unsigned char, HASH160_LEN> ret;
        GDK_VERIFY(wally_hash160(data.data(), data.size(), ret.data(), ret.size()));
        return ret;
    }

    std::array<unsigned char, SHA256_LEN> sha256(byte_span_t data)
    {
        std::array<unsigned char, SHA256_LEN> ret;
        GDK_VERIFY(wally_sha256(data.data(), data.size(), ret.data(), ret.size()));
        return ret;
    }

    std::array<unsigned char, SHA256_LEN> sha256d(byte_span_t data)
    {
        std::array<unsigned char, SHA256_LEN> ret;
        GDK_VERIFY(wally_sha256d(data.data(), data.size(), ret.data(), ret.size()));
        return ret;
    }

    std::array<unsigned char, SHA512_LEN> sha512(byte_span_t data)
    {
        std::array<unsigned char, SHA512_LEN> ret;
        GDK_VERIFY(wally_sha512(data.data(), data.size(), ret.data(), ret.size()));
        return ret;
    }

    std::array<unsigned char, HMAC_SHA256_LEN> hmac_sha256(byte_span_t key, byte_span_t data)
    {
        std::array<unsigned char, HMAC_SHA256_LEN> ret;
        GDK_VERIFY(wally_hmac_sha256(key.data(), key.size(), data.data(), data.size(), ret.data(), ret.size()));
        return ret;
    }

    std::array<unsigned char, HMAC_SHA512_LEN> hmac_sha512(byte_span_t key, byte_span_t data)
    {
        std::array<unsigned char, HMAC_SHA512_LEN> ret;
        GDK_VERIFY(wally_hmac_sha512(key.data(), key.size(), data.data(), data.size(), ret.data(), ret.size()));
        return ret;
    }

    pbkdf2_hmac512_t pbkdf2_hmac_sha512(byte_span_t password, byte_span_t salt, uint32_t cost)
    {
        const int32_t flags = 0;
        pbkdf2_hmac512_t ret;
        GDK_VERIFY(wally_pbkdf2_hmac_sha512(
            password.data(), password.size(), salt.data(), salt.size(), flags, cost, ret.data(), ret.size()));
        return ret;
    }

    std::array<unsigned char, PBKDF2_HMAC_SHA256_LEN> pbkdf2_hmac_sha512_256(
        byte_span_t password, byte_span_t salt, uint32_t cost)
    {
        auto tmp = pbkdf2_hmac_sha512(password, salt, cost);
        std::array<unsigned char, PBKDF2_HMAC_SHA256_LEN> out;
        std::copy(std::begin(tmp), std::begin(tmp) + out.size(), std::begin(out));
        wally_bzero(tmp.data(), tmp.size());
        return out;
    }

    //
    // BIP 32
    //
    std::array<unsigned char, BIP32_SERIALIZED_LEN> bip32_key_serialize(const ext_key& hdkey, uint32_t flags)
    {
        std::array<unsigned char, BIP32_SERIALIZED_LEN> ret;
        GDK_VERIFY(::bip32_key_serialize(&hdkey, flags, ret.data(), ret.size()));
        return ret;
    }

    wally_ext_key_ptr bip32_key_unserialize_alloc(byte_span_t data)
    {
        ext_key* p;
        GDK_VERIFY(::bip32_key_unserialize_alloc(data.data(), data.size(), &p));
        return wally_ext_key_ptr{ p };
    }

    ext_key bip32_public_key_from_parent_path(const ext_key& parent, uint32_span_t path)
    {
        const uint32_t flags = BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH;
        ext_key key;
        GDK_VERIFY(::bip32_key_from_parent_path(&parent, path.data(), path.size(), flags, &key));
        return key;
    }

    ext_key bip32_public_key_from_parent(const ext_key& parent, uint32_t pointer)
    {
        return bip32_public_key_from_parent_path(parent, gsl::make_span(&pointer, 1));
    }

    wally_ext_key_ptr bip32_public_key_from_bip32_xpub(const std::string& bip32_xpub)
    {
        return bip32_key_unserialize_alloc(base58check_to_bytes(bip32_xpub));
    }

    wally_ext_key_ptr bip32_key_from_parent_path_alloc(
        const wally_ext_key_ptr& parent, uint32_span_t path, uint32_t flags)
    {
        ext_key* p;
        GDK_VERIFY(::bip32_key_from_parent_path_alloc(parent.get(), path.data(), path.size(), flags, &p));
        return wally_ext_key_ptr{ p };
    }

    wally_ext_key_ptr bip32_key_init_alloc(uint32_t version, uint32_t depth, uint32_t child_num, byte_span_t chain_code,
        byte_span_t public_key, byte_span_t private_key, byte_span_t hash, byte_span_t parent)
    {
        ext_key* p;
        GDK_VERIFY(::bip32_key_init_alloc(version, depth, child_num, chain_code.data(), chain_code.size(),
            public_key.data(), public_key.size(), private_key.data(), private_key.size(), hash.data(), hash.size(),
            parent.data(), parent.size(), &p));
        return wally_ext_key_ptr{ p };
    }

    wally_ext_key_ptr bip32_key_from_seed_alloc(byte_span_t seed, uint32_t version, uint32_t flags)
    {
        ext_key* p;
        GDK_VERIFY(::bip32_key_from_seed_alloc(seed.data(), seed.size(), version, flags, &p));
        return wally_ext_key_ptr{ p };
    }

    // BIP 38
    std::vector<unsigned char> bip38_raw_to_private_key(byte_span_t priv_key, byte_span_t passphrase, uint32_t flags)
    {
        std::vector<unsigned char> private_key(EC_PRIVATE_KEY_LEN);
        GDK_VERIFY(::bip38_raw_to_private_key(priv_key.data(), priv_key.size(), passphrase.data(), passphrase.size(),
            flags, private_key.data(), private_key.size()));
        return private_key;
    }

    size_t bip38_raw_get_flags(byte_span_t priv_key)
    {
        size_t flags;
        GDK_VERIFY(::bip38_raw_get_flags(priv_key.data(), priv_key.size(), &flags));
        return flags;
    }

    //
    // Scripts
    //
    void scriptsig_multisig_from_bytes(
        byte_span_t script, byte_span_t signatures, uint32_span_t sighashes, std::vector<unsigned char>& out)
    {
        const uint32_t flags = 0;
        size_t written;
        GDK_VERIFY(wally_scriptsig_multisig_from_bytes(script.data(), script.size(), signatures.data(),
            signatures.size(), sighashes.data(), sighashes.size(), flags, &out[0], out.size(), &written));
        GDK_RUNTIME_ASSERT(written <= out.size());
        out.resize(written);
    }

    std::vector<unsigned char> scriptsig_p2pkh_from_der(byte_span_t public_key, byte_span_t sig)
    {
        std::vector<unsigned char> out(2 + public_key.size() + 2 + sig.size());
        size_t written;
        GDK_VERIFY(wally_scriptsig_p2pkh_from_der(
            public_key.data(), public_key.size(), sig.data(), sig.size(), out.data(), out.size(), &written));
        GDK_RUNTIME_ASSERT(written <= out.size());
        out.resize(written);
        return out;
    }

    void scriptpubkey_csv_2of2_then_1_from_bytes(
        byte_span_t keys, uint32_t csv_blocks, bool optimize, std::vector<unsigned char>& out)
    {
        GDK_RUNTIME_ASSERT(!out.empty());
        const uint32_t flags = 0;
        size_t written;
        auto fn = optimize ? wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt
                           : wally_scriptpubkey_csv_2of2_then_1_from_bytes;
        GDK_VERIFY(fn(keys.data(), keys.size(), csv_blocks, flags, &out[0], out.size(), &written));
        GDK_RUNTIME_ASSERT(written <= out.size());
        out.resize(written);
    }

    void scriptpubkey_csv_2of3_then_2_from_bytes(byte_span_t keys, uint32_t csv_blocks, std::vector<unsigned char>& out)
    {
        GDK_RUNTIME_ASSERT(!out.empty());
        const uint32_t flags = 0;
        size_t written;
        GDK_VERIFY(wally_scriptpubkey_csv_2of3_then_2_from_bytes(
            keys.data(), keys.size(), csv_blocks, flags, &out[0], out.size(), &written));
        GDK_RUNTIME_ASSERT(written <= out.size());
        out.resize(written);
    }

    uint32_t get_csv_blocks_from_csv_redeem_script(byte_span_t redeem_script)
    {
        size_t csv_blocks_offset;

        if (redeem_script.at(0) == OP_DEPTH && redeem_script.at(1) == OP_1SUB && redeem_script.at(2) == OP_IF) {
            // 2of2 redeem script, with csv_blocks at:
            // OP_DEPTH OP_1SUB OP_IF <main_pubkey> OP_CHECKSIGVERIFY OP_ELSE <csv_blocks>
            csv_blocks_offset = 1 + 1 + 1 + (EC_PUBLIC_KEY_LEN + 1) + 1 + 1;
        } else if (redeem_script.at(0) == EC_PUBLIC_KEY_LEN
            && redeem_script.at(EC_PUBLIC_KEY_LEN + 1) == OP_CHECKSIGVERIFY
            && redeem_script.at(EC_PUBLIC_KEY_LEN + 2) == EC_PUBLIC_KEY_LEN
            && redeem_script.at(EC_PUBLIC_KEY_LEN * 2 + 3) == OP_CHECKSIG
            && redeem_script.at(EC_PUBLIC_KEY_LEN * 2 + 4) == OP_IFDUP) {
            // 2of2 optimized redeem script, with csv_blocks at:
            // <recovery_pubkey> OP_CHECKSIGVERIFY <main_pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF <csv_blocks>
            csv_blocks_offset = (EC_PUBLIC_KEY_LEN + 1) + 1 + (EC_PUBLIC_KEY_LEN + 1) + 1 + 1 + 1;
        } else {
            GDK_RUNTIME_ASSERT_MSG(false, "Invalid CSV redeem script");
            __builtin_unreachable();
        }
        // TODO: Move script integer parsing to wally and generalize
        size_t len = redeem_script.at(csv_blocks_offset);
        GDK_RUNTIME_ASSERT(len <= 4);
        // Negative CSV blocks are not allowed
        GDK_RUNTIME_ASSERT((redeem_script.at(csv_blocks_offset + len) & 0x80) == 0);

        uint32_t csv_blocks = 0;
        for (size_t i = 0; i < len; ++i) {
            uint32_t b = redeem_script.at(csv_blocks_offset + 1 + i);
            csv_blocks |= (b << (8 * i));
        }
        return csv_blocks;
    }

    std::vector<ecdsa_sig_t> get_sigs_from_multisig_script_sig(byte_span_t script_sig)
    {
        constexpr bool has_sighash = true;
        size_t offset = 0;
        size_t push_len = 0;
        // OP_0 <ga_sig> <user_sig> <redeem_script>

        GDK_RUNTIME_ASSERT(script_sig.at(offset) == OP_0);
        ++offset;

        push_len = script_sig.at(offset);
        GDK_RUNTIME_ASSERT(push_len <= EC_SIGNATURE_DER_MAX_LEN + 1);
        ++offset;
        GDK_RUNTIME_ASSERT(static_cast<size_t>(script_sig.size()) >= offset + push_len);
        const ecdsa_sig_t ga_sig = ec_sig_from_der(script_sig.subspan(offset, push_len), has_sighash);
        offset += push_len;

        push_len = script_sig.at(offset);
        GDK_RUNTIME_ASSERT(push_len <= EC_SIGNATURE_DER_MAX_LEN + 1);
        ++offset;
        GDK_RUNTIME_ASSERT(static_cast<size_t>(script_sig.size()) >= offset + push_len);
        const ecdsa_sig_t user_sig = ec_sig_from_der(script_sig.subspan(offset, push_len), has_sighash);

        return std::vector<ecdsa_sig_t>({ ga_sig, user_sig });
    }

    void scriptpubkey_multisig_from_bytes(byte_span_t keys, uint32_t threshold, std::vector<unsigned char>& out)
    {
        GDK_RUNTIME_ASSERT(!out.empty());
        const uint32_t flags = 0;
        size_t written;
        GDK_VERIFY(wally_scriptpubkey_multisig_from_bytes(
            keys.data(), keys.size(), threshold, flags, &out[0], out.size(), &written));
        GDK_RUNTIME_ASSERT(written <= out.size());
        out.resize(written);
    }

    std::vector<unsigned char> scriptpubkey_p2pkh_from_hash160(byte_span_t hash)
    {
        GDK_RUNTIME_ASSERT(hash.size() == HASH160_LEN);
        size_t written;
        std::vector<unsigned char> ret(WALLY_SCRIPTPUBKEY_P2PKH_LEN);
        GDK_VERIFY(wally_scriptpubkey_p2pkh_from_bytes(hash.data(), hash.size(), 0, &ret[0], ret.size(), &written));
        GDK_RUNTIME_ASSERT(written == WALLY_SCRIPTPUBKEY_P2PKH_LEN);
        return ret;
    }

    std::vector<unsigned char> scriptpubkey_p2sh_from_hash160(byte_span_t hash)
    {
        GDK_RUNTIME_ASSERT(hash.size() == HASH160_LEN);
        size_t written;
        std::vector<unsigned char> ret(WALLY_SCRIPTPUBKEY_P2SH_LEN);
        GDK_VERIFY(wally_scriptpubkey_p2sh_from_bytes(hash.data(), hash.size(), 0, &ret[0], ret.size(), &written));
        GDK_RUNTIME_ASSERT(written == WALLY_SCRIPTPUBKEY_P2SH_LEN);
        return ret;
    }

    std::vector<unsigned char> witness_program_from_bytes(byte_span_t script, uint32_t flags)
    {
        size_t written;
        std::vector<unsigned char> ret(WALLY_WITNESSSCRIPT_MAX_LEN);
        GDK_VERIFY(
            wally_witness_program_from_bytes(script.data(), script.size(), flags, &ret[0], ret.size(), &written));
        GDK_RUNTIME_ASSERT(written <= ret.size());
        ret.resize(written);
        return ret;
    }

    std::array<unsigned char, SHA256_LEN> format_bitcoin_message_hash(byte_span_t message)
    {
        const uint32_t flags = BITCOIN_MESSAGE_FLAG_HASH;
        size_t written;
        std::array<unsigned char, SHA256_LEN> ret;
        GDK_VERIFY(
            wally_format_bitcoin_message(message.data(), message.size(), flags, ret.data(), ret.size(), &written));
        GDK_RUNTIME_ASSERT(written == ret.size());
        return ret;
    }

    std::string electrum_script_hash_hex(byte_span_t script_bytes) { return b2h_rev(sha256(script_bytes)); }

    void scrypt(byte_span_t password, byte_span_t salt, uint32_t cost, uint32_t block_size, uint32_t parallelism,
        std::vector<unsigned char>& out)
    {
        GDK_RUNTIME_ASSERT(!out.empty());
        GDK_VERIFY(wally_scrypt(password.data(), password.size(), salt.data(), salt.size(), cost, block_size,
            parallelism, &out[0], out.size()));
    }

    std::string bip39_mnemonic_from_bytes(byte_span_t data)
    {
        char* s;
        GDK_VERIFY(::bip39_mnemonic_from_bytes(nullptr, data.data(), data.size(), &s));
        if (::bip39_mnemonic_validate(nullptr, s) != GA_OK) {
            wally_free_string(s);
            // This should only be possible with bad hardware/cosmic rays
            GDK_RUNTIME_ASSERT_MSG(false, "Mnemonic creation failed!");
        }
        return make_string(s);
    }

    void bip39_mnemonic_validate(const std::string& mnemonic)
    {
        GDK_VERIFY(::bip39_mnemonic_validate(nullptr, mnemonic.c_str()));
    }

    std::vector<unsigned char> bip39_mnemonic_to_seed(const std::string& mnemonic, const std::string& password)
    {
        GDK_VERIFY(::bip39_mnemonic_validate(nullptr, mnemonic.c_str()));
        size_t written;
        std::vector<unsigned char> ret(BIP39_SEED_LEN_512); // FIXME: secure_array
        GDK_VERIFY(::bip39_mnemonic_to_seed(
            mnemonic.c_str(), password.empty() ? nullptr : password.c_str(), &ret[0], ret.size(), &written));
        return ret;
    }

    std::vector<unsigned char> bip39_mnemonic_to_bytes(const std::string& mnemonic)
    {
        size_t written;
        std::vector<unsigned char> entropy(BIP39_ENTROPY_LEN_288); // FIXME: secure_array
        GDK_VERIFY(::bip39_mnemonic_to_bytes(nullptr, mnemonic.data(), entropy.data(), entropy.size(), &written));
        GDK_RUNTIME_ASSERT(
            written == BIP39_ENTROPY_LEN_128 || written == BIP39_ENTROPY_LEN_256 || written == BIP39_ENTROPY_LEN_288);
        entropy.resize(written);
        return entropy;
    }

    //
    // Strings/Addresses
    //
    std::string b2h(byte_span_t data)
    {
        char* ret;
        GDK_VERIFY(wally_hex_from_bytes(data.data(), data.size(), &ret));
        return make_string(ret);
    }

    std::string b2h_rev(byte_span_t data)
    {
        char* ret;
        std::vector<unsigned char> buff(data.rbegin(), data.rend());
        GDK_VERIFY(wally_hex_from_bytes(buff.data(), buff.size(), &ret));
        return make_string(ret);
    }

    static auto h2b(const char* hex, size_t siz, bool rev, uint8_t prefix = 0)
    {
        GDK_RUNTIME_ASSERT(hex != nullptr && siz != 0);
        size_t written;
        const size_t bytes_siz = siz / 2;
        std::vector<unsigned char> buff(bytes_siz + (prefix != 0 ? 1 : 0));
        auto buff_data = buff.data() + (prefix != 0 ? 1 : 0);
        GDK_VERIFY(wally_hex_to_bytes(hex, buff_data, bytes_siz, &written));
        GDK_RUNTIME_ASSERT(written == bytes_siz);
        if (rev) {
            std::reverse(buff_data, buff_data + bytes_siz);
        }
        if (prefix != 0) {
            buff[0] = prefix;
        }
        return buff;
    }

    std::vector<unsigned char> h2b(const char* hex) { return h2b(hex, strlen(hex), false); }
    std::vector<unsigned char> h2b(const std::string& hex) { return h2b(hex.data(), hex.size(), false); }
    std::vector<unsigned char> h2b(const std::string& hex, uint8_t prefix)
    {
        return h2b(hex.data(), hex.size(), false, prefix);
    }

    std::vector<unsigned char> h2b_rev(const char* hex) { return h2b(hex, strlen(hex), true); }
    std::vector<unsigned char> h2b_rev(const std::string& hex) { return h2b(hex.data(), hex.size(), true); }
    std::vector<unsigned char> h2b_rev(const std::string& hex, uint8_t prefix)
    {
        return h2b(hex.data(), hex.size(), true, prefix);
    }

    bool validate_hex(const std::string& hex, size_t len)
    {
        try {
            return h2b(hex).size() == len;
        } catch (const std::exception&) {
            // Fall through
        }
        return false;
    }

    std::vector<unsigned char> addr_segwit_v0_to_bytes(const std::string& addr, const std::string& family)
    {
        const uint32_t flags = 0;
        size_t written;
        std::vector<unsigned char> ret(WALLY_SCRIPTPUBKEY_P2WSH_LEN);
        GDK_VERIFY(wally_addr_segwit_to_bytes(addr.c_str(), family.c_str(), flags, &ret[0], ret.size(), &written));
        GDK_RUNTIME_ASSERT(written == WALLY_SCRIPTPUBKEY_P2WSH_LEN || written == WALLY_SCRIPTPUBKEY_P2WPKH_LEN);
        GDK_RUNTIME_ASSERT(ret[0] == 0); // Must be a segwit v0 script
        ret.resize(written);
        return ret;
    }

    std::string public_key_to_p2pkh_addr(unsigned char btc_version, byte_span_t public_key)
    {
        std::array<unsigned char, HASH160_LEN + 1> addr;
        GDK_VERIFY(wally_ec_public_key_verify(public_key.data(), public_key.size()));
        const auto hash = hash160(public_key);
        addr[0] = btc_version;
        std::copy(hash.begin(), hash.end(), addr.begin() + 1);
        return base58check_from_bytes(addr);
    }

    std::string base58check_from_bytes(byte_span_t data)
    {
        char* ret;
        GDK_VERIFY(wally_base58_from_bytes(data.data(), data.size(), BASE58_FLAG_CHECKSUM, &ret));
        return make_string(ret);
    }

    std::vector<unsigned char> base58check_to_bytes(const std::string& base58)
    {
        size_t written;
        GDK_VERIFY(wally_base58_get_length(base58.data(), &written));
        std::vector<unsigned char> ret(written);
        GDK_VERIFY(wally_base58_to_bytes(base58.data(), BASE58_FLAG_CHECKSUM, &ret[0], ret.size(), &written));
        GDK_RUNTIME_ASSERT(written <= ret.size());
        ret.resize(written);
        return ret;
    }

    wally_string_ptr base64_string_from_bytes(byte_span_t bytes)
    {
        char* output = nullptr;
        GDK_VERIFY(wally_base64_from_bytes(bytes.data(), bytes.size(), 0, &output));
        return wally_string_ptr(output);
    }

    std::string base64_from_bytes(byte_span_t bytes)
    {
        auto ret = base64_string_from_bytes(bytes);
        return std::string(ret.get());
    }

    std::vector<unsigned char> base64_to_bytes(const std::string& base64)
    {
        size_t written;
        GDK_VERIFY(wally_base64_get_maximum_length(base64.data(), 0, &written));
        std::vector<unsigned char> ret(written);
        GDK_VERIFY(wally_base64_to_bytes(base64.data(), 0, &ret[0], ret.size(), &written));
        GDK_RUNTIME_ASSERT(written <= ret.size());
        ret.resize(written);
        return ret;
    }

    //
    // Signing/Encryption
    //
    void aes(byte_span_t key, byte_span_t data, uint32_t flags, std::vector<unsigned char>& out)
    {
        GDK_RUNTIME_ASSERT(!out.empty());
        GDK_VERIFY(wally_aes(key.data(), key.size(), data.data(), data.size(), flags, &out[0], out.size()));
    }

    void aes_cbc(byte_span_t key, byte_span_t iv, byte_span_t data, uint32_t flags, std::vector<unsigned char>& out)
    {
        size_t written;
        GDK_RUNTIME_ASSERT(!out.empty());
        GDK_VERIFY(wally_aes_cbc(key.data(), key.size(), iv.data(), iv.size(), data.data(), data.size(), flags, &out[0],
            out.size(), &written));
        GDK_RUNTIME_ASSERT(written <= out.size());
        out.resize(written);
    }

    ecdsa_sig_t ec_sig_from_bytes(byte_span_t private_key, byte_span_t hash, uint32_t flags)
    {
        ecdsa_sig_t ret;
        GDK_VERIFY(wally_ec_sig_from_bytes(
            private_key.data(), private_key.size(), hash.data(), hash.size(), flags, ret.data(), ret.size()));
        return ret;
    }

    std::vector<unsigned char> ec_sig_to_der(byte_span_t sig, bool sighash)
    {
        std::vector<unsigned char> der(EC_SIGNATURE_DER_MAX_LEN + (sighash ? 1 : 0));
        size_t written;
        GDK_VERIFY(wally_ec_sig_to_der(sig.data(), sig.size(), der.data(), der.size(), &written));
        GDK_RUNTIME_ASSERT(written <= der.size());
        der.resize(written);
        if (sighash) {
            der.push_back(WALLY_SIGHASH_ALL);
        }
        return der;
    }

    ecdsa_sig_t ec_sig_from_der(byte_span_t der, bool sighash)
    {
        ecdsa_sig_t ret;
        GDK_VERIFY(wally_ec_sig_from_der(der.data(), der.size() - (sighash ? 1 : 0), ret.data(), ret.size()));
        return ret;
    }

    bool ec_sig_verify(byte_span_t public_key, byte_span_t message_hash, byte_span_t sig, uint32_t flags)
    {
        return wally_ec_sig_verify(public_key.data(), public_key.size(), message_hash.data(), message_hash.size(),
                   flags, sig.data(), sig.size())
            == WALLY_OK;
    }

    std::vector<unsigned char> ec_public_key_from_private_key(byte_span_t private_key)
    {
        std::vector<unsigned char> ret(EC_PUBLIC_KEY_LEN);
        GDK_VERIFY(
            wally_ec_public_key_from_private_key(private_key.data(), private_key.size(), ret.data(), ret.size()));
        return ret;
    }

    std::vector<unsigned char> ec_public_key_decompress(byte_span_t public_key)
    {
        std::vector<unsigned char> ret(EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
        GDK_VERIFY(wally_ec_public_key_decompress(public_key.data(), public_key.size(), ret.data(), ret.size()));
        return ret;
    }

    std::pair<std::vector<unsigned char>, bool> to_private_key_bytes(
        const std::string& priv_key, const std::string& passphrase, bool mainnet)
    {
        if (boost::algorithm::starts_with(priv_key, "xprv") || boost::algorithm::starts_with(priv_key, "tprv")) {
            // BIP 32 Serialized private key
            // TODO: Support scanning for children under BIP44 paths
            ext_key master;
            GDK_VERIFY(bip32_key_from_base58(priv_key.c_str(), &master));
            std::vector<unsigned char> ret(master.priv_key + 1, master.priv_key + 1 + EC_PRIVATE_KEY_LEN);
            wally_bzero(&master, sizeof(master));
            constexpr bool compressed = false;
            return { ret, compressed };
        }

        // FIXME: Add wally constants for the WIF base58 lengths
        if (priv_key.size() == 51u || priv_key.size() == 52u) {
            // WIF
            const bool compressed = priv_key.size() == 52u;
            std::vector<unsigned char> priv_key_bytes(EC_PRIVATE_KEY_LEN);
            GDK_VERIFY(wally_wif_to_bytes(priv_key.c_str(), mainnet ? 0x80 : 0xef,
                compressed ? WALLY_WIF_FLAG_COMPRESSED : WALLY_WIF_FLAG_UNCOMPRESSED, priv_key_bytes.data(),
                priv_key_bytes.size()));
            return { priv_key_bytes, compressed };
        }

        // BIP38
        GDK_RUNTIME_ASSERT(priv_key.size() == 58);
        auto bytes = base58check_to_bytes(priv_key);
        const size_t flags = bip38_raw_get_flags(bytes);
        const bool compressed = (flags & BIP38_KEY_COMPRESSED) != 0;
        return { bip38_raw_to_private_key(gsl::make_span(bytes), ustring_span(passphrase),
                     flags | (mainnet ? BIP38_KEY_MAINNET : BIP38_KEY_TESTNET)),
            compressed };
    }

    bool ec_private_key_verify(byte_span_t bytes)
    {
        return wally_ec_private_key_verify(bytes.data(), bytes.size()) == WALLY_OK;
    }

    std::pair<priv_key_t, std::vector<unsigned char>> get_ephemeral_keypair()
    {
        priv_key_t private_key;
        do {
            private_key = get_random_bytes<32>();
        } while (!ec_private_key_verify(private_key));
        return { private_key, ec_public_key_from_private_key(private_key) };
    }

    std::vector<unsigned char> ecdh(byte_span_t public_key, byte_span_t private_key)
    {
        std::vector<unsigned char> ret(SHA256_LEN);
        GDK_VERIFY(wally_ecdh(
            public_key.data(), public_key.size(), private_key.data(), private_key.size(), ret.data(), ret.size()));
        return ret;
    }

    std::vector<unsigned char> ae_host_commit_from_bytes(byte_span_t host_entropy, uint32_t flags)
    {
        std::vector<unsigned char> ret(WALLY_HOST_COMMITMENT_LEN);
        GDK_VERIFY(
            wally_ae_host_commit_from_bytes(host_entropy.data(), host_entropy.size(), flags, ret.data(), ret.size()));
        return ret;
    }

    bool ae_verify(byte_span_t public_key, byte_span_t message_hash, byte_span_t host_entropy,
        byte_span_t signer_commitment, byte_span_t sig, uint32_t flags)
    {
        return wally_ae_verify(public_key.data(), public_key.size(), message_hash.data(), message_hash.size(),
                   host_entropy.data(), host_entropy.size(), signer_commitment.data(), signer_commitment.size(), flags,
                   sig.data(), sig.size())
            == WALLY_OK;
    }

    //
    // Elements
    //
    std::array<unsigned char, ASSET_GENERATOR_LEN> asset_generator_from_bytes(byte_span_t asset, byte_span_t abf)
    {
        std::array<unsigned char, ASSET_GENERATOR_LEN> generator;
        GDK_VERIFY(wally_asset_generator_from_bytes(
            asset.data(), asset.size(), abf.data(), abf.size(), generator.data(), generator.size()));
        return generator;
    }

    std::array<unsigned char, ASSET_TAG_LEN> asset_final_vbf(
        uint64_span_t values, size_t num_inputs, byte_span_t abf, byte_span_t vbf)
    {
        std::array<unsigned char, ASSET_TAG_LEN> v;
        GDK_VERIFY(wally_asset_final_vbf(values.data(), values.size(), num_inputs, abf.data(), abf.size(), vbf.data(),
            vbf.size(), v.data(), v.size()));
        return v;
    }

    std::array<unsigned char, ASSET_COMMITMENT_LEN> asset_value_commitment(
        uint64_t value, byte_span_t vbf, byte_span_t generator)
    {
        std::array<unsigned char, ASSET_COMMITMENT_LEN> commitment;
        GDK_VERIFY(wally_asset_value_commitment(
            value, vbf.data(), vbf.size(), generator.data(), generator.size(), commitment.data(), commitment.size()));
        return commitment;
    }

    std::vector<unsigned char> asset_rangeproof(uint64_t value, byte_span_t public_key, byte_span_t private_key,
        byte_span_t asset, byte_span_t abf, byte_span_t vbf, byte_span_t commitment, byte_span_t extra,
        byte_span_t generator, uint64_t min_value, int exp, int min_bits)
    {
        std::vector<unsigned char> rangeproof(ASSET_RANGEPROOF_MAX_LEN);
        size_t written;
        GDK_VERIFY(wally_asset_rangeproof(value, public_key.data(), public_key.size(), private_key.data(),
            private_key.size(), asset.data(), asset.size(), abf.data(), abf.size(), vbf.data(), vbf.size(),
            commitment.data(), commitment.size(), extra.data(), extra.size(), generator.data(), generator.size(),
            min_value, exp, min_bits, rangeproof.data(), rangeproof.size(), &written));
        rangeproof.resize(written);
        return rangeproof;
    }

    size_t asset_surjectionproof_size(size_t num_inputs)
    {
        size_t written;
        GDK_VERIFY(wally_asset_surjectionproof_size(num_inputs, &written));
        return written;
    }

    std::vector<unsigned char> asset_surjectionproof(byte_span_t output_asset, byte_span_t output_abf,
        byte_span_t output_generator, byte_span_t bytes, byte_span_t asset, byte_span_t abf, byte_span_t generator)
    {
        size_t written;
        std::vector<unsigned char> surjproof(asset_surjectionproof_size(asset.size() / ASSET_TAG_LEN));
        GDK_VERIFY(wally_asset_surjectionproof(output_asset.data(), output_asset.size(), output_abf.data(),
            output_abf.size(), output_generator.data(), output_generator.size(), bytes.data(), bytes.size(),
            asset.data(), asset.size(), abf.data(), abf.size(), generator.data(), generator.size(), surjproof.data(),
            surjproof.size(), &written));
        surjproof.resize(written);
        return surjproof;
    }

    unblind_t asset_unblind(byte_span_t private_key, byte_span_t rangeproof, byte_span_t commitment,
        byte_span_t nonce_commitment, byte_span_t extra_commitment, byte_span_t generator)
    {
        asset_id_t asset_id;
        vbf_t vbf;
        abf_t abf;
        uint64_t value;

        GDK_VERIFY(wally_asset_unblind(nonce_commitment.data(), nonce_commitment.size(), private_key.data(),
            private_key.size(), rangeproof.data(), rangeproof.size(), commitment.data(), commitment.size(),
            extra_commitment.data(), extra_commitment.size(), generator.data(), generator.size(), asset_id.data(),
            asset_id.size(), abf.data(), abf.size(), vbf.data(), vbf.size(), &value));

        return std::make_tuple(asset_id, vbf, abf, value);
    }

    unblind_t asset_unblind_with_nonce(byte_span_t blinding_nonce, byte_span_t rangeproof, byte_span_t commitment,
        byte_span_t extra_commitment, byte_span_t generator)
    {
        asset_id_t asset_id;
        vbf_t vbf;
        abf_t abf;
        uint64_t value;

        GDK_VERIFY(wally_asset_unblind_with_nonce(blinding_nonce.data(), blinding_nonce.size(), rangeproof.data(),
            rangeproof.size(), commitment.data(), commitment.size(), extra_commitment.data(), extra_commitment.size(),
            generator.data(), generator.size(), asset_id.data(), asset_id.size(), abf.data(), abf.size(), vbf.data(),
            vbf.size(), &value));

        return std::make_tuple(asset_id, vbf, abf, value);
    }

    std::string confidential_addr_to_addr(const std::string& address, uint32_t prefix)
    {
        char* ret;
        GDK_VERIFY(wally_confidential_addr_to_addr(address.c_str(), prefix, &ret));
        return make_string(ret);
    }

    std::string confidential_addr_to_addr_segwit(
        const std::string& address, const std::string& confidential_prefix, const std::string& prefix)
    {
        char* ret;
        GDK_VERIFY(
            wally_confidential_addr_to_addr_segwit(address.c_str(), confidential_prefix.c_str(), prefix.c_str(), &ret));
        return make_string(ret);
    }

    pub_key_t confidential_addr_to_ec_public_key(const std::string& address, uint32_t prefix)
    {
        pub_key_t pub_key;
        GDK_VERIFY(wally_confidential_addr_to_ec_public_key(address.c_str(), prefix, pub_key.data(), pub_key.size()));
        return pub_key;
    }

    pub_key_t confidential_addr_segwit_to_ec_public_key(
        const std::string& address, const std::string& confidential_prefix)
    {
        pub_key_t pub_key;
        GDK_VERIFY(wally_confidential_addr_segwit_to_ec_public_key(
            address.c_str(), confidential_prefix.c_str(), pub_key.data(), pub_key.size()));
        return pub_key;
    }

    std::string confidential_addr_from_addr(const std::string& address, uint32_t prefix, byte_span_t public_key)
    {
        char* ret;
        GDK_VERIFY(
            wally_confidential_addr_from_addr(address.c_str(), prefix, public_key.data(), public_key.size(), &ret));
        return make_string(ret);
    }

    blinding_key_t asset_blinding_key_from_seed(byte_span_t seed)
    {
        blinding_key_t blinding_key;
        GDK_VERIFY(
            wally_asset_blinding_key_from_seed(seed.data(), seed.size(), blinding_key.data(), blinding_key.size()));
        return blinding_key;
    }

    priv_key_t asset_blinding_key_to_ec_private_key(byte_span_t blinding_key, byte_span_t script)
    {
        priv_key_t priv_key;
        GDK_VERIFY(wally_asset_blinding_key_to_ec_private_key(
            blinding_key.data(), blinding_key.size(), script.data(), script.size(), priv_key.data(), priv_key.size()));
        return priv_key;
    }

    //
    // Transactions
    //
    uint32_t tx_flags(bool is_liquid)
    {
        return WALLY_TX_FLAG_USE_WITNESS | (is_liquid ? WALLY_TX_FLAG_USE_ELEMENTS : 0);
    }

    bool tx_is_elements(const wally_tx_ptr& tx)
    {
        size_t written;
        GDK_VERIFY(wally_tx_is_elements(tx.get(), &written));
        return written == 1;
    }

    size_t tx_get_length(const wally_tx_ptr& tx, uint32_t flags)
    {
        size_t written;
        GDK_VERIFY(wally_tx_get_length(tx.get(), flags, &written));
        return written;
    }

    std::vector<unsigned char> tx_to_bytes(const wally_tx_ptr& tx, uint32_t flags)
    {
        std::vector<unsigned char> buff(tx_get_length(tx, flags));
        size_t written;
        GDK_VERIFY(wally_tx_to_bytes(tx.get(), flags, buff.data(), buff.size(), &written));
        GDK_RUNTIME_ASSERT(written == buff.size());
        return buff;
    }

    void tx_add_raw_output(const wally_tx_ptr& tx, uint64_t satoshi, byte_span_t script)
    {
        const uint32_t flags = 0;
        GDK_VERIFY(wally_tx_add_raw_output(tx.get(), satoshi, script.data(), script.size(), flags));
    }

    void tx_add_elements_raw_output(const wally_tx_ptr& tx, byte_span_t script, byte_span_t asset, byte_span_t value,
        byte_span_t nonce, byte_span_t surjectionproof, byte_span_t rangeproof)
    {
        GDK_VERIFY(wally_tx_add_elements_raw_output(tx.get(), script.data(), script.size(), asset.data(), asset.size(),
            value.data(), value.size(), nonce.data(), nonce.size(), surjectionproof.data(), surjectionproof.size(),
            rangeproof.data(), rangeproof.size(), 0));
    }

    void tx_elements_output_commitment_set(const wally_tx_ptr& tx, size_t index, byte_span_t asset, byte_span_t value,
        byte_span_t nonce, byte_span_t surjectionproof, byte_span_t rangeproof)
    {
        GDK_RUNTIME_ASSERT(index < tx->num_outputs);
        GDK_VERIFY(wally_tx_elements_output_commitment_set(&tx->outputs[index], asset.data(), asset.size(),
            value.data(), value.size(), nonce.data(), nonce.size(), surjectionproof.data(), surjectionproof.size(),
            rangeproof.data(), rangeproof.size()));
    }

    std::array<unsigned char, SHA256_LEN> tx_get_btc_signature_hash(
        const wally_tx_ptr& tx, size_t index, byte_span_t script, uint64_t satoshi, uint32_t sighash, uint32_t flags)
    {
        std::array<unsigned char, SHA256_LEN> tx_hash;
        GDK_VERIFY(wally_tx_get_btc_signature_hash(
            tx.get(), index, script.data(), script.size(), satoshi, sighash, flags, tx_hash.data(), tx_hash.size()));
        return tx_hash;
    }

    std::array<unsigned char, SHA256_LEN> tx_get_elements_signature_hash(
        const wally_tx_ptr& tx, size_t index, byte_span_t script, byte_span_t value, uint32_t sighash, uint32_t flags)
    {
        std::array<unsigned char, SHA256_LEN> tx_hash;
        GDK_VERIFY(wally_tx_get_elements_signature_hash(tx.get(), index, script.data(), script.size(), value.data(),
            value.size(), sighash, flags, tx_hash.data(), tx_hash.size()));
        return tx_hash;
    }

    wally_tx_ptr tx_init(
        uint32_t locktime, size_t inputs_allocation_len, size_t outputs_allocation_len, uint32_t version)
    {
        struct wally_tx* p;
        GDK_VERIFY(wally_tx_init_alloc(version, locktime, inputs_allocation_len, outputs_allocation_len, &p));
        return wally_tx_ptr(p);
    }

    wally_tx_ptr tx_from_bin(byte_span_t tx_bin, uint32_t flags)
    {
        struct wally_tx* p;
        GDK_VERIFY(wally_tx_from_bytes(tx_bin.data(), tx_bin.size(), flags, &p));
        return wally_tx_ptr(p);
    }

    wally_tx_ptr tx_from_hex(const std::string& tx_hex, uint32_t flags)
    {
        struct wally_tx* p;
        GDK_VERIFY(wally_tx_from_hex(tx_hex.c_str(), flags, &p));
        return wally_tx_ptr(p);
    }

    void tx_add_raw_input(const wally_tx_ptr& tx, byte_span_t txhash, uint32_t index, uint32_t sequence,
        byte_span_t script, const wally_tx_witness_stack_ptr& witness)
    {
        const uint32_t flags = 0;
        if (!tx_is_elements(tx)) {
            GDK_VERIFY(wally_tx_add_raw_input(tx.get(), txhash.data(), txhash.size(), index, sequence, script.data(),
                script.size(), witness.get(), flags));
        } else {
            GDK_VERIFY(wally_tx_add_elements_raw_input(tx.get(), txhash.data(), txhash.size(), index, sequence,
                script.data(), script.size(), witness.get(), nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0,
                nullptr, 0, nullptr, flags));
        }
    }

    size_t tx_get_vsize(const wally_tx_ptr& tx)
    {
        size_t written;
        GDK_VERIFY(wally_tx_get_vsize(tx.get(), &written));
        return written;
    }

    size_t tx_get_weight(const wally_tx_ptr& tx)
    {
        size_t written;
        GDK_VERIFY(wally_tx_get_weight(tx.get(), &written));
        return written;
    }

    void tx_set_input_script(const wally_tx_ptr& tx, size_t index, byte_span_t script)
    {
        GDK_VERIFY(wally_tx_set_input_script(tx.get(), index, script.data(), script.size()));
    }

    void tx_set_input_witness(const wally_tx_ptr& tx, size_t index, const wally_tx_witness_stack_ptr& witness)
    {
        GDK_VERIFY(wally_tx_set_input_witness(tx.get(), index, witness.get()));
    }

    size_t tx_vsize_from_weight(size_t weight)
    {
        size_t written;
        GDK_VERIFY(wally_tx_vsize_from_weight(weight, &written));
        return written;
    }

    wally_tx_witness_stack_ptr tx_witness_stack_init(size_t allocation_len)
    {
        struct wally_tx_witness_stack* p;
        GDK_VERIFY(wally_tx_witness_stack_init_alloc(allocation_len, &p));
        return wally_tx_witness_stack_ptr(p);
    }

    void tx_witness_stack_add(const wally_tx_witness_stack_ptr& stack, byte_span_t witness)
    {
        GDK_VERIFY(wally_tx_witness_stack_add(stack.get(), witness.data(), witness.size()));
    }

    void tx_witness_stack_add_dummy(const wally_tx_witness_stack_ptr& stack, uint32_t flags)
    {
        GDK_VERIFY(wally_tx_witness_stack_add_dummy(stack.get(), flags));
    }

    cvalue_t tx_confidential_value_from_satoshi(uint64_t satoshi)
    {
        cvalue_t ct_value;
        GDK_VERIFY(wally_tx_confidential_value_from_satoshi(satoshi, ct_value.data(), ct_value.size()));
        return ct_value;
    }

    uint64_t tx_confidential_value_to_satoshi(byte_span_t ct_value)
    {
        uint64_t satoshi;
        GDK_VERIFY(wally_tx_confidential_value_to_satoshi(ct_value.data(), ct_value.size(), &satoshi));
        return satoshi;
    }

    xpub_t make_xpub(const std::string& chain_code_hex, const std::string& public_key_hex)
    {
        size_t written;
        xpub_t xpub;
        GDK_VERIFY(wally_hex_to_bytes(chain_code_hex.c_str(), xpub.first.data(), xpub.first.size(), &written));
        GDK_RUNTIME_ASSERT(written == xpub.first.size());
        GDK_VERIFY(wally_hex_to_bytes(public_key_hex.c_str(), xpub.second.data(), xpub.second.size(), &written));
        GDK_RUNTIME_ASSERT(written == xpub.second.size());
        return xpub;
    }

    xpub_t make_xpub(const ext_key* hdkey)
    {
        xpub_t xpub;
        std::copy(std::begin(hdkey->chain_code), std::end(hdkey->chain_code), std::begin(xpub.first));
        std::copy(std::begin(hdkey->pub_key), std::end(hdkey->pub_key), std::begin(xpub.second));
        return xpub;
    }

    xpub_t make_xpub(const std::string& bip32_xpub)
    {
        return make_xpub(bip32_public_key_from_bip32_xpub(bip32_xpub).get());
    }

    std::string bip32_key_to_base58(const struct ext_key* hdkey, uint32_t flags)
    {
        char* s;
        GDK_VERIFY(::bip32_key_to_base58(hdkey, flags, &s));
        return make_string(s);
    }
} /* namespace sdk */
} /* namespace ga */
