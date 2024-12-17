#include "signer.hpp"
#include "containers.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "json_utils.hpp"
#include "memory.hpp"
#include "network_parameters.hpp"
#include "utils.hpp"

namespace green {

    namespace {
        static wally_ext_key_ptr derive(
            const wally_ext_key_ptr& hdkey, uint32_span_t path, uint32_t flags = BIP32_FLAG_KEY_PRIVATE)
        {
            // FIXME: Private keys should be derived into mlocked memory
            GDK_RUNTIME_ASSERT(hdkey);
            return bip32_key_from_parent_path_alloc(hdkey, path, flags | BIP32_FLAG_SKIP_HASH);
        }

        static nlohmann::json get_credentials_json(const nlohmann::json& credentials)
        {
            if (credentials.empty()) {
                // Hardware wallet or remote service
                return {};
            }

            if (auto username = j_str(credentials, "username"); username) {
                return signer::normalize_watch_only_credentials(credentials);
            }

            if (auto user_mnemonic = j_str(credentials, "mnemonic"); user_mnemonic) {
                // Mnemonic, or a hex seed
                const auto bip39_passphrase = j_str(credentials, "bip39_passphrase");
                std::string mnemonic = *user_mnemonic;
                if (mnemonic.find(' ') != std::string::npos) {
                    // Mnemonic, possibly encrypted
                    if (auto password = j_str(credentials, "password"); password) {
                        GDK_RUNTIME_ASSERT_MSG(!bip39_passphrase, "cannot use bip39_passphrase and password");
                        // Encrypted; decrypt it
                        mnemonic = decrypt_mnemonic(mnemonic, *password);
                    }
                    auto passphrase = bip39_passphrase.value_or(std::string{});
                    auto seed = b2h(bip39_mnemonic_to_seed(mnemonic, passphrase));
                    nlohmann::json ret = { { "mnemonic", std::move(mnemonic) }, { "seed", std::move(seed) } };
                    if (!passphrase.empty()) {
                        ret["bip39_passphrase"] = std::move(passphrase);
                    }
                    return ret;
                }
                if (mnemonic.size() == 129u && mnemonic.back() == 'X') {
                    // Hex seed (a 512 bit bip32 seed encoding in hex with 'X' appended)
                    GDK_RUNTIME_ASSERT_MSG(!bip39_passphrase, "cannot use bip39_passphrase and hex seed");
                    mnemonic.pop_back();
                    return { { "seed", std::move(mnemonic) } };
                }
            }

            const auto slip132_pubkeys = j_array(credentials, "slip132_extended_pubkeys");
            const auto descriptors = j_array(credentials, "core_descriptors");
            if (descriptors && !slip132_pubkeys && !descriptors->empty()) {
                // Descriptor watch-only login
                return { { "core_descriptors", std::move(*descriptors) } };
            }
            if (slip132_pubkeys && !descriptors && !slip132_pubkeys->empty()) {
                // Descriptor watch-only login
                return { { "slip132_extended_pubkeys", std::move(*slip132_pubkeys) } };
            }
            // Unknown or invalid credentials
            throw_user_error("Invalid credentials"); // FIXME: res::
        }

        static const nlohmann::json GREEN_DEVICE_JSON{ { "device_type", "green-backend" }, { "supports_low_r", true },
            { "supports_arbitrary_scripts", true }, { "supports_host_unblinding", false },
            { "supports_external_blinding", true }, { "supports_liquid", liquid_support_level::lite },
            { "supports_ae_protocol", ae_protocol_support_level::none }, { "supports_p2tr", true } };

        static const nlohmann::json WATCH_ONLY_DEVICE_JSON{ { "device_type", "watch-only" }, { "supports_low_r", true },
            { "supports_arbitrary_scripts", true }, { "supports_host_unblinding", true },
            { "supports_external_blinding", true }, { "supports_liquid", liquid_support_level::lite },
            { "supports_ae_protocol", ae_protocol_support_level::none }, { "supports_p2tr", true } };

        static const nlohmann::json SOFTWARE_DEVICE_JSON{ { "device_type", "software" }, { "supports_low_r", true },
            { "supports_arbitrary_scripts", true }, { "supports_host_unblinding", true },
            { "supports_external_blinding", true }, { "supports_liquid", liquid_support_level::lite },
            { "supports_ae_protocol", ae_protocol_support_level::none }, { "supports_p2tr", true } };

        static nlohmann::json get_device_json(const nlohmann::json& hw_device, const nlohmann::json& credentials)
        {
            nlohmann::json ret;
            auto device
                = hw_device.empty() ? nlohmann::json::object() : hw_device.value("device", nlohmann::json::object());
            if (!device.empty()) {
                ret.swap(device);
                if (!credentials.empty()) {
                    throw user_error("HWW/remote signer and login credentials cannot be used together");
                }
            } else if (credentials.contains("username") || credentials.contains("slip132_extended_pubkeys")
                || credentials.contains("core_descriptors")) {
                ret = WATCH_ONLY_DEVICE_JSON;
            } else if (credentials.contains("seed")) {
                ret = SOFTWARE_DEVICE_JSON;
            } else {
                throw user_error("Hardware device or credentials required");
            }

            const bool overwrite_null = true;
            json_add_if_missing(ret, "supports_low_r", false, overwrite_null);
            json_add_if_missing(ret, "supports_arbitrary_scripts", false, overwrite_null);
            json_add_if_missing(ret, "supports_host_unblinding", false, overwrite_null);
            json_add_if_missing(ret, "supports_external_blinding", false, overwrite_null);
            json_add_if_missing(ret, "supports_liquid", liquid_support_level::none, overwrite_null);
            json_add_if_missing(ret, "supports_ae_protocol", ae_protocol_support_level::none, overwrite_null);
            json_add_if_missing(ret, "supports_p2tr", false, overwrite_null);
            json_add_if_missing(ret, "device_type", std::string("hardware"), overwrite_null);
            const auto device_type = j_str_or_empty(ret, "device_type");
            if (device_type == "hardware") {
                if (ret.value("name", std::string()).empty()) {
                    throw user_error("Hardware device JSON requires a non-empty 'name' element");
                }
            } else if (device_type == "green-backend") {
                // Don't allow overriding Green backend settings
                ret = GREEN_DEVICE_JSON;
            } else if (device_type != "software" && device_type != "watch-only") {
                throw user_error(std::string("Unknown device type ") + device_type);
            }
            return ret;
        }
    } // namespace

    const std::array<uint32_t, 1> signer::LOGIN_PATH{ { 0x4741b11e } };
    const std::array<uint32_t, 1> signer::REGISTER_PATH{ { harden(0x4741) } }; // 'GA'
    const std::array<uint32_t, 1> signer::CLIENT_SECRET_PATH{ { harden(0x70617373) } }; // 'pass'
    const std::array<unsigned char, 8> signer::PASSWORD_SALT = {
        { 0x70, 0x61, 0x73, 0x73, 0x73, 0x61, 0x6c, 0x74 } // 'passsalt'
    };
    const std::array<unsigned char, 8> signer::BLOB_SALT = {
        { 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x61, 0x6c, 0x74 } // 'blobsalt'
    };
    const std::array<unsigned char, 8> signer::WATCH_ONLY_SALT = {
        { 0x5f, 0x77, 0x6f, 0x5f, 0x73, 0x61, 0x6c, 0x74 } // '_wo_salt'
    };
    const std::array<unsigned char, 8> signer::WO_SEED_U = {
        { 0x01, 0x77, 0x6f, 0x5f, 0x75, 0x73, 0x65, 0x72 } // [1]'wo_user'
    };
    const std::array<unsigned char, 8> signer::WO_SEED_P = {
        { 0x02, 0x77, 0x6f, 0x5f, 0x70, 0x61, 0x73, 0x73 } // [2]'wo_pass'
    };
    const std::array<unsigned char, 8> signer::WO_SEED_K = {
        { 0x03, 0x77, 0x6f, 0x5f, 0x62, 0x6C, 0x6f, 0x62 } // [3]'wo_blob'
    };

    signer::signer(
        const network_parameters& net_params, const nlohmann::json& hw_device, const nlohmann::json& credentials)
        : m_is_main_net(net_params.is_main_net())
        , m_is_liquid(net_params.is_liquid())
        , m_btc_version(net_params.btc_version())
        , m_credentials(get_credentials_json(credentials))
        , m_device(get_device_json(hw_device, m_credentials))
    {
        if (m_is_liquid && get_liquid_support() == liquid_support_level::none) {
            throw user_error(res::id_the_hardware_wallet_you_are);
        }

        if (const auto seed_hex = j_str(m_credentials, "seed"); seed_hex) {
            // FIXME: Allocate m_master_key in mlocked memory
            std::vector<unsigned char> seed = h2b(*seed_hex);
            const uint32_t version = m_is_main_net ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_TEST_PRIVATE;
            m_master_key = bip32_key_from_seed_alloc(seed, version, 0);
            if (m_is_liquid) {
                m_master_blinding_key = asset_blinding_key_from_seed(seed);
            }
            bzero_and_free(seed);
        }
    }

    signer::~signer()
    {
        if (m_master_blinding_key) {
            wally_bzero(m_master_blinding_key->data(), m_master_blinding_key->size());
        }
    }

    bool signer::is_compatible_with(const std::shared_ptr<signer>& other) const
    {
        if (get_device() != other->get_device()) {
            return false;
        }
        auto my_credentials = get_credentials();
        j_erase(my_credentials, "master_blinding_key");
        auto other_credentials = other->get_credentials();
        j_erase(other_credentials, "master_blinding_key");
        return my_credentials == other_credentials;
    }

    std::string signer::get_mnemonic(const std::string& password)
    {
        if (is_hardware() || is_watch_only() || is_remote()) {
            return std::string();
        }
        if (const auto mnemonic = j_str(m_credentials, "mnemonic"); mnemonic) {
            return encrypt_mnemonic(*mnemonic, password); // Mnemonic
        }
        return j_strref(m_credentials, "seed") + "X"; // Hex seed
    }

    nlohmann::json signer::normalize_watch_only_credentials(const nlohmann::json& credentials)
    {
        const auto& username = j_strref(credentials, "username");
        const auto& password = j_strref(credentials, "password");
        nlohmann::json ret = { { "username", username }, { "password", password } };
        auto raw_data = j_str_or_empty(credentials, "raw_watch_only_data");
        auto data = j_str_or_empty(credentials, "watch_only_data");
        if (!raw_data.empty() || !data.empty()) {
            // Blobserver rich watch-only login
            const auto entropy = compute_watch_only_entropy(username, password);
            if (raw_data.empty()) {
                raw_data = b2h(decrypt_watch_only_data(entropy, data));
            } else if (data.empty()) {
                data = encrypt_watch_only_data(entropy, h2b(raw_data));
            }
            constexpr auto expected_size = (pub_key_t().size() + pbkdf2_hmac256_t().size()) * 2;
            if (raw_data.size() != expected_size) {
                // Decrypted to the wrong length: invalid username, password
                // or watch-only data.
                throw user_error(res::id_user_not_found_or_invalid);
            }
            ret["raw_watch_only_data"] = std::move(raw_data);
            ret["watch_only_data"] = std::move(data);
        }
        return ret;
    }

    bool signer::supports_low_r() const
    {
        // Note we always use AE if the HW supports it
        return !use_ae_protocol() && j_boolref(m_device, "supports_low_r");
    }

    bool signer::supports_arbitrary_scripts() const { return j_boolref(m_device, "supports_arbitrary_scripts"); }

    liquid_support_level signer::get_liquid_support() const { return m_device.at("supports_liquid"); }

    bool signer::supports_host_unblinding() const { return j_boolref(m_device, "supports_host_unblinding"); }

    bool signer::supports_external_blinding() const { return j_boolref(m_device, "supports_external_blinding"); }

    bool signer::supports_p2tr() const { return j_boolref(m_device, "supports_p2tr"); }

    ae_protocol_support_level signer::get_ae_protocol_support() const { return m_device.at("supports_ae_protocol"); }

    bool signer::use_ae_protocol() const { return get_ae_protocol_support() != ae_protocol_support_level::none; }

    bool signer::is_remote() const { return j_strref(m_device, "device_type") == "green-backend"; }

    bool signer::is_liquid() const { return m_is_liquid; }

    bool signer::is_watch_only() const { return j_strref(m_device, "device_type") == "watch-only"; }

    bool signer::is_hardware() const { return j_strref(m_device, "device_type") == "hardware"; }

    bool signer::is_descriptor_watch_only() const
    {
        return m_credentials.contains("core_descriptors") || m_credentials.contains("slip132_extended_pubkeys");
    }

    const nlohmann::json& signer::get_device() const { return m_device; }

    nlohmann::json signer::get_credentials() const
    {
        auto credentials = m_credentials;
        if (m_is_liquid) {
            // Return the master blinding key if we have one
            std::unique_lock<std::mutex> locker{ m_mutex };
            if (m_master_blinding_key.has_value()) {
                auto key = gsl::make_span(m_master_blinding_key.value());
                credentials["master_blinding_key"] = b2h(key.last(HMAC_SHA256_LEN));
            }
        }
        return credentials;
    }

    std::string signer::get_master_bip32_xpub() { return get_bip32_xpub({}); }

    bool signer::has_master_bip32_xpub() { return has_bip32_xpub({}); }

    std::string signer::get_bip32_xpub(uint32_span_t path)
    {
        std::vector<uint32_t> parent_path{ path.begin(), path.end() }, child_path;
        child_path.reserve(path.size());
        std::optional<xpub_hdkey> parent_key;

        {
            // Search for the cached xpub or a parent we can derive it from
            std::unique_lock<std::mutex> locker{ m_mutex };
            for (;;) {
                auto cached = m_cached_bip32_xpubs.find(parent_path);
                if (cached != m_cached_bip32_xpubs.end()) {
                    if (child_path.empty()) {
                        // Found the full derived key, return it
                        return cached->second;
                    }
                    // Found a parent of the key we are looking for
                    parent_key = xpub_hdkey(cached->second);
                    break;
                }
                if (parent_path.empty() || is_hardened(parent_path.back())) {
                    // Root key or hardened parent we don't have yet: try below
                    break;
                }
                // Try the next highest possible parent
                child_path.insert(child_path.begin(), parent_path.back());
                parent_path.pop_back();
            }
        }
        if (path.empty()) {
            // Master xpub requested. encache and return it
            return cache_bip32_xpub({}, xpub_hdkey(*m_master_key).to_base58()).first;
        }
        if (!parent_path.empty() && !parent_key) {
            // Derive and encache the parent key from the master key
            parent_key = xpub_hdkey(*derive(m_master_key, parent_path, BIP32_FLAG_KEY_PUBLIC));
            cache_bip32_xpub(parent_path, parent_key->to_base58());
        }
        if (!parent_key) {
            GDK_RUNTIME_ASSERT(m_master_key);
            parent_key = xpub_hdkey(*m_master_key);
        }
        if (child_path.empty()) {
            // Return our root key, which is already cached
            return xpub_hdkey(*parent_key).to_base58();
        }
        // Derive, encache and return the child key from its parent,
        // using the full path as our cache key
        return cache_bip32_xpub(path, parent_key->derive(child_path).to_base58()).first;
    }

    bool signer::has_bip32_xpub(uint32_span_t path)
    {
        if (m_master_key) {
            return true; // We can derive any xpub we need
        }
        std::vector<uint32_t> parent_path{ path.begin(), path.end() };
        std::unique_lock<std::mutex> locker{ m_mutex };
        for (;;) {
            auto cached = m_cached_bip32_xpubs.find(parent_path);
            if (cached != m_cached_bip32_xpubs.end()) {
                return true; // Found
            }
            if (parent_path.empty() || is_hardened(parent_path.back())) {
                // Root key or hardened parent we don't have
                return false;
            }
            // Try the next highest possible parent
            parent_path.pop_back();
        }
    }

    std::pair<std::string, bool> signer::cache_bip32_xpub(uint32_span_t path, const std::string& bip32_xpub)
    {
        std::unique_lock<std::mutex> locker{ m_mutex };
        cache_t::key_type parent_path{ path.begin(), path.end() };
        auto ret = m_cached_bip32_xpubs.emplace(std::move(parent_path), bip32_xpub);
        if (!ret.second && ret.first->second != bip32_xpub) {
            // The already cached xpub does not match the one we have been
            // asked to cache. This could be a trivial mismatch such as on
            // the parent fingerprint, or may be a consequential mismatch.
            const xpub_hdkey existing_xpub(ret.first->second);
            const xpub_hdkey new_xpub(bip32_xpub);
            if (existing_xpub != new_xpub) {
                // Consequential: mismatch on the pubkey or chaincode.
                // Either our cache is invalid, or the signer has
                // returned an invalid xpub. Both are fatal errors.
                GDK_LOG(error) << "xpub mismatch: " << ret.first->second << " != " << bip32_xpub;
                throw user_error("signer provided xpub does not match cached xpub");
            }
        }
        if (path.empty() && !m_master_fingerprint) {
            // Master xpub: set or verify the master fingerprint
            auto fingerprint = xpub_hdkey(bip32_xpub).get_fingerprint();
            if (m_master_fingerprint) {
                GDK_RUNTIME_ASSERT(fingerprint == *m_master_fingerprint);
            } else {
                m_master_fingerprint = std::move(fingerprint);
            }
        }
        return { bip32_xpub, ret.second }; // Returns true if the xpub was inserted
    }

    signer::cache_t signer::get_cached_bip32_xpubs()
    {
        std::unique_lock<std::mutex> locker{ m_mutex };
        return m_cached_bip32_xpubs;
    }

    nlohmann::json signer::get_cached_bip32_xpubs_json()
    {
        auto paths_and_xpubs = get_cached_bip32_xpubs();
        nlohmann::json xpubs_json;
        for (auto& item : paths_and_xpubs) {
            // We cache the values inverted, i.e. xpub: path
            // because the master key path is empty JSON keys can't be empty
            xpubs_json.emplace(std::move(item.second), std::move(item.first));
        }
        return xpubs_json;
    }

    ec_sig_t signer::ecdsa_sign(uint32_span_t path, byte_span_t message)
    {
        const auto derived = derive(m_master_key, path);
        const auto priv_key = gsl::make_span(derived->priv_key).subspan(1);
        return ec_sig_from_bytes(priv_key, message);
    }

    ec_sig_t signer::schnorr_sign(uint32_span_t path, byte_span_t message)
    {
        const auto derived = derive(m_master_key, path);
        const auto priv_key = gsl::make_span(derived->priv_key).subspan(1);
        // Apply the taptweak to the private key.
        // As we don't support script path spending we pass a null merkle_root
        std::array<unsigned char, EC_PRIVATE_KEY_LEN> tweaked;
        constexpr uint32_t flags = 0;
        GDK_VERIFY(wally_ec_private_key_bip341_tweak(
            priv_key.data(), priv_key.size(), nullptr, 0, flags, tweaked.data(), tweaked.size()));
        auto ret = ec_sig_from_bytes(tweaked, message, EC_FLAG_SCHNORR);
        wally_bzero(tweaked.data(), tweaked.size());
        return ret;
    }

    bool signer::has_master_blinding_key() const
    {
        std::unique_lock<std::mutex> locker{ m_mutex };
        return m_master_blinding_key.has_value();
    }

    blinding_key_t signer::get_master_blinding_key() const
    {
        std::unique_lock<std::mutex> locker{ m_mutex };
        GDK_RUNTIME_ASSERT(m_master_blinding_key.has_value());
        return m_master_blinding_key.value();
    }

    void signer::set_master_blinding_key(const std::string& blinding_key_hex)
    {
        if (!blinding_key_hex.empty()) {
            const auto key_bytes = h2b(blinding_key_hex);
            const auto key_size = key_bytes.size();
            GDK_RUNTIME_ASSERT(key_size == SHA512_LEN || key_size == SHA512_LEN / 2);
            blinding_key_t key{ 0 };
            // Handle both full and half-size blinding keys
            std::copy(key_bytes.begin(), key_bytes.end(), key.begin() + (SHA512_LEN - key_size));
            std::unique_lock<std::mutex> locker{ m_mutex };
            m_master_blinding_key = key;
        }
    }

    priv_key_t signer::get_blinding_key_from_script(byte_span_t script)
    {
        std::unique_lock<std::mutex> locker{ m_mutex };
        GDK_RUNTIME_ASSERT(m_master_blinding_key.has_value());
        return asset_blinding_key_to_ec_private_key(*m_master_blinding_key, script);
    }

    std::vector<unsigned char> signer::get_blinding_pubkey_from_script(byte_span_t script)
    {
        return ec_public_key_from_private_key(get_blinding_key_from_script(script));
    }

    std::vector<unsigned char> signer::get_master_fingerprint()
    {
        std::unique_lock<std::mutex> locker{ m_mutex };
        GDK_RUNTIME_ASSERT(m_master_fingerprint);
        return *m_master_fingerprint;
    }

    void signer::set_master_fingerprint(const std::string& fingerprint_hex)
    {
        GDK_RUNTIME_ASSERT(fingerprint_hex.size() == BIP32_KEY_FINGERPRINT_LEN * 2);
        std::unique_lock<std::mutex> locker{ m_mutex };
        m_master_fingerprint = h2b(fingerprint_hex);
    }

} // namespace green
