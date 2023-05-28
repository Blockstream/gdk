#include "signer.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "memory.hpp"
#include "network_parameters.hpp"
#include "utils.hpp"

namespace ga {
namespace sdk {

    namespace {
        static wally_ext_key_ptr derive(
            const wally_ext_key_ptr& hdkey, uint32_span_t path, uint32_t flags = BIP32_FLAG_KEY_PRIVATE)
        {
            // FIXME: Private keys should be derived into mlocked memory
            return bip32_key_from_parent_path_alloc(hdkey, path, flags | BIP32_FLAG_SKIP_HASH);
        }

        static std::string derive_login_bip32_xpub(const wally_ext_key_ptr& master_key)
        {
            auto login_hdkey = derive(master_key, signer::LOGIN_PATH, BIP32_FLAG_KEY_PUBLIC);
            return base58check_from_bytes(bip32_key_serialize(*login_hdkey, BIP32_FLAG_KEY_PUBLIC));
        }

        static nlohmann::json get_credentials_json(const nlohmann::json& credentials)
        {
            if (credentials.empty()) {
                // Hardware wallet or remote service
                return {};
            }

            const auto username_p = credentials.find("username");
            if (username_p != credentials.end()) {
                // Watch-only login
                return { { "username", *username_p }, { "password", credentials.at("password") } };
            }

            const auto mnemonic_p = credentials.find("mnemonic");
            if (mnemonic_p != credentials.end()) {
                // Mnemonic, or a hex seed
                std::string mnemonic = *mnemonic_p;
                if (mnemonic.find(' ') != std::string::npos) {
                    // Mnemonic, possibly encrypted
                    const auto password_p = credentials.find("password");
                    if (password_p != credentials.end()) {
                        GDK_RUNTIME_ASSERT_MSG(
                            !credentials.contains("bip39_passphrase"), "cannot use bip39_passphrase and password");
                        // Encrypted; decrypt it
                        mnemonic = decrypt_mnemonic(mnemonic, *password_p);
                    }
                    const std::string passphrase = json_get_value(credentials, "bip39_passphrase");
                    nlohmann::json ret
                        = { { "mnemonic", mnemonic }, { "seed", b2h(bip39_mnemonic_to_seed(mnemonic, passphrase)) } };
                    if (!passphrase.empty()) {
                        ret["bip39_passphrase"] = passphrase;
                    }
                    return ret;
                }
                if (mnemonic.size() == 129u && mnemonic.back() == 'X') {
                    GDK_RUNTIME_ASSERT_MSG(
                        !credentials.contains("bip39_passphrase"), "cannot use bip39_passphrase and hex seed");
                    // Hex seed (a 512 bits bip32 seed encoding in hex with 'X' appended)
                    mnemonic.pop_back();
                    return { { "seed", mnemonic } };
                }
            }

            const auto core_descriptors_p = credentials.find("core_descriptors");
            const auto slip132_extended_pubkeys_p = credentials.find("slip132_extended_pubkeys");
            if (core_descriptors_p != credentials.end()) {
                if (slip132_extended_pubkeys_p != credentials.end()) {
                    throw user_error(
                        "You can only provide either 'core_descriptors' or 'slip132_extended_pubkeys', not both");
                }
                // Watch-only login
                return { { "core_descriptors", *core_descriptors_p } };
            }

            if (slip132_extended_pubkeys_p != credentials.end()) {
                // Watch-only login
                return { { "slip132_extended_pubkeys", *slip132_extended_pubkeys_p } };
            }

            throw user_error("Invalid credentials");
        }

        static const nlohmann::json GREEN_DEVICE_JSON{ { "device_type", "green-backend" }, { "supports_low_r", true },
            { "supports_arbitrary_scripts", true }, { "supports_host_unblinding", false },
            { "supports_external_blinding", true }, { "supports_liquid", liquid_support_level::lite },
            { "supports_ae_protocol", ae_protocol_support_level::none } };

        static const nlohmann::json WATCH_ONLY_DEVICE_JSON{ { "device_type", "watch-only" }, { "supports_low_r", true },
            { "supports_arbitrary_scripts", true }, { "supports_host_unblinding", true },
            { "supports_external_blinding", true }, { "supports_liquid", liquid_support_level::lite },
            { "supports_ae_protocol", ae_protocol_support_level::none } };

        static const nlohmann::json SOFTWARE_DEVICE_JSON{ { "device_type", "software" }, { "supports_low_r", true },
            { "supports_arbitrary_scripts", true }, { "supports_host_unblinding", true },
            { "supports_external_blinding", true }, { "supports_liquid", liquid_support_level::lite },
            { "supports_ae_protocol", ae_protocol_support_level::none } };

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
            json_add_if_missing(ret, "supports_external_blinding", true, overwrite_null);
            json_add_if_missing(ret, "supports_liquid", liquid_support_level::none, overwrite_null);
            json_add_if_missing(ret, "supports_ae_protocol", ae_protocol_support_level::none, overwrite_null);
            json_add_if_missing(ret, "device_type", std::string("hardware"), overwrite_null);
            const auto device_type = json_get_value(ret, "device_type");
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

    const std::array<uint32_t, 0> signer::EMPTY_PATH{};
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

        auto seed_p = m_credentials.find("seed");
        if (seed_p != m_credentials.end()) {
            // FIXME: Allocate m_master_key in mlocked memory
            std::vector<unsigned char> seed = h2b(*seed_p);
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

    bool signer::is_compatible_with(std::shared_ptr<signer> other) const
    {
        return get_credentials() == other->get_credentials() && get_device() == other->get_device();
    }

    std::string signer::get_mnemonic(const std::string& password)
    {
        if (is_hardware() || is_watch_only() || is_remote()) {
            return std::string();
        }
        const auto mnemonic_p = m_credentials.find("mnemonic");
        if (mnemonic_p != m_credentials.end()) {
            return encrypt_mnemonic(*mnemonic_p, password); // Mnemonic
        }
        return m_credentials.at("seed").get<std::string>() + "X"; // Hex seed
    }

    bool signer::supports_low_r() const
    {
        // Note we always use AE if the HW supports it
        return !use_ae_protocol() && m_device["supports_low_r"];
    }

    bool signer::supports_arbitrary_scripts() const { return m_device["supports_arbitrary_scripts"]; }

    liquid_support_level signer::get_liquid_support() const { return m_device["supports_liquid"]; }

    bool signer::supports_host_unblinding() const { return m_device["supports_host_unblinding"]; }

    bool signer::supports_external_blinding() const { return m_device["supports_external_blinding"]; }

    ae_protocol_support_level signer::get_ae_protocol_support() const { return m_device["supports_ae_protocol"]; }

    bool signer::use_ae_protocol() const { return get_ae_protocol_support() != ae_protocol_support_level::none; }

    bool signer::is_remote() const { return m_device["device_type"] == "green-backend"; }

    bool signer::is_liquid() const { return m_is_liquid; }

    bool signer::is_watch_only() const { return m_device["device_type"] == "watch-only"; }

    bool signer::is_hardware() const { return m_device["device_type"] == "hardware"; }

    const nlohmann::json& signer::get_device() const { return m_device; }

    const nlohmann::json& signer::get_credentials() const { return m_credentials; }

    std::string signer::get_bip32_xpub(const std::vector<uint32_t>& path)
    {
        {
            std::unique_lock<std::mutex> locker{ m_mutex };
            auto cached = m_cached_bip32_xpubs.find(path);
            if (cached != m_cached_bip32_xpubs.end()) {
                return cached->second;
            }
        }
        ext_key* hdkey = m_master_key.get();
        GDK_RUNTIME_ASSERT(hdkey);
        wally_ext_key_ptr derived;
        std::string login_bip32_xpub;
        if (!path.empty()) {
            derived = derive(m_master_key, path);
            hdkey = derived.get();
        } else {
            // We are encaching the master pubkey. Encache the login pubkey
            // at the same time to save callers having to re-derive it multiple times
            // for message signing/verification.
            login_bip32_xpub = derive_login_bip32_xpub(m_master_key);
        }
        auto ret = base58check_from_bytes(bip32_key_serialize(*hdkey, BIP32_FLAG_KEY_PUBLIC));
        std::unique_lock<std::mutex> locker{ m_mutex };
        m_cached_bip32_xpubs.emplace(path, ret);
        if (!login_bip32_xpub.empty()) {
            m_cached_bip32_xpubs.emplace(make_vector(LOGIN_PATH), login_bip32_xpub);
        }
        return ret;
    }

    std::string signer::get_master_bip32_xpub() { return get_bip32_xpub(std::vector<uint32_t>()); }

    bool signer::has_bip32_xpub(const std::vector<uint32_t>& path)
    {
        std::unique_lock<std::mutex> locker{ m_mutex };
        return m_cached_bip32_xpubs.find(path) != m_cached_bip32_xpubs.end();
    }

    bool signer::cache_bip32_xpub(const std::vector<uint32_t>& path, const std::string& bip32_xpub)
    {
        std::unique_lock<std::mutex> locker{ m_mutex };
        auto ret = m_cached_bip32_xpubs.emplace(path, bip32_xpub);
        if (!ret.second) {
            // Already present, verify that the value matches
            GDK_RUNTIME_ASSERT(ret.first->second == bip32_xpub);
            return false; // Not updated
        }
        if (path.empty()) {
            // Encaching master pubkey, encache the login pubkey as above
            auto master_pubkey = bip32_public_key_from_bip32_xpub(bip32_xpub);
            m_cached_bip32_xpubs.emplace(make_vector(LOGIN_PATH), derive_login_bip32_xpub(master_pubkey));
        }
        return true; // Updated
    }

    signer::cache_t signer::get_cached_bip32_xpubs()
    {
        std::unique_lock<std::mutex> locker{ m_mutex };
        return m_cached_bip32_xpubs;
    }

    ecdsa_sig_t signer::sign_hash(uint32_span_t path, byte_span_t hash)
    {
        GDK_RUNTIME_ASSERT(m_master_key.get());
        wally_ext_key_ptr derived = derive(m_master_key, path);
        return ec_sig_from_bytes(gsl::make_span(derived->priv_key).subspan(1), hash);
    }

    ecdsa_sig_rec_t signer::sign_rec_hash(uint32_span_t path, byte_span_t hash)
    {
        GDK_RUNTIME_ASSERT(m_master_key.get());
        wally_ext_key_ptr derived = derive(m_master_key, path);
        return ec_sig_rec_from_bytes(gsl::make_span(derived->priv_key).subspan(1), hash);
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

} // namespace sdk
} // namespace ga
