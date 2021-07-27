#include "signer.hpp"
#include "exception.hpp"
#include "network_parameters.hpp"
#include "utils.hpp"

namespace ga {
namespace sdk {

    namespace {
        static wally_ext_key_ptr derive(const wally_ext_key_ptr& hdkey, uint32_span_t path)
        {
            // FIXME: Private keys should be derived into mlocked memory
            return bip32_key_from_parent_path_alloc(hdkey, path, BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH);
        }

        static nlohmann::json get_device_json(const nlohmann::json& hw_device)
        {
            GDK_RUNTIME_ASSERT(!hw_device.empty());

            nlohmann::json ret = hw_device;
            const bool overwrite_null = true;
            json_add_if_missing(ret, "supports_low_r", false, overwrite_null);
            json_add_if_missing(ret, "supports_arbitrary_scripts", false, overwrite_null);
            json_add_if_missing(ret, "supports_host_unblinding", false, overwrite_null);
            json_add_if_missing(ret, "supports_liquid", liquid_support_level::none, overwrite_null);
            json_add_if_missing(ret, "supports_ae_protocol", ae_protocol_support_level::none, overwrite_null);
            json_add_if_missing(ret, "device_type", std::string("hardware"), overwrite_null);
            if (ret.at("device_type") == "hardware" && ret.value("name", std::string()).empty()) {
                throw user_error("Hardware device JSON requires a non-empty 'name' element");
            }
            return ret;
        }

        static const nlohmann::json WATCH_ONLY_DEVICE_JSON{ { "device_type", "watch-only" }, { "supports_low_r", true },
            { "supports_arbitrary_scripts", true }, { "supports_host_unblinding", false },
            { "supports_liquid", liquid_support_level::none },
            { "supports_ae_protocol", ae_protocol_support_level::none } };

        static const nlohmann::json SOFTWARE_DEVICE_JSON{ { "device_type", "software" }, { "supports_low_r", true },
            { "supports_arbitrary_scripts", true }, { "supports_host_unblinding", true },
            { "supports_liquid", liquid_support_level::lite },
            { "supports_ae_protocol", ae_protocol_support_level::none } };
    } // namespace

    const std::array<uint32_t, 1> signer::LOGIN_PATH{ { 0x4741b11e } };
    const std::array<uint32_t, 1> signer::CLIENT_SECRET_PATH{ { harden(0x70617373) } }; // 'pass'
    const std::array<unsigned char, 8> signer::PASSWORD_SALT = {
        { 0x70, 0x61, 0x73, 0x73, 0x73, 0x61, 0x6c, 0x74 } // 'passsalt'
    };
    const std::array<unsigned char, 8> signer::BLOB_SALT = {
        { 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x61, 0x6c, 0x74 } // 'blobsalt'
    };

    signer::signer(const network_parameters& net_params, const nlohmann::json& hw_device)
        : m_is_main_net(net_params.is_main_net())
        , m_is_liquid(net_params.is_liquid())
        , m_btc_version(net_params.btc_version())
        , m_device(get_device_json(hw_device))
    {
    }

    signer::signer(const network_parameters& net_params, const std::string& mnemonic_or_xpub)
        : signer(net_params, SOFTWARE_DEVICE_JSON)
    {
        // FIXME: Allocate m_master_key in mlocked memory
        if (mnemonic_or_xpub.find(' ') != std::string::npos) {
            // mnemonic
            // FIXME: secure_array
            m_mnemonic = mnemonic_or_xpub;
            const auto seed = bip39_mnemonic_to_seed(mnemonic_or_xpub);
            const uint32_t version = m_is_main_net ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_TEST_PRIVATE;
            m_master_key = bip32_key_from_seed_alloc(seed, version, 0);
            if (m_is_liquid) {
                m_master_blinding_key = asset_blinding_key_from_seed(seed);
            }
        } else if (mnemonic_or_xpub.size() == 129 && mnemonic_or_xpub[128] == 'X') {
            // hex seed (a 512 bits bip32 seed encoding in hex with 'X' appended)
            // FIXME: Some previously supported HWs do not have bip39 support.
            // Entering the hex seed in the recover phase should provide access
            // to the wallet. A better approach could be to separate the bip32
            // seed derivation from 'mnemonic to seed' derivation, which should
            // facilitate non-bip39 mnemonic future integration. For these
            // reasons this is a temporary solution.
            const auto seed = h2b(mnemonic_or_xpub.substr(0, 128));
            const uint32_t version = m_is_main_net ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_TEST_PRIVATE;
            m_master_key = bip32_key_from_seed_alloc(seed, version, 0);
            if (m_is_liquid) {
                m_master_blinding_key = asset_blinding_key_from_seed(seed);
            }
        } else {
            // xpub
            m_master_key = bip32_public_key_from_bip32_xpub(mnemonic_or_xpub);
        }
    }

    std::shared_ptr<signer> signer::make_watch_only_signer(const network_parameters& net_params)
    {
        return std::make_shared<signer>(net_params, WATCH_ONLY_DEVICE_JSON);
    }

    std::shared_ptr<signer> signer::make_hardware_signer(
        const network_parameters& net_params, const nlohmann::json& hw_device)
    {
        return std::make_shared<signer>(net_params, hw_device);
    }

    std::shared_ptr<signer> signer::make_software_signer(
        const network_parameters& net_params, const std::string& mnemonic_or_xpub)
    {
        return std::make_shared<signer>(net_params, mnemonic_or_xpub);
    }

    signer::~signer()
    {
        if (m_master_blinding_key) {
            wally_bzero(m_master_blinding_key->data(), m_master_blinding_key->size());
        }
    }

    std::string signer::get_mnemonic(const std::string& password)
    {
        return m_mnemonic.empty() || password.empty() ? m_mnemonic : encrypt_mnemonic(m_mnemonic, password);
    }

    bool signer::supports_low_r() const
    {
        if (get_ae_protocol_support() != ae_protocol_support_level::none) {
            return false; // Always use AE if the HW supports it
        }
        return m_device["supports_low_r"];
    }

    bool signer::supports_arbitrary_scripts() const { return m_device["supports_arbitrary_scripts"]; }

    liquid_support_level signer::get_liquid_support() const { return m_device["supports_liquid"]; }

    bool signer::supports_host_unblinding() const { return m_device["supports_host_unblinding"]; }

    ae_protocol_support_level signer::get_ae_protocol_support() const { return m_device["supports_ae_protocol"]; }

    bool signer::is_liquid() const { return m_is_liquid; }

    bool signer::is_watch_only() const { return m_device["device_type"] == "watch-only"; }

    bool signer::is_hardware() const { return m_device["device_type"] == "hardware"; }

    const nlohmann::json& signer::get_device() const { return m_device; }

    xpub_t signer::get_xpub(uint32_span_t path)
    {
        ext_key* hdkey = m_master_key.get();
        GDK_RUNTIME_ASSERT(hdkey);
        wally_ext_key_ptr derived;
        if (!path.empty()) {
            derived = derive(m_master_key, path);
            hdkey = derived.get();
        }
        return make_xpub(hdkey);
    }

    std::string signer::get_bip32_xpub(uint32_span_t path)
    {
        ext_key* hdkey = m_master_key.get();
        GDK_RUNTIME_ASSERT(hdkey);
        wally_ext_key_ptr derived;
        if (!path.empty()) {
            derived = derive(m_master_key, path);
            hdkey = derived.get();
        }
        return base58check_from_bytes(bip32_key_serialize(*hdkey, BIP32_FLAG_KEY_PUBLIC));
    }

    ecdsa_sig_t signer::sign_hash(uint32_span_t path, byte_span_t hash)
    {
        GDK_RUNTIME_ASSERT(m_master_key.get());
        wally_ext_key_ptr derived = derive(m_master_key, path);
        return ec_sig_from_bytes(gsl::make_span(derived->priv_key).subspan(1), hash);
    }

    bool signer::has_master_blinding_key() const { return m_master_blinding_key.has_value(); }

    blinding_key_t signer::get_master_blinding_key() const
    {
        GDK_RUNTIME_ASSERT(has_master_blinding_key());
        return m_master_blinding_key.get();
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
            m_master_blinding_key = key;
        }
    }

    priv_key_t signer::get_blinding_key_from_script(byte_span_t script)
    {
        GDK_RUNTIME_ASSERT(has_master_blinding_key());
        return asset_blinding_key_to_ec_private_key(*m_master_blinding_key, script);
    }

    std::vector<unsigned char> signer::get_blinding_pubkey_from_script(byte_span_t script)
    {
        return ec_public_key_from_private_key(get_blinding_key_from_script(script));
    }

} // namespace sdk
} // namespace ga
